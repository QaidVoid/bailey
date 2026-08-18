//! Enforcement backend.
//!
//! Builds a deny-by-default confinement from a [`Policy`] and runs the target
//! under it. Filesystem and network access are enforced with Landlock, the
//! syscall surface is trimmed with seccomp, and resource limits are applied
//! best-effort with cgroup v2. All of this is unprivileged on a kernel with
//! Landlock and does not require a setuid binary or a daemon.
//!
//! Landlock is additive and deny-by-default: only the paths and ports granted
//! by the policy are reachable. Because the target's dynamic linker and shared
//! libraries are themselves filesystem access, a policy must grant read and
//! execute on the system paths a program needs, or it will not start. The
//! bundled profiles exist to supply those defaults.

use std::collections::BTreeMap;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use enumflags2::BitFlags;
use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};

use crate::backend::isolation::{self, BindMount, Conceal, IsolationPlan};
use crate::backend::network::{self, NetworkMode};
use crate::backend::world::{self, World};
use crate::backend::{Backend, BackendError, Target};
use crate::policy::{self, Egress, Policy, ResourceLimits};

/// Landlock ABI the backend targets. Best-effort compatibility degrades this
/// gracefully on older kernels.
///
/// ABI 6 (Linux 6.12) adds scoping, which is what keeps a target away from
/// abstract UNIX sockets and from signalling processes outside the sandbox. It
/// adds no filesystem access rights over ABI 5, so raising the target does not
/// change how a policy's grants are interpreted.
const TARGET_ABI: ABI = ABI::V6;

/// Default size of the private `/tmp` when the policy does not set one.
const DEFAULT_TMP_BYTES: u64 = 64 * 1024 * 1024;

/// Default size of the private `/dev/shm`. Graphics and audio stacks use it for
/// buffers, so it is more generous than `/tmp`.
const DEFAULT_SHM_BYTES: u64 = 256 * 1024 * 1024;

/// Deny-by-default enforcement backend.
#[derive(Debug, Default)]
pub struct EnforceBackend {
    /// Reconstruct the target's world with namespaces (defense in depth).
    pub isolate: bool,
}

impl Backend for EnforceBackend {
    fn run(&self, policy: &Policy, target: &Target) -> Result<i32, BackendError> {
        report_degradation(policy);

        let seccomp = build_seccomp_filter()
            .map_err(|err| BackendError::Unsupported(format!("seccomp: {err}")))?;

        // User namespaces gate both the isolation layer and the network
        // namespace, so the host is probed once for both.
        let userns = isolation::available();
        let mode = network::select(policy, userns);
        network::report(mode, policy);

        let isolated = self.isolate && userns;
        let world = World::derive(&target.program, policy, isolated);
        world.prepare().map_err(BackendError::Io)?;
        if isolated && !world.kept_invocation_dir {
            eprintln!(
                "bailey: warning: the working directory is not granted, so it is \
                 absent under isolation; starting in {} instead",
                world.cwd.display()
            );
        }

        let mut plan = LandlockPlan::from_policy(policy);
        plan.add_world_grants(&world);

        let isolation = if self.isolate {
            if userns {
                Some(build_isolation_plan(policy, mode, &world))
            } else {
                eprintln!(
                    "bailey: warning: unprivileged user namespaces unavailable; \
                     running without namespace isolation"
                );
                None
            }
        } else {
            None
        };

        if isolation.is_none() {
            report_unenforceable_denials(policy);
        }

        // Without the isolation layer, the network namespace is entered on its
        // own, so a plain `bailey run` still gets real egress denial.
        let network_only = isolation.is_none() && mode == NetworkMode::Isolated;

        // The cgroup is created before the fork so the target can join it from
        // `pre_exec`. Joining before exec is what makes the limits cover every
        // process the target goes on to create.
        let cgroup = CgroupGuard::create(&policy.resources);
        let procs = cgroup.procs_path();

        let mut command = Command::new(&target.program);
        command.args(&target.args);
        // The environment is built rather than inherited, so a caller's
        // credentials do not cross into the sandbox.
        command.env_clear();
        command.envs(world::environment(policy, &world));
        // Under isolation the working directory is entered after the pivot,
        // since the path only exists in the reconstructed root. Outside it, the
        // caller's directory is simply inherited.
        if let Some(cwd) = &target.cwd {
            command.current_dir(cwd);
        }
        let staging = isolation.as_ref().map(|plan| plan.staging.clone());

        // Safety: the closure runs in the forked child before exec. Bailey is
        // single-threaded at this point, so the usual fork-safety hazard of
        // touching another thread's locks does not apply. Namespaces and the
        // reconstructed root are set up first, then Landlock is applied against
        // the new root, then seccomp closes the syscall surface last.
        unsafe {
            command.pre_exec(move || {
                set_no_new_privs()?;
                // Before the namespaces, while the host's cgroup filesystem is
                // still reachable.
                if let Some(procs) = &procs {
                    std::fs::write(procs, "0")?;
                }
                if let Some(isolation) = &isolation {
                    isolation::enter(isolation)?;
                } else if network_only {
                    network::enter_isolated()?;
                }
                plan.apply()?;
                seccompiler::apply_filter(&seccomp)
                    .map_err(|err| io::Error::other(format!("seccomp: {err}")))?;
                Ok(())
            });
        }

        let mut child = command.spawn().map_err(BackendError::Io)?;
        let status = child.wait().map_err(BackendError::Io)?;
        drop(cgroup);
        // The staging directory was only ever a mountpoint in the target's own
        // namespace; on the host it is an empty directory to clean up.
        if let Some(staging) = staging {
            let _ = std::fs::remove_dir(&staging);
        }
        Ok(status.code().unwrap_or(-1))
    }
}

/// The Landlock rules derived from a policy, owned so it can move into the
/// `pre_exec` closure.
struct LandlockPlan {
    filesystem: Vec<(PathBuf, BitFlags<AccessFs>)>,
    handle_connect: bool,
    handle_bind: bool,
    connect_ports: Vec<u16>,
    bind_ports: Vec<u16>,
}

impl LandlockPlan {
    fn from_policy(policy: &Policy) -> Self {
        let mut filesystem = Vec::new();
        for rule in &policy.filesystem {
            if let Some(bits) = fs_access_bits(rule.access) {
                filesystem.push((rule.path.clone(), bits));
            }
        }
        for rule in &policy.devices {
            if let Some(bits) = fs_access_bits(rule.access) {
                filesystem.push((rule.path.clone(), bits));
            }
        }

        let (handle_connect, connect_ports) = match &policy.network.egress {
            Egress::AllowAll => (false, Vec::new()),
            Egress::DenyAll => (true, Vec::new()),
            Egress::Allow(rules) => (true, rules.iter().filter_map(|rule| rule.port).collect()),
        };
        let handle_bind = handle_connect || !policy.network.bind_ports.is_empty();

        Self {
            filesystem,
            handle_connect,
            handle_bind,
            connect_ports,
            bind_ports: policy.network.bind_ports.clone(),
        }
    }

    /// Grant the writable areas the sandbox itself provides.
    ///
    /// These are not in the policy, because they are decided when the world is
    /// built: a private home the target may write to, and, under isolation, the
    /// private `/tmp` and `/dev/shm` that replace the host's shared ones.
    fn add_world_grants(&mut self, world: &World) {
        let read_write = AccessFs::from_read(TARGET_ABI) | AccessFs::from_write(TARGET_ABI);
        if world.home_host.is_some() {
            self.filesystem
                .push((world.home_inside.clone(), read_write));
        }
        if world.private_tmp {
            self.filesystem.push((PathBuf::from("/tmp"), read_write));
        }
        if world.private_shm {
            self.filesystem
                .push((PathBuf::from("/dev/shm"), read_write));
        }
    }

    fn apply(&self) -> io::Result<()> {
        let mut net = BitFlags::<AccessNet>::empty();
        if self.handle_connect {
            net |= AccessNet::ConnectTcp;
        }
        if self.handle_bind {
            net |= AccessNet::BindTcp;
        }

        let mut ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(TARGET_ABI))
            .map_err(landlock_err)?;
        if !net.is_empty() {
            ruleset = ruleset.handle_access(net).map_err(landlock_err)?;
        }
        // Abstract UNIX sockets live outside the filesystem, so no path rule can
        // reach them, and signals are not filesystem access at all. Scoping is
        // the only rule that covers either. Older kernels drop it best-effort.
        ruleset = ruleset
            .scope(Scope::from_all(TARGET_ABI))
            .map_err(landlock_err)?;

        let mut created = ruleset.create().map_err(landlock_err)?;
        for (path, access) in &self.filesystem {
            match PathFd::new(path) {
                Ok(fd) => {
                    created = created
                        .add_rule(PathBeneath::new(fd, *access))
                        .map_err(landlock_err)?;
                }
                // A granted path that does not exist is skipped rather than
                // aborting the whole run.
                Err(_) => continue,
            }
        }
        for port in &self.connect_ports {
            created = created
                .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                .map_err(landlock_err)?;
        }
        for port in &self.bind_ports {
            created = created
                .add_rule(NetPort::new(*port, AccessNet::BindTcp))
                .map_err(landlock_err)?;
        }

        let status = created.restrict_self().map_err(landlock_err)?;
        if status.ruleset == RulesetStatus::NotEnforced {
            eprintln!("bailey: warning: Landlock is not enforced by this kernel");
        }
        Ok(())
    }
}

/// Build the bind-mount and concealment set for isolation from the policy.
///
/// Nested paths under an already-included directory are skipped (they come
/// along with the parent bind), and `/proc` is omitted because a fresh `/proc`
/// is mounted in the new PID namespace.
///
/// A denied path is never bound. Where a denial sits beneath a path that is
/// bound, it arrives with its parent and is covered over instead, which is what
/// makes a nested denial enforceable: Landlock rules can only add access.
fn build_isolation_plan(policy: &Policy, mode: NetworkMode, world: &World) -> IsolationPlan {
    let denied = |path: &Path| policy.denied.iter().any(|deny| path.starts_with(deny));

    let mut paths: Vec<PathBuf> = policy
        .filesystem
        .iter()
        .map(|rule| rule.path.clone())
        .chain(policy.devices.iter().map(|rule| rule.path.clone()))
        .filter(|path| !path.starts_with("/proc"))
        .filter(|path| !denied(path))
        .collect();
    paths.sort();
    paths.dedup();

    let mut binds = Vec::new();
    let mut roots: Vec<PathBuf> = Vec::new();
    for path in paths {
        if roots.iter().any(|root| path.starts_with(root)) {
            continue;
        }
        let is_dir = std::fs::metadata(&path)
            .map(|meta| meta.is_dir())
            .unwrap_or(false);
        if !path.exists() {
            continue;
        }
        if is_dir {
            roots.push(path.clone());
        }
        binds.push(BindMount {
            source: path,
            is_dir,
        });
    }

    let conceal = policy
        .denied
        .iter()
        .filter(|path| binds.iter().any(|bind| path.starts_with(&bind.source)))
        .filter_map(|path| {
            let is_dir = std::fs::metadata(path).ok()?.is_dir();
            Some(Conceal {
                path: path.clone(),
                is_dir,
            })
        })
        .collect();

    IsolationPlan {
        binds,
        conceal,
        network: mode == NetworkMode::Isolated,
        home: world
            .home_host
            .as_ref()
            .map(|host| (host.clone(), world.home_inside.clone())),
        private_tmp: world.private_tmp,
        tmp_bytes: policy.resources.tmp_bytes.unwrap_or(DEFAULT_TMP_BYTES),
        private_shm: world.private_shm,
        shm_bytes: policy.resources.shm_bytes.unwrap_or(DEFAULT_SHM_BYTES),
        cwd: world.cwd.clone(),
        staging: PathBuf::from(format!("/tmp/.bailey-root.{}", std::process::id())),
    }
}

fn fs_access_bits(access: policy::Access) -> Option<BitFlags<AccessFs>> {
    let mut bits = BitFlags::<AccessFs>::empty();
    if access.contains(policy::Access::READ) {
        bits |= AccessFs::from_read(TARGET_ABI);
    }
    if access.contains(policy::Access::WRITE) {
        bits |= AccessFs::from_write(TARGET_ABI);
    }
    if access.contains(policy::Access::EXECUTE) {
        bits |= AccessFs::Execute;
    }
    if bits.is_empty() { None } else { Some(bits) }
}

fn landlock_err(err: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("landlock: {err}"))
}

/// Report denials that cannot be honored without the isolation layer.
///
/// A denial beneath a granted parent is enforced by covering the path over
/// inside the mount namespace. With isolation off there is no mechanism for it,
/// so the run says so rather than leaving the policy quietly weaker than it
/// reads.
fn report_unenforceable_denials(policy: &Policy) {
    for path in policy.nested_denials() {
        eprintln!(
            "bailey: warning: `{}` is denied but nested under a granted path, \
             and is not enforced without `--isolate`. Grant the specific \
             subdirectories you need instead of granting the parent.",
            path.display()
        );
    }
}

fn report_degradation(policy: &Policy) {
    if let Egress::Allow(rules) = &policy.network.egress
        && rules.iter().any(|rule| rule.host != "*")
    {
        eprintln!(
            "bailey: warning: host-based egress rules are not enforced by Landlock; \
                 outbound access is limited by TCP port only"
        );
    }
}

fn set_no_new_privs() -> io::Result<()> {
    // Required before applying seccomp or Landlock without CAP_SYS_ADMIN.
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Syscalls denied to the target. These are not needed by normal applications
/// and are common building blocks for sandbox escape, privilege escalation, or
/// tampering with other processes.
fn denied_syscalls() -> &'static [i64] {
    &[
        libc::SYS_ptrace,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_open_by_handle_at,
        libc::SYS_acct,
    ]
}

fn build_seccomp_filter() -> anyhow::Result<seccompiler::BpfProgram> {
    use seccompiler::{SeccompAction, SeccompFilter};

    let mut rules = BTreeMap::new();
    for &nr in denied_syscalls() {
        // An empty rule vector matches the syscall unconditionally.
        rules.insert(nr, Vec::new());
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        target_arch()?,
    )?;
    Ok(filter.try_into()?)
}

fn target_arch() -> anyhow::Result<seccompiler::TargetArch> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(seccompiler::TargetArch::x86_64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Ok(seccompiler::TargetArch::aarch64)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        anyhow::bail!("unsupported architecture for seccomp")
    }
}

/// Applies cgroup v2 resource limits for the duration of a run and removes the
/// cgroup when dropped. All operations are best-effort: on a system without a
/// writable delegated cgroup the limits are skipped with a warning rather than
/// failing the run.
///
/// The cgroup is created before the target is spawned; the target joins it
/// itself from `pre_exec`, so membership is inherited by everything it forks.
struct CgroupGuard {
    dir: Option<PathBuf>,
}

impl CgroupGuard {
    fn create(limits: &ResourceLimits) -> Self {
        if limits.memory_bytes.is_none()
            && limits.pids_max.is_none()
            && limits.cpu_percent.is_none()
        {
            return Self { dir: None };
        }
        match try_create_cgroup(limits) {
            Ok(dir) => Self { dir: Some(dir) },
            Err(err) => {
                eprintln!("bailey: warning: resource limits not applied: {err}");
                Self { dir: None }
            }
        }
    }

    /// The `cgroup.procs` path the target writes itself into before exec.
    fn procs_path(&self) -> Option<PathBuf> {
        self.dir.as_ref().map(|dir| dir.join("cgroup.procs"))
    }
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        if let Some(dir) = &self.dir {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

fn try_create_cgroup(limits: &ResourceLimits) -> io::Result<PathBuf> {
    let base = current_cgroup()?;
    let dir = base.join(format!("bailey.{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;

    if let Some(memory) = limits.memory_bytes {
        std::fs::write(dir.join("memory.max"), memory.to_string())?;
    }
    if let Some(pids) = limits.pids_max {
        std::fs::write(dir.join("pids.max"), pids.to_string())?;
    }
    if let Some(cpu) = limits.cpu_percent {
        let quota = u64::from(cpu) * 1000;
        std::fs::write(dir.join("cpu.max"), format!("{quota} 100000"))?;
    }

    Ok(dir)
}

fn current_cgroup() -> io::Result<PathBuf> {
    let content = std::fs::read_to_string("/proc/self/cgroup")?;
    let relative = content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| io::Error::other("no cgroup v2 membership in /proc/self/cgroup"))?
        .trim();
    let relative = relative.strip_prefix('/').unwrap_or(relative);
    Ok(Path::new("/sys/fs/cgroup").join(relative))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Access, DeviceRule, FsRule};

    #[test]
    fn read_grant_maps_to_read_and_execute_bits() {
        let read = fs_access_bits(Access::READ).unwrap();
        assert!(read.contains(AccessFs::from_read(TARGET_ABI)));

        let exec = fs_access_bits(Access::EXECUTE).unwrap();
        assert!(exec.contains(AccessFs::Execute));

        assert!(fs_access_bits(Access::empty()).is_none());
    }

    #[test]
    fn plan_includes_devices_and_derives_net_handling() {
        let mut policy = Policy::default();
        policy.filesystem.push(FsRule {
            path: PathBuf::from("/usr"),
            access: Access::READ | Access::EXECUTE,
        });
        policy.devices.push(DeviceRule {
            path: PathBuf::from("/dev/dri"),
            access: Access::READ | Access::WRITE,
        });

        let plan = LandlockPlan::from_policy(&policy);
        assert_eq!(plan.filesystem.len(), 2);
        // Default egress is DenyAll, so connect is handled with no allowed ports.
        assert!(plan.handle_connect);
        assert!(plan.connect_ports.is_empty());
    }

    #[test]
    fn seccomp_filter_builds() {
        assert!(build_seccomp_filter().is_ok());
    }
}
