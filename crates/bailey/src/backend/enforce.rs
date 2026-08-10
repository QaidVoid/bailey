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
    Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
};

use crate::backend::isolation::{self, BindMount, IsolationPlan};
use crate::backend::{Backend, BackendError, Target};
use crate::policy::{self, Egress, Policy, ResourceLimits};

/// Landlock ABI the backend targets. Best-effort compatibility degrades this
/// gracefully on older kernels.
const TARGET_ABI: ABI = ABI::V5;

/// Deny-by-default enforcement backend.
#[derive(Debug, Default)]
pub struct EnforceBackend {
    /// Reconstruct the target's world with namespaces (defense in depth).
    pub isolate: bool,
}

impl Backend for EnforceBackend {
    fn run(&self, policy: &Policy, target: &Target) -> Result<i32, BackendError> {
        report_degradation(policy);

        let plan = LandlockPlan::from_policy(policy);
        let seccomp = build_seccomp_filter()
            .map_err(|err| BackendError::Unsupported(format!("seccomp: {err}")))?;

        let isolation = if self.isolate {
            if isolation::available() {
                Some(build_isolation_plan(policy))
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

        let mut command = Command::new(&target.program);
        command.args(&target.args);
        if let Some(cwd) = &target.cwd {
            command.current_dir(cwd);
        }

        // Safety: the closure runs in the forked child before exec. Bailey is
        // single-threaded at this point, so the usual fork-safety hazard of
        // touching another thread's locks does not apply. Namespaces and the
        // reconstructed root are set up first, then Landlock is applied against
        // the new root, then seccomp closes the syscall surface last.
        unsafe {
            command.pre_exec(move || {
                set_no_new_privs()?;
                if let Some(isolation) = &isolation {
                    isolation::enter(isolation)?;
                }
                plan.apply()?;
                seccompiler::apply_filter(&seccomp)
                    .map_err(|err| io::Error::other(format!("seccomp: {err}")))?;
                Ok(())
            });
        }

        let mut child = command.spawn().map_err(BackendError::Io)?;
        let _cgroup = CgroupGuard::apply(&policy.resources, child.id());
        let status = child.wait().map_err(BackendError::Io)?;
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

/// Build the bind-mount set for isolation from the policy's granted paths.
///
/// Nested paths under an already-included directory are skipped (they come
/// along with the parent bind), and `/proc` is omitted because a fresh `/proc`
/// is mounted in the new PID namespace.
fn build_isolation_plan(policy: &Policy) -> IsolationPlan {
    let mut paths: Vec<PathBuf> = policy
        .filesystem
        .iter()
        .map(|rule| rule.path.clone())
        .chain(policy.devices.iter().map(|rule| rule.path.clone()))
        .filter(|path| !path.starts_with("/proc"))
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
    IsolationPlan { binds }
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
struct CgroupGuard {
    dir: Option<PathBuf>,
}

impl CgroupGuard {
    fn apply(limits: &ResourceLimits, pid: u32) -> Self {
        if limits.memory_bytes.is_none()
            && limits.pids_max.is_none()
            && limits.cpu_percent.is_none()
        {
            return Self { dir: None };
        }
        match try_apply_cgroup(limits, pid) {
            Ok(dir) => Self { dir: Some(dir) },
            Err(err) => {
                eprintln!("bailey: warning: resource limits not applied: {err}");
                Self { dir: None }
            }
        }
    }
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        if let Some(dir) = &self.dir {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

fn try_apply_cgroup(limits: &ResourceLimits, pid: u32) -> io::Result<PathBuf> {
    let base = current_cgroup()?;
    let dir = base.join(format!("bailey.{pid}"));
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

    std::fs::write(dir.join("cgroup.procs"), pid.to_string())?;
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
