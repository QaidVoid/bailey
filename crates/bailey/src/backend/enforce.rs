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

use crate::backend::cgroup;
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

/// Prefix of the host-visible directory a reconstructed root is staged in.
const STAGING_PREFIX: &str = ".bailey-root.";

/// Default size of the private `/tmp` when the policy does not set one.
const DEFAULT_TMP_BYTES: u64 = 64 * 1024 * 1024;

/// Default size of the private `/dev/shm`. Graphics and audio stacks use it for
/// buffers, so it is more generous than `/tmp`.
const DEFAULT_SHM_BYTES: u64 = 256 * 1024 * 1024;

/// What a run actually enforced.
///
/// Every layer can be absent or partial on a given host, and each one degrades
/// quietly by design so a program still runs. The summary is what keeps that
/// from being indistinguishable from a run that enforced nothing.
#[derive(Debug, Default, Clone)]
pub struct RunReport {
    /// Layers that were applied.
    pub applied: Vec<String>,
    /// Layers the host could not provide, with the reason.
    ///
    /// A layer the user chose not to use is not a gap and is not listed here:
    /// the summary exists to surface what was taken away, not to restate the
    /// command line.
    pub skipped: Vec<(String, String)>,
}

impl RunReport {
    fn applied(&mut self, layer: &str) {
        self.applied.push(layer.to_owned());
    }

    fn skipped(&mut self, layer: &str, reason: &str) {
        self.skipped.push((layer.to_owned(), reason.to_owned()));
    }

    /// Print what the run enforced, without an exit status.
    fn print_established(&self) {
        eprintln!("bailey: enforced: {}", self.applied.join(", "));
        for (layer, reason) in &self.skipped {
            eprintln!("bailey: not enforced, {layer}: {reason}");
        }
    }

    /// Print the summary for a person.
    pub fn print(&self, exit_code: i32) {
        self.print_established();
        if exit_code != 0 {
            eprintln!("bailey: target exited with {exit_code}");
        }
    }

    /// Render the summary as JSON, for a caller that is not a person.
    pub fn to_json(&self, exit_code: i32) -> String {
        let applied: Vec<String> = self.applied.iter().map(|l| format!("\"{l}\"")).collect();
        let skipped: Vec<String> = self
            .skipped
            .iter()
            .map(|(layer, reason)| format!("{{\"layer\":\"{layer}\",\"reason\":\"{reason}\"}}"))
            .collect();
        format!(
            "{{\"applied\":[{}],\"skipped\":[{}],\"exit_code\":{}}}",
            applied.join(","),
            skipped.join(","),
            exit_code
        )
    }
}

/// Deny-by-default enforcement backend.
#[derive(Debug, Default)]
pub struct EnforceBackend {
    /// Reconstruct the target's world with namespaces (defense in depth).
    pub isolate: bool,
    /// Stop the target just before it executes, so a caller can attach
    /// something to it before it runs. The caller is then responsible for
    /// continuing it.
    pub stop_before_exec: bool,
    /// How to report what the run enforced.
    pub summary: Summary,
    /// Put the target in a cgroup of its own even when the policy sets no
    /// limits, so something else can scope to it.
    pub always_cgroup: bool,
    /// Writable paths granted on the user's behalf rather than by their config.
    ///
    /// A grant beneath one of these that the user wrote without write access is
    /// kept unwritable, since they never asked for the wider grant that would
    /// otherwise swallow it. The private home and private temporary storage are
    /// found from the world; this is for the ones a command adds, such as a
    /// confined shell's launch directory.
    pub implicit_write: Vec<PathBuf>,
}

/// How a run reports what it enforced.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Summary {
    /// A short block on stderr after the target exits.
    #[default]
    Text,
    /// A short block on stderr once the sandbox is established, before the
    /// target is spawned.
    ///
    /// For a target that takes the terminal and holds it, such as a shell, a
    /// summary printed on exit arrives after it stopped being useful. Printing
    /// before the fork rather than after it is what keeps the target's own
    /// first output from racing ahead of the summary.
    Established,
    /// One line of JSON, for a caller that parses it.
    Json,
    /// Nothing.
    Quiet,
}

impl Backend for EnforceBackend {
    fn run(&self, policy: &Policy, target: &Target) -> Result<i32, BackendError> {
        let confined = self.spawn(policy, target)?;
        confined.wait()
    }
}

impl EnforceBackend {
    /// Establish the confinement and spawn the target under it, without waiting.
    ///
    /// This is what lets the audit backend confine and observe the same process:
    /// it needs the target's PID, and needs the target held, before letting it
    /// run.
    pub fn spawn(&self, policy: &Policy, target: &Target) -> Result<Confined, BackendError> {
        report_degradation(policy);

        let seccomp = build_seccomp_filter()
            .map_err(|err| BackendError::Unsupported(format!("seccomp: {err}")))?;

        // User namespaces gate both the isolation layer and the network
        // namespace, so the host is probed once for both.
        let userns = isolation::available();
        // Inside a sandbox the probe fails because our own seccomp filter denies
        // `unshare`, not because the host lacks anything. The namespaces of the
        // outer sandbox are still in force: they are properties of the process,
        // inherited and impossible to drop.
        let nested = world::inside_sandbox();
        let inherited = network::Inherited::detect();
        let mode = network::select(policy, userns);
        network::report(mode, policy, inherited);

        let mut report = RunReport::default();
        report.applied("landlock");
        report.applied("seccomp");
        match mode {
            NetworkMode::Isolated => report.applied("network namespace"),
            NetworkMode::LandlockOnly
                if !userns && inherited == network::Inherited::IsolatedNamespace =>
            {
                report.applied("network namespace (inherited)")
            }
            NetworkMode::LandlockOnly if !userns && nested => report.skipped(
                "network namespace",
                "inside a sandbox that did not create one, so only TCP is restricted",
            ),
            // A policy that allows egress cannot use an empty namespace, which
            // is a consequence of the policy rather than a gap in the host.
            NetworkMode::LandlockOnly if !userns => report.skipped(
                "network namespace",
                "unprivileged user namespaces unavailable, so only TCP is restricted",
            ),
            NetworkMode::LandlockOnly => {}
        }

        let isolated = self.isolate && userns;
        let world = World::derive(&target.program, policy, isolated);
        world.prepare(nested).map_err(BackendError::Io)?;
        if isolated && !world.kept_invocation_dir {
            // Naming the host path matters: inside the sandbox the private home
            // sits at the real home's path, so printing that would read as
            // "it started in your home directory", which is the opposite of
            // what happened.
            let landed = world
                .home_host
                .as_deref()
                .unwrap_or(world.cwd.as_path())
                .display();
            eprintln!(
                "bailey: warning: the working directory is not granted, so it is \
                 absent under isolation; starting in the private home instead \
                 ({landed}). Grant the directory to keep it."
            );
        }

        let mut plan = LandlockPlan::from_policy(policy);
        plan.add_world_grants(&world);

        let isolation = if self.isolate {
            if userns {
                report.applied("namespace isolation");
                Some(build_isolation_plan(
                    policy,
                    mode,
                    &world,
                    &self.implicit_write,
                ))
            } else if nested {
                // A second world cannot be built, and does not need to be: this
                // process is already inside one that it cannot leave.
                report.applied("namespace isolation (inherited)");
                None
            } else {
                report.skipped(
                    "namespace isolation",
                    "unprivileged user namespaces unavailable",
                );
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
            report_unenforceable_denials(policy, nested);
        }

        // Without the isolation layer, the network namespace is entered on its
        // own, so a plain `bailey run` still gets real egress denial.
        let network_only = isolation.is_none() && mode == NetworkMode::Isolated;

        // The cgroup is created before the fork so the target can join it from
        // `pre_exec`. Joining before exec is what makes the limits cover every
        // process the target goes on to create.
        let cgroup = CgroupGuard::create(&policy.resources, self.always_cgroup);
        let procs = cgroup.procs_path();
        if policy.resources == ResourceLimits::default() {
            // The policy asked for none, so there is nothing to report.
        } else if procs.is_some() {
            report.applied("resource limits");
        } else {
            report.skipped(
                "resource limits",
                cgroup
                    .failure
                    .as_deref()
                    .unwrap_or("no writable delegated cgroup"),
            );
        }

        let mut command = Command::new(&target.program);
        command.args(&target.args);
        // The environment is built rather than inherited, so a caller's
        // credentials do not cross into the sandbox.
        command.env_clear();
        command.envs(world::environment(policy, &world, mode));
        // Under isolation the working directory is entered after the pivot,
        // since the path only exists in the reconstructed root. Outside it, the
        // caller's directory is simply inherited.
        if let Some(cwd) = &target.cwd {
            command.current_dir(cwd);
        }
        let staging = StagingGuard {
            dir: isolation.as_ref().map(|plan| plan.staging.clone()),
        };
        let stop_before_exec = self.stop_before_exec;

        // Safety: the closure runs in the forked child before exec. Bailey is
        // single-threaded at this point, so the usual fork-safety hazard of
        // touching another thread's locks does not apply. Namespaces and the
        // reconstructed root are set up first, then Landlock is applied against
        // the new root, then seccomp closes the syscall surface last.
        unsafe {
            command.pre_exec(move || {
                set_no_new_privs()?;
                if stop_before_exec {
                    // Trace ourselves, so the kernel stops this process at
                    // `execve` rather than before it. Stopping earlier would
                    // deadlock: the parent's spawn does not return until this
                    // process execs or fails.
                    libc::ptrace(
                        libc::PTRACE_TRACEME,
                        0,
                        std::ptr::null_mut::<libc::c_void>(),
                        std::ptr::null_mut::<libc::c_void>(),
                    );
                }
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

        if self.summary == Summary::Established {
            report.print_established();
        }

        let child = command.spawn().map_err(BackendError::Io)?;
        Ok(Confined {
            child,
            cgroup,
            staging,
            report,
            summary: self.summary,
        })
    }
}

/// Removes the host-visible staging directory a reconstructed root was built
/// in, however the run ends.
///
/// Cleanup used to happen only on the success path, so a `pre_exec` that failed
/// after creating the directory, or a caller that dropped the run without
/// waiting, left one behind for every attempt.
struct StagingGuard {
    dir: Option<PathBuf>,
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if let Some(dir) = &self.dir {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

/// A target running under enforcement, not yet waited on.
pub struct Confined {
    child: std::process::Child,
    cgroup: CgroupGuard,
    staging: StagingGuard,
    report: RunReport,
    summary: Summary,
}

impl Confined {
    /// The target's process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The id of the cgroup the target belongs to, when it has one of its own.
    pub fn cgroup_id(&self) -> Option<u64> {
        self.cgroup.id()
    }

    /// Wait for the target to exit and tear the run's world down.
    pub fn wait(mut self) -> Result<i32, BackendError> {
        let status = self.child.wait().map_err(BackendError::Io)?;
        drop(self.cgroup);
        // The staging directory was only ever a mountpoint in the target's own
        // namespace; on the host it is an empty directory, removed when the
        // guard drops.
        drop(self.staging);
        let code = status.code().unwrap_or(-1);
        match self.summary {
            Summary::Text => self.report.print(code),
            Summary::Json => println!("{}", self.report.to_json(code)),
            // Already printed, before the target ever ran.
            Summary::Established | Summary::Quiet => {}
        }
        Ok(code)
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
        if let Some(terminal) = &world.terminal {
            self.filesystem.push((terminal.clone(), read_write));
        }
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
/// Remove staging directories belonging to runs that are no longer alive.
///
/// [`StagingGuard`] removes the directory on every path a run can return by, but
/// a signal does not unwind: a Ctrl-C, or anything else that sends SIGINT or
/// SIGTERM, leaves it behind. Sweeping before making our own means the leak
/// heals on the next run rather than accumulating one directory per interrupted
/// run.
///
/// This can only ever remove an empty directory. On the host the staging path is
/// a bare mountpoint, since the tmpfs and everything built on it live in the
/// target's own mount namespace, so `remove_dir` refusing a non-empty directory
/// is the guarantee that nothing else can be caught by this.
fn sweep_stale_staging() {
    let Ok(entries) = std::fs::read_dir("/tmp") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(owner) = name
            .to_str()
            .and_then(|name| name.strip_prefix(STAGING_PREFIX))
        else {
            continue;
        };
        // A directory whose owner is still running belongs to a run in progress,
        // which may well be a concurrent one.
        if Path::new("/proc").join(owner).exists() {
            continue;
        }
        // Another user's leftovers are not ours to remove, and saying so would
        // be noise on every run.
        let _ = std::fs::remove_dir(entry.path());
    }
}

fn build_isolation_plan(
    policy: &Policy,
    mode: NetworkMode,
    world: &World,
    implicit_write: &[PathBuf],
) -> IsolationPlan {
    sweep_stale_staging();

    let denied = |path: &Path| policy.denied.iter().any(|deny| path.starts_with(deny));

    let mut paths: Vec<PathBuf> = policy
        .filesystem
        .iter()
        .map(|rule| rule.path.clone())
        .chain(policy.devices.iter().map(|rule| rule.path.clone()))
        // The terminal has to exist inside the reconstructed root, or a program
        // that opens its own tty by name finds nothing there.
        .chain(world.terminal.clone())
        .filter(|path| !path.starts_with("/proc"))
        .filter(|path| !denied(path))
        .collect();
    paths.sort();
    paths.dedup();

    // What the policy names, before any of it is turned into mounts: a symlink
    // is only worth preserving when following it lands somewhere granted.
    let granted: Vec<PathBuf> = paths.clone();

    let mut binds = Vec::new();
    let mut links = Vec::new();
    let mut roots: Vec<PathBuf> = Vec::new();
    for path in paths {
        if roots.iter().any(|root| path.starts_with(root)) {
            continue;
        }
        if !path.exists() {
            continue;
        }
        // A symlink is recreated rather than bound when the policy already
        // provides what it points at. Binding through it would put a regular
        // file where the link was, and a program that resolves paths relative to
        // itself, an interpreter loading its own modules, then looks beside the
        // link rather than beside the file: node fails to find its own code that
        // way.
        //
        // Where the policy does *not* cover the destination, the link is bound
        // through as before. That is what makes a lone symlinked binary run
        // without granting the store it points into, which is the ordinary case
        // for anything installed by a version manager.
        if let Ok(to) = std::fs::read_link(&path) {
            let resolved = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            let provided = granted.iter().any(|grant| resolved.starts_with(grant));
            // Files only. A link to a directory is a mountpoint other paths are
            // placed under, and on a system where `/bin` is a link to `usr/bin`,
            // recreating it means the next path beneath it is created inside the
            // bound `/usr` rather than in the new root.
            let to_file = std::fs::metadata(&resolved)
                .map(|meta| meta.is_file())
                .unwrap_or(false);
            if provided && to_file {
                links.push(isolation::SymLink { at: path, to });
                continue;
            }
        }
        let is_dir = std::fs::metadata(&path)
            .map(|meta| meta.is_dir())
            .unwrap_or(false);
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

    let mut read_only = policy.read_only.clone();
    read_only.extend(unwritable_beneath_implicit(policy, world, implicit_write));

    IsolationPlan {
        binds,
        links,
        conceal,
        read_only,
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
        staging: PathBuf::from(format!("/tmp/{STAGING_PREFIX}{}", std::process::id())),
    }
}

/// Granted paths that sit beneath something bailey granted for writing on the
/// user's behalf, and that the user did not grant for writing.
///
/// Bailey adds grants nobody wrote, because a policy that cannot reach the thing
/// it is about is not a policy: the private home, private temporary storage, and
/// a confined shell's launch directory. Landlock rights only add, so a writable
/// implicit grant covers every narrower grant beneath it and the narrower one
/// cannot take the right back. A user who wrote `read` would get write, and the
/// write would reach the host file through the bind mount.
///
/// Remounting those paths read-only is what holds the grant the user actually
/// wrote. It is the same mechanism a `read_only` island uses, and the VFS
/// enforces it whatever Landlock says.
///
/// This deliberately does not apply to two grants the *user* wrote. Granting
/// write on a directory and read on something beneath it resolves to a writable
/// path, which is the documented merge rule and is what they asked for.
fn unwritable_beneath_implicit(
    policy: &Policy,
    world: &World,
    implicit: &[PathBuf],
) -> Vec<PathBuf> {
    let mut roots: Vec<&Path> = implicit.iter().map(PathBuf::as_path).collect();
    if world.home_host.is_some() {
        roots.push(&world.home_inside);
    }
    if roots.is_empty() {
        return Vec::new();
    }

    policy
        .filesystem
        .iter()
        .filter(|rule| !rule.access.contains(policy::Access::WRITE))
        .map(|rule| &rule.path)
        .filter(|path| {
            roots
                .iter()
                .any(|root| path.as_path() != *root && path.starts_with(root))
        })
        .cloned()
        .collect()
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
fn report_unenforceable_denials(policy: &Policy, nested: bool) {
    // Inside a sandbox there is no `--no-isolate` to drop: the mount namespace
    // cannot be rebuilt at all, so pointing at the flag would send someone after
    // a fix that does not exist. What the outer sandbox itself denied is still
    // denied; it is this run's own additions that have nowhere to go.
    let remedy = if nested {
        "this run is inside another sandbox, which cannot build a second world; \
         the outer sandbox's own denials still apply"
    } else {
        "drop `--no-isolate` to enforce it"
    };
    for path in policy.nested_read_only() {
        eprintln!(
            "bailey: warning: `{}` is marked read-only inside a writable grant, \
             which a mount namespace enforces; this run has none, so it stays \
             writable. {remedy}.",
            path.display()
        );
    }
    for path in policy.nested_denials() {
        eprintln!(
            "bailey: warning: `{}` is denied but nested under a granted path, \
             and is not enforced without namespace isolation. {remedy}.",
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

/// `kexec_file_load`, which libc does not name on every target it exists on.
///
/// The syscall is present on aarch64, but the musl bindings have no constant for
/// it, so naming it through libc alone makes the crate build for glibc and not
/// for musl. The number is stable kernel ABI.
#[cfg(all(target_arch = "aarch64", target_env = "musl"))]
const SYS_KEXEC_FILE_LOAD: libc::c_long = 294;
#[cfg(not(all(target_arch = "aarch64", target_env = "musl")))]
const SYS_KEXEC_FILE_LOAD: libc::c_long = libc::SYS_kexec_file_load;

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
        SYS_KEXEC_FILE_LOAD,
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
    failure: Option<String>,
}

impl CgroupGuard {
    fn create(limits: &ResourceLimits, even_without_limits: bool) -> Self {
        if !even_without_limits
            && limits.memory_bytes.is_none()
            && limits.pids_max.is_none()
            && limits.cpu_percent.is_none()
        {
            return Self {
                dir: None,
                failure: None,
            };
        }
        match try_create_cgroup(limits) {
            Ok(dir) => Self {
                dir: Some(dir),
                failure: None,
            },
            // Not reported here: the run summary carries it, so a single fact
            // does not appear twice.
            Err(err) => Self {
                dir: None,
                failure: Some(err.to_string()),
            },
        }
    }

    /// The `cgroup.procs` path the target writes itself into before exec.
    fn procs_path(&self) -> Option<PathBuf> {
        self.dir.as_ref().map(|dir| dir.join("cgroup.procs"))
    }

    /// The kernel's id for this cgroup, which is what a BPF program comparing
    /// `bpf_get_current_cgroup_id()` sees. On cgroup v2 it is the directory's
    /// inode number.
    fn id(&self) -> Option<u64> {
        use std::os::unix::fs::MetadataExt;
        let dir = self.dir.as_ref()?;
        std::fs::metadata(dir).ok().map(|meta| meta.ino())
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
    let needed = cgroup::needed_controllers(limits);
    let base = cgroup::usable_root(&needed).ok_or_else(|| {
        io::Error::other(
            "no cgroup this user may create runs in; a delegated subtree is \
             needed, or name one with BAILEY_CGROUP_ROOT",
        )
    })?;
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
