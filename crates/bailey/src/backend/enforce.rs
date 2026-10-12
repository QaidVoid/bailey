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
use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use enumflags2::BitFlags;
use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};

use crate::backend::cgroup;
use crate::backend::forward;
use crate::backend::fuse;
use crate::backend::isolation::{self, BindMount, Conceal, IsolationPlan, ReadOnly};
use crate::backend::network::{self, NetworkMode};
use crate::backend::relay;
use crate::backend::world::{self, World};
use crate::backend::{Backend, BackendError, Target};
use crate::policy::{self, Egress, FsRule, Policy, PortForward, ResourceLimits};
use crate::strings::quoted as json_string;

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
        let applied: Vec<String> = self.applied.iter().map(|l| json_string(l)).collect();
        let skipped: Vec<String> = self
            .skipped
            .iter()
            .map(|(layer, reason)| {
                format!(
                    "{{\"layer\":{},\"reason\":{}}}",
                    json_string(layer),
                    json_string(reason)
                )
            })
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
    /// The run is already in a namespace whose egress is held to one broker,
    /// so it neither makes a namespace of its own nor reports UDP as open.
    pub egress_broker: bool,
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

        let seccomp = build_seccomp_filter(policy.self_fuse)
            .map_err(|err| BackendError::Unsupported(format!("seccomp: {err}")))?;
        let keep_mount = policy.self_fuse;

        // User namespaces gate both the isolation layer and the network
        // namespace, so the host is probed once for both.
        let userns = isolation::available();
        // Inside a sandbox the probe fails because our own seccomp filter denies
        // `unshare`, not because the host lacks anything. The namespaces of the
        // outer sandbox are still in force: they are properties of the process,
        // inherited and impossible to drop.
        let nested = world::inside_sandbox();
        let inherited = network::Inherited::detect();
        let mode = if self.egress_broker {
            NetworkMode::Brokered
        } else {
            network::select(policy, userns)
        };
        network::report(mode, policy, inherited);
        if network::bind_is_loopback_only(policy, mode) {
            eprintln!(
                "bailey: note: the bound ports are reachable only from inside the sandbox; \
                 this policy denies egress, which keeps it in a network namespace of its own"
            );
        }

        let mut report = RunReport::default();
        // Asked of the kernel rather than assumed, and then asked of the run:
        // on a host without Landlock the ruleset still applies without error
        // and enforces nothing, so claiming it here would report a boundary
        // that is not there. The same is true of a run that keeps the mount
        // power, because a Landlock domain and a new filesystem cannot coexist
        // and the ruleset is the half that gives way.
        match crate::backend::probe::landlock_abi() {
            Some(_) if !keep_mount => report.applied("landlock"),
            Some(_) => report.skipped(
                "landlock",
                "self_fuse keeps the mount power a Landlock domain would remove",
            ),
            None => report.skipped("landlock", "the kernel does not provide Landlock"),
        }
        report.applied("seccomp");
        if policy.self_fuse {
            report.applied("self-serve fuse mounts");
        }
        match mode {
            NetworkMode::Isolated => report.applied("network namespace"),
            NetworkMode::LandlockOnly
                if !userns && inherited == network::Inherited::IsolatedNamespace =>
            {
                report.applied("network namespace (inherited)")
            }
            NetworkMode::LandlockOnly if !userns && inherited == network::Inherited::Brokered => {
                report.applied("egress broker (inherited)")
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
            NetworkMode::Brokered => report.applied("egress broker"),
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

        // Self-serve FUSE is the target holding mount power inside the run's
        // own namespace. Without a namespace to hold, the power would land on
        // the host's, so the run is refused rather than widened.
        if policy.self_fuse && !isolated {
            return Err(BackendError::Command(
                "the policy allows self-serve fuse mounts, which need \
                 namespace isolation to stay inside the run; run without \
                 --no-isolate, or clear `self_fuse`"
                    .into(),
            ));
        }

        // FUSE mounts run as the caller, before any confinement exists, and
        // ride into the sandbox as relocated grants on the extended policy.
        // Everything below sees that policy, so the mounts are bound, placed,
        // and covered by Landlock like any other grant. A policy naming a
        // mount without the isolation that places it is refused, the way a
        // nested denial is.
        let mut fuse_guard = fuse::FuseGuard::default();
        let fuse_policy;
        let policy = if !policy.fuse.is_empty() {
            if !isolated {
                return Err(BackendError::Command(
                    "the policy names fuse mounts, which need namespace \
                     isolation to be placed; run without --no-isolate, or \
                     remove the [[fuse]] entries"
                        .into(),
                ));
            }
            fuse::sweep_stale();
            let run_dir = fuse::run_dir();
            let mounted = fuse::mount_all(&policy.fuse, &run_dir)?;
            for mount in &mounted {
                report.applied(&format!("fuse mount at {}", mount.at().display()));
            }
            fuse_guard = fuse::FuseGuard::new(run_dir, mounted.clone());
            fuse_policy = policy_with_fuse(policy, &mounted);
            &fuse_policy
        } else {
            policy
        };

        // Socket relays listen as the caller, then ride in as binds. Like the
        // FUSE mounts they need isolation to be placed, and they refuse to
        // share a path with a grant: the relay exists to keep the directory
        // holding the real socket ungranted.
        let mut relay_guard: Option<relay::RelayGuard> = None;
        let relay_policy;
        let policy = if !policy.sockets.is_empty() {
            if !isolated {
                return Err(BackendError::Command(
                    "the policy relays sockets, which need namespace isolation \
                     to be placed; run without --no-isolate, or remove the \
                     [[socket]] entries"
                        .into(),
                ));
            }
            for socket in &policy.sockets {
                for rule in &policy.filesystem {
                    let visible = rule.at.as_ref().unwrap_or(&rule.path);
                    if visible.starts_with(&socket.at) || socket.at.starts_with(visible) {
                        return Err(BackendError::Command(format!(
                            "a socket relay at `{}` overlaps the grant on `{}`; \
                             the relay exists to keep that directory ungranted, \
                             so grant the directory or drop the relay",
                            socket.at.display(),
                            visible.display()
                        )));
                    }
                }
            }
            relay::sweep_stale();
            // A brokered URL needs the helper it opens with, and a run whose
            // policy names it should say so before the target starts rather
            // than answer every request with ERR.
            if policy
                .sockets
                .iter()
                .any(|socket| socket.service.as_deref() == Some("url-open"))
            {
                crate::cli::resolve_helper("xdg-open")
                    .map_err(|err| BackendError::Command(format!("the url-open relay: {err}")))?;
            }
            let dir = relay::run_dir();
            let ats: Vec<PathBuf> = policy.sockets.iter().map(|s| s.at.clone()).collect();
            let guard = relay::listen_all(&ats, &dir).map_err(BackendError::Io)?;
            for (relay, socket) in guard.relays().iter().zip(&policy.sockets) {
                let destination = if socket.service.as_deref() == Some("url-open") {
                    relay::Destination::OpenUrl
                } else {
                    relay::Destination::Socket(socket.host.clone())
                };
                relay.serve(destination);
                report.applied(&format!("socket relay at {}", socket.at.display()));
            }
            relay_policy = policy_with_relays(policy, guard.relays());
            relay_guard = Some(guard);
            &relay_policy
        } else {
            policy
        };

        // A forward hands its listener across as a file descriptor, and that
        // only makes sense when the listener is bound somewhere the host is
        // not: inside the target's own loopback. Without the namespace the
        // sandbox side would listen on the host's, and the parent would dial
        // the same stack it already sits on.
        let mut forward_announce: Option<UnixStream> = None;
        let mut forward_child_end: Option<UnixStream> = None;
        let mut forward_forwards: Option<Vec<PortForward>> = None;
        if !policy.forwards.is_empty() {
            if mode != NetworkMode::Isolated {
                // The two reasons read differently to the user: an egress
                // allowance is a choice in the policy they can revisit, while
                // missing namespaces or `--no-isolate` is about the host or
                // the invocation.
                let reason = if !matches!(policy.network.egress, Egress::DenyAll) {
                    "the policy allows egress, which keeps the target in the \
                     host's network namespace, and a forward needs the \
                     sandbox's own loopback; deny egress and reach the \
                     outside through what a forward carries, or remove the \
                     [[forward]] entries"
                } else {
                    "the policy forwards ports, which need the target in a \
                     network namespace of its own; run with isolation on, or \
                     remove the [[forward]] entries"
                };
                return Err(BackendError::Command(reason.into()));
            }
            // The same file can arrive twice, explicit and discovered, and
            // layers can name a forward again. An identical repeat collapses;
            // two destinations for one inside port is a contradiction.
            let mut forwards: Vec<PortForward> = Vec::new();
            for forward in &policy.forwards {
                match forwards.iter_mut().find(|named| named.port == forward.port) {
                    Some(named) if named.host_port == forward.host_port => {}
                    Some(named) => {
                        return Err(BackendError::Command(format!(
                            "two forwards dial out from port {}: one to host \
                             port {}, one to {}",
                            forward.port, named.host_port, forward.host_port
                        )));
                    }
                    None => forwards.push(forward.clone()),
                }
            }
            for forward in &forwards {
                if policy.network.bind_ports.contains(&forward.port) {
                    return Err(BackendError::Command(format!(
                        "a forward and a bound port share {}; the forward's \
                         listener needs the port inside the sandbox, the bind \
                         needs it on the host, and one number cannot be both",
                        forward.port
                    )));
                }
            }
            let (announce, child_end) = UnixStream::pair().map_err(BackendError::Io)?;
            forward_child_end = Some(child_end);
            forward_announce = Some(announce);
            forward_forwards = Some(forwards);
        }

        // Relocation only happens where a root is reconstructed to put it in.
        let mut plan = LandlockPlan::build(
            policy,
            self.isolate && userns,
            mode == NetworkMode::Isolated,
        );
        plan.add_world_grants(&world);

        let isolation = if self.isolate {
            if userns {
                report.applied("namespace isolation");
                let plan = build_isolation_plan(policy, mode, &world, &self.implicit_write)?;
                // The bind source has to exist before it is bound at /tmp. It
                // is created empty, which is what /tmp starts as anyway.
                if let Some(dir) = &plan.tmp_dir {
                    std::fs::create_dir_all(dir).map_err(BackendError::Io)?;
                }
                Some(plan)
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
            report_widened_grants(policy, &self.implicit_write, nested);
        }

        // Without the isolation layer, the network namespace is entered on its
        // own, so a plain `bailey run` still gets real egress denial.
        let network_only = isolation.is_none() && mode == NetworkMode::Isolated;

        // The cgroup is created before the fork so the target can join it from
        // `pre_exec`. Joining before exec is what makes the limits cover every
        // process the target goes on to create.
        let cgroup = CgroupGuard::create(&policy.resources, self.always_cgroup);
        let procs = cgroup.procs_path();
        // Where no cgroup bounds the process count, `RLIMIT_NPROC` can, but
        // only on a run that makes a user namespace of its own: the count is
        // per user within a namespace, so in the caller's it is the caller's
        // own processes and the policy's number would refuse the first fork.
        let pids_via_rlimit = policy
            .resources
            .pids_max
            .filter(|_| procs.is_none() && (isolation.is_some() || network_only));
        // The file size limit is an rlimit rather than a cgroup control, so it
        // holds with or without a delegated cgroup and is reported on its own.
        // Folding it in here would report it skipped on a host with no cgroup,
        // when it is the one limit that still applied. A process limit met by
        // the rlimit above is taken out for the same reason.
        let mut via_cgroup = ResourceLimits {
            file_bytes: None,
            ..policy.resources.clone()
        };
        if pids_via_rlimit.is_some() {
            via_cgroup.pids_max = None;
        }
        if via_cgroup == ResourceLimits::default() {
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
        if policy.resources.file_bytes.is_some() {
            report.applied("file size limit");
        }
        if pids_via_rlimit.is_some() {
            report.applied("process limit");
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
        let file_bytes = policy.resources.file_bytes;
        // The child end's descriptor number, valid in the forked child where
        // fd numbers are preserved. Sending goes from the child end; the
        // announce end below is the one the parent reads.
        let forward_fd = forward_child_end.as_ref().map(|s| s.as_raw_fd());
        let forward_ports = forward_forwards.clone().unwrap_or_default();
        // Under isolation the target is spawned by the PID 1 supervisor rather
        // than exec'd by this process, so its exact shape travels with the
        // closure (the command itself stays behind for the parent's spawn).
        let target_program = target.program.clone();
        let target_args = target.args.clone();
        let target_cwd = target.cwd.clone();
        let target_env: Vec<(OsString, OsString)> = command
            .get_envs()
            .filter_map(|(key, value)| {
                value.map(|value| (key.to_os_string(), value.to_os_string()))
            })
            .collect();

        // Safety: the closure runs in the forked child before exec. Bailey is
        // single-threaded at this point, so the usual fork-safety hazard of
        // touching another thread's locks does not apply. Namespaces and the
        // reconstructed root are set up first, then Landlock is applied against
        // the new root, then seccomp closes the syscall surface last.
        unsafe {
            command.pre_exec(move || {
                set_no_new_privs()?;
                // Set before the namespaces and before seccomp: an rlimit is
                // inherited across fork and exec, so every process the target
                // goes on to start carries it too, and lowering it here cannot
                // be undone by a target that has no privilege to raise it.
                if let Some(bytes) = file_bytes {
                    set_file_size_limit(bytes)?;
                }
                // A process may raise its own soft limit as far as the hard
                // one, so leaving the hard limit unlimited lets a target
                // arrange its own core dump. Where that dump goes is the
                // host's `core_pattern`, which may be a program that runs
                // outside the sandbox with the target's memory.
                set_no_core_dumps()?;
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
                // After the namespaces, where the count starts at this process:
                // set before them it would charge the fork isolation makes to
                // reach PID 1 against the policy's number.
                if let Some(max) = pids_via_rlimit {
                    set_process_limit(max)?;
                }
                // Inside the namespace now and before any policy: the forward
                // listeners must bind the sandbox's own loopback, and Landlock
                // comes after. The descriptors cross to the parent and are
                // closed here at exec.
                if let Some(fd) = forward_fd {
                    forward::arm(fd, &forward_ports)?;
                }
                // Landlock and self-serve mounts cannot be combined: this
                // kernel refuses a new filesystem to any process under a
                // Landlock domain, and a FUSE mount is a new filesystem.
                // Confinement then rests on the reconstructed root alone,
                // which is why the config refuses the mount-backed
                // restrictions the target could take down.
                if !keep_mount {
                    plan.apply()?;
                }
                seccompiler::apply_filter(&seccomp)
                    .map_err(|err| io::Error::other(format!("seccomp: {err}")))?;
                // Last, so everything above still has what it needs. With no
                // capabilities left, a user namespace a target reaches through
                // `clone` maps nothing the target could not already name, and
                // the mount syscalls it would need inside one are denied
                // outright; `unshare` and `setns` are denied for the same
                // reason.
                drop_capabilities(keep_mount)?;
                // This process is PID 1 of the sandbox. Exec'ing the target
                // here would make the target the namespace's init, and the
                // kernel reaps nothing for an init: every orphan the target
                // leaves would stay a zombie pinning a host PID until the run
                // ended. The target runs as a child instead, and this process
                // waits, reaping what reparents to it. Only a non-isolated run
                // falls through to the exec below.
                if isolation.is_some() {
                    isolation::run_as_init(
                        &target_program,
                        &target_args,
                        &target_env,
                        target_cwd.as_deref(),
                    )?;
                }
                Ok(())
            });
        }

        if self.summary == Summary::Established {
            report.print_established();
        }

        // The handover arrives from inside the pre-exec fork, and under
        // isolation the intermediate parent never execs, so the spawn below
        // does not return until the run is over. Receiving on this thread
        // would serve nothing but the corpse: the relay runs on its own
        // thread instead, for as long as the process lives, which for a run
        // is the same span.
        let forward_up = forward_forwards.is_some().then(|| {
            let up = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let announce = forward_announce.expect("an announce exists for forwards");
            let forwards = forward_forwards
                .clone()
                .expect("announced forwards are set");
            let up_for_thread = up.clone();
            std::thread::spawn(move || {
                if let Ok(guard) = forward::ForwardGuard::receive(&announce, &forwards) {
                    up_for_thread.store(true, std::sync::atomic::Ordering::Release);
                    guard.serve(forward::PUMP_IDLE);
                }
            });
            up
        });

        let child = command.spawn().map_err(BackendError::Io)?;
        // The parent's copy of the child end must close before the handover is
        // read, or the socket never reaches an end when the sandbox dies.
        drop(forward_child_end);
        if let (Some(up), Some(forwards)) = (&forward_up, &forward_forwards) {
            if up.load(std::sync::atomic::Ordering::Acquire) {
                for forward in forwards {
                    report.applied(&format!(
                        "forward 127.0.0.1:{} to host port {}",
                        forward.port, forward.host_port
                    ));
                }
            } else {
                report.skipped("forward", "the handover never arrived");
            }
        }
        Ok(Confined {
            child,
            cgroup,
            staging,
            fuse: fuse_guard,
            relay: relay_guard,
            report,
            summary: self.summary,
        })
    }
}

/// A copy of `policy` with a grant for every FUSE mount, placed where the
/// target sees it.
fn policy_with_fuse(policy: &Policy, mounted: &[fuse::Mounted]) -> Policy {
    let mut extended = policy.clone();
    extended
        .filesystem
        .extend(mounted.iter().map(|mount| mount.rule()));
    extended
}

/// A copy of `policy` with a bind for every relay socket, placed where the
/// target sees it.
fn policy_with_relays(policy: &Policy, relays: &[relay::Relay]) -> Policy {
    let mut extended = policy.clone();
    extended
        .filesystem
        .extend(relays.iter().map(|relay| FsRule {
            path: relay.listener_path.clone(),
            access: policy::Access::READ | policy::Access::WRITE | policy::Access::EXECUTE,
            at: Some(relay.at.clone()),
        }));
    extended
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
    fuse: fuse::FuseGuard,
    relay: Option<relay::RelayGuard>,
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
        // The mounts are on the host, so they come down after the target is
        // gone and there is no one left to read them.
        drop(self.fuse);
        // The relay listeners close with the run, so a client inside cannot
        // reach past it.
        drop(self.relay);
        // The forwarded listeners live on the relay thread, which ends with
        // the process; the sandbox's loopback stops existing with the last
        // holder of the namespace.
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

/// Open a granted path for Landlock without opening the file itself.
///
/// `O_PATH` names the path while performing no device open and requiring no
/// permission on the file, which is what lets a grant install on `/dev/tty`
/// where there is no controlling terminal, and on anything unreadable.
///
/// Written against `libc::open` rather than `landlock::PathFd::new`, which
/// opens through `std::fs::OpenOptions`: that masks custom flags with
/// `!O_ACCMODE`, and musl counts `O_PATH` within `O_ACCMODE`, so the flag is
/// dropped and the open degrades to a plain read. Both shipped binaries are
/// musl, where that failed every run with an unopenable grant.
fn open_grant(path: &Path) -> io::Result<OwnedFd> {
    let raw = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("grant holds a nul byte: {}", path.display()),
        )
    })?;
    // SAFETY: `raw` is a valid nul-terminated string, and the returned
    // descriptor, when non-negative, is owned from here on.
    let fd = unsafe { libc::open(raw.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
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
    /// Build the Landlock rules for a policy.
    ///
    /// `relocates` says whether a reconstructed root will be built. It decides
    /// which path a relocated grant is named by, and getting it wrong inverts
    /// the grant: with no root to pivot into, `at` names a host path the policy
    /// never granted, while the path it did grant goes unnamed.
    /// `isolates_network` says whether the run gets a network namespace of its
    /// own, which decides whether a bound port can be connected to.
    fn build(policy: &Policy, relocates: bool, isolates_network: bool) -> Self {
        let mut filesystem = Vec::new();
        for rule in &policy.filesystem {
            if let Some(bits) = fs_access_bits(rule.access) {
                // The path as the target sees it. Landlock is applied after the
                // pivot, so a relocated hierarchy must be named where it ended
                // up: naming the host path would open nothing and the rule
                // would be dropped as a path that does not exist. Without the
                // pivot there is no such path, and the host one is what exists.
                let path = if relocates {
                    rule.visible().clone()
                } else {
                    rule.path.clone()
                };
                filesystem.push((path, bits));
            }
        }
        for rule in &policy.devices {
            if let Some(bits) = fs_access_bits(rule.access) {
                filesystem.push((rule.path.clone(), bits));
            }
        }

        let (handle_connect, mut connect_ports) = match &policy.network.egress {
            Egress::AllowAll => (false, Vec::new()),
            Egress::DenyAll => (true, Vec::new()),
            Egress::Allow(rules) => (true, rules.iter().filter_map(|rule| rule.port).collect()),
        };
        // A port the policy binds is one it means to be connected to. Denying
        // egress denies every connect, including the one to the service this
        // same policy just asked for, which leaves the port bound and useless.
        // Inside a private namespace there is nowhere else such a connection
        // could go, so permitting it widens nothing.
        if isolates_network {
            connect_ports.extend(policy.network.bind_ports.iter().copied());
            // A forward is a dial the target means to make: its listener sits
            // on the sandbox's own loopback, and egress denial would refuse
            // the very connection the forward exists to carry.
            connect_ports.extend(policy.forwards.iter().map(|f| f.port));
            connect_ports.sort_unstable();
            connect_ports.dedup();
        }
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
        // Read means exactly reading. `AccessFs::from_read` would also carry
        // `Execute`, which the policy never asked for here: a run would be
        // able to execute what it wrote into its private home, `/tmp`, or
        // `/dev/shm` while `policy.toml` said it could not. Execute is a
        // separate right, granted where the policy grants it.
        let read_write = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::from_write(TARGET_ABI);
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
            match open_grant(path) {
                Ok(fd) => {
                    created = created
                        .add_rule(PathBeneath::new(fd, *access))
                        .map_err(landlock_err)?;
                }
                // A granted path that does not exist is skipped rather than
                // aborting the whole run. Anything else means the rule could
                // not be installed for a reason the policy did not ask for,
                // and carrying on would report a grant that is not there.
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    // Only an errno crosses back to the parent from here, so
                    // what went wrong is said on the way out.
                    eprintln!("bailey: could not grant {}: {source}", path.display());
                    return Err(source);
                }
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
        // `PartiallyEnforced` is not the signal it reads as: best effort trims
        // the rights of any rule that cannot carry them, such as directory
        // rights on a file, so an ordinary run reports it on a kernel that
        // supports everything asked of it. What does mean part of the policy
        // is unexpressible is a kernel older than the ABI the rules are
        // written against, which is worth saying once.
        if let Some(current) = crate::backend::probe::landlock_abi()
            && current < TARGET_ABI as u32
        {
            eprintln!(
                "bailey: warning: this kernel speaks Landlock ABI {current}, and the policy is \
                 written for {}, so the rights added after it are not enforced",
                TARGET_ABI as u32
            );
        }
        Ok(())
    }
}

/// The host directory a reconstructed root is staged in.
///
/// Under the session runtime directory when there is a private one, in the
/// temp directory otherwise. Either way the name is fresh for this run.
fn staging_dir() -> io::Result<PathBuf> {
    match runtime_dir_host() {
        Some(runtime) => fresh_dir(&runtime),
        None => fresh_dir(&std::env::temp_dir()),
    }
}

/// Create a staging directory with a fresh name under `parent`.
fn fresh_dir(parent: &Path) -> io::Result<PathBuf> {
    claim_staging(&parent.join(format!("{STAGING_PREFIX}{}", random_suffix())))
}

/// Create `path` as a private staging directory, refusing one that is taken.
fn claim_staging(path: &Path) -> io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|err| {
            if err.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(
                    err.kind(),
                    format!("the staging directory `{}` already exists", path.display()),
                )
            } else {
                err
            }
        })?;
    Ok(path.to_path_buf())
}

/// The session runtime directory to stage in, when it is a private one.
///
/// `$XDG_RUNTIME_DIR` is per-user, mode 0700, and owned by the session
/// manager where one exists, so a directory created there cannot be
/// pre-created or named by another user. Any other mode does not qualify and
/// the run falls back to an unpredictable name in the temp directory.
fn runtime_dir_host() -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let dir = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
    if !dir.is_absolute() {
        return None;
    }
    let mode = dir.metadata().ok()?.permissions().mode();
    (mode & 0o777 == 0o700).then_some(dir)
}

/// A suffix another process cannot predict.
///
/// Drawn from the hasher seeds the standard library takes from the operating
/// system, so a name built from it cannot be pre-created by a process that
/// only knows the pid.
fn random_suffix() -> String {
    use std::hash::{BuildHasher, Hasher};

    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    format!("{:016x}", hasher.finish())
}

/// Remove the staging leftover named for this run's own pid, if any.
///
/// [`StagingGuard`] removes the directory on every path a run can return by,
/// but a signal does not unwind: a Ctrl-C, or anything else that kills bailey
/// without unwinding, leaves it behind. Sweeping before making our own means
/// a leftover heals on the next run rather than accumulating one per
/// interrupted run.
///
/// Only the exact name this run's pid identifies is removed. The shared temp
/// directory cannot tell one user's leftover from another's, so nothing else
/// is matched, and the empty directories earlier versions left behind wait
/// for the system's temp cleanup instead.
fn sweep_stale_staging() {
    sweep_staging(&std::env::temp_dir());
}

/// Remove this run's own leftover staging directory from `dir`.
fn sweep_staging(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir.join(format!("{STAGING_PREFIX}{}", std::process::id())));
}

/// The host path behind one the target sees, following a relocated grant.
fn to_host_path(policy: &Policy, path: &Path) -> PathBuf {
    for rule in &policy.filesystem {
        if let Some(at) = &rule.at
            && let Ok(rest) = path.strip_prefix(at)
        {
            return rule.path.join(rest);
        }
    }
    path.to_path_buf()
}

/// Where the target sees a host path, following a relocated grant.
fn to_visible_path(policy: &Policy, path: &Path) -> PathBuf {
    for rule in &policy.filesystem {
        if let Some(at) = &rule.at
            && let Ok(rest) = path.strip_prefix(&rule.path)
        {
            return at.join(rest);
        }
    }
    path.to_path_buf()
}

/// The `statfs` magic of a FUSE filesystem.
const FUSE_MAGIC: i64 = 0x6573_5546;

/// Build the bind-mount and concealment set for isolation from the policy.
///
/// Nested paths under an already-included directory are skipped (they come
/// along with the parent bind), and `/proc` is omitted because a fresh `/proc`
/// is mounted in the new PID namespace.
///
/// A denied path is never bound. Where a denial sits beneath a path that is
/// bound, it arrives with its parent and is covered over instead, which is what
/// makes a nested denial enforceable: Landlock rules can only add access.
fn build_isolation_plan(
    policy: &Policy,
    mode: NetworkMode,
    world: &World,
    implicit_write: &[PathBuf],
) -> Result<IsolationPlan, BackendError> {
    sweep_stale_staging();

    // A deny or a read-only island may be written either where the host keeps
    // the path or where the target will see it, and a relocated grant makes
    // those different. Each is put into the terms the step that uses it works
    // in, or it matches nothing and is silently dropped.
    let denied_paths: Vec<PathBuf> = policy
        .denied
        .iter()
        .map(|path| to_host_path(policy, path))
        .collect();
    let denied = |path: &Path| denied_paths.iter().any(|deny| path.starts_with(deny));

    let relocation: BTreeMap<PathBuf, PathBuf> = policy
        .filesystem
        .iter()
        .filter_map(|rule| rule.at.clone().map(|at| (rule.path.clone(), at)))
        .collect();

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
        let meta = match probe_grant(&path)? {
            GrantState::Missing => continue,
            GrantState::Live(meta) => meta,
        };
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
        let is_dir = meta.is_dir();
        if is_dir {
            roots.push(path.clone());
        }
        let at = relocation
            .get(&path)
            .cloned()
            .unwrap_or_else(|| path.clone());
        binds.push(BindMount {
            source: path,
            at,
            is_dir,
        });
    }

    let mut conceal = Vec::new();
    for path in &denied_paths {
        // Concealment covers a denied path where it ends up, which is not
        // where the host keeps it once its parent has been relocated.
        // Covering the host path would leave the denied one reachable at
        // its new location, which is the grant leaking exactly what the
        // deny was written to withhold.
        let Some(bind) = binds.iter().find(|bind| path.starts_with(&bind.source)) else {
            continue;
        };
        let Ok(relative) = path.strip_prefix(&bind.source) else {
            continue;
        };
        let is_dir = match probe_grant(path)? {
            // A denied path that does not exist needs no cover: there is
            // nothing on the host, so nothing can arrive inside the bind.
            GrantState::Missing => continue,
            GrantState::Live(meta) => meta.is_dir(),
        };
        conceal.push(Conceal {
            path: bind.at.join(relative),
            is_dir,
        });
    }

    // The remount happens inside the reconstructed root, so an island is named
    // where the target sees it. The host spelling travels with it, because the
    // question of whether the sandbox lost the path can only be asked there.
    let mut read_only: Vec<ReadOnly> = policy
        .read_only
        .iter()
        .map(|path| ReadOnly {
            host: path.clone(),
            visible: to_visible_path(policy, path),
        })
        .collect();
    read_only.extend(unwritable_beneath_implicit(policy, world, implicit_write));
    read_only.extend(metadata_read_only(policy));
    read_only.sort_by(|a, b| a.visible.cmp(&b.visible));
    read_only.dedup_by(|a, b| a.visible == b.visible);

    Ok(IsolationPlan {
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
        tmp_dir: policy.resources.tmp_dir.clone(),
        devpts: world.devpts,
        private_shm: world.private_shm,
        shm_bytes: policy.resources.shm_bytes.unwrap_or(DEFAULT_SHM_BYTES),
        runtime_dir: world::runtime_dir_inside(policy),
        cwd: world.cwd.clone(),
        staging: staging_dir()?,
    })
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
) -> Vec<ReadOnly> {
    // The remount that consumes this vector strips the leading `/` and resolves
    // what is left beneath the reconstructed root, so every entry has to be
    // spelled where the target sees it. The roots are translated into the same
    // spelling before they are compared against the rules, or a relocated grant
    // is never recognised as sitting beneath its own root and is skipped in
    // silence.
    let mut roots: Vec<PathBuf> = implicit
        .iter()
        .map(|path| to_visible_path(policy, path))
        .collect();
    if world.home_host.is_some() {
        roots.push(world.home_inside.clone());
    }
    if roots.is_empty() {
        return Vec::new();
    }

    policy
        .filesystem
        .iter()
        .filter(|rule| !rule.access.contains(policy::Access::WRITE))
        .map(|rule| ReadOnly {
            host: rule.path.clone(),
            visible: rule.visible().clone(),
        })
        .filter(|entry| {
            roots.iter().any(|root| {
                entry.visible.as_path() != root.as_path() && entry.visible.starts_with(root)
            })
        })
        .collect()
}

/// Read-only grants that no writable grant overlaps, so the path is read-only
/// in effect and can be mounted read-only.
///
/// Landlock does not mediate chmod, chown, utimes or xattr, so without the
/// mount those still succeed on a path the policy only grants read. A grant a
/// writable grant overlaps in either direction is left alone: a writable
/// ancestor keeps the path writable, which is the documented merge rule, and a
/// writable descendant would be broken by remounting its parent.
fn metadata_read_only(policy: &Policy) -> Vec<ReadOnly> {
    policy
        .filesystem
        .iter()
        .filter(|rule| !rule.access.contains(policy::Access::WRITE))
        // A kernel filesystem cannot be remounted read-only from a user
        // namespace: it is inherited with its flags locked, and the attempt
        // fails the whole run. There is nothing to close there either, since
        // its attributes are the kernel's rather than a file's.
        .filter(|rule| !is_kernel_filesystem(&rule.path))
        .filter(|rule| {
            !policy.filesystem.iter().any(|other| {
                other.access.contains(policy::Access::WRITE)
                    && (rule.path.starts_with(other.path.as_path())
                        || other.path.starts_with(rule.path.as_path()))
            })
        })
        .map(|rule| ReadOnly {
            host: rule.path.clone(),
            visible: rule.visible().clone(),
        })
        .collect()
}

/// Whether a path sits on a filesystem the kernel synthesises.
///
/// Read with `statfs`, so a path is judged by what it is really on rather than
/// by matching its name.
fn is_kernel_filesystem(path: &Path) -> bool {
    // sysfs, proc, cgroup v1 and v2, devpts, debugfs, securityfs, tracefs, bpf.
    const KERNEL_MAGIC: [i64; 9] = [
        0x6265_6572,
        0x9fa0,
        0x0027_e0eb,
        0x6367_7270,
        0x1cd1,
        0x6462_6720,
        0x7363_6673,
        0x7472_6163,
        -0x3501_b5ef,
    ];
    statfs_magic(path).is_some_and(|magic| KERNEL_MAGIC.contains(&magic))
}

/// Whether a path sits on a FUSE filesystem.
fn is_fuse(path: &Path) -> bool {
    statfs_magic(path) == Some(FUSE_MAGIC)
}

/// The `statfs` magic of the filesystem a path sits on.
fn statfs_magic(path: &Path) -> Option<i64> {
    let Ok(raw) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return None;
    };
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(raw.as_ptr(), &mut buf) } != 0 {
        return None;
    }
    Some(buf.f_type as i64)
}

/// What a failed read of a granted path usually means.
///
/// A mount whose server has gone away answers reads with EIO or ESTALE once
/// the connection is torn down, and hangs before that. FUSE is where this
/// happens most, so the note names it when `statfs` can still see the mount.
fn stale_mount_note(path: &Path) -> String {
    if is_fuse(path) {
        "The path sits on a FUSE filesystem; check that the mount is alive.".to_string()
    } else {
        "A stale FUSE or network mount is the usual cause; check that the \
         mounts this path depends on are alive."
            .to_string()
    }
}

/// The state of a path the policy names.
enum GrantState {
    /// The path does not exist. Grants may name optional paths, so this is a
    /// normal skip.
    Missing,
    /// The path exists.
    Live(std::fs::Metadata),
}

/// Read the state of a path the policy names.
///
/// A missing path is skipped, and any other failure refuses the run: a grant
/// that cannot be read would leave the target narrower than the policy says,
/// which is a silence this tool exists to refuse.
fn probe_grant(path: &Path) -> Result<GrantState, BackendError> {
    match std::fs::metadata(path) {
        Ok(meta) => Ok(GrantState::Live(meta)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(GrantState::Missing),
        Err(err) => Err(BackendError::UnreadablePath(format!(
            "the policy grants `{}`, but it could not be read: {}. {} The run is \
             refused rather than started narrower than the policy says.",
            path.display(),
            err,
            stale_mount_note(path),
        ))),
    }
}

fn fs_access_bits(access: policy::Access) -> Option<BitFlags<AccessFs>> {
    let mut bits = BitFlags::<AccessFs>::empty();
    if access.contains(policy::Access::READ) {
        bits |= AccessFs::ReadFile | AccessFs::ReadDir;
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
/// Say when a narrower grant is widened by an implicit write root.
///
/// Landlock rights are additive, so a `read` grant beneath a directory the run
/// grants for writing, such as the one a confined shell starts in, is writable
/// however narrowly it was written. The isolation layer takes the right back by
/// remounting the narrower path read-only; without a mount namespace there is
/// no way to subtract it, so the only honest thing is to say so.
fn report_widened_grants(policy: &Policy, implicit_write: &[PathBuf], nested: bool) {
    let remedy = if nested {
        "this run is inside another sandbox, which cannot build a second world"
    } else {
        "drop `--no-isolate` to keep it read-only"
    };
    for rule in &policy.filesystem {
        if rule.access.contains(policy::Access::WRITE) {
            continue;
        }
        let Some(root) = implicit_write
            .iter()
            .find(|root| rule.path.starts_with(root) && rule.path != **root)
        else {
            continue;
        };
        eprintln!(
            "bailey: warning: `{}` is granted read-only but sits inside `{}`, which this \
             run grants for writing, so it is writable. {remedy}.",
            rule.path.display(),
            root.display()
        );
    }
}

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

/// Caps the size of any single file the target writes.
///
/// Both the soft and hard limit are set. Leaving the hard limit alone would
/// leave the soft one advisory, since a process may raise its own soft limit
/// up to the hard one, and the target is exactly the party being restrained.
///
/// Exceeding it raises SIGXFSZ, and a write past the limit fails with EFBIG
/// for a process that handles or ignores the signal.
/// Drop every capability, so the target cannot act on the namespace it is in.
///
/// The bounding set goes first, because a capability dropped from it cannot be
/// regained by any later exec. The securebits then stop the kernel handing
/// capabilities back across a `setuid` or an `execve`.
///
/// With `keep_mount`, `CAP_SYS_ADMIN` survives instead: it stays in the
/// bounding set and the permitted and inheritable sets, and is raised ambient
/// before the securebits land, so it crosses the exec of an ordinary binary.
/// This is what `self_fuse` promises: the power to mount inside the run's own
/// namespace, and nothing beyond it.
fn drop_capabilities(keep_mount: bool) -> io::Result<()> {
    // SECBIT_NOROOT, SECBIT_NO_SETUID_FIXUP, SECBIT_NO_CAP_AMBIENT_RAISE and
    // the lock bit of each, so none of it can be undone.
    const SECUREBITS: libc::c_ulong = 0b1100_1111;
    const CAP_LAST: libc::c_ulong = 40;
    const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;
    const CAP_SYS_ADMIN: libc::c_ulong = 21;
    const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
    const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    unsafe {
        libc::prctl(libc::PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
        // Beyond the last capability this kernel knows, the call simply fails,
        // which is the signal to stop rather than an error to report.
        for cap in 0..=CAP_LAST {
            if keep_mount && cap == CAP_SYS_ADMIN {
                continue;
            }
            if libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 {
                break;
            }
        }
    }

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    if keep_mount {
        // CAP_SYS_ADMIN is 21, so bit 21 of the low word.
        data[0].effective |= 1 << 21;
        data[0].permitted |= 1 << 21;
        data[0].inheritable |= 1 << 21;
    }
    if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    unsafe {
        // Ambient before the securebits: SECBIT_NO_CAP_AMBIENT_RAISE is
        // among them and would refuse the raise. It must be ambient to
        // survive the exec of an ordinary binary, which is every binary a
        // policy grants.
        if keep_mount
            && libc::prctl(
                libc::PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_RAISE,
                21, /* CAP_SYS_ADMIN */
                0,
                0,
            ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        libc::prctl(libc::PR_SET_SECUREBITS, SECUREBITS, 0, 0, 0);
    }
    Ok(())
}

/// Pin `RLIMIT_CORE` to zero, hard as well as soft.
fn set_no_core_dumps() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Bound the number of processes with `RLIMIT_NPROC`, standing in for the
/// cgroup's `pids.max` where no cgroup was delegated.
///
/// The count behind this limit is kept per user within a user namespace, so it
/// only means the policy's number on a run that made one: there the count
/// begins at the target, and every process it goes on to start is charged to
/// it. On a run that stayed in the caller's namespace the same number would
/// count every process the caller already owns, which is why this is not set
/// there at all.
///
/// The soft and hard limit are both set, since a process may raise its own
/// soft limit as far as the hard one.
fn set_process_limit(max: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: max as libc::rlim_t,
        rlim_max: max as libc::rlim_t,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_file_size_limit(bytes: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: bytes as libc::rlim_t,
        rlim_max: bytes as libc::rlim_t,
    };
    let result = unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) };
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
        libc::SYS_pivot_root,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_open_by_handle_at,
        libc::SYS_acct,
        // `memfd_create` makes an anonymous executable inode that no
        // filesystem rule can name, so a `PathBeneath` rule on execute cannot
        // reach it. With it denied there is nothing for `execveat` to name
        // through `AT_EMPTY_PATH`, and everything the target runs comes off a
        // path the policy granted.
        libc::SYS_memfd_create,
        // Landlock is checked when a file is opened, not when a descriptor is
        // duplicated, so a descriptor taken from bailey carries the access
        // bailey had. Without a PID namespace the target can name bailey and
        // ask for one, which reaches the trust store and the config that was
        // just verified.
        libc::SYS_pidfd_getfd,
        // Landlock still mediates the filesystem operations a ring issues, but
        // a ring does not go through `sys_ioctl`, so the subvolume denials
        // below would be reachable through it. Nothing here needs io_uring.
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_chroot,
        libc::SYS_quotactl,
        // Same-uid cross-process reach that neither Landlock nor the namespace
        // covers.
        libc::SYS_kcmp,
        libc::SYS_process_madvise,
        libc::SYS_process_mrelease,
        // Bounded only by the ambient memlock limit, which is the host's.
        libc::SYS_mlockall,
    ]
}

/// The mount syscall family: `mount(2)` and the new mount API that reaches
/// the same power across several calls.
///
/// Denied by default. A policy with `self_fuse` lets them through, because
/// the kernel still gates every one on `CAP_SYS_ADMIN` in the run's user
/// namespace, which is exactly the capability `self_fuse` keeps.
const MOUNT_SYSCALLS: &[i64] = &[
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
];

/// Type bytes of the ioctl families that create a subvolume or a snapshot,
/// `_IOC_TYPE(nr)`, in bits 8 to 15 of the request.
///
/// Landlock mediates the VFS path operations, so `mkdir`, `open(O_CREAT)` and
/// `symlink` outside the granted tree are already denied. It does not mediate
/// ioctls on a directory, and a filesystem with subvolumes creates them that
/// way. A snapshot of a subvolume the target controls, taken into any host
/// directory it may merely read that sits on the same filesystem, plants a
/// directory of arbitrary files outside the sandbox. Denying these families
/// here, where Landlock cannot reach, closes that. `0x94` is btrfs (and
/// `FICLONE`, so a reflink copy is refused with it and falls back to a full
/// copy); `0xbc` is bcachefs.
const SUBVOL_IOCTL_TYPES: [u64; 2] = [0x94, 0xbc];

/// Terminal requests that put bytes into the input queue of a shared tty.
///
/// `TIOCSTI` pushes a byte as though it had been typed, so a target that can
/// reach the caller's terminal can run a command in the caller's shell after
/// the sandbox exits. `TIOCLINUX` reaches the console selection buffer the same
/// way. Current kernels gate `TIOCSTI` behind a capability and a sysctl, and
/// the older ones this still supports do not.
const TERMINAL_INJECTION_IOCTLS: [u64; 2] = [0x5412, 0x541c];

fn build_seccomp_filter(self_fuse: bool) -> anyhow::Result<seccompiler::BpfProgram> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    };

    let mut rules = BTreeMap::new();
    for &nr in denied_syscalls() {
        // An empty rule vector matches the syscall unconditionally.
        rules.insert(nr, Vec::new());
    }
    if !self_fuse {
        for &nr in MOUNT_SYSCALLS {
            rules.insert(nr, Vec::new());
        }
    }

    // ioctl carries too much that is ordinary to deny whole, so only the
    // subvolume families are refused, each matched on the type byte of the
    // request. The rules are alternatives: an ioctl of either type is denied,
    // every other is left to the kernel.
    let mut ioctl_rules = SUBVOL_IOCTL_TYPES
        .iter()
        .map(|&ty| {
            Ok(SeccompRule::new(vec![SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(0xff00),
                ty << 8,
            )?])?)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    // The terminal is shared with the caller's shell, and these two write to
    // it as though the user had typed. Whole request numbers rather than a
    // family, so only these are refused.
    for request in TERMINAL_INJECTION_IOCTLS {
        ioctl_rules.push(SeccompRule::new(vec![SeccompCondition::new(
            1,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            request,
        )?])?);
    }
    rules.insert(libc::SYS_ioctl, ioctl_rules);

    // A namespace can be built one `clone` at a time, so the `CLONE_NEW*`
    // flags are matched where they sit: in the low word of the first
    // argument. Ordinary thread and process creation sets none of them, and
    // is untouched.
    const NAMESPACE_CLONE_FLAGS: [u64; 7] = [
        libc::CLONE_NEWNS as u64,
        libc::CLONE_NEWCGROUP as u64,
        libc::CLONE_NEWUTS as u64,
        libc::CLONE_NEWIPC as u64,
        libc::CLONE_NEWUSER as u64,
        libc::CLONE_NEWPID as u64,
        libc::CLONE_NEWNET as u64,
    ];
    let clone_rules = NAMESPACE_CLONE_FLAGS
        .iter()
        .map(|&flag| {
            Ok(SeccompRule::new(vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(flag),
                flag,
            )?])?)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    rules.insert(libc::SYS_clone, clone_rules);
    // `clone3` carries the same flags behind a pointer, which a seccomp
    // filter cannot dereference, and denying it whole would break thread
    // creation: a thread pool falls back only on `ENOSYS`, not on the `EPERM`
    // this filter answers with. The `clone` rules above cover the caller it
    // shares the ABI with, and the capability drop after everything else here
    // is what leaves a namespace a target does build holding nothing it could
    // not already reach.

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        target_arch()?,
    )?;
    Ok(guard_architecture(filter.try_into()?))
}

/// `AUDIT_ARCH_*` value for the architecture the filter was built for. seccomp
/// reports it in `seccomp_data.arch`, and every rule's syscall number is only
/// meaningful for this one.
#[cfg(target_arch = "x86_64")]
const NATIVE_AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const NATIVE_AUDIT_ARCH: u32 = 0xc000_00b7;

/// Prepends an architecture check to a generated filter.
///
/// seccompiler compares the syscall number and never looks at
/// `seccomp_data.arch`. A denied syscall reached through a foreign ABI carries
/// a different number under a different architecture, matches no rule, and
/// falls through to the allow action. On x86_64 both the i386 `int 0x80` entry
/// and the x32 ABI do exactly this: measured, a filter that denies a syscall by
/// its native number still runs it when it arrives as the i386 or x32 number.
///
/// The prologue refuses anything whose architecture is not the one the rules
/// were written for. On x86_64 it also refuses the x32 numbering, which shares
/// the native architecture but sets bit 30 of the number. A refused call
/// returns `EPERM`, the same as any other denial, so a foreign ABI is closed
/// rather than left to the incidental behaviour of the rest of the filter.
fn guard_architecture(program: seccompiler::BpfProgram) -> seccompiler::BpfProgram {
    use seccompiler::sock_filter;

    // Classic BPF opcodes and seccomp offsets, which libc does not name.
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JGE_K: u16 = 0x35;
    const BPF_RET_K: u16 = 0x06;
    const ARCH_OFFSET: u32 = 4; // offsetof(seccomp_data, arch)
    const NR_OFFSET: u32 = 0; // offsetof(seccomp_data, nr)
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    const RET_ERRNO_EPERM: u32 = 0x0005_0000 | (libc::EPERM as u32);

    let stmt = |code: u16, k: u32| sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| sock_filter { code, jt, jf, k };

    let mut prologue = vec![
        // A = seccomp_data.arch
        stmt(BPF_LD_W_ABS, ARCH_OFFSET),
        // native arch: skip the refusal; otherwise fall into it
        jump(BPF_JMP_JEQ_K, NATIVE_AUDIT_ARCH, 1, 0),
        stmt(BPF_RET_K, RET_ERRNO_EPERM),
    ];
    // On x86_64 the x32 ABI shares the native arch and only differs by bit 30
    // of the syscall number, so the arch check alone does not stop it.
    #[cfg(target_arch = "x86_64")]
    {
        prologue.extend_from_slice(&[
            // A = seccomp_data.nr
            stmt(BPF_LD_W_ABS, NR_OFFSET),
            // nr with the x32 bit set: fall into the refusal; otherwise skip it
            jump(BPF_JMP_JGE_K, X32_SYSCALL_BIT, 0, 1),
            stmt(BPF_RET_K, RET_ERRNO_EPERM),
        ]);
    }
    let _ = NR_OFFSET;

    prologue.extend(program);
    prologue
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
    // A pid is reused, so a leftover directory from an earlier run with the
    // same number would be joined and written to rather than replaced. Created
    // outright, so an existing one is an error rather than a surprise.
    let dir = base.join(format!("bailey.{}", std::process::id()));
    match std::fs::create_dir(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            // Left behind by a run that could not clean up. Its limits are not
            // this run's, so it is emptied of settings by being replaced.
            std::fs::remove_dir(&dir).and_then(|()| std::fs::create_dir(&dir))?;
        }
        Err(error) => return Err(error),
    }

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
    use crate::policy::{Access, DeviceRule, Egress, FsRule, PortForward};

    /// Builds a plan for a test and removes the staging directory it created,
    /// since only a run holds the guard that removes it.
    fn plan_for(policy: &Policy, implicit: &[PathBuf]) -> IsolationPlan {
        let world = World::derive(Path::new("/bin/true"), policy, true);
        let plan = build_isolation_plan(policy, NetworkMode::Isolated, &world, implicit).unwrap();
        let _ = std::fs::remove_dir(&plan.staging);
        plan
    }

    /// A grant descriptor must be path-only: reading through it fails.
    ///
    /// This is what proves the `O_PATH` survived. A descriptor that lost it
    /// still opens the path, so only the read tells the two apart.
    fn assert_path_only(fd: &OwnedFd) {
        use std::os::fd::AsFd;
        let file = std::fs::File::from(fd.as_fd().try_clone_to_owned().unwrap());
        let err = std::io::Read::read(&mut &file, &mut [0u8; 1]).unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EBADF),
            "a grant descriptor must not carry read access"
        );
    }

    #[test]
    fn grant_descriptors_are_path_only() {
        let fd = open_grant(Path::new("/dev/null")).expect("a grant opens");
        assert_path_only(&fd);
    }

    #[test]
    fn a_tty_grant_installs_without_opening_the_device() {
        // The daemon case from issue #32: a plain open of `/dev/tty` fails
        // with `ENXIO` where there is no controlling terminal, and naming it
        // must not. Skipped where the node itself is absent, which is about
        // the host rather than the grant.
        if !Path::new("/dev/tty").exists() {
            return;
        }
        let fd = open_grant(Path::new("/dev/tty")).expect("a tty grant installs");
        assert_path_only(&fd);
    }

    #[test]
    fn read_grants_read_without_execute() {
        let read = fs_access_bits(Access::READ).unwrap();
        assert!(read.contains(AccessFs::ReadFile));
        assert!(read.contains(AccessFs::ReadDir));
        assert!(!read.contains(AccessFs::Execute));

        let exec = fs_access_bits(Access::EXECUTE).unwrap();
        assert!(exec.contains(AccessFs::Execute));
        assert!(!exec.contains(AccessFs::ReadFile));

        assert!(fs_access_bits(Access::empty()).is_none());
    }

    /// The areas the sandbox provides are granted for reading and writing,
    /// not for running what the target puts there. `AccessFs::from_read`
    /// carries `Execute`, and using it here made `/tmp` and `/dev/shm`
    /// executable in every run while the policy said otherwise.
    #[test]
    fn world_grants_read_and_write_without_execute() {
        let policy = Policy::default();
        let world = World::derive(Path::new("/bin/true"), &policy, true);
        assert!(world.private_tmp, "isolation gives the run a private /tmp");

        let mut plan = LandlockPlan::build(&policy, true, false);
        plan.add_world_grants(&world);
        let tmp = plan
            .filesystem
            .iter()
            .find(|(path, _)| path == &PathBuf::from("/tmp"))
            .map(|(_, bits)| *bits)
            .expect("the private /tmp is granted");
        assert!(tmp.contains(AccessFs::ReadFile));
        assert!(tmp.contains(AccessFs::WriteFile));
        assert!(
            !tmp.contains(AccessFs::Execute),
            "a run must not execute what it wrote into /tmp"
        );
    }

    /// `memfd_create` makes an anonymous executable inode no filesystem rule
    /// can name, so it is denied outright rather than left to the grants.
    #[test]
    fn memfd_create_is_denied() {
        assert!(denied_syscalls().contains(&libc::SYS_memfd_create));
    }

    /// The namespace flags are matched on `clone`'s first argument, and the
    /// filter only proves it builds: a rule seccompiler rejected would surface
    /// here rather than as every run failing to start.
    #[test]
    fn the_seccomp_filter_builds_with_the_clone_rules() {
        assert!(build_seccomp_filter(false).is_ok());
        assert!(build_seccomp_filter(true).is_ok());
    }

    /// A forward is a dial the target means to make, on a loopback that has
    /// nothing else on it. Egress denial must not refuse the connection the
    /// forward exists to carry.
    #[test]
    fn forward_ports_are_connectable_where_egress_is_denied() {
        let mut policy = Policy::default();
        policy.forwards.push(PortForward {
            port: 9876,
            host_port: 9876,
        });
        let plan = LandlockPlan::build(&policy, true, true);
        assert!(plan.connect_ports.contains(&9876));
    }

    /// With egress allowed there is no connect rule at all, and a forward must
    /// not introduce one: permitting connects for it would open every host
    /// port, not just the one forwarded.
    #[test]
    fn forward_ports_do_not_introduce_connect_rules_where_egress_is_allowed() {
        let mut policy = Policy::default();
        policy.network.egress = Egress::AllowAll;
        policy.forwards.push(PortForward {
            port: 9876,
            host_port: 9876,
        });
        let plan = LandlockPlan::build(&policy, true, false);
        assert!(plan.connect_ports.is_empty());
        assert!(!plan.handle_connect);
    }

    #[test]
    fn read_only_grants_with_no_writable_overlap_are_remounted() {
        let mut policy = Policy::default();
        policy.filesystem.push(FsRule {
            path: PathBuf::from("/data"),
            access: Access::READ,
            at: None,
        });
        assert_eq!(
            metadata_read_only(&policy)
                .iter()
                .map(|entry| entry.visible.clone())
                .collect::<Vec<_>>(),
            vec![PathBuf::from("/data")]
        );

        policy.filesystem.push(FsRule {
            path: PathBuf::from("/data/logs"),
            access: Access::WRITE,
            at: None,
        });
        assert!(metadata_read_only(&policy).is_empty());
    }

    #[test]
    fn a_relocated_read_only_grant_is_remounted_where_it_lands() {
        let mut policy = Policy::default();
        policy.filesystem.push(FsRule {
            path: PathBuf::from("/host/project"),
            access: Access::READ,
            at: Some(PathBuf::from("/workspace")),
        });
        assert_eq!(
            metadata_read_only(&policy)
                .iter()
                .map(|entry| entry.visible.clone())
                .collect::<Vec<_>>(),
            vec![PathBuf::from("/workspace")]
        );
    }

    /// A relocated grant beneath an implicit-write root is the case where the two
    /// producers disagreed: one answered with the host spelling, the other with
    /// the spelling the target sees, and the remount consumer resolves under the
    /// new root, so only the second one can ever match. The whole vector has to
    /// be in that spelling, or the entry is skipped in silence and the path stays
    /// writable against the host file.
    #[test]
    fn a_relocated_read_grant_beneath_an_implicit_root_is_remounted() {
        let mut policy = Policy::default();
        policy.filesystem.push(FsRule {
            path: PathBuf::from("/var/tmp/proj/src"),
            access: Access::READ | Access::WRITE,
            at: Some(PathBuf::from("/workspace")),
        });
        policy.filesystem.push(FsRule {
            path: PathBuf::from("/var/tmp/proj/src/versions"),
            access: Access::READ,
            at: Some(PathBuf::from("/workspace/versions")),
        });
        let implicit = [PathBuf::from("/var/tmp/proj/src")];

        let plan = plan_for(&policy, &implicit);
        assert!(
            plan.read_only
                .iter()
                .any(|entry| entry.visible == Path::new("/workspace/versions")),
            "the read-only entry must be spelled where the target sees it: {:?}",
            plan.read_only
        );
        assert!(
            !plan
                .read_only
                .iter()
                .any(|entry| entry.visible.starts_with("/var/tmp")),
            "no entry may keep the host spelling, which the remount cannot \
             resolve: {:?}",
            plan.read_only
        );
    }

    #[test]
    fn the_isolation_plan_remounts_a_read_only_grant() {
        let mut policy = Policy::default();
        policy.filesystem.push(FsRule {
            path: PathBuf::from("/data"),
            access: Access::READ,
            at: None,
        });
        let plan = plan_for(&policy, &[]);
        assert!(
            plan.read_only
                .iter()
                .any(|entry| entry.visible == Path::new("/data"))
        );
    }

    /// A forward needs the sandbox's own loopback, which only exists while
    /// egress is denied: an allowance keeps the target in the host's
    /// namespace, and the refusal must say that rather than send the user
    /// hunting for an isolation flag that is already on.
    #[test]
    fn forwards_under_an_egress_allowance_name_the_allowance() {
        let mut policy = Policy::default();
        policy.network.egress = Egress::AllowAll;
        policy.forwards.push(PortForward {
            port: 11434,
            host_port: 11434,
        });
        let backend = EnforceBackend::default();
        let target = Target {
            program: "/bin/true".into(),
            args: Vec::new(),
            cwd: None,
        };
        let message = backend
            .run(&policy, &target)
            .expect_err("an egress allowance must refuse forwards")
            .to_string();
        assert!(message.contains("allows egress"), "{message}");
        assert!(!message.contains("isolation on"), "{message}");
    }

    /// A grant whose state cannot be read would start the target narrower
    /// than the policy says, which is the silence this run refuses. A dead
    /// FUSE or network mount answers exactly this way, with an error that is
    /// not `NotFound`.
    #[test]
    fn an_unreadable_grant_refuses_the_plan() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            // Root reads through every mode bit, so there is no way to stage
            // the failure this test is about.
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let jail = dir.path().join("jail");
        let secret = jail.join("secret");
        std::fs::create_dir_all(&secret).unwrap();
        std::fs::set_permissions(&jail, std::fs::Permissions::from_mode(0o000)).unwrap();
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
            }
        }
        let _restore = Restore(jail.clone());

        let mut policy = Policy::default();
        policy.filesystem.push(FsRule {
            path: secret.clone(),
            access: Access::READ,
            at: None,
        });
        let world = World::derive(Path::new("/bin/true"), &policy, true);
        let err = match build_isolation_plan(&policy, NetworkMode::Isolated, &world, &[]) {
            Err(err) => err,
            Ok(_) => {
                if unsafe { libc::geteuid() } == 0 {
                    return;
                }
                panic!("an unreadable grant must refuse the run");
            }
        };
        let message = err.to_string();
        assert!(message.contains("could not be read"), "{message}");
        assert!(message.contains(&secret.display().to_string()), "{message}");
    }

    /// A grant naming a path that does not exist is a normal skip: policies
    /// name optional paths, and that behavior predates the refusal.
    #[test]
    fn a_missing_grant_is_still_skipped() {
        let mut policy = Policy::default();
        policy.filesystem.push(FsRule {
            path: PathBuf::from("/nonexistent/grant/target"),
            access: Access::READ,
            at: None,
        });
        let plan = plan_for(&policy, &[]);
        assert!(plan.binds.is_empty(), "a missing path is not bound");
    }

    /// The staging directory a plan names exists the moment the plan is built,
    /// is private, and is not named by the run's pid alone.
    ///
    /// `build_isolation_plan` is the entry runs and tests share, so these hold
    /// wherever the run stages: under the session runtime directory when one
    /// qualifies, in the temp directory otherwise.
    #[test]
    fn the_staging_directory_is_fresh_and_private() {
        use std::os::unix::fs::PermissionsExt;

        let policy = Policy::default();
        let world = World::derive(Path::new("/bin/true"), &policy, true);

        let plan = build_isolation_plan(&policy, NetworkMode::Isolated, &world, &[]).unwrap();
        let meta = std::fs::metadata(&plan.staging)
            .expect("the staging directory exists once the plan is built");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o700,
            "the staging directory is private: {}",
            plan.staging.display()
        );
        let name = plan
            .staging
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(
            name.starts_with(STAGING_PREFIX),
            "the staging directory is named for bailey: {name}"
        );
        assert_ne!(
            name,
            format!("{STAGING_PREFIX}{}", std::process::id()),
            "the name must not be the pid alone: {name}"
        );

        // A concurrent run stages beside this one, never at its name.
        let other = build_isolation_plan(&policy, NetworkMode::Isolated, &world, &[]).unwrap();
        assert_ne!(plan.staging, other.staging, "the name is fresh per run");

        let _ = std::fs::remove_dir(&plan.staging);
        let _ = std::fs::remove_dir(&other.staging);
    }

    /// A staging path that is taken is refused, and the refusal names it.
    ///
    /// `fresh_dir` is called with an injected base, so the test controls where
    /// the directories land and does not depend on what the shared temp
    /// directory holds.
    #[test]
    fn a_taken_staging_path_is_refused_by_its_name() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();

        let first = fresh_dir(base.path()).expect("a fresh staging directory is created");
        let mode = std::fs::metadata(&first).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "the staging directory is private");

        let second = fresh_dir(base.path()).expect("the next staging directory is fresh");
        assert_ne!(first, second, "two staging directories never share a name");

        let err = claim_staging(&first).expect_err("a taken staging path is refused");
        assert!(
            err.to_string().contains(&first.display().to_string()),
            "the refusal names the path: {err}"
        );

        let _ = std::fs::remove_dir(&first);
        let _ = std::fs::remove_dir(&second);
    }

    /// The sweep takes only the leftover named for this run's own pid.
    ///
    /// A directory left by a run of another identity, or planted by any user,
    /// is neither matched nor touched: the shared temp directory cannot tell
    /// whose a leftover is, so nothing that is not ours by name is removed.
    #[test]
    fn the_sweep_takes_only_its_own_leftover() {
        let dir = tempfile::tempdir().unwrap();
        let foreign = dir.path().join(format!("{STAGING_PREFIX}987654321"));
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("decoy"), "not ours").unwrap();
        let own = dir
            .path()
            .join(format!("{STAGING_PREFIX}{}", std::process::id()));
        std::fs::create_dir_all(&own).unwrap();

        sweep_staging(dir.path());

        assert!(
            foreign.is_dir(),
            "another run's staging is not ours to remove"
        );
        assert!(
            foreign.join("decoy").is_file(),
            "nothing inside it is touched"
        );
        assert!(!own.exists(), "this run's own leftover is removed");

        let _ = std::fs::remove_dir_all(&foreign);
    }

    /// The classifier reads what a path is really on, so a plain directory is
    /// never mistaken for FUSE.
    #[test]
    fn a_plain_directory_is_not_fuse() {
        let dir = tempfile::tempdir().unwrap();
        assert!(statfs_magic(dir.path()).is_some(), "statfs answers");
        assert!(!is_fuse(dir.path()), "a tmpfs directory is not FUSE");
    }

    #[test]
    fn plan_includes_devices_and_derives_net_handling() {
        let mut policy = Policy::default();
        policy.filesystem.push(FsRule {
            path: PathBuf::from("/usr"),
            access: Access::READ | Access::EXECUTE,
            at: None,
        });
        policy.devices.push(DeviceRule {
            path: PathBuf::from("/dev/dri"),
            access: Access::READ | Access::WRITE,
        });

        let plan = LandlockPlan::build(&policy, true, false);
        assert_eq!(plan.filesystem.len(), 2);
        // Default egress is DenyAll, so connect is handled with no allowed ports.
        assert!(plan.handle_connect);
        assert!(plan.connect_ports.is_empty());
    }

    #[test]
    fn seccomp_filter_builds() {
        assert!(build_seccomp_filter(false).is_ok());
        assert!(build_seccomp_filter(true).is_ok());
    }

    /// Constructs an ioctl request number the way the kernel macros do, so the
    /// test refuses the same encoding the filter matches on rather than a
    /// hand-copied constant.
    fn ioctl_nr(ty: u64, nr: u64, size: u64) -> libc::c_ulong {
        const DIR_WRITE: u64 = 1;
        ((DIR_WRITE << 30) | (size << 16) | (ty << 8) | nr) as libc::c_ulong
    }

    /// The escape is an ioctl Landlock never saw, so the proof is at the
    /// syscall boundary: with the real filter applied, a subvolume ioctl is
    /// stopped with EPERM before it reaches any filesystem, while an ordinary
    /// ioctl is left to the kernel. Run in a child because a filter cannot be
    /// lifted.
    #[test]
    fn the_filter_denies_subvolume_ioctls_and_spares_the_rest() {
        let filter: seccompiler::BpfProgram = build_seccomp_filter(false).unwrap();

        // btrfs SNAP_CREATE and SUBVOL_CREATE_V2, the pair the report used, and
        // bcachefs SUBVOLUME_CREATE, the same class on the other filesystem.
        let btrfs_snap_create = ioctl_nr(SUBVOL_IOCTL_TYPES[0], 1, 4096);
        let btrfs_subvol_create_v2 = ioctl_nr(SUBVOL_IOCTL_TYPES[0], 24, 4096);
        let bcachefs_subvol_create = ioctl_nr(SUBVOL_IOCTL_TYPES[1], 16, 4096);
        // FIONREAD: type 'T' (0x54), an everyday ioctl that must still reach the
        // kernel, which answers it on /dev/null with anything but the EPERM
        // seccomp would have returned.
        let fionread = libc::FIONREAD as libc::c_ulong;

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            seccompiler::apply_filter(&filter).unwrap();
            let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
            let mut out: libc::c_int = 0;
            let mut errno_of = |req: libc::c_ulong| -> i32 {
                unsafe {
                    *libc::__errno_location() = 0;
                    // The request is `c_ulong` on glibc and `c_int` on musl,
                    // and an ioctl encoding fits in 32 bits either way.
                    libc::ioctl(fd, req as _, &mut out);
                    *libc::__errno_location()
                }
            };
            let denied = errno_of(btrfs_snap_create) == libc::EPERM
                && errno_of(btrfs_subvol_create_v2) == libc::EPERM
                && errno_of(bcachefs_subvol_create) == libc::EPERM;
            // The benign ioctl must not be the one seccomp refused.
            let benign_survived = errno_of(fionread) != libc::EPERM;
            let code = if denied && benign_survived { 0 } else { 1 };
            unsafe { libc::_exit(code) };
        }

        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let exited = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        assert!(
            exited,
            "subvolume ioctls were not denied, or a benign ioctl was"
        );
    }

    #[test]
    fn a_deny_under_a_relocated_grant_is_concealed() {
        let mut policy = Policy::default();
        policy.filesystem.push(FsRule {
            path: PathBuf::from("/host/data"),
            access: Access::READ | Access::WRITE,
            at: Some(PathBuf::from("/workspace")),
        });
        // Written where the target sees it, which is the only path an operator
        // reading the policy could name.
        policy.denied.push(PathBuf::from("/workspace/secret"));

        assert_eq!(
            to_host_path(&policy, Path::new("/workspace/secret")),
            PathBuf::from("/host/data/secret")
        );
        // And back the other way, for an island that is remounted inside the
        // reconstructed root.
        assert_eq!(
            to_visible_path(&policy, Path::new("/host/data/logs")),
            PathBuf::from("/workspace/logs")
        );
        // A path under no relocation is left as it was written.
        assert_eq!(
            to_host_path(&policy, Path::new("/etc/passwd")),
            PathBuf::from("/etc/passwd")
        );
    }

    #[test]
    fn a_relocated_grant_follows_the_root_that_will_exist() {
        let mut policy = Policy::default();
        policy.filesystem.push(FsRule {
            path: PathBuf::from("/host/data"),
            access: Access::READ,
            at: Some(PathBuf::from("/host/secret")),
        });

        // With a reconstructed root the grant is named where it lands.
        let relocated = LandlockPlan::build(&policy, true, false);
        assert!(
            relocated
                .filesystem
                .iter()
                .any(|(path, _)| path == Path::new("/host/secret"))
        );

        // Without one there is no such path, and naming `at` would grant a
        // host path the policy never mentioned while withholding the one it
        // did.
        let plain = LandlockPlan::build(&policy, false, false);
        assert!(
            plain
                .filesystem
                .iter()
                .any(|(path, _)| path == Path::new("/host/data"))
        );
        assert!(
            !plain
                .filesystem
                .iter()
                .any(|(path, _)| path == Path::new("/host/secret"))
        );
    }

    #[test]
    fn terminal_injection_requests_are_named_whole() {
        // A family mask would take ordinary terminal requests with it, so
        // these two are matched as whole numbers.
        assert_eq!(TERMINAL_INJECTION_IOCTLS, [0x5412, 0x541c]);
        assert!(!TERMINAL_INJECTION_IOCTLS.contains(&0x5401));
    }

    #[test]
    fn descriptor_passing_and_rings_are_denied() {
        // A duplicated descriptor carries the access the opener had, and a
        // ring reaches ioctls without passing the ioctl rules below.
        let denied = denied_syscalls();
        for nr in [
            libc::SYS_pidfd_getfd,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_chroot,
            libc::SYS_quotactl,
            libc::SYS_kcmp,
            libc::SYS_process_madvise,
            libc::SYS_process_mrelease,
            libc::SYS_mlockall,
        ] {
            assert!(denied.contains(&nr), "syscall {nr} should be denied");
        }
    }

    #[test]
    fn the_whole_mount_family_is_denied() {
        // The old mount(2) and its split successors reach the same power, so a
        // denylist that stops one but not the others stops nothing. The family
        // lives in `MOUNT_SYSCALLS` alone, which is the only thing `self_fuse`
        // lifts; the calls that would leave the namespace are denied outright
        // and never lifted.
        for nr in MOUNT_SYSCALLS {
            assert!(
                !denied_syscalls().contains(nr),
                "syscall {nr} must sit in MOUNT_SYSCALLS alone, so self_fuse lifts it and nothing else"
            );
        }
        for nr in [libc::SYS_pivot_root, libc::SYS_setns, libc::SYS_unshare] {
            assert!(
                denied_syscalls().contains(&nr),
                "syscall {nr} must stay denied even with self_fuse"
            );
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod arch_guard_tests {
    use super::*;

    /// setns(-1, 0) through the i386 `int 0x80` entry (i386 nr 346). Returns
    /// eax: EBADF means the kernel ran it, EPERM means the filter refused it.
    unsafe fn setns_i386() -> i32 {
        let mut ret: i32 = 346;
        unsafe {
            core::arch::asm!(
                "xchg {tmp}, rbx",
                "int 0x80",
                "xchg {tmp}, rbx",
                tmp = in(reg) -1i64,
                inout("eax") ret,
                in("ecx") 0,
                in("edx") 0,
                options(nostack),
            );
        }
        ret
    }

    /// Runs a probe in a child under the real filter and returns its exit code.
    /// A code in 0..256 is the probe's own; 256 + signal means it was killed.
    fn under_filter(probe: fn()) -> i32 {
        let filter: seccompiler::BpfProgram = build_seccomp_filter(false).unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            seccompiler::apply_filter(&filter).unwrap();
            probe();
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        if libc::WIFSIGNALED(status) {
            256 + libc::WTERMSIG(status)
        } else {
            libc::WEXITSTATUS(status)
        }
    }

    #[test]
    fn a_denied_syscall_is_refused_through_every_abi() {
        // Native x86_64 setns is denied by a rule: EPERM.
        let native = under_filter(|| {
            let e = unsafe {
                *libc::__errno_location() = 0;
                libc::syscall(libc::SYS_setns, -1, 0);
                *libc::__errno_location()
            };
            unsafe { libc::_exit(if e == libc::EPERM { 0 } else { 1 }) };
        });
        assert_eq!(native, 0, "native setns should be EPERM");

        // i386 setns must now be EPERM, not EBADF (executed) and not a signal.
        let i386 = under_filter(|| {
            let eax = unsafe { setns_i386() };
            unsafe { libc::_exit(if eax == -libc::EPERM { 0 } else { 1 }) };
        });
        assert_eq!(
            i386, 0,
            "i386 setns via int 0x80 must be refused with EPERM"
        );

        // x32 setns (native arch, nr | 0x40000000) must be EPERM too.
        let x32 = under_filter(|| {
            let e = unsafe {
                *libc::__errno_location() = 0;
                libc::syscall(libc::SYS_setns | 0x4000_0000, -1, 0);
                *libc::__errno_location()
            };
            unsafe { libc::_exit(if e == libc::EPERM { 0 } else { 1 }) };
        });
        assert_eq!(x32, 0, "x32 setns must be refused with EPERM");
    }

    #[test]
    fn a_native_allowed_syscall_still_works() {
        // getpid is denied by nothing and native: it must run, not be refused.
        let code = under_filter(|| {
            let pid = unsafe { libc::syscall(libc::SYS_getpid) };
            unsafe { libc::_exit(if pid > 0 { 0 } else { 1 }) };
        });
        assert_eq!(code, 0, "a native, undenied syscall must still run");
    }
}
