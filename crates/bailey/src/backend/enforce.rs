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
//!
//! Every refusal the seccomp filter makes lives in one of the named tables in
//! this file, and a unit test holds the enforcement page of the documentation
//! to the union of those tables. A refusal written without a named table, one
//! in the hand-built prologue for instance, is invisible to that test and must
//! be documented by hand alongside it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use enumflags2::BitFlags;
use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};

use crate::backend::audit_notify;
use crate::backend::cgroup;
use crate::backend::forward;
use crate::backend::fuse;
use crate::backend::isolation::{self, BindMount, Conceal, IsolationPlan, ReadOnly};
use crate::backend::network::{self, NetworkMode};
use crate::backend::relay;
use crate::backend::world::{self, World};
use crate::backend::{Backend, BackendError, Target, random_suffix};

/// The environment marker a fallback audit arms for its target, so an inner
/// bailey can tell an inherited listener from plain filters and refuse to
/// stack a second one.
const AUDIT_LISTENER_MARKER: &str = "BAILEY_AUDIT_LISTENER";
use crate::event::Usage;
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

/// The Landlock ABI that carries the socket connect right, newer than
/// everything else the policy uses.
pub(crate) const ABI_SOCKET_CONNECT: u32 = 9;

/// Why socket connect control is skipped, on a kernel older than ABI 9.
///
/// The run summary and `bailey doctor` say the same thing, so the wording is
/// one constant: what the kernel lacks, and what that means for every policy
/// written for the connect list.
pub(crate) const CONNECT_SKIP_REASON: &str = "needs Landlock ABI 9 (Linux 7.1); any socket the target can reach by path \
     can be connected to";

/// Prefix of the host-visible directory a reconstructed root is staged in.
const STAGING_PREFIX: &str = ".bailey-root.";

/// Default size of the private `/tmp` when the policy does not set one.
const DEFAULT_TMP_BYTES: u64 = 64 * 1024 * 1024;

/// Default size of the private `/dev/shm`. Graphics and audio stacks use it for
/// buffers, so it is more generous than `/tmp`.
const DEFAULT_SHM_BYTES: u64 = 256 * 1024 * 1024;

/// How a run ended.
///
/// A code alone does not say whether the target failed or was killed, and a
/// reader who has to act on it needs the difference: a bug to look for, or a
/// kill to account for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exit {
    /// The exit code, counting a signal death as `128 + signal` the way a
    /// shell does.
    pub code: i32,
    /// The signal the wait saw kill the target, when it saw one.
    pub signal: Option<i32>,
}

impl Exit {
    /// Read how a finished process ended.
    pub fn of(status: std::process::ExitStatus) -> Self {
        let signal = status.signal();
        let code = status
            .code()
            .unwrap_or_else(|| signal.map_or(-1, |signal| 128 + signal));
        Exit { code, signal }
    }

    /// The line the run reports, or none when the target ended cleanly.
    ///
    /// A signal the wait saw is a fact, and is reported as one. A code above
    /// 128 is not: the isolated path reaps the target inside its own PID
    /// namespace and exits with `128 + signal` itself, so the parent sees an
    /// ordinary exit and cannot tell that from a target that chose the same
    /// code. Saying which of the two it has keeps the summary from claiming
    /// more than it knows.
    fn said(&self) -> Option<String> {
        match (self.code, self.signal) {
            (0, None) => None,
            (_, Some(signal)) => Some(format!("bailey: target killed by {}", signal_name(signal))),
            (code, None) if code > 128 => Some(format!(
                "bailey: target exited with {code}, the shell code for {}",
                signal_name(code - 128)
            )),
            (code, None) => Some(format!("bailey: target exited with {code}")),
        }
    }
}

/// A signal by the name and number a reader knows it by.
fn signal_name(signal: i32) -> String {
    match nix::sys::signal::Signal::try_from(signal) {
        Ok(named) => format!("{} ({signal})", named.as_str()),
        Err(_) => format!("signal {signal}"),
    }
}

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
    pub fn print(&self, exit: Exit) {
        self.print_established();
        if let Some(line) = exit.said() {
            eprintln!("{line}");
        }
    }

    /// Render the summary as JSON, for a caller that is not a person.
    pub fn to_json(&self, exit: Exit) -> String {
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
        let signal = exit
            .signal
            .map_or_else(|| "null".to_owned(), |signal| signal.to_string());
        format!(
            "{{\"applied\":[{}],\"skipped\":[{}],\"exit_code\":{},\"signal\":{signal}}}",
            applied.join(","),
            skipped.join(","),
            exit.code
        )
    }
}

/// Describe the destination rules a private run enforces, for the summary.
///
/// Each allow rule with its protocol and port, each pinned name with the
/// addresses it resolved to, each deny rule, and whether DNS questions are
/// answered. One line, so the enforced list stays one list.
fn egress_destinations_report(policy: &Policy, pins: &[crate::cli::Pin]) -> Vec<String> {
    use crate::policy::{Destination, Egress};

    let mut parts: Vec<String> = Vec::new();
    if let Egress::Allow(rules) = &policy.network.egress {
        for rule in rules {
            let mut part = match rule.port {
                Some(port) => format!("{} {}:{port}", rule.protocol.name(), rule.host),
                None => format!("{} {}", rule.protocol.name(), rule.host),
            };
            if let Destination::Name(name) = &rule.host
                && let Some(pin) = pins.iter().find(|pin| &pin.name == name)
                && !pin.addresses.is_empty()
            {
                let addresses: Vec<String> = pin
                    .addresses
                    .iter()
                    .map(|address| address.to_string())
                    .collect();
                part.push_str(&format!(" pinned to {}", addresses.join(" ")));
            }
            parts.push(part);
        }
    }
    for rule in &policy.network.deny {
        match rule.port {
            Some(port) => parts.push(format!("deny {}:{port}", rule.host)),
            None => parts.push(format!("deny {}", rule.host)),
        }
    }
    parts
}

/// The DNS tail of the destinations report: only a run whose netfilter
/// table carries the DNS verdict may name one.
fn dns_destinations_report(policy: &Policy) -> String {
    if policy.network.dns_allowed() {
        "dns answered by the forwarder".to_owned()
    } else {
        "dns dropped".to_owned()
    }
}

/// Whether a run that enters namespaces of its own creates a fresh guard user
/// namespace first.
///
/// The layout table in the change design decides: every run that builds its
/// namespaces from the host does, whatever layer follows. A proxied run is
/// already beneath the proxy namespace, which is the guard, and a second one
/// would spend the proxy namespace's only slot before the run's own namespace
/// asked for it.
fn creates_guard(guard_in_place: bool) -> bool {
    !guard_in_place
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
    /// limits, so something else can scope to it. The cgroup is then asked to
    /// carry the measuring controllers too, so the run's `memory.peak` and
    /// `pids.peak` can be read from it; a host that delegates only what the
    /// limits need still gets the cgroup, without the peaks.
    pub always_cgroup: bool,
    /// Writable paths granted on the user's behalf rather than by their config.
    ///
    /// A grant beneath one of these that the user wrote without write access is
    /// kept unwritable, since they never asked for the wider grant that would
    /// otherwise swallow it. The private home and private temporary storage are
    /// found from the world; this is for the ones a command adds, such as a
    /// confined shell's launch directory.
    pub implicit_write: Vec<PathBuf>,
    /// The network decision the run made above this backend, with the mode,
    /// what chose it, and why.
    ///
    /// `None` for a caller that made no decision, which is `bailey audit`: it
    /// selects through [`network::select`] and reports what the policy's mode
    /// would have done instead of applying it.
    pub network: Option<crate::backend::network::NetworkDecision>,
    /// A guard user namespace bailey created already bounds this process, so
    /// the namespace layers run beneath it instead of creating their own.
    ///
    /// Only an egress proxy run is in this position: its private namespace is
    /// the guard, and creating a second one would spend its only slot before
    /// the run's own namespace asked for it.
    pub guard_in_place: bool,
    /// The child end of the socketpair the seccomp fallback observer hands
    /// its listener over through. `Some` only for a fallback audit; the run
    /// paths never set it, and it refuses to combine with `isolate`.
    pub audit_listener: Option<RawFd>,
    /// The hostnames the policy's egress rules name, with the addresses each
    /// resolved to on the host before the run.
    ///
    /// The generated `/etc/hosts` built from these is what pins the names a
    /// client resolves inside the sandbox to the addresses the netfilter
    /// rules admit. Empty when the policy names no hostname.
    pub pins: Vec<crate::cli::Pin>,
    /// The per-run directory holding the combined trust bundle, when the run
    /// intercepts. The isolation plan binds the bundle file inside it over
    /// the system bundle paths, and the run removes the directory at the end.
    pub ca_bundle: Option<PathBuf>,
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
        if self.audit_listener.is_some() && self.isolate {
            return Err(BackendError::Command(
                "the fallback observer cannot run under namespace isolation: the \
                 recorded paths would name the reconstructed root's view of the \
                 filesystem, which reconciliation cannot place"
                    .into(),
            ));
        }
        report_degradation(policy);
        // Publication is arranged by the proxy network setup above this
        // backend. A policy that still asks for it here was never set up, and
        // running it would silently drop the promise.
        if !policy.network.publish_ports.is_empty() {
            return Err(BackendError::Command(
                "published ports need the private namespace, which this run \
                 did not establish"
                    .into(),
            ));
        }

        let seccomp = build_seccomp_filter(policy.self_fuse)
            .map_err(|err| BackendError::Unsupported(format!("seccomp: {err}")))?;
        let keep_mount = policy.self_fuse;

        // User namespaces gate both the isolation layer and the network
        // namespace, so the host is probed once for both. A proxied run skips
        // the probe: this process just created the proxy namespace, which is
        // proof enough, and the probe would spend the guard's single slot for
        // the moment between the probe child's exit and the run's own
        // namespace, where the kernel's count can still read one.
        let userns = if self.guard_in_place {
            true
        } else {
            isolation::available()
        };
        // Inside a sandbox the probe fails because our own seccomp filter denies
        // `unshare`, not because the host lacks anything. The namespaces of the
        // outer sandbox are still in force: they are properties of the process,
        // inherited and impossible to drop.
        let nested = world::inside_sandbox();
        let inherited = network::Inherited::detect();
        let mode = self
            .network
            .as_ref()
            .map_or_else(|| network::select(policy, userns), |decision| decision.mode);
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
        // Named with a count so a run that lists three sockets reads
        // differently from one that lists none: the count is what tells a
        // broken config (zero where the display should be) from an enforcing
        // one.
        let listed_connect = policy
            .filesystem
            .iter()
            .filter(|rule| rule.access.contains(policy::Access::CONNECT))
            .count();
        let socket_connect_abi =
            crate::backend::probe::landlock_abi().is_some_and(|abi| abi >= ABI_SOCKET_CONNECT);
        if listed_connect > 0 {
            if socket_connect_abi {
                report.applied(&format!("unix socket connect ({listed_connect} listed)"));
            } else {
                report.skipped("socket connect control", CONNECT_SKIP_REASON);
            }
        }
        report.applied("seccomp");
        if policy.self_fuse {
            report.applied("self-serve fuse mounts");
        }
        match mode {
            NetworkMode::Isolated => report.applied("network namespace"),
            NetworkMode::Private => report.applied("network namespace (private)"),
            NetworkMode::Brokered => match policy.network.broker {
                Some(crate::policy::Broker::Builtin) => report.applied("egress broker (built-in)"),
                Some(crate::policy::Broker::External(..)) => {
                    report.applied("egress broker (external)")
                }
                None => report.applied("egress broker"),
            },
            NetworkMode::LandlockOnly => match inherited {
                network::Inherited::IsolatedNamespace | network::Inherited::PrivateNamespace => {
                    report.applied("network namespace (inherited)")
                }
                network::Inherited::Brokered => report.applied("egress broker (inherited)"),
                _ if nested => report.skipped(
                    "network namespace",
                    "inside a sandbox that did not create one, so only TCP is restricted",
                ),
                // A policy that allows egress cannot use an empty namespace,
                // which is a consequence of the policy rather than a gap in
                // the host.
                _ if !userns => report.skipped(
                    "network namespace",
                    "unprivileged user namespaces unavailable, so only TCP is restricted",
                ),
                _ => {}
            },
        }
        // What chose the mode, and why this run got it: a mode set by a
        // project config or a flag reads differently from one the automatic
        // choice fell into, and a caller parsing the JSON sees the same line.
        if let Some(decision) = &self.network {
            report.applied(&format!(
                "network mode: {} ({}: {})",
                decision.mode.name(),
                decision.source,
                decision.reason
            ));
            // The destination rules are the private namespace's boundary, so
            // the run names what it admits and drops: a summary that only
            // named the mode would leave a policy naming ten hosts
            // indistinguishable from one naming none. A brokered run enforces
            // none of them, and its reason above says so.
            if decision.mode == NetworkMode::Private {
                report.applied(&format!(
                    "egress destinations: {}; {}",
                    egress_destinations_report(policy, &self.pins).join("; "),
                    dns_destinations_report(policy)
                ));
            }
            // A Landlock-only run still carries its own TCP port verdicts,
            // and a summary that named only the mode would leave a run
            // restricting ten ports indistinguishable from one restricting
            // none. Deny, UDP and DNS verdicts cannot exist in this mode:
            // they need the namespace it could not build, and the decision
            // refuses them before the run starts.
            if decision.mode == NetworkMode::LandlockOnly {
                report.applied(&format!(
                    "egress destinations (Landlock): {}",
                    egress_destinations_report(policy, &self.pins).join("; ")
                ));
            }
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
            let forwards = forward::validate(&policy.forwards, &policy.network.bind_ports)
                .map_err(BackendError::Command)?;
            let (announce, child_end) = UnixStream::pair().map_err(BackendError::Io)?;
            forward_child_end = Some(child_end);
            forward_announce = Some(announce);
            forward_forwards = Some(forwards);
        }

        // The files a private run's names and DNS setting need are written
        // before anything else reads the policy, so the Landlock plan and the
        // isolation plan both see the grants that place them. Written on the
        // host before the fork, from the addresses resolved before the
        // namespace existed. A brokered run keeps its own DNS posture, and
        // modes without pasta have no forwarder to name.
        let generated_files = if self.isolate
            && userns
            && self
                .network
                .as_ref()
                .is_some_and(|decision| decision.mode == NetworkMode::Private)
        {
            write_generated_files(&self.pins, policy.network.dns_allowed())
                .map_err(BackendError::Io)?
        } else {
            None
        };
        // The bundle file inside the per-run directory, what the plan binds
        // and what the CA variables name when nothing covers it.
        let ca_bundle_file = self.ca_bundle.as_ref().map(|dir| dir.join("ca-bundle.pem"));
        let generated_policy;
        let policy = if let Some((_, files)) = &generated_files {
            generated_policy = policy_with_generated(policy, files);
            &generated_policy
        } else {
            policy
        };

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
                let plan = build_isolation_plan(
                    policy,
                    mode,
                    &world,
                    &self.implicit_write,
                    ca_bundle_file.as_deref(),
                )?;
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

        // The trust bundle an intercepted run sees: under isolation the
        // covered system path, without it the per-run file itself. Either
        // way the target needs a Landlock read grant for the path it is
        // handed, and the CA variables name it.
        let ca_visible = isolation
            .as_ref()
            .and_then(|plan| plan.ca_bundle_visible.clone())
            .or_else(|| ca_bundle_file.clone().filter(|_| isolation.is_none()));
        if let Some(path) = &ca_visible
            && let Some(bits) = fs_access_bits(policy::Access::READ)
        {
            plan.filesystem.push((path.clone(), bits));
        }
        let ca_policy;
        let policy = if let Some(path) = &ca_visible {
            ca_policy = policy_with_ca_variables(policy, path);
            &ca_policy
        } else {
            policy
        };

        // Without the isolation layer, the network namespace is entered on its
        // own, so a plain `bailey run` still gets real egress denial.
        let network_only = isolation.is_none() && mode == NetworkMode::Isolated;

        // Which layer answers a namespace-creating syscall, decided by the
        // layout: a run whose namespaces bailey builds, or whose target sits
        // in the proxy namespace, carries the guard user namespace, and the
        // rest rely on the filter alone.
        if isolation.is_some() || network_only || self.guard_in_place {
            report.applied("nested namespaces: refused (kernel limit, seccomp)");
        } else {
            report.applied("nested namespaces: refused (seccomp only)");
        }

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
        // the rlimit above is taken out for the same reason, as are the other
        // two rlimits: the open-file limit holds on every host, and the
        // address-space fallback is what answers a memory limit no cgroup
        // could carry.
        let mut via_cgroup = ResourceLimits {
            file_bytes: None,
            open_files: None,
            address_space_bytes: None,
            ..policy.resources.clone()
        };
        if pids_via_rlimit.is_some() {
            via_cgroup.pids_max = None;
        }
        if via_cgroup == ResourceLimits::default() {
            // The policy asked for none, so there is nothing to report.
        } else if procs.is_some() {
            report.applied("resource limits");
            if cgroup.scope.is_some() {
                report.applied("systemd user scope");
            }
        } else {
            report.skipped(
                "resource limits",
                &limits_skip_reason(cgroup.failure.as_deref(), cgroup.scope_failure.as_deref()),
            );
        }
        if policy.resources.file_bytes.is_some() {
            report.applied("file size limit");
        }
        if pids_via_rlimit.is_some() {
            report.applied("process limit");
        }
        if policy.resources.open_files.is_some() {
            report.applied("open file limit");
        }
        let address_space_via_rlimit = address_space_fallback(&policy.resources, procs.is_some());
        if address_space_via_rlimit.is_some() {
            report.applied("per-process address space");
        }

        let mut command = Command::new(&target.program);
        command.args(&target.args);
        // The environment is built rather than inherited, so a caller's
        // credentials do not cross into the sandbox.
        command.env_clear();
        // What this run's target sits in is what this run established, or,
        // inside a sandbox, what this run inherited: the outer run's network
        // is not this one's to restate, and a run inside the target must read
        // the same truth a run inside this one would.
        let published_net = if nested {
            std::env::var("BAILEY_SANDBOX_NET").ok()
        } else {
            Some(network::Inherited::publish(mode).to_owned())
        };
        command.envs(world::environment(policy, &world, published_net.as_deref()));
        // Under isolation the working directory is entered after the pivot,
        // since the path only exists in the reconstructed root. Outside it, the
        // caller's directory is simply inherited.
        if let Some(cwd) = &target.cwd {
            command.current_dir(cwd);
        }
        let staging = StagingGuard {
            dirs: isolation
                .as_ref()
                .map(|plan| plan.staging.clone())
                .into_iter()
                .collect(),
            plain: generated_files
                .map(|(dir, _)| vec![dir])
                .unwrap_or_default()
                .into_iter()
                .chain(self.ca_bundle.clone())
                .collect(),
        };
        let stop_before_exec = self.stop_before_exec;
        let create_guard = creates_guard(self.guard_in_place);
        let audit_listener = self.audit_listener;
        let file_bytes = policy.resources.file_bytes;
        let open_files = policy.resources.open_files;
        // The marker tells an inner bailey that this run armed a listener: a
        // stack holds exactly one, so a fallback audit the target starts must
        // refuse. No kernel interface asks whether the inherited stack carries
        // a listener rather than plain filters, so the built environment
        // carries the answer instead.
        if audit_listener.is_some() {
            command.env(AUDIT_LISTENER_MARKER, "1");
        }
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

        // Safety: the closure runs in the forked child before exec. Bailey
        // may be multi-threaded at this point: the forward relay thread and
        // the audit supervisor thread both exist, and both block in `recvmsg`
        // at the fork, so neither holds a lock the child could inherit and
        // then wait on. Namespaces and the reconstructed root are set up
        // first, then Landlock is applied against the new root, then seccomp
        // closes the syscall surface last.
        // Close-on-exec, so a successful exec leaves the parent reading
        // nothing, and a failed setup leaves its message behind.
        let (setup_error_read, setup_error_write) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
                .map_err(|err| BackendError::Io(io::Error::from_raw_os_error(err as i32)))?;
        let setup_error_fd = setup_error_write.as_raw_fd();
        unsafe {
            command.pre_exec(move || {
                let result = (|| -> io::Result<()> {
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
                        isolation::enter(isolation, create_guard)
                            .map_err(|error| io::Error::other(format!("enter: {error}")))?;
                    } else if network_only {
                        network::enter_isolated(create_guard)?;
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
                    // Both rlimits land after the setup steps that open
                    // descriptors or map memory (the namespace and root
                    // reconstruction, the forward listeners, the Landlock
                    // ruleset), so the target's numbers bound the target's tree
                    // rather than the run's own scaffolding. Seccomp and the
                    // capability drop after them need neither new descriptors nor
                    // meaningful address space. The PID 1 supervisor that spawns
                    // the target under isolation comes after and is bounded,
                    // which is correct: it is part of the target's tree.
                    if let Some(count) = open_files {
                        set_open_files_limit(count)?;
                    }
                    if let Some(bytes) = address_space_via_rlimit {
                        set_address_space_limit(bytes)?;
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
                    // The fallback audit's observer, armed last of all: nothing
                    // bailey does in the child after this point is notified
                    // except the final exec, and the listener crosses to the
                    // supervisor before the target can name anything. The child
                    // end of the handover socket is close-on-exec, so it does not
                    // survive into the target either.
                    if let Some(handover) = audit_listener {
                        // An inherited listener means this audit is nested
                        // inside another fallback audit, and a stack holds
                        // exactly one. The outer run arms the marker with its
                        // target's environment, so the marker is what refuses
                        // cleanly. Mainstream kernels answer the second install
                        // with EBUSY (EINVAL where the arming task is a fork of
                        // an observed process), which covers a listener nobody
                        // marked; some kernels let the install stand and fail
                        // the exec instead, and the errno mapping below is what
                        // names those.
                        if std::env::var_os(AUDIT_LISTENER_MARKER).is_some() {
                            return Err(io::Error::other(
                                "a seccomp listener already observes this \
                             process, and a fallback audit cannot run \
                             nested",
                            ));
                        }
                        audit_notify::arm(handover).map_err(|err| {
                            if err
                                .raw_os_error()
                                .is_some_and(|errno| errno == libc::EBUSY || errno == libc::EINVAL)
                            {
                                io::Error::other(
                                    "a seccomp listener already observes this \
                                 process, and a fallback audit cannot run \
                                 nested",
                                )
                            } else {
                                err
                            }
                        })?;
                    }
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
                })();
                // An error that carries only a message reaches the parent as a
                // bare EINVAL, which is all `Command` passes back, so the
                // message goes down the pipe first.
                if let Err(error) = &result
                    && error.raw_os_error().is_none()
                {
                    let message = error.to_string();
                    libc::write(setup_error_fd, message.as_ptr().cast(), message.len());
                }
                result
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

        let spawned = command.spawn();
        let child = match spawned {
            Ok(child) => child,
            Err(error) => {
                drop(setup_error_write);
                let mut message = String::new();
                let _ = io::Read::read_to_string(
                    &mut std::fs::File::from(setup_error_read),
                    &mut message,
                );
                if !message.is_empty() {
                    return Err(BackendError::Command(message));
                }
                return Err(BackendError::Io(error));
            }
        };
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
            // Connecting to the relay is what the relay exists for, and the
            // socket connect right is its own grant on a Landlock ABI 9
            // kernel, so read and write alone would refuse the handshake.
            access: policy::Access::READ
                | policy::Access::WRITE
                | policy::Access::EXECUTE
                | policy::Access::CONNECT,
            at: Some(relay.at.clone()),
        }));
    extended
}

/// A copy of `policy` with a read grant for each generated file, placed
/// where the target sees it, and each path held read-only.
fn policy_with_generated(policy: &Policy, generated: &[(PathBuf, PathBuf)]) -> Policy {
    let mut extended = policy.clone();
    for (source, at) in generated {
        extended.filesystem.push(FsRule {
            path: source.clone(),
            access: policy::Access::READ,
            at: Some(at.clone()),
        });
        extended.read_only.push(at.clone());
    }
    extended
}

/// Name the covered trust path in every variable a TLS client reads.
///
/// `SSL_CERT_FILE` alone would miss requests, which keeps its own bundle and
/// ignores the system path unless `REQUESTS_CA_BUNDLE` is set, so that
/// variable is load-bearing rather than convenient.
fn policy_with_ca_variables(policy: &Policy, path: &Path) -> Policy {
    let mut extended = policy.clone();
    let value = path.display().to_string();
    for name in [
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "PIP_CERT",
        "NODE_EXTRA_CA_CERTS",
        "DENO_CERT",
        "CARGO_HTTP_CAINFO",
        "AWS_CA_BUNDLE",
    ] {
        extended.env.set.insert(name.into(), value.clone());
    }
    extended
}

/// Write the files a private run's names need.
///
/// `hosts` pins the names the policy resolved, one line per address in
/// answer order, with nothing else in the file: the sandbox resolves
/// exactly the names the policy pinned, and nothing more. `resolv.conf`
/// names the namespace's DNS forwarder when the setting allows questions.
/// Both live in one staging directory of their own, because the staging
/// root itself becomes the tmpfs mountpoint and anything written inside it
/// before that mount is covered.
///
/// The pair is the staging directory and the host-to-sandbox file placements
/// to bind.
type GeneratedFiles = (PathBuf, Vec<(PathBuf, PathBuf)>);

fn write_generated_files(
    pins: &[crate::cli::Pin],
    dns_forward: bool,
) -> io::Result<Option<GeneratedFiles>> {
    if pins.is_empty() && !dns_forward {
        return Ok(None);
    }
    let dir = staging_dir()?;
    let mut generated = Vec::new();
    if !pins.is_empty() {
        let mut body = String::from("# Generated by bailey from the policy's egress rules.\n");
        // The file replaces `/etc/hosts` whole, so the loopback names stay
        // answered whatever the policy pins.
        body.push_str("127.0.0.1 localhost\n::1 localhost\n");
        for pin in pins {
            for addr in &pin.addresses {
                body.push_str(&format!("{addr} {}\n", pin.name));
            }
        }
        let file = dir.join("hosts");
        std::fs::write(&file, body)?;
        generated.push((file, PathBuf::from("/etc/hosts")));
    }
    if dns_forward {
        let file = dir.join("resolv.conf");
        std::fs::write(
            &file,
            format!("nameserver {}\n", crate::cli::DNS_FORWARDER_V4),
        )?;
        generated.push((file, PathBuf::from("/etc/resolv.conf")));
    }
    Ok(Some((dir, generated)))
}

/// Removes the host-visible staging directory a reconstructed root was built
/// in, however the run ends.
///
/// Cleanup used to happen only on the success path, so a `pre_exec` that failed
/// after creating the directory, or a caller that dropped the run without
/// waiting, left one behind for every attempt.
///
/// A signal still does not unwind, so it leaves a directory behind. The sweep
/// at the start of the next run is what heals that, which is why the staging
/// name carries the pid.
struct StagingGuard {
    dirs: Vec<PathBuf>,
    /// Staging that holds generated files. These are plain directories whose
    /// contents are ours alone, so removal takes the contents with them. The
    /// mountpoint staging above must stay `remove_dir`-only: it is empty on
    /// the host by construction, and a directory with contents was filled by
    /// something else.
    plain: Vec<PathBuf>,
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        for dir in &self.plain {
            let _ = std::fs::remove_dir_all(dir);
        }
        for dir in &self.dirs {
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
    pub fn wait(self) -> Result<i32, BackendError> {
        self.wait_measured().map(|(code, _)| code)
    }

    /// Wait for the target, read the run's resource peaks from its cgroup, and
    /// tear the run's world down.
    ///
    /// The peaks only exist while the cgroup does, so they are read after the
    /// target exits and before the guard removes the directory. A caller that
    /// wants them must come here rather than to [`Self::wait`].
    pub fn wait_measured(mut self) -> Result<(i32, Usage), BackendError> {
        let status = self.child.wait().map_err(BackendError::Io)?;
        let usage = self.cgroup.peaks();
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
        let exit = Exit::of(status);
        match self.summary {
            Summary::Text => self.report.print(exit),
            Summary::Json => println!("{}", self.report.to_json(exit)),
            // Already printed, before the target ever ran.
            Summary::Established | Summary::Quiet => {}
        }
        Ok((exit.code, usage))
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
    /// Whether any rule grants the socket-connect right, which decides
    /// whether the ruleset handles it at all.
    socket_connect: bool,
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
        let mut socket_connect = false;
        for rule in &policy.filesystem {
            socket_connect |= rule.access.contains(policy::Access::CONNECT);
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
            // Landlock's connect list is TCP only, so a UDP rule's port is
            // not this list's to carry: the private namespace's netfilter
            // table enforces it.
            Egress::Allow(rules) => (
                true,
                rules
                    .iter()
                    .filter(|rule| rule.protocol == crate::policy::Protocol::Tcp)
                    .filter_map(|rule| rule.port)
                    .collect(),
            ),
        };
        // DNS over TCP reaches the forwarder when the setting allows it; the
        // netfilter table is what keeps the port from anywhere else. A run
        // whose egress is allowed outright handles no connect right at all,
        // so it names no port here either: adding one would refuse the
        // ruleset the policy never asked to bind.
        if matches!(policy.network.egress, Egress::Allow(_)) && policy.network.dns_allowed() {
            connect_ports.push(53);
            connect_ports.sort_unstable();
            connect_ports.dedup();
        }
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
            socket_connect,
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
        // The socket connect right arrived in ABI v9, after everything else
        // the policy uses, so it is handled beside the rest: without it the
        // kernel restricts no pathname socket at all, and an unlisted socket
        // would be reachable through any granted directory. On a kernel
        // without the right, best-effort drops it, and the warning below says
        // so rather than letting a connect list quietly turn decorative.
        ruleset = ruleset
            .handle_access(AccessFs::ResolveUnix)
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
        // Socket connect is newer than everything else the policy asks for, so
        // a kernel between ABI 6 and 8 enforces the rest of the policy exactly
        // while every connect listed is allowed. Saying so is the difference
        // between a degraded run and a silently open one.
        if self.socket_connect
            && crate::backend::probe::landlock_abi().is_some_and(|abi| abi < ABI_SOCKET_CONNECT)
        {
            eprintln!(
                "bailey: warning: connecting to UNIX sockets is not restricted on this \
                 kernel: the socket connect right needs Landlock ABI 9, so every entry \
                 in the connect list is allowed"
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
///
/// The name carries the run's pid alongside the unpredictable suffix, so a
/// later run can tell whose a leftover was and whether that run is still
/// alive, which is what makes it sweepable. The suffix is what stops another
/// user naming the path in advance: the pid is observable, the suffix is not.
fn fresh_dir(parent: &Path) -> io::Result<PathBuf> {
    claim_staging(&parent.join(format!(
        "{STAGING_PREFIX}{}.{}",
        std::process::id(),
        random_suffix()
    )))
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
///
/// The mode alone is not the test: a 0700 directory owned by someone else is
/// unreadable to us but not ours, and a run that staged in one would fail on
/// the create rather than fall back. Ownership is asked as well.
fn runtime_dir_host() -> Option<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let dir = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
    if !dir.is_absolute() {
        return None;
    }
    let meta = dir.metadata().ok()?;
    let me = unsafe { libc::geteuid() };
    if meta.uid() != me {
        return None;
    }
    (meta.permissions().mode() & 0o777 == 0o700).then_some(dir)
}

/// Remove the staging leftovers of runs that are no longer alive.
///
/// [`StagingGuard`] removes the directory on every path a run can return by,
/// but a signal does not unwind: a Ctrl-C, or anything else that kills bailey
/// without unwinding, leaves it behind. Sweeping before making our own means
/// a leftover heals on the next run rather than accumulating one per
/// interrupted run.
///
/// A leftover is identified by the pid its name carries, and removed only when
/// that pid is gone, the entry is this user's own directory, and the directory
/// is empty. A run still alive may well be a concurrent one, another user's
/// staging is not ours to remove, and a directory with contents was filled by
/// something else, so none of the three is touched.
///
/// Both places a run may stage are swept, because a run that staged under the
/// session runtime directory leaves a directory the temp directory never sees.
fn sweep_stale_staging() {
    let temp = std::env::temp_dir();
    sweep_staging(&temp);
    if let Some(runtime) = runtime_dir_host()
        && runtime != temp
    {
        sweep_staging(&runtime);
    }
}

/// Remove the dead runs' staging leftovers from `dir`.
fn sweep_staging(dir: &Path) {
    use std::os::unix::fs::MetadataExt;

    let me = unsafe { libc::geteuid() };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(rest) = name.strip_prefix(STAGING_PREFIX) else {
            continue;
        };
        // The name is `<pid>.<suffix>`. A bare pid is the shape the staging
        // directory had before the suffix existed, so a leftover written by an
        // older bailey is recognized too. Anything else is not ours to
        // interpret.
        let (pid, _) = rest.split_once('.').unwrap_or((rest, ""));
        if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        // A process id that is still running belongs to a run in progress,
        // which may well be a concurrent one.
        if Path::new("/proc").join(pid).exists() {
            continue;
        }
        // Another user's leftovers are not ours to remove, and saying so would
        // be noise on every run. The entry must also be a directory we own.
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_dir() || meta.uid() != me {
            continue;
        }
        // A mountpoint staging directory is empty on the host by construction:
        // the tmpfs is mounted over it inside the target's own mount
        // namespace, so nothing a run does ever lands in it. The other shape a
        // run leaves is the generated-files staging, which holds nothing but
        // the files bailey wrote there. A non-empty directory that is neither
        // was filled by something else and is not ours however its name is
        // spelled. `remove_dir` refusing a non-empty directory is the whole
        // guarantee.
        let generated = generated_file_names(&entry.path());
        match generated {
            None => {
                let _ = std::fs::remove_dir(entry.path());
            }
            Some(names) => {
                for name in names {
                    let _ = std::fs::remove_file(entry.path().join(name));
                }
                let _ = std::fs::remove_dir(entry.path());
            }
        }
    }
}

/// The generated files a staging directory holds, when it holds only those.
///
/// A run that died between writing the generated files and mounting them left
/// a directory that the mountpoint rule above would refuse forever: the files
/// make it non-empty, and nothing else would ever empty it. A directory whose
/// every entry is one of the names the generated-files staging uses is one of
/// those, and it is safe to empty.
fn generated_file_names(dir: &Path) -> Option<Vec<&'static str>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let name = match entry.file_name().to_str()? {
            "hosts" => "hosts",
            "resolv.conf" => "resolv.conf",
            _ => return None,
        };
        if entry.metadata().ok()?.is_dir() {
            return None;
        }
        names.push(name);
    }
    if names.is_empty() { None } else { Some(names) }
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
    ca_bundle: Option<&Path>,
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

    // The interception bundle: bound read-only over every
    // system trust path the reconstructed root carries, and the host's own
    // bundle added as a bind of its own when the root carries none, so
    // there is always one to cover. A path a denial covers over is
    // skipped: the cover would hide the bundle again.
    let mut ca_bundle_source = None;
    let mut ca_bundle_overlays = Vec::new();
    let mut ca_bundle_visible = None;
    if !policy.http.intercept.is_empty() {
        let Some(bundle) = ca_bundle else {
            return Err(BackendError::Command(
                "the policy intercepts hosts, which needs the CA bundle \
                 directory this run did not create; the run is refused"
                    .into(),
            ));
        };
        ca_bundle_source = Some(bundle.to_path_buf());
        for listed in crate::broker::CA_BUNDLE_PATHS {
            let path = PathBuf::from(listed);
            if conceal.iter().any(|cover| path.starts_with(&cover.path)) {
                continue;
            }
            let present = binds
                .iter()
                .any(|bind| (bind.is_dir && path.starts_with(&bind.at)) || bind.at == path)
                || links.iter().any(|link| link.at == path);
            if present {
                if ca_bundle_visible.is_none() {
                    ca_bundle_visible = Some(path.clone());
                }
                ca_bundle_overlays.push(path);
            }
        }
        if ca_bundle_overlays.is_empty() {
            let host = crate::broker::system_ca_bundle().ok_or_else(|| {
                BackendError::Command(
                    "no system trust bundle exists on this host, and an \
                     intercepted run has nothing to bind its CA over; the \
                     run is refused"
                        .into(),
                )
            })?;
            binds.push(BindMount {
                source: host.clone(),
                at: host.clone(),
                is_dir: false,
            });
            ca_bundle_visible = Some(host.clone());
            ca_bundle_overlays.push(host);
        }
    }

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
        ca_bundle_source,
        ca_bundle_overlays,
        ca_bundle_visible,
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
    // Socket connect is the ABI v9 right, so naming it here is what keeps a
    // `connect` grant from being folded into a read or write grant, which
    // would hand every socket in the hierarchy to any granted path.
    if access.contains(policy::Access::CONNECT) {
        bits |= AccessFs::ResolveUnix;
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
    note_runtime_dir_grant(policy);
}

/// The note for a policy that grants the session runtime directory without
/// listing any socket in it.
///
/// Before socket connect had its own right, a read grant on the runtime
/// directory was how a target reached the compositor and audio. On a kernel
/// with Landlock ABI 9 that grant no longer connects, so a policy written the
/// old way silently loses the display. One line says what changed and what to
/// write instead, on a kernel where it applies.
fn note_runtime_dir_grant(policy: &Policy) {
    let Some(abi) = crate::backend::probe::landlock_abi() else {
        return;
    };
    if abi < ABI_SOCKET_CONNECT {
        return;
    }
    let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") else {
        return;
    };
    let runtime = PathBuf::from(runtime);
    if !runtime.is_absolute() {
        return;
    }
    let covered = policy.filesystem.iter().any(|rule| {
        rule.access
            .intersects(policy::Access::READ | policy::Access::WRITE)
            && runtime.starts_with(&rule.path)
    });
    let listed = policy.filesystem.iter().any(|rule| {
        rule.access.contains(policy::Access::CONNECT) && rule.path.starts_with(&runtime)
    });
    if covered && !listed {
        eprintln!(
            "bailey: note: the runtime directory {} is granted, and on this kernel \
             its service sockets need a `connect` entry to be connectable; none \
             beneath it is listed",
            runtime.display()
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

/// Lower the caller's own rlimit to the policy's ceiling, never raise it.
///
/// An unprivileged process cannot raise a hard limit, so a policy asking for
/// more than the caller has would fail in the child and refuse the run for
/// nothing. Taking the minimum of the two means the target is always bounded
/// by at most the policy's number, and never granted anything the caller
/// could not already do. The soft limit stays where it was when that was
/// already lower, rather than being lifted to the policy's number, which
/// keeps programs using `select()` from being handed descriptors above 1024
/// they never asked for.
macro_rules! lower_rlimit {
    ($resource:expr, $ceiling:expr) => {{
        let ceiling = $ceiling as libc::rlim_t;
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit($resource, &mut current) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let limit = libc::rlimit {
            rlim_cur: current.rlim_cur.min(ceiling),
            rlim_max: current.rlim_max.min(ceiling),
        };
        if unsafe { libc::setrlimit($resource, &limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }};
}

/// `RLIMIT_NOFILE`: the largest descriptor number a process may newly open.
/// Inherited descriptors above it stay open, which is how the kernel defines
/// the limit, not something bailey chooses.
fn set_open_files_limit(count: u64) -> io::Result<()> {
    lower_rlimit!(libc::RLIMIT_NOFILE, count)
}

/// `RLIMIT_AS`: what a process may map, which is not what it may keep
/// resident. Applied only as the opt-in stand-in for a memory limit no cgroup
/// could carry, and reported as exactly that.
fn set_address_space_limit(bytes: u64) -> io::Result<()> {
    lower_rlimit!(libc::RLIMIT_AS, bytes)
}

/// The per-process address-space fallback is a stand-in for `memory` where no
/// cgroup could carry it, so it applies only when a memory limit is set and
/// the run got no cgroup. A cgroup's `memory.max` is the sound answer where
/// one exists, and layering an address-space bound on top would only add the
/// large-reservation breakage.
fn address_space_fallback(resources: &ResourceLimits, cgroup: bool) -> Option<u64> {
    resources
        .address_space_bytes
        .filter(|_| resources.memory_bytes.is_some() && !cgroup)
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

/// Syscalls denied to the target, each entry carrying the kernel name the
/// documentation page uses. These are not needed by normal applications and
/// are common building blocks for sandbox escape, privilege escalation, or
/// tampering with other processes. Every new refusal goes into this table or
/// one of the other named tables below, so the docs test can hold the page
/// and the filter to the same list.
fn denied_syscalls() -> &'static [(&'static str, i64)] {
    &[
        ("ptrace", libc::SYS_ptrace),
        ("add_key", libc::SYS_add_key),
        ("request_key", libc::SYS_request_key),
        ("keyctl", libc::SYS_keyctl),
        ("kexec_load", libc::SYS_kexec_load),
        ("kexec_file_load", SYS_KEXEC_FILE_LOAD),
        ("init_module", libc::SYS_init_module),
        ("finit_module", libc::SYS_finit_module),
        ("delete_module", libc::SYS_delete_module),
        ("bpf", libc::SYS_bpf),
        ("perf_event_open", libc::SYS_perf_event_open),
        ("userfaultfd", libc::SYS_userfaultfd),
        ("swapon", libc::SYS_swapon),
        ("swapoff", libc::SYS_swapoff),
        ("reboot", libc::SYS_reboot),
        ("pivot_root", libc::SYS_pivot_root),
        ("setns", libc::SYS_setns),
        ("unshare", libc::SYS_unshare),
        ("process_vm_readv", libc::SYS_process_vm_readv),
        ("process_vm_writev", libc::SYS_process_vm_writev),
        ("open_by_handle_at", libc::SYS_open_by_handle_at),
        ("acct", libc::SYS_acct),
        // `memfd_create` makes an anonymous executable inode that no
        // filesystem rule can name, so a `PathBeneath` rule on execute cannot
        // reach it. With it denied there is nothing for `execveat` to name
        // through `AT_EMPTY_PATH`, and everything the target runs comes off a
        // path the policy granted.
        ("memfd_create", libc::SYS_memfd_create),
        // Landlock is checked when a file is opened, not when a descriptor is
        // duplicated, so a descriptor taken from bailey carries the access
        // bailey had. Without a PID namespace the target can name bailey and
        // ask for one, which reaches the trust store and the config that was
        // just verified.
        ("pidfd_getfd", libc::SYS_pidfd_getfd),
        // Landlock still mediates the filesystem operations a ring issues, but
        // a ring does not go through `sys_ioctl`, so the subvolume denials
        // below would be reachable through it. Nothing here needs io_uring.
        ("io_uring_setup", libc::SYS_io_uring_setup),
        ("io_uring_enter", libc::SYS_io_uring_enter),
        ("io_uring_register", libc::SYS_io_uring_register),
        ("chroot", libc::SYS_chroot),
        ("quotactl", libc::SYS_quotactl),
        // Same-uid cross-process reach that neither Landlock nor the namespace
        // covers.
        ("kcmp", libc::SYS_kcmp),
        ("process_madvise", libc::SYS_process_madvise),
        ("process_mrelease", libc::SYS_process_mrelease),
        // Bounded only by the ambient memlock limit, which is the host's.
        ("mlockall", libc::SYS_mlockall),
    ]
}

/// The mount syscall family: `mount(2)` and the new mount API that reaches
/// the same power across several calls.
///
/// Denied by default. A policy with `self_fuse` lets them through, because
/// the kernel still gates every one on `CAP_SYS_ADMIN` in the run's user
/// namespace, which is exactly the capability `self_fuse` keeps. Each entry
/// carries the kernel name the documentation page uses.
const MOUNT_SYSCALLS: &[(&str, i64)] = &[
    ("mount", libc::SYS_mount),
    ("umount2", libc::SYS_umount2),
    ("fsopen", libc::SYS_fsopen),
    ("fsconfig", libc::SYS_fsconfig),
    ("fsmount", libc::SYS_fsmount),
    ("move_mount", libc::SYS_move_mount),
    ("open_tree", libc::SYS_open_tree),
    ("fspick", libc::SYS_fspick),
    ("mount_setattr", libc::SYS_mount_setattr),
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
/// copy); `0xbc` is bcachefs. Each entry carries the filesystem name the
/// documentation page uses.
const SUBVOL_IOCTL_TYPES: [(&str, u64); 2] = [("btrfs", 0x94), ("bcachefs", 0xbc)];

/// Terminal requests that put bytes into the input queue of a shared tty.
///
/// `TIOCSTI` pushes a byte as though it had been typed, so a target that can
/// reach the caller's terminal can run a command in the caller's shell after
/// the sandbox exits. `TIOCLINUX` reaches the console selection buffer the same
/// way. Current kernels gate `TIOCSTI` behind a capability and a sysctl, and
/// the older ones this still supports do not. Each entry carries the request
/// name the documentation page uses.
const TERMINAL_INJECTION_IOCTLS: [(&str, u64); 2] = [("TIOCSTI", 0x5412), ("TIOCLINUX", 0x541c)];

/// The `CLONE_NEW*` flags a namespace can be built one `clone` at a time
/// with, each carrying the flag name the documentation page uses.
const NAMESPACE_CLONE_FLAGS: [(&str, u64); 7] = [
    ("CLONE_NEWNS", libc::CLONE_NEWNS as u64),
    ("CLONE_NEWCGROUP", libc::CLONE_NEWCGROUP as u64),
    ("CLONE_NEWUTS", libc::CLONE_NEWUTS as u64),
    ("CLONE_NEWIPC", libc::CLONE_NEWIPC as u64),
    ("CLONE_NEWUSER", libc::CLONE_NEWUSER as u64),
    ("CLONE_NEWPID", libc::CLONE_NEWPID as u64),
    ("CLONE_NEWNET", libc::CLONE_NEWNET as u64),
];

fn build_seccomp_filter(self_fuse: bool) -> anyhow::Result<seccompiler::BpfProgram> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    };

    let mut rules = BTreeMap::new();
    for &(_, nr) in denied_syscalls() {
        // An empty rule vector matches the syscall unconditionally.
        rules.insert(nr, Vec::new());
    }
    if !self_fuse {
        for &(_, nr) in MOUNT_SYSCALLS {
            rules.insert(nr, Vec::new());
        }
    }

    // ioctl carries too much that is ordinary to deny whole, so only the
    // subvolume families are refused, each matched on the type byte of the
    // request. The rules are alternatives: an ioctl of either type is denied,
    // every other is left to the kernel.
    let mut ioctl_rules = SUBVOL_IOCTL_TYPES
        .iter()
        .map(|&(_, ty)| {
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
    for (_, request) in TERMINAL_INJECTION_IOCTLS {
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
    let clone_rules = NAMESPACE_CLONE_FLAGS
        .iter()
        .map(|&(_, flag)| {
            Ok(SeccompRule::new(vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(flag),
                flag,
            )?])?)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    rules.insert(libc::SYS_clone, clone_rules);
    // `clone3` carries the same flags behind a pointer, which no seccomp
    // filter can dereference. The prologue answers it `ENOSYS`, so every libc
    // and runtime that tries `clone3` first falls back to `clone`, where the
    // flags above decide, and the kernel limit in the run's guard namespace
    // holds whatever still slips through. The capability drop after everything
    // here is what leaves a namespace a target does build holding nothing it
    // could not already reach.

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        target_arch()?,
    )?;
    Ok(prepend_seccomp_guards(filter.try_into()?))
}

/// `AUDIT_ARCH_*` value for the architecture the filter was built for. seccomp
/// reports it in `seccomp_data.arch`, and every rule's syscall number is only
/// meaningful for this one.
#[cfg(target_arch = "x86_64")]
pub(crate) const NATIVE_AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
pub(crate) const NATIVE_AUDIT_ARCH: u32 = 0xc000_00b7;

/// Builds the guard instructions that precede every generated filter.
///
/// These carry the refusals the generated seccompiler filter cannot express,
/// because seccompiler gives every rule in a filter the same action and these
/// need errnos of their own, plus the architecture check that seccompiler
/// never writes.
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
fn seccomp_guards() -> Vec<seccompiler::sock_filter> {
    use seccompiler::sock_filter;

    // Classic BPF opcodes and seccomp offsets, which libc does not name.
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JGE_K: u16 = 0x35;
    const BPF_RET_K: u16 = 0x06;
    const ARCH_OFFSET: u32 = 4; // offsetof(seccomp_data, arch)
    const NR_OFFSET: u32 = 0; // offsetof(seccomp_data, nr)
    // Low words of `seccomp_data.args[0]` and `args[2]`, the `socket` family
    // and protocol. Little-endian, which is all bailey builds for.
    const SOCKET_FAMILY_OFFSET: u32 = 16;
    const SOCKET_PROTOCOL_OFFSET: u32 = 32;
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    const RET_ERRNO_EPERM: u32 = 0x0005_0000 | (libc::EPERM as u32);
    const RET_ERRNO_EAFNOSUPPORT: u32 = 0x0005_0000 | (libc::EAFNOSUPPORT as u32);
    const RET_ERRNO_EPROTONOSUPPORT: u32 = 0x0005_0000 | (libc::EPROTONOSUPPORT as u32);
    const RET_ERRNO_ENOPROTOOPT: u32 = 0x0005_0000 | (libc::ENOPROTOOPT as u32);
    const RET_ERRNO_ENOSYS: u32 = 0x0005_0000 | (libc::ENOSYS as u32);

    const AF_SMC: i32 = 43;
    const IPPROTO_SMC: i32 = 256;
    const IPPROTO_MPTCP: i32 = 262;

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

    // Landlock's TCP rules act only on sockets where `sk_is_tcp()` holds, so
    // these socket kinds would slip past every TCP port rule while still
    // reaching TCP endpoints: MPTCP is a stream protocol that falls back to
    // plain TCP on the wire, and SMC falls back through a socket the kernel
    // opens without the caller's Landlock domain. SMC answers either as its
    // own family or, on 6.11 and later, as an INET socket naming the SMC
    // protocol, so both shapes are refused at `socket()`, before a socket
    // exists to connect or bind with, and with the errno a kernel without
    // the feature returns, so aware clients fall back to TCP and stay under
    // Landlock. The block matches the arguments by their low words, as an
    // `int` argument's upper register word carries nothing the kernel itself
    // relies on. It reloads the syscall number rather than reusing the load
    // above, so it reads the same on every supported architecture.
    let mut socket_guards = vec![
        // A = seccomp_data.nr
        stmt(BPF_LD_W_ABS, NR_OFFSET),
        // not a socket call: jump past the rest of the block to the filter
        sock_filter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 0,
            k: libc::SYS_socket as u32,
        },
        // A = the family argument
        stmt(BPF_LD_W_ABS, SOCKET_FAMILY_OFFSET),
        // family AF_SMC: fall into the refusal; otherwise skip it
        jump(BPF_JMP_JEQ_K, AF_SMC as u32, 0, 1),
        stmt(BPF_RET_K, RET_ERRNO_EAFNOSUPPORT),
        // A = the protocol argument
        stmt(BPF_LD_W_ABS, SOCKET_PROTOCOL_OFFSET),
        // protocol IPPROTO_SMC: fall into the refusal; otherwise skip it
        jump(BPF_JMP_JEQ_K, IPPROTO_SMC as u32, 0, 1),
        stmt(BPF_RET_K, RET_ERRNO_EPROTONOSUPPORT),
        // protocol IPPROTO_MPTCP: fall into the refusal; otherwise skip it
        jump(BPF_JMP_JEQ_K, IPPROTO_MPTCP as u32, 0, 1),
        stmt(BPF_RET_K, RET_ERRNO_ENOPROTOOPT),
    ];
    // From the gate, a jump of `jf` skips everything between it and the first
    // instruction after the block.
    socket_guards[1].jf = (socket_guards.len() - 2) as u8;
    prologue.extend_from_slice(&socket_guards);

    // `clone3` carries the namespace flags in a struct a filter cannot read,
    // so it is refused whole, with the errno that makes libcs treat it as
    // unimplemented and fall back to `clone`, whose flags the rules in the
    // filter below do read. `EPERM` would end thread pools rather than route
    // them to the fallback. What no filter sees, the guard user namespace of
    // the run bounds instead.
    let clone3_guards = vec![
        // A = seccomp_data.nr
        stmt(BPF_LD_W_ABS, NR_OFFSET),
        // not clone3: skip the refusal and fall into the filter
        jump(BPF_JMP_JEQ_K, libc::SYS_clone3 as u32, 0, 1),
        stmt(BPF_RET_K, RET_ERRNO_ENOSYS),
    ];
    prologue.extend_from_slice(&clone3_guards);

    prologue
}

/// Prepends the guard prologue to a generated filter.
fn prepend_seccomp_guards(program: seccompiler::BpfProgram) -> seccompiler::BpfProgram {
    let mut guarded = seccomp_guards();
    guarded.extend(program);
    guarded
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

/// The sockets the broker may create: the internet protocol families only.
///
/// The broker needs no local IPC once it has its descriptors, and a broker
/// that could open a UNIX socket could reach the caller's session bus,
/// `ssh-agent` or `gpg-agent`, which hold the caller's authority. Its filter
/// therefore refuses `socket` and `socketpair` for every family except
/// `AF_INET` and `AF_INET6`.
/// The family is an integer argument, so the filter reads it from the
/// registers and there is nothing to race. `AF_NETLINK` needs no exception:
/// glibc's `AI_ADDRCONFIG` probe fails and it assumes both families, which
/// is what a run wants anyway.
fn broker_socket_family_guards() -> Vec<seccompiler::sock_filter> {
    use seccompiler::sock_filter;

    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const NR_OFFSET: u32 = 0;
    const SOCKET_FAMILY_OFFSET: u32 = 16;
    const RET_ERRNO_EPERM: u32 = 0x0005_0000 | (libc::EPERM as u32);

    let stmt = |code: u16, k: u32| sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| sock_filter { code, jt, jf, k };

    // Block layout, with `past` the first instruction after it:
    //   [0] load the syscall number
    //   [1] socket:     fall into the family check
    //   [2] socketpair: fall into the family check, else jump to past
    //   [3] load the family
    //   [4] AF_INET:        jump to past
    //   [5] AF_INET6:       jump to past
    //   [6] refuse the rest
    vec![
        stmt(BPF_LD_W_ABS, NR_OFFSET),
        jump(BPF_JMP_JEQ_K, libc::SYS_socket as u32, 1, 0),
        jump(BPF_JMP_JEQ_K, libc::SYS_socketpair as u32, 0, 4),
        stmt(BPF_LD_W_ABS, SOCKET_FAMILY_OFFSET),
        jump(BPF_JMP_JEQ_K, libc::AF_INET as u32, 2, 0),
        jump(BPF_JMP_JEQ_K, libc::AF_INET6 as u32, 1, 0),
        stmt(BPF_RET_K, RET_ERRNO_EPERM),
    ]
}

/// bailey's seccomp denylist with the broker's IPC boundary.
///
/// The broker runs under the same denylist the target runs, with the socket
/// family guard in front. Applied by [`confine_broker`],
/// which refuses rather than continuing without it.
pub(crate) fn broker_seccomp_program() -> anyhow::Result<seccompiler::BpfProgram> {
    let mut program = broker_socket_family_guards();
    program.extend(prepend_seccomp_guards(build_seccomp_filter(false)?));
    Ok(program)
}

/// The Landlock ABI the broker confines under: a test's forced value when
/// one is set, the kernel's otherwise.
///
/// `BAILEY_BROKER_LANDLOCK_ABI` exists so the below-ABI-6 behaviour the
/// kernel-matrix job sees on old kernels can also be exercised on a new
/// one. Forcing a value higher than the kernel has is answered honestly:
/// the ruleset then covers more than the kernel enforces, and the layers
/// report what was actually enforced.
fn broker_landlock_abi() -> Option<u32> {
    if let Ok(forced) = std::env::var("BAILEY_BROKER_LANDLOCK_ABI")
        && let Ok(version) = forced.trim().parse::<u32>()
    {
        return Some(version);
    }
    crate::backend::probe::landlock_abi()
}

/// The `landlock` crate's ABI value for a version number, clamped to the
/// newest the crate names.
fn landlock_abi_of(version: u32) -> ABI {
    match version {
        1 => ABI::V1,
        2 => ABI::V2,
        3 => ABI::V3,
        4 => ABI::V4,
        5 => ABI::V5,
        _ => ABI::V6,
    }
}

/// Whether the HTTP rules allow a connect to any port.
///
/// A rule without a port allows every port to its host, and Landlock can
/// bound a connect by port alone, so no set of port grants covers such a
/// rule. The caller drops the connect layer instead: every port passes
/// Landlock, and the broker's own ACL stays the boundary for hosts and
/// ports.
fn broker_connects_any_port(http: &crate::policy::HttpPolicy) -> bool {
    http.allow.iter().any(|rule| rule.port.is_none())
}

/// The TCP connect ports the HTTP rules can produce, plus 53 for DNS over
/// TCP.
///
/// A rule without a port can produce both the CONNECT default and the
/// cleartext default. Denied rules never produce a connect, so only the
/// allowances are read.
fn broker_connect_ports(http: &crate::policy::HttpPolicy) -> Vec<u16> {
    let mut ports = std::collections::BTreeSet::new();
    ports.insert(53);
    for rule in &http.allow {
        match rule.port {
            Some(port) => {
                ports.insert(port);
            }
            None => {
                ports.insert(443);
                ports.insert(80);
            }
        }
    }
    ports.into_iter().collect()
}

/// Confine the broker process itself.
///
/// Landlock first: read access to the two files name resolution needs, TCP
/// connect only to the ports the HTTP rules can produce plus 53, abstract
/// UNIX sockets and signals scoped where the kernel has ABI 6, and pathname
/// UNIX resolution handled with no grant from ABI 9. No socket is granted
/// for name resolution: glibc falls back from an unreachable NSS socket to
/// plain DNS. Then bailey's seccomp denylist with the socket family filter.
///
/// A kernel without Landlock degrades rather than refuses: the seccomp
/// family filter is the boundary and holds there. The returned layers say
/// what was actually enforced, for the ready line and the run summary. The
/// seccomp filter is not optional: its failure refuses.
pub fn confine_broker(http: &crate::policy::HttpPolicy) -> io::Result<crate::broker::BrokerLayers> {
    let mut layers = crate::broker::BrokerLayers::default();

    if let Some(version) = broker_landlock_abi()
        && version >= 1
    {
        let abi = landlock_abi_of(version);
        let read: BitFlags<AccessFs> = AccessFs::ReadFile | AccessFs::ReadDir;
        let ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(abi))
            .and_then(|ruleset| {
                if version >= 9 {
                    // Handled with no grant: a pathname UNIX socket cannot
                    // be resolved into an open, and nothing is added to
                    // permit one.
                    ruleset.handle_access(AccessFs::ResolveUnix)
                } else {
                    Ok(ruleset)
                }
            })
            .and_then(|ruleset| {
                // The connect layer is only handled when the port grants
                // can cover the rules: a portless allowance allows every
                // port to its host, and handling the right with no grants
                // would deny what the rule allows.
                if version >= 4 && !broker_connects_any_port(http) {
                    ruleset.handle_access(AccessNet::ConnectTcp)
                } else {
                    Ok(ruleset)
                }
            })
            .and_then(|ruleset| {
                if version >= 6 {
                    ruleset.scope(Scope::from_all(landlock_abi_of(6)))
                } else {
                    Ok(ruleset)
                }
            })
            .map_err(|error| io::Error::other(format!("landlock ruleset: {error}")))?;
        let mut created = ruleset
            .create()
            .map_err(|error| io::Error::other(format!("landlock create: {error}")))?;
        for path in ["/etc/resolv.conf", "/etc/hosts"] {
            if let Ok(file) = std::fs::File::open(path) {
                created = created
                    .add_rule(PathBeneath::new(&file, read))
                    .map_err(|error| io::Error::other(format!("landlock grant {path}: {error}")))?;
            }
        }
        // The upstream TLS sessions verify certificates against the host's
        // own roots, so the bundle files are readable to the
        // broker, and the directories beside them, because the loader lists
        // a hashed-certificates directory as well as reading a bundle file.
        // Nothing else of /etc is granted.
        for path in crate::broker::CA_BUNDLE_PATHS {
            if let Ok(file) = std::fs::File::open(path) {
                created = created
                    .add_rule(PathBeneath::new(&file, AccessFs::ReadFile))
                    .map_err(|error| io::Error::other(format!("landlock grant {path}: {error}")))?;
            }
            if let Some(dir) = std::path::Path::new(path).parent()
                && let Ok(handle) = std::fs::File::open(dir)
            {
                created = created
                    .add_rule(PathBeneath::new(&handle, read))
                    .map_err(|error| {
                        io::Error::other(format!("landlock grant {}: {error}", dir.display()))
                    })?;
            }
        }
        // A portless allowance allows every port to its host, and no set of
        // port grants covers that, so the connect layer is left unhandled
        // and the broker's ACL is the boundary. With only ported rules, the
        // grants cover what they can produce. Before Landlock ABI 4 there is
        // no network right to grant, so the broker's ports go unrestricted,
        // which its layers report.
        if version >= 4 && !broker_connects_any_port(http) {
            for port in broker_connect_ports(http) {
                created = created
                    .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
                    .map_err(|error| {
                        io::Error::other(format!("landlock grant port {port}: {error}"))
                    })?;
            }
        }
        let status = created
            .restrict_self()
            .map_err(|error| io::Error::other(format!("landlock restrict: {error}")))?;
        // A kernel that reports PartiallyEnforced here has dropped the
        // crate's preview rights, such as pathname UNIX resolution when its
        // ABI has no such right yet. Everything it supports was enforced,
        // and the layers below report that, gated by the ABI each layer
        // needs. Only a ruleset that is not enforced at all leaves a layer
        // false beside the version gates.
        let enforced = status.ruleset != RulesetStatus::NotEnforced;
        layers.landlock = enforced && version >= 6;
        layers.landlock_network = enforced && version >= 4 && !broker_connects_any_port(http);
    }

    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let program =
        broker_seccomp_program().map_err(|error| io::Error::other(format!("seccomp: {error}")))?;
    seccompiler::apply_filter(&program)
        .map_err(|error| io::Error::other(format!("seccomp: {error}")))?;
    layers.seccomp = true;
    Ok(layers)
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
    /// The user-manager scope the run's cgroup came from, when one was asked
    /// for and granted.
    scope: Option<String>,
    /// Why the scope request failed after it was sent, when it was. A gate
    /// that stopped the request leaves this unset: the run's reason stays
    /// what it was before scope requests existed.
    scope_failure: Option<String>,
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
                scope: None,
                scope_failure: None,
            };
        }
        let needed = cgroup::needed_controllers(limits);
        // A run asked for a cgroup without limits is also asked for the
        // measuring controllers, so the peaks can be read from it. Falling
        // back to the limits' controllers alone is today's request: a host
        // that delegates only those keeps the scoping and loses the peaks.
        let wanted = if even_without_limits {
            cgroup::measuring_controllers(&needed)
        } else {
            needed.clone()
        };
        let mut base = None;
        for controllers in cgroup::controller_searches(even_without_limits, &wanted, &needed) {
            if let Some(root) = cgroup::usable_root(&controllers) {
                base = Some(root);
                break;
            }
        }
        let mut scope = None;
        let mut scope_failure = None;
        if base.is_none() {
            match cgroup::request_user_scope() {
                cgroup::UserScope::Granted(unit) => {
                    // The scope holds bailey now, so the same walk as before
                    // finds it as the nearest usable ancestor.
                    base = cgroup::usable_root(&wanted);
                    scope = Some(unit);
                }
                cgroup::UserScope::Refused(reason) => scope_failure = Some(reason),
                cgroup::UserScope::Unavailable(_) => {}
            }
        }
        // Not reported here: the run summary carries it, so a single fact
        // does not appear twice.
        match base
            .ok_or_else(|| {
                io::Error::other(
                    "no cgroup this user may create runs in; a delegated subtree is \
                     needed, or name one with BAILEY_CGROUP_ROOT",
                )
            })
            .and_then(|base| create_run_cgroup(base, limits))
        {
            Ok(dir) => Self {
                dir: Some(dir),
                failure: None,
                scope,
                scope_failure: None,
            },
            Err(err) => Self {
                dir: None,
                failure: Some(err.to_string()),
                scope: None,
                scope_failure,
            },
        }
    }

    /// The `cgroup.procs` path the target writes itself into before exec.
    fn procs_path(&self) -> Option<PathBuf> {
        self.dir.as_ref().map(|dir| dir.join("cgroup.procs"))
    }

    /// The run's resource peaks, read from the cgroup before it is removed.
    /// A run with no cgroup reports both peaks as unmeasured, with the reason.
    fn peaks(&self) -> Usage {
        match &self.dir {
            Some(dir) => cgroup::read_peaks(dir),
            None => Usage {
                memory_peak_bytes: None,
                tasks_peak: None,
                unmeasured: vec![
                    "memory: no cgroup for this run".to_owned(),
                    "tasks: no cgroup for this run".to_owned(),
                ],
            },
        }
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

/// Create the run's own cgroup under an already-found `base`, with the
/// policy's limits written into it.
fn create_run_cgroup(base: PathBuf, limits: &ResourceLimits) -> io::Result<PathBuf> {
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

/// The skipped reason for resource limits: the failure that stopped the
/// cgroup, with the user manager's refusal appended when one was received. A
/// request that no gate let through leaves the reason unchanged.
fn limits_skip_reason(failure: Option<&str>, scope_failure: Option<&str>) -> String {
    let reason = failure.unwrap_or("no writable delegated cgroup");
    match scope_failure {
        Some(refusal) => format!("{reason}; systemd user scope: {refusal}"),
        None => reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A listener handover cannot be combined with namespace isolation. The
    /// guard runs before any setup, so the refusal costs nothing and leaves
    /// no world behind.
    #[test]
    fn an_audit_listener_refuses_isolation() {
        let backend = EnforceBackend {
            isolate: true,
            audit_listener: Some(3),
            ..EnforceBackend::default()
        };
        let target = Target {
            program: PathBuf::from("/bin/true"),
            args: Vec::new(),
            cwd: None,
        };
        let err = match backend.spawn(&Policy::default(), &target) {
            Err(err) => err,
            Ok(_) => panic!("the combination is refused"),
        };
        assert!(err.to_string().contains("namespace isolation"), "{err}");
    }
    use crate::policy::{Access, DeviceRule, Egress, FsRule, PortForward, ResourceLimits};
    use std::collections::BTreeSet;
    use std::io::Write as _;

    /// The skip reason is the one place a user learns what an older kernel
    /// costs a connect-list policy, so it must say both the requirement and
    /// the consequence.
    #[test]
    fn the_connect_skip_reason_names_the_kernel_and_the_cost() {
        assert!(
            CONNECT_SKIP_REASON.contains("ABI 9"),
            "the reason must name the ABI: {CONNECT_SKIP_REASON}"
        );
        assert!(
            CONNECT_SKIP_REASON.contains("can be connected to"),
            "the reason must say what the policy loses: {CONNECT_SKIP_REASON}"
        );
    }

    /// A run that never got a cgroup reports both peaks as unmeasured with
    /// the reason, which is what an audit on such a host writes to its trace.
    #[test]
    fn a_run_without_a_cgroup_reports_its_peaks_unmeasured() {
        let guard = CgroupGuard::create(&ResourceLimits::default(), false);
        assert!(guard.dir.is_none());
        let usage = guard.peaks();
        assert_eq!(usage.memory_peak_bytes, None);
        assert_eq!(usage.tasks_peak, None);
        assert_eq!(
            usage.unmeasured,
            vec![
                "memory: no cgroup for this run",
                "tasks: no cgroup for this run",
            ]
        );
    }

    /// The skipped reason for limits must stay byte-identical on a host where
    /// no request was ever sent, and name the manager's refusal when one was.
    #[test]
    fn the_limits_skip_reason_carries_the_scope_refusal() {
        assert_eq!(
            limits_skip_reason(
                Some(
                    "no cgroup this user may create runs in; a delegated subtree is \
                      needed, or name one with BAILEY_CGROUP_ROOT"
                ),
                None,
            ),
            "no cgroup this user may create runs in; a delegated subtree is \
             needed, or name one with BAILEY_CGROUP_ROOT"
        );
        assert_eq!(
            limits_skip_reason(
                None,
                Some("org.freedesktop.systemd1.ScopeNotRunning: refused")
            ),
            "no writable delegated cgroup; systemd user scope: \
             org.freedesktop.systemd1.ScopeNotRunning: refused"
        );
    }

    /// Report a unit test as skipped and record the skip where CI asks for
    /// it, mirroring `tests/common/mod.rs`: the same printed line, the same
    /// log line, with the thread's module path as the test's name.
    fn skip(reason: &str) {
        eprintln!("skipping: {reason}");
        let Some(path) = std::env::var_os("BAILEY_TEST_SKIP_LOG") else {
            return;
        };
        let Ok(mut log) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        else {
            return;
        };
        let name = std::thread::current();
        let test = name.name().unwrap_or("unknown");
        let _ = writeln!(log, "{}::{}\t{}", env!("CARGO_CRATE_NAME"), test, reason);
    }

    /// The fallback is opt-in twice over: it needs both `address_space` set
    /// and `memory` set, and a run that got a cgroup never layers it on. If
    /// this ever applies without those, an opt-in has become a default.
    #[test]
    fn the_address_space_fallback_applies_only_where_it_was_asked_for() {
        let resources = ResourceLimits {
            memory_bytes: Some(2_000_000_000),
            address_space_bytes: Some(8_000_000_000),
            ..ResourceLimits::default()
        };
        assert_eq!(
            address_space_fallback(&resources, false),
            Some(8_000_000_000),
            "a cgroup-less run with both keys set applies the fallback"
        );
        assert_eq!(
            address_space_fallback(&resources, true),
            None,
            "a cgroup carries the memory limit, so the fallback must stay off"
        );
        let memory_only = ResourceLimits {
            memory_bytes: Some(2_000_000_000),
            ..ResourceLimits::default()
        };
        assert_eq!(
            address_space_fallback(&memory_only, false),
            None,
            "memory alone must not imply the fallback"
        );
        let fallback_only = ResourceLimits {
            address_space_bytes: Some(8_000_000_000),
            ..ResourceLimits::default()
        };
        assert_eq!(
            address_space_fallback(&fallback_only, false),
            None,
            "resolution refuses a fallback without memory, and the decision \
             must agree with it"
        );
    }

    /// Builds a plan for a test and removes the staging directory it created,
    /// since only a run holds the guard that removes it.
    fn plan_for(policy: &Policy, implicit: &[PathBuf]) -> IsolationPlan {
        let world = World::derive(Path::new("/bin/true"), policy, true);
        let plan =
            build_isolation_plan(policy, NetworkMode::Isolated, &world, implicit, None).unwrap();
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

    /// Walking every combination of access bits, the socket connect right
    /// appears exactly where `Access::CONNECT` is set. Read or write on a
    /// hierarchy must never read as the right to connect to the sockets in
    /// it, and connect must never arrive unasked.
    #[test]
    fn the_connect_right_appears_only_where_connect_is_set() {
        let bits = [
            Access::READ,
            Access::WRITE,
            Access::EXECUTE,
            Access::CONNECT,
        ];
        for mask in 0..(1 << bits.len()) {
            let access = bits
                .iter()
                .enumerate()
                .filter(|(position, _)| mask & (1 << position) != 0)
                .map(|(_, bit)| *bit)
                .fold(Access::empty(), |acc, bit| acc | bit);
            let mapped = fs_access_bits(access);
            match (access.contains(Access::CONNECT), mapped) {
                (true, Some(mapped)) => {
                    assert!(
                        mapped.contains(AccessFs::ResolveUnix),
                        "`{access:?}` must carry the socket connect right"
                    );
                    let without = mapped & !AccessFs::ResolveUnix;
                    // Everything else the entry grants must survive the
                    // mapping: connect adds a bit, it does not replace any.
                    // A connect-only entry maps to the connect right alone.
                    let expected = fs_access_bits(access - Access::CONNECT).unwrap_or_default();
                    assert_eq!(
                        without, expected,
                        "`{access:?}` must map to its other rights plus connect, nothing else"
                    );
                }
                (true, None) => {
                    panic!("a connect-only grant must map to the connect right");
                }
                (false, Some(mapped)) => {
                    assert!(
                        !mapped.contains(AccessFs::ResolveUnix),
                        "`{access:?}` must not carry the socket connect right"
                    );
                }
                (false, None) => {}
            }
        }

        // The areas the sandbox provides on its own behalf are never
        // connectable: nothing the target talks to through them is a socket
        // bailey did not put there itself, and the relays carry their own
        // connect grant.
        let world = World::derive(Path::new("/bin/true"), &Policy::default(), false);
        let mut plan = LandlockPlan {
            filesystem: Vec::new(),
            handle_connect: false,
            socket_connect: false,
            handle_bind: false,
            connect_ports: Vec::new(),
            bind_ports: Vec::new(),
        };
        plan.add_world_grants(&world);
        assert!(
            plan.filesystem
                .iter()
                .all(|(_, access)| !access.contains(AccessFs::ResolveUnix)),
            "world grants must never carry the socket connect right"
        );
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
        assert!(denied_syscalls().contains(&("memfd_create", libc::SYS_memfd_create)));
    }

    /// The enforcement page holds the same refusal list the named tables do.
    /// The backticked names between the markers must equal the union of the
    /// tables exactly, so the next refusal updates the page in the same
    /// commit. Only the named tables are covered: a refusal written into the
    /// prologue without a table is invisible here and must be documented by
    /// hand, which the module documentation says.
    #[test]
    fn the_documented_refusals_match_the_named_tables() {
        const PAGE: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/guide/enforcement.md"
        ));
        const MARKER_START: &str = "<!-- seccomp-denied:start -->";
        const MARKER_END: &str = "<!-- seccomp-denied:end -->";

        assert_eq!(
            PAGE.matches(MARKER_START).count(),
            1,
            "docs/guide/enforcement.md must contain exactly one {MARKER_START}"
        );
        assert_eq!(
            PAGE.matches(MARKER_END).count(),
            1,
            "docs/guide/enforcement.md must contain exactly one {MARKER_END}"
        );
        let (before, rest) = PAGE
            .split_once(MARKER_START)
            .expect("the start marker is present, checked above");
        let (marked, _) = rest
            .split_once(MARKER_END)
            .expect("the end marker is present, checked above");
        assert!(
            !before.contains(MARKER_END)
                && !rest[rest.rfind(MARKER_END).unwrap() + MARKER_END.len()..]
                    .contains(MARKER_START),
            "the markers must wrap one block, not overlap"
        );

        // Backticked spans are the odd segments of a backtick split.
        let documented: BTreeSet<&str> = marked
            .split('`')
            .enumerate()
            .filter(|(i, _)| i % 2 == 1)
            .map(|(_, name)| name)
            .collect();
        assert!(!documented.is_empty(), "the marked block names nothing");

        let refused: BTreeSet<&str> = denied_syscalls()
            .iter()
            .map(|(name, _)| *name)
            .chain(MOUNT_SYSCALLS.iter().map(|(name, _)| *name))
            .chain(SUBVOL_IOCTL_TYPES.iter().map(|(name, _)| *name))
            .chain(TERMINAL_INJECTION_IOCTLS.iter().map(|(name, _)| *name))
            .chain(NAMESPACE_CLONE_FLAGS.iter().map(|(name, _)| *name))
            .collect();

        let missing: Vec<_> = refused.difference(&documented).collect();
        let extra: Vec<_> = documented.difference(&refused).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "docs/guide/enforcement.md and the filter disagree. \
             denied by the filter but missing from the page: {missing:?}; \
             named on the page but not denied: {extra:?}"
        );
    }

    /// The namespace flags are matched on `clone`'s first argument, and the
    /// filter only proves it builds: a rule seccompiler rejected would surface
    /// here rather than as every run failing to start.
    #[test]
    fn the_seccomp_filter_builds_with_the_clone_rules() {
        assert!(build_seccomp_filter(false).is_ok());
        assert!(build_seccomp_filter(true).is_ok());
    }

    /// Mirrors `seccomp_data` so a probe can be written field by field and
    /// read back as the bytes a BPF program loads from.
    #[repr(C)]
    struct SeccompDataProbe {
        nr: i32,
        arch: u32,
        instruction_pointer: u64,
        args: [u64; 6],
    }

    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JGE_K: u16 = 0x35;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

    /// Runs the guards over a probe's bytes and returns the `SECCOMP_RET_*`
    /// action. `None` means the guards fell through to the generated filter,
    /// which is where allowed calls go.
    fn simulate_guards(guards: &[seccompiler::sock_filter], data: &[u8]) -> Option<u32> {
        let mut pc = 0usize;
        let mut acc: u32 = 0;
        loop {
            let insn = guards.get(pc)?;
            match insn.code {
                BPF_LD_W_ABS => {
                    let at = insn.k as usize;
                    acc = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
                    pc += 1;
                }
                BPF_JMP_JEQ_K => {
                    pc = if acc == insn.k {
                        pc + 1 + insn.jt as usize
                    } else {
                        pc + 1 + insn.jf as usize
                    };
                }
                BPF_JMP_JGE_K => {
                    pc = if acc >= insn.k {
                        pc + 1 + insn.jt as usize
                    } else {
                        pc + 1 + insn.jf as usize
                    };
                }
                BPF_RET_K => return Some(insn.k),
                other => panic!("guard instruction at {pc} has unknown opcode {other:#x}"),
            }
        }
    }

    fn probe_bytes(data: &SeccompDataProbe) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(data).cast::<u8>(),
                std::mem::size_of::<SeccompDataProbe>(),
            )
        }
    }

    /// The socket guards match the arguments by their low words at the offsets
    /// the `seccomp_data` layout defines, and refuse exactly MPTCP and SMC.
    /// The probe is built field by field, so a wrong offset in the guards
    /// reads the wrong word and fails here.
    /// An architecture other than the one the filter was built for.
    #[cfg(target_arch = "x86_64")]
    const FOREIGN_AUDIT_ARCH: u32 = 0xc000_00b7;
    #[cfg(target_arch = "aarch64")]
    const FOREIGN_AUDIT_ARCH: u32 = 0xc000_003e;

    #[test]
    fn the_socket_guards_read_the_low_words_of_the_family_and_protocol() {
        assert_eq!(std::mem::offset_of!(SeccompDataProbe, args), 16);
        assert_eq!(
            std::mem::offset_of!(SeccompDataProbe, args) + 2 * std::mem::size_of::<u64>(),
            32
        );

        let guards = seccomp_guards();
        let probe = |nr: i32, arch: u32, family: i32, protocol: i32| {
            let data = SeccompDataProbe {
                nr,
                arch,
                instruction_pointer: 0,
                args: [
                    family as u64,
                    libc::SOCK_STREAM as u64,
                    protocol as u64,
                    0,
                    0,
                    0,
                ],
            };
            simulate_guards(&guards, probe_bytes(&data))
        };

        let socket = libc::SYS_socket as i32;
        assert_eq!(
            probe(socket, NATIVE_AUDIT_ARCH, libc::AF_INET, 262),
            Some(SECCOMP_RET_ERRNO | libc::ENOPROTOOPT as u32),
            "an MPTCP socket must be refused with ENOPROTOOPT"
        );
        assert_eq!(
            probe(socket, NATIVE_AUDIT_ARCH, libc::AF_INET, 256),
            Some(SECCOMP_RET_ERRNO | libc::EPROTONOSUPPORT as u32),
            "an INET socket naming the SMC protocol must be refused with \
             EPROTONOSUPPORT, not left to become an SMC socket on kernels \
             that have it"
        );
        assert_eq!(
            probe(socket, NATIVE_AUDIT_ARCH, libc::AF_INET6, 256),
            Some(SECCOMP_RET_ERRNO | libc::EPROTONOSUPPORT as u32),
            "the SMC protocol refusal must not depend on the address family"
        );
        assert_eq!(
            probe(socket, NATIVE_AUDIT_ARCH, 43, 0),
            Some(SECCOMP_RET_ERRNO | libc::EAFNOSUPPORT as u32),
            "an AF_SMC socket must be refused with EAFNOSUPPORT"
        );
        // Both refusals must work regardless of what the other argument holds,
        // which is what pins the two offsets apart.
        assert_eq!(
            probe(socket, NATIVE_AUDIT_ARCH, 43, 262),
            Some(SECCOMP_RET_ERRNO | libc::EAFNOSUPPORT as u32),
            "the family check must fire before the protocol check"
        );
        assert_eq!(
            probe(socket, NATIVE_AUDIT_ARCH, libc::AF_INET, 0),
            None,
            "protocol 0 is ordinary TCP and must reach the filter"
        );
        assert_eq!(
            probe(socket, NATIVE_AUDIT_ARCH, libc::AF_INET, libc::IPPROTO_TCP),
            None,
            "protocol IPPROTO_TCP must reach the filter"
        );
        assert_eq!(
            probe(socket, NATIVE_AUDIT_ARCH, libc::AF_INET6, 132),
            None,
            "SCTP stays outside these guards"
        );
        assert_eq!(
            probe(socket, NATIVE_AUDIT_ARCH, libc::AF_INET6, 262),
            Some(SECCOMP_RET_ERRNO | libc::ENOPROTOOPT as u32),
            "the MPTCP refusal must not depend on the address family"
        );
        assert_eq!(
            probe(libc::SYS_clone as i32, NATIVE_AUDIT_ARCH, libc::AF_INET, 0),
            None,
            "a non-socket call must leave the guard block untouched"
        );
        assert_eq!(
            probe(socket, FOREIGN_AUDIT_ARCH, libc::AF_INET, 0),
            Some(SECCOMP_RET_ERRNO | libc::EPERM as u32),
            "a foreign architecture must still be refused with EPERM"
        );
    }

    /// Installs the built filter in a forked child and probes `clone3` and
    /// thread creation through it, so the refusal is the errno libcs fall
    /// back on and the fallback itself really runs.
    #[test]
    fn clone3_is_refused_while_threads_still_start() {
        let program = build_seccomp_filter(false).expect("the filter builds");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    libc::_exit(PROBE_PRCTL_FAILED);
                }
                let fprog = libc::sock_fprog {
                    len: program.len() as u16,
                    filter: program.as_ptr().cast::<libc::sock_filter>().cast_mut(),
                };
                if libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &fprog) != 0 {
                    libc::_exit(PROBE_SECCOMP_FAILED);
                }
                // A clone3 asking for a fresh user namespace. The struct is
                // `clone_args`: flags first, exit signal fifth, 64 bytes.
                const CLONE_NEWUSER: u64 = 0x1000_0000;
                const CLONE_NEWNET: u64 = 0x4000_0000;
                let request: [u64; 8] = [
                    CLONE_NEWUSER | CLONE_NEWNET,
                    0,
                    0,
                    0,
                    libc::SIGCHLD as u64,
                    0,
                    0,
                    0,
                ];
                let created = libc::syscall(libc::SYS_clone3, request.as_ptr(), 64usize);
                if created == 0 {
                    // The filter let clone3 through and this is the new
                    // process it made, inside a user namespace of its own.
                    libc::_exit(1);
                }
                if created > 0 {
                    let mut status: libc::c_int = 0;
                    libc::waitpid(created as libc::pid_t, &mut status, 0);
                    libc::_exit(2);
                }
                if *libc::__errno_location() != libc::ENOSYS {
                    libc::_exit(3);
                }
                // Thread creation tries clone3 first on glibc and must reach
                // its clone fallback, which the filter leaves alone.
                extern "C" fn thread_body(_arg: *mut libc::c_void) -> *mut libc::c_void {
                    std::ptr::null_mut()
                }
                // `pthread_t` is a pointer on musl and an integer on glibc, so
                // it is zeroed rather than assigned a number.
                let mut tid: libc::pthread_t = std::mem::zeroed();
                if libc::pthread_create(
                    &mut tid,
                    std::ptr::null(),
                    thread_body,
                    std::ptr::null_mut(),
                ) != 0
                {
                    libc::_exit(4);
                }
                if libc::pthread_join(tid, std::ptr::null_mut()) != 0 {
                    libc::_exit(5);
                }
                libc::_exit(0);
            }
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(
            waited,
            pid,
            "waitpid failed: {}",
            std::io::Error::last_os_error()
        );
        assert!(libc::WIFEXITED(status), "the probe child did not exit");
        match libc::WEXITSTATUS(status) {
            0 => {}
            code if code == PROBE_SECCOMP_FAILED => {
                skip("this host will not install an unprivileged seccomp filter")
            }
            code if code == PROBE_PRCTL_FAILED => skip("this host will not set no_new_privs"),
            1 => panic!("clone3 was not refused: a process was created in a new user namespace"),
            2 => panic!("clone3 was not refused: a child was created"),
            3 => panic!("clone3 must be refused with ENOSYS, which libcs fall back on"),
            4 => panic!("pthread_create failed under the filter"),
            5 => panic!("pthread_join failed under the filter"),
            other => panic!("the probe child exited with unexpected code {other}"),
        }
    }

    /// Exit codes the probe child reports back. 1 to 5 name the assertion that
    /// failed, 70 and 72 name the setup steps, so a host without unprivileged
    /// seccomp reads as a skip rather than as a broken filter.
    const PROBE_PRCTL_FAILED: i32 = 70;
    const PROBE_SECCOMP_FAILED: i32 = 72;

    /// Installs the built filter in a forked child and probes `socket()`
    /// through it, so each guard's errno is the one the kernel actually hands
    /// to userspace.
    #[test]
    fn the_filter_refuses_mptcp_and_smc_sockets_in_a_child() {
        let program = build_seccomp_filter(false).expect("the filter builds");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    libc::_exit(PROBE_PRCTL_FAILED);
                }
                let fprog = libc::sock_fprog {
                    len: program.len() as u16,
                    filter: program.as_ptr().cast::<libc::sock_filter>().cast_mut(),
                };
                if libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &fprog) != 0 {
                    libc::_exit(PROBE_SECCOMP_FAILED);
                }
                let errno_of = |family: i32, kind: i32, protocol: i32| {
                    let fd = libc::socket(family, kind, protocol);
                    if fd >= 0 {
                        libc::close(fd);
                        0
                    } else {
                        *libc::__errno_location()
                    }
                };
                if errno_of(43, libc::SOCK_STREAM, 0) != libc::EAFNOSUPPORT {
                    libc::_exit(1);
                }
                if errno_of(libc::AF_INET, libc::SOCK_STREAM, 262) != libc::ENOPROTOOPT {
                    libc::_exit(2);
                }
                if errno_of(libc::AF_INET, libc::SOCK_STREAM, 256) != libc::EPROTONOSUPPORT {
                    libc::_exit(6);
                }
                if errno_of(libc::AF_INET, libc::SOCK_STREAM, 0) != 0 {
                    libc::_exit(3);
                }
                if errno_of(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP) != 0 {
                    libc::_exit(4);
                }
                if errno_of(libc::AF_INET, libc::SOCK_DGRAM, 0) != 0 {
                    libc::_exit(5);
                }
                libc::_exit(0);
            }
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(
            waited,
            pid,
            "waitpid failed: {}",
            std::io::Error::last_os_error()
        );
        assert!(libc::WIFEXITED(status), "the probe child did not exit");
        match libc::WEXITSTATUS(status) {
            0 => {}
            code if code == PROBE_SECCOMP_FAILED => {
                skip("this host will not install an unprivileged seccomp filter")
            }
            code if code == PROBE_PRCTL_FAILED => skip("this host will not set no_new_privs"),
            1 => panic!("the AF_SMC refusal returned the wrong errno"),
            2 => panic!("the MPTCP refusal returned the wrong errno"),
            6 => panic!("the SMC protocol refusal returned the wrong errno"),
            3 => panic!("socket(AF_INET, SOCK_STREAM, 0) was refused by the filter"),
            4 => panic!("socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) was refused by the filter"),
            5 => panic!("socket(AF_INET, SOCK_DGRAM, 0) was refused by the filter"),
            other => panic!("the probe child exited with unexpected code {other}"),
        }
    }

    /// Installs the broker's filter in a forked child and probes the IPC
    /// boundary: `socket` and `socketpair` for `AF_UNIX` are
    /// refused with `EPERM`, the internet families pass.
    #[test]
    fn the_broker_filter_refuses_unix_sockets_in_a_child() {
        let program = broker_seccomp_program().expect("the filter builds");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    libc::_exit(PROBE_PRCTL_FAILED);
                }
                let fprog = libc::sock_fprog {
                    len: program.len() as u16,
                    filter: program.as_ptr().cast::<libc::sock_filter>().cast_mut(),
                };
                if libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &fprog) != 0 {
                    libc::_exit(PROBE_SECCOMP_FAILED);
                }
                let errno_of = |family: i32| {
                    let fd = libc::socket(family, libc::SOCK_STREAM, 0);
                    if fd >= 0 {
                        libc::close(fd);
                        0
                    } else {
                        *libc::__errno_location()
                    }
                };
                let mut pair = [0 as libc::c_int; 2];
                let paired =
                    libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr());
                let pair_errno = if paired == 0 {
                    0
                } else {
                    *libc::__errno_location()
                };
                if errno_of(libc::AF_UNIX) != libc::EPERM {
                    libc::_exit(1);
                }
                if pair_errno != libc::EPERM {
                    libc::_exit(2);
                }
                if errno_of(libc::AF_INET) != 0 {
                    libc::_exit(3);
                }
                if errno_of(libc::AF_INET6) != 0 {
                    libc::_exit(4);
                }
                libc::_exit(0);
            }
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(
            waited,
            pid,
            "waitpid failed: {}",
            std::io::Error::last_os_error()
        );
        assert!(libc::WIFEXITED(status), "the probe child did not exit");
        match libc::WEXITSTATUS(status) {
            0 => {}
            code if code == PROBE_SECCOMP_FAILED => {
                skip("this host will not install an unprivileged seccomp filter")
            }
            code if code == PROBE_PRCTL_FAILED => skip("this host will not set no_new_privs"),
            1 => panic!("socket(AF_UNIX) was not refused with EPERM"),
            2 => panic!("socketpair(AF_UNIX) was not refused with EPERM"),
            3 => panic!("socket(AF_INET) was refused by the broker filter"),
            4 => panic!("socket(AF_INET6) was refused by the broker filter"),
            other => panic!("the probe child exited with unexpected code {other}"),
        }
    }

    /// The layout table in the change design, asserted for all four rows: a
    /// run that builds namespaces from the host creates a fresh guard, and a
    /// proxied run runs beneath the guard the proxy namespace already is.
    #[test]
    fn the_layout_table_decides_who_creates_the_guard() {
        assert!(creates_guard(false), "an isolated run creates a guard");
        assert!(
            creates_guard(false),
            "a network-only run without a proxy creates a guard too"
        );
        assert!(
            !creates_guard(true),
            "a proxied isolated run runs beneath the proxy namespace's guard"
        );
        assert!(
            !creates_guard(true),
            "a proxied run without isolation runs in the guard directly"
        );
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
        let err = match build_isolation_plan(&policy, NetworkMode::Isolated, &world, &[], None) {
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

        let plan = build_isolation_plan(&policy, NetworkMode::Isolated, &world, &[], None).unwrap();
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
        // The name carries the pid so a later run can tell whose a leftover
        // was, and an unpredictable suffix so nobody else can name it first.
        let rest = name.strip_prefix(STAGING_PREFIX).unwrap();
        let (pid, suffix) = rest.split_once('.').expect("the name is <pid>.<suffix>");
        assert_eq!(pid, std::process::id().to_string(), "the pid is carried");
        assert!(!suffix.is_empty(), "the suffix is carried: {name}");
        assert_ne!(
            name,
            format!("{STAGING_PREFIX}{}", std::process::id()),
            "the name must not be the pid alone: {name}"
        );

        // A concurrent run stages beside this one, never at its name.
        let other =
            build_isolation_plan(&policy, NetworkMode::Isolated, &world, &[], None).unwrap();
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

    /// The sweep heals a leftover and touches nothing it cannot prove is ours.
    ///
    /// A leftover is matched by the pid its name carries, and removed only when
    /// that pid is gone, the entry is a directory this user owns, and the
    /// directory is empty. A run still alive may be a concurrent one, so its
    /// staging stays. A bare pid is the shape an older bailey wrote, so a
    /// leftover of that shape heals too.
    #[test]
    fn the_sweep_heals_a_leftover_and_leaves_the_rest_alone() {
        let dir = tempfile::tempdir().unwrap();

        // A leftover of a run whose pid is gone: the shape `fresh_dir` makes.
        let healed = dir
            .path()
            .join(format!("{STAGING_PREFIX}987654321.deadbeefdeadbeef"));
        std::fs::create_dir_all(&healed).unwrap();
        // The shape a staging directory had before the suffix existed.
        let old = dir.path().join(format!("{STAGING_PREFIX}987654320"));
        std::fs::create_dir_all(&old).unwrap();
        // A live run's staging, which may well be a concurrent one.
        let live = dir
            .path()
            .join(format!("{STAGING_PREFIX}{}.cafe", std::process::id()));
        std::fs::create_dir_all(&live).unwrap();
        // A name that carries no pid is not ours to interpret.
        let unparsed = dir.path().join(format!("{STAGING_PREFIX}nonsense"));
        std::fs::create_dir_all(&unparsed).unwrap();
        std::fs::write(unparsed.join("decoy"), "not ours").unwrap();

        sweep_staging(dir.path());

        assert!(!healed.exists(), "a dead run's leftover is healed");
        assert!(!old.exists(), "a leftover of the old name shape is healed");
        assert!(live.is_dir(), "a live run's staging is left alone");
        assert!(
            unparsed.join("decoy").is_file(),
            "a name carrying no pid is left alone"
        );

        let _ = std::fs::remove_dir_all(&live);
        let _ = std::fs::remove_dir_all(&unparsed);
    }

    /// A directory with contents is not a staging leftover however its name is
    /// spelled.
    ///
    /// A staging directory is empty on the host by construction: the tmpfs is
    /// mounted over it inside the target's own mount namespace, so nothing a
    /// run does ever lands in it. Emptiness is what identifies one, so files
    /// under a staging-shaped name were put there by something else and are
    /// not ours to remove. `remove_dir` refusing a non-empty directory is the
    /// guarantee, the same one the sweep before the pid carried in its name
    /// relied on.
    #[test]
    fn a_leftover_with_contents_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();

        // The shape the current run makes, filled in.
        let current = dir
            .path()
            .join(format!("{STAGING_PREFIX}987654321.feedface"));
        std::fs::create_dir_all(current.join("nested")).unwrap();
        std::fs::write(current.join("kept"), "not a staging directory").unwrap();
        std::fs::write(
            current.join("nested").join("kept"),
            "not a staging directory",
        )
        .unwrap();
        // The shape an older bailey made, also filled in.
        let old = dir.path().join(format!("{STAGING_PREFIX}987654320"));
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("kept"), "not a staging directory").unwrap();

        sweep_staging(dir.path());

        assert!(
            current.join("kept").is_file(),
            "a filled directory is not swept"
        );
        assert!(
            current.join("nested").join("kept").is_file(),
            "the sweep does not recurse"
        );
        assert!(
            old.join("kept").is_file(),
            "a filled old-shape directory is not swept"
        );
    }

    /// A generated-files staging a dead run left is healed, and a lookalike
    /// that holds anything else is not.
    ///
    /// A run that died between writing the generated files and tearing them
    /// down leaves a directory the emptiness rule above would refuse forever,
    /// because nothing would ever empty it. The sweep recognizes the exact
    /// shape the generated-files staging has (only `hosts` and `resolv.conf`
    /// files) and empties that one; a directory that carries any other name
    /// stays untouched.
    #[test]
    fn the_sweep_heals_a_generated_files_leftover_and_no_lookalike() {
        let dir = tempfile::tempdir().unwrap();

        // The exact shape a dead run's generated-files staging has.
        let healed = dir.path().join(format!("{STAGING_PREFIX}987654321.c0ffee"));
        std::fs::create_dir_all(&healed).unwrap();
        std::fs::write(healed.join("hosts"), "127.0.0.1 pinned\n").unwrap();
        std::fs::write(healed.join("resolv.conf"), "nameserver 10.0.2.3\n").unwrap();
        // The same shape plus one name the generated staging never writes.
        let lookalike = dir.path().join(format!("{STAGING_PREFIX}987654320.c0ffee"));
        std::fs::create_dir_all(&lookalike).unwrap();
        std::fs::write(lookalike.join("hosts"), "127.0.0.1 pinned\n").unwrap();
        std::fs::write(lookalike.join("kept"), "not ours").unwrap();

        sweep_staging(dir.path());

        assert!(!healed.exists(), "a generated-files leftover is healed");
        assert!(
            lookalike.join("kept").is_file(),
            "a lookalike holding another file is not swept"
        );

        let _ = std::fs::remove_dir_all(&healed);
        let _ = std::fs::remove_dir_all(&lookalike);
    }

    /// A session runtime directory that is not this user's own is refused, even
    /// at mode 0700.
    ///
    /// The mode alone is not the test: a private directory owned by somebody
    /// else is unreadable to us but not ours, and a run that staged in one
    /// would fail on the create rather than fall back to the temp directory.
    /// What is pinned here is the mode half and the own-directory half; a
    /// directory of another uid cannot be created in a test, so the ownership
    /// branch is read rather than executed.
    #[test]
    fn a_runtime_directory_must_be_private_and_ours() {
        use std::os::unix::fs::PermissionsExt;
        let _env = crate::test_support::env_lock();

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", dir.path()) };
        assert_eq!(
            runtime_dir_host(),
            Some(dir.path().to_path_buf()),
            "this process's own 0700 directory qualifies"
        );

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            runtime_dir_host(),
            None,
            "a directory that is not 0700 does not qualify"
        );

        unsafe { std::env::remove_var("XDG_RUNTIME_DIR") };
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

    /// DNS over TCP reaches the forwarder only when the setting allows it,
    /// and never under denied egress, where port 53 would be the one hole in
    /// an otherwise closed policy.
    #[test]
    fn landlock_connect_gains_port_53_only_when_dns_is_allowed() {
        use crate::policy::{DnsSetting, Egress, EgressRule};
        let policy = |dns, egress| {
            let mut policy = Policy::default();
            policy.network.dns = dns;
            policy.network.egress = egress;
            policy
        };
        let wildcard = |dns| {
            policy(
                dns,
                Egress::Allow(vec![EgressRule {
                    host: crate::policy::Destination::Any,
                    protocol: crate::policy::Protocol::Tcp,
                    port: Some(443),
                }]),
            )
        };
        let plan = LandlockPlan::build(&wildcard(DnsSetting::Auto), true, false);
        assert!(plan.connect_ports.contains(&53));
        assert!(plan.connect_ports.contains(&443));

        let plan = LandlockPlan::build(&wildcard(DnsSetting::Allow), true, false);
        assert!(plan.connect_ports.contains(&53));

        let plan = LandlockPlan::build(&wildcard(DnsSetting::Deny), true, false);
        assert!(!plan.connect_ports.contains(&53));
        assert!(plan.connect_ports.contains(&443));

        // A policy of named hosts only allows no DNS automatically.
        let mut named = Policy::default();
        named.network.egress = Egress::Allow(vec![EgressRule {
            host: crate::policy::Destination::Address("203.0.113.7".parse().unwrap()),
            protocol: crate::policy::Protocol::Tcp,
            port: Some(443),
        }]);
        let plan = LandlockPlan::build(&named, true, false);
        assert!(!plan.connect_ports.contains(&53));

        // Denied egress keeps the port closed whatever the setting says.
        let plan = LandlockPlan::build(&policy(DnsSetting::Allow, Egress::DenyAll), true, false);
        assert!(!plan.connect_ports.contains(&53));
    }

    /// Landlock's connect list carries TCP only, so a UDP-only allowance
    /// puts no port on it: the port a UDP rule names is the private
    /// namespace's netfilter table to carry, not Landlock's.
    #[test]
    fn a_udp_only_rule_contributes_no_landlock_connect_port() {
        use crate::policy::{Destination, Egress, EgressRule, Protocol};
        let mut policy = Policy::default();
        policy.network.egress = Egress::Allow(vec![EgressRule {
            host: Destination::Any,
            protocol: Protocol::Udp,
            port: Some(5353),
        }]);
        let plan = LandlockPlan::build(&policy, true, false);
        assert!(
            !plan.connect_ports.contains(&5353),
            "a UDP rule's port must not open TCP connect: {:?}",
            plan.connect_ports
        );
        assert!(plan.handle_connect);
    }

    /// The generated files a private run carries: the pinned names, one line
    /// per address, and the forwarder address when DNS is allowed.
    #[test]
    fn generated_files_pin_names_and_name_the_forwarder() {
        let pins = [crate::cli::Pin {
            name: "api.example.com".to_owned(),
            addresses: vec![
                "203.0.113.7".parse().unwrap(),
                "2001:db8::7".parse().unwrap(),
            ],
        }];
        let (dir, files) = write_generated_files(&pins, true).unwrap().unwrap();
        let hosts = String::from_utf8(std::fs::read(&files[0].0).unwrap()).unwrap();
        assert_eq!(
            hosts,
            "# Generated by bailey from the policy's egress rules.\n\
             127.0.0.1 localhost\n\
             ::1 localhost\n\
             203.0.113.7 api.example.com\n\
             2001:db8::7 api.example.com\n"
        );
        assert_eq!(files[0].1, PathBuf::from("/etc/hosts"));
        let resolv = String::from_utf8(std::fs::read(&files[1].0).unwrap()).unwrap();
        assert_eq!(
            resolv,
            format!("nameserver {}\n", crate::cli::DNS_FORWARDER_V4)
        );
        assert_eq!(files[1].1, PathBuf::from("/etc/resolv.conf"));
        let _ = std::fs::remove_dir(&dir);

        // Nothing to generate, no directory and no files.
        assert!(write_generated_files(&[], false).unwrap().is_none());
    }

    /// The generated hosts always answers localhost: the file replaces the
    /// sandbox's `/etc/hosts` whole, so the pinned names alone would leave
    /// the loopback name to whatever the resolver falls back to.
    #[test]
    fn generated_hosts_answer_localhost() {
        let pins = [crate::cli::Pin {
            name: "api.example.com".to_owned(),
            addresses: vec!["203.0.113.7".parse().unwrap()],
        }];
        let (dir, files) = write_generated_files(&pins, true).unwrap().unwrap();
        let hosts = String::from_utf8(std::fs::read(&files[0].0).unwrap()).unwrap();
        assert!(hosts.contains("127.0.0.1 localhost\n"), "{hosts}");
        assert!(hosts.contains("::1 localhost\n"), "{hosts}");
        let _ = std::fs::remove_dir(&dir);
    }

    /// The grants the generated files ride in on: read at the paths the
    /// target sees, and each path held read-only.
    #[test]
    fn generated_files_extend_the_policy_with_read_only_grants() {
        let policy = Policy::default();
        let generated = vec![(
            PathBuf::from("/run/user/1000/.bailey-generated.x/hosts"),
            PathBuf::from("/etc/hosts"),
        )];
        let extended = policy_with_generated(&policy, &generated);
        assert_eq!(extended.filesystem.len(), 1);
        assert_eq!(extended.filesystem[0].access, Access::READ);
        assert_eq!(extended.filesystem[0].at, Some(PathBuf::from("/etc/hosts")));
        assert!(extended.read_only.contains(&PathBuf::from("/etc/hosts")));
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
        let btrfs_snap_create = ioctl_nr(SUBVOL_IOCTL_TYPES[0].1, 1, 4096);
        let btrfs_subvol_create_v2 = ioctl_nr(SUBVOL_IOCTL_TYPES[0].1, 24, 4096);
        let bcachefs_subvol_create = ioctl_nr(SUBVOL_IOCTL_TYPES[1].1, 16, 4096);
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
        assert_eq!(
            TERMINAL_INJECTION_IOCTLS,
            [("TIOCSTI", 0x5412), ("TIOCLINUX", 0x541c)]
        );
        assert!(
            !TERMINAL_INJECTION_IOCTLS
                .iter()
                .any(|&(_, nr)| nr == 0x5401)
        );
    }

    #[test]
    fn descriptor_passing_and_rings_are_denied() {
        // A duplicated descriptor carries the access the opener had, and a
        // ring reaches ioctls without passing the ioctl rules below.
        let denied = denied_syscalls();
        for (name, nr) in [
            ("pidfd_getfd", libc::SYS_pidfd_getfd),
            ("io_uring_setup", libc::SYS_io_uring_setup),
            ("io_uring_enter", libc::SYS_io_uring_enter),
            ("io_uring_register", libc::SYS_io_uring_register),
            ("chroot", libc::SYS_chroot),
            ("quotactl", libc::SYS_quotactl),
            ("kcmp", libc::SYS_kcmp),
            ("process_madvise", libc::SYS_process_madvise),
            ("process_mrelease", libc::SYS_process_mrelease),
            ("mlockall", libc::SYS_mlockall),
        ] {
            assert!(
                denied.contains(&(name, nr)),
                "syscall {name} should be denied"
            );
        }
    }

    #[test]
    fn the_whole_mount_family_is_denied() {
        // The old mount(2) and its split successors reach the same power, so a
        // denylist that stops one but not the others stops nothing. The family
        // lives in `MOUNT_SYSCALLS` alone, which is the only thing `self_fuse`
        // lifts; the calls that would leave the namespace are denied outright
        // and never lifted.
        for &(_, nr) in MOUNT_SYSCALLS {
            assert!(
                !denied_syscalls().iter().any(|&(_, n)| n == nr),
                "syscall {nr} must sit in MOUNT_SYSCALLS alone, so self_fuse lifts it and nothing else"
            );
        }
        for (name, nr) in [
            ("pivot_root", libc::SYS_pivot_root),
            ("setns", libc::SYS_setns),
            ("unshare", libc::SYS_unshare),
        ] {
            assert!(
                denied_syscalls().contains(&(name, nr)),
                "syscall {name} must stay denied even with self_fuse"
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

    /// A number on its own does not say whether the target failed or was
    /// killed. The wait saw this one die, so the summary says so.
    #[test]
    fn a_signal_the_wait_saw_is_named_in_the_summary() {
        let killed = Exit::of(std::process::ExitStatus::from_raw(libc::SIGTERM));
        assert_eq!(killed.code, 128 + libc::SIGTERM);
        assert_eq!(killed.signal, Some(libc::SIGTERM));
        let said = killed.said().expect("a killed target is reported");
        assert!(said.contains("killed by SIGTERM (15)"), "{said}");
    }

    /// The isolated path reaps the target inside its own PID namespace and
    /// exits with `128 + signal` itself, so the parent sees an ordinary exit
    /// code. That code is named for what it means, not claimed as a signal
    /// the parent saw.
    #[test]
    fn a_code_above_128_is_named_as_the_shell_code_it_is() {
        let reaped = Exit::of(std::process::ExitStatus::from_raw(143 << 8));
        assert_eq!(reaped.signal, None);
        let said = reaped.said().expect("a failure is reported");
        assert!(said.contains("exited with 143"), "{said}");
        assert!(said.contains("SIGTERM"), "{said}");
    }

    #[test]
    fn an_ordinary_exit_says_its_code_and_a_clean_one_says_nothing() {
        let failed = Exit::of(std::process::ExitStatus::from_raw(3 << 8));
        assert_eq!((failed.code, failed.signal), (3, None));
        let said = failed.said().expect("a failure is reported");
        assert!(said.contains("exited with 3"), "{said}");

        let clean = Exit::of(std::process::ExitStatus::from_raw(0));
        assert_eq!(clean.said(), None);
    }

    /// A caller parsing the JSON has to be able to tell the two apart too.
    #[test]
    fn the_json_carries_the_signal_beside_the_code() {
        let report = RunReport::default();
        let killed = report.to_json(Exit::of(std::process::ExitStatus::from_raw(libc::SIGTERM)));
        assert!(killed.contains("\"exit_code\":143"), "{killed}");
        assert!(killed.contains("\"signal\":15"), "{killed}");

        let exited = report.to_json(Exit::of(std::process::ExitStatus::from_raw(3 << 8)));
        assert!(exited.contains("\"exit_code\":3"), "{exited}");
        assert!(exited.contains("\"signal\":null"), "{exited}");
    }
}
