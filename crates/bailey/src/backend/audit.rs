//! Audit backend.
//!
//! Runs the target while recording its filesystem and network access, producing
//! a [`Trace`] for reconciliation. The recording is done by the privileged
//! [`crate::backend::audit_helper`], so the main tool stays unprivileged.
//!
//! The target runs confined. Audit is the mode people reach for when they do not
//! yet know what a program does, which makes it exactly the wrong mode to run
//! unknown code with full authority. The policy is widened to an envelope that
//! lets a well-behaved program work, and the envelope is reported before the run
//! so it is inspectable rather than implicit.

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use crate::backend::audit_notify::Supervisor;
use crate::backend::enforce::{self, EnforceBackend};
use crate::backend::{BackendError, Target, audit_helper};
use crate::event::{Observer, Trace};
use crate::policy::{Access, FsRule, Policy};

/// Which observer records an audit's trace.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ObserverChoice {
    /// Start the eBPF helper; when it cannot run, record with the seccomp
    /// fallback and say so.
    #[default]
    Auto,
    /// The eBPF helper only. The audit fails when it cannot run.
    Ebpf,
    /// The seccomp notification fallback only. The helper is never started.
    Seccomp,
}

impl std::fmt::Display for ObserverChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            ObserverChoice::Auto => "auto",
            ObserverChoice::Ebpf => "ebpf",
            ObserverChoice::Seccomp => "seccomp",
        };
        f.write_str(name)
    }
}

/// Permissive-but-recording audit backend.
#[derive(Debug, Default)]
pub struct AuditBackend {
    /// Run the target with no confinement at all. An explicit opt-out for
    /// software the user already trusts.
    pub unconfined: bool,
    /// Reconstruct the target's world with namespaces during the audit.
    ///
    /// Not usable yet: the recorder holds the target at its exec trap, and
    /// `PTRACE_TRACEME` is not inherited across the fork the isolation layer
    /// performs to make the target PID 1, so the stop never reaches bailey.
    pub isolate: bool,
    /// Which observer records the trace.
    pub observer: ObserverChoice,
}

impl AuditBackend {
    /// Run `target` while recording its access, returning the target's exit
    /// code and the recorded trace.
    pub fn run_and_record(
        &self,
        policy: &Policy,
        target: &Target,
    ) -> Result<(i32, Trace), BackendError> {
        if self.unconfined {
            if self.observer == ObserverChoice::Seccomp {
                return Err(BackendError::Command(
                    "`--unconfined` needs the eBPF observer: the fallback \
                     records only the syscalls its own filter sees, and an \
                     unconfined run installs no filter"
                        .into(),
                ));
            }
            eprintln!(
                "bailey: warning: auditing without confinement; the target runs \
                 with your full authority"
            );
            return audit_helper::run_unconfined(target);
        }

        let envelope = envelope(policy, target);
        report_envelope(&envelope, policy);

        match self.observer {
            ObserverChoice::Ebpf => {
                let recorder = audit_helper::Recorder::start()?;
                self.record_ebpf(recorder, &envelope, target)
            }
            ObserverChoice::Seccomp => self.record_seccomp(&envelope, target),
            ObserverChoice::Auto => match audit_helper::Recorder::start() {
                Ok(recorder) => self.record_ebpf(recorder, &envelope, target),
                Err(helper_error) => {
                    eprintln!(
                        "bailey: warning: {helper_error}; recording with the \
                         seccomp fallback observer instead. It is less complete \
                         than eBPF, and each observed open, exec and connect \
                         waits for bailey."
                    );
                    self.record_seccomp(&envelope, target)
                        .map_err(|fallback_error| {
                            BackendError::Command(format!(
                                "both audit observers failed. The eBPF helper: \
                             {helper_error}. The seccomp fallback: {fallback_error}"
                            ))
                        })
                }
            },
        }
    }

    /// The eBPF path: the recorder is already running, so spawn held at exec,
    /// hand the target over, and funnel through [`audit_helper::record`].
    fn record_ebpf(
        &self,
        recorder: audit_helper::Recorder,
        envelope: &Policy,
        target: &Target,
    ) -> Result<(i32, Trace), BackendError> {
        let backend = EnforceBackend {
            isolate: self.isolate,
            stop_before_exec: true,
            // The audit output is the point of the run; a layer summary on top
            // of it would bury the findings.
            summary: enforce::Summary::Quiet,
            // Scoping observation to a cgroup is race-free, so a run gets one
            // whether or not the policy sets limits.
            always_cgroup: true,
            implicit_write: Vec::new(),
            network: None,
            guard_in_place: false,
            audit_listener: None,
            pins: Vec::new(),
        };
        let confined = backend.spawn(envelope, target)?;
        // `record` is the only funnel for a confined eBPF audit: it waits
        // through `wait_measured`, so its trace always carries the run's
        // peaks, measured or explained.
        audit_helper::record(recorder, confined)
    }

    /// The seccomp fallback path: a supervisor thread answers the target's
    /// notifications while the same envelope confines it.
    ///
    /// The target is not held at exec: its exec is itself a notified syscall,
    /// and the supervisor started here answers it. Usage still comes from
    /// [`enforce::Confined::wait_measured`], so a fallback trace carries the
    /// run's peaks exactly as an eBPF trace does.
    fn record_seccomp(
        &self,
        envelope: &Policy,
        target: &Target,
    ) -> Result<(i32, Trace), BackendError> {
        let (handover_parent, handover_child) = UnixStream::pair().map_err(BackendError::Io)?;
        let supervisor = Supervisor::start(handover_parent);
        let backend = EnforceBackend {
            isolate: self.isolate,
            // The exec is observed through the listener, so there is no
            // ptrace stop to wait for.
            stop_before_exec: false,
            summary: enforce::Summary::Quiet,
            always_cgroup: true,
            implicit_write: Vec::new(),
            network: None,
            guard_in_place: false,
            audit_listener: Some(handover_child.as_raw_fd()),
            pins: Vec::new(),
        };
        let confined = match backend.spawn(envelope, target) {
            Ok(confined) => {
                // The child has its own copy of the socket from the fork;
                // this copy only keeps the handover socket alive.
                drop(handover_child);
                confined
            }
            Err(spawn_error) => {
                // The child is gone or never armed; the handover socket
                // reaching end of file is what ends the supervisor. A failure
                // the supervisor recorded, such as an unreadable target under
                // a hardened ptrace policy, is the run's own verdict.
                drop(handover_child);
                let outcome = supervisor.finish();
                if let Some(failure) = outcome.failure {
                    return Err(BackendError::Command(failure));
                }
                return Err(nested_or(spawn_error));
            }
        };
        let (code, usage) = confined.wait_measured()?;
        let outcome = supervisor.finish();
        let mut trace = Trace::new(outcome.events, outcome.dropped);
        trace.usage = Some(usage);
        trace.observer = Observer::Seccomp;
        trace.loss = outcome.loss;
        Ok((code, trace))
    }
}

/// A spawn failure with `EBUSY` or `EINVAL` on the fallback path is the
/// nested audit: the inherited filter stack already carries a listener, and
/// the kernel answered the second install, or the exec that followed it,
/// with that errno. Both name the same cause to the user.
fn nested_or(error: BackendError) -> BackendError {
    match error {
        BackendError::Io(err)
            if err
                .raw_os_error()
                .is_some_and(|errno| errno == libc::EBUSY || errno == libc::EINVAL) =>
        {
            BackendError::Command(
                "a seccomp listener already observes this process, and a \
                 fallback audit cannot run nested"
                    .into(),
            )
        }
        other => other,
    }
}

/// Widen `policy` enough for a target to run while being observed.///
/// The widening is deliberately narrow: read access to the target's own
/// directory, which is what a program most often needs and most often lacks
/// before its profile exists. Network policy is untouched, so a target audited
/// under the default policy still cannot reach the network, and the attempt is
/// recorded rather than served.
fn envelope(policy: &Policy, target: &Target) -> Policy {
    let mut envelope = policy.clone();
    if let Some(dir) = target_dir(target) {
        envelope.filesystem.push(FsRule {
            path: dir,
            access: Access::READ,
            at: None,
        });
    }
    envelope
}

fn target_dir(target: &Target) -> Option<PathBuf> {
    std::path::absolute(&target.program)
        .ok()?
        .parent()
        .map(Path::to_path_buf)
}

fn report_envelope(envelope: &Policy, policy: &Policy) {
    if envelope.filesystem.len() > policy.filesystem.len() {
        eprintln!("bailey: audit envelope: policy plus read on the target's own directory");
    } else {
        eprintln!("bailey: audit envelope: the resolved policy, unchanged");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Report a unit test as skipped and record the skip where CI asks for
    /// it, mirroring `tests/common/mod.rs` and the other lib-side helpers:
    /// the same printed line, the same log shape, keyed by crate and module
    /// path.
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
        use std::io::Write as _;
        let name = std::thread::current();
        let test = name.name().unwrap_or("unknown");
        let _ = writeln!(log, "{}::{}\t{}", env!("CARGO_CRATE_NAME"), test, reason);
    }

    /// A trivial target that exits at once.
    fn target() -> Target {
        Target {
            program: PathBuf::from("/bin/true"),
            args: Vec::new(),
            cwd: None,
        }
    }

    /// Install one allow-everything seccomp filter on this process, the way
    /// a service manager's `SystemCallFilter` entries and Flatpak leave
    /// several on a service. None of them is a listener.
    fn install_plain_filter() {
        unsafe {
            assert_eq!(
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
                0,
                "no_new_privs: {}",
                std::io::Error::last_os_error()
            );
            let instruction = libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x7fff_0000,
            };
            let program = libc::sock_fprog {
                len: 1,
                filter: &instruction as *const libc::sock_filter as *mut libc::sock_filter,
            };
            assert_eq!(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
                0,
                "seccomp filter: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    /// A service may carry several plain seccomp filters before bailey is
    /// ever asked to audit it: systemd's `SystemCallFilter` and Flatpak
    /// leave them on a process, and none of them is a listener. None of
    /// that refuses a fallback audit; only an inherited listener does.
    #[test]
    fn a_fallback_audit_runs_over_inherited_plain_filters() {
        if !matches!(
            crate::backend::probe::fallback_status(),
            crate::backend::probe::FallbackStatus::Available
        ) {
            skip("the fallback observer is unavailable on this host");
            return;
        }
        // The installs only take on a fresh task: a filter installed in a
        // libtest worker thread does not reach `/proc/self/status` on every
        // kernel, and the target would inherit nothing. The fork makes the
        // inherited stack real.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            install_plain_filter();
            install_plain_filter();
            // The floor the CLI always layers under a target, from the
            // `untrusted` profile: the system paths a dynamically linked
            // binary resolves and loads through. Without them the exec
            // itself is the first denial, not the run the audit observes.
            let mut policy = Policy::default();
            for dir in ["/usr", "/lib", "/lib64", "/bin", "/sbin"] {
                policy.filesystem.push(FsRule {
                    path: PathBuf::from(dir),
                    access: Access::READ | Access::EXECUTE,
                    at: None,
                });
            }
            let outcome = AuditBackend {
                unconfined: false,
                isolate: false,
                observer: ObserverChoice::Seccomp,
            }
            .run_and_record(&policy, &target());
            match outcome {
                Ok((0, _trace)) => unsafe { libc::_exit(0) },
                Ok((status, _)) => {
                    eprintln!("the audited target exited {status}");
                    unsafe { libc::_exit(1) }
                }
                Err(err) => {
                    eprintln!("the fallback audit failed over the inherited stack: {err}");
                    unsafe { libc::_exit(2) }
                }
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
        assert!(libc::WIFEXITED(status), "the forked child did not exit");
        match libc::WEXITSTATUS(status) {
            0 => {}
            1 => panic!("the audited target did not exit cleanly over plain inherited filters"),
            2 => panic!("the fallback audit was refused over plain inherited filters"),
            other => panic!("the forked child exited with unexpected code {other}"),
        }
    }

    /// Every observer path through `run_and_record` returns a trace whose
    /// usage is `Some`, measured or explained. A second observer added later
    /// (the unprivileged fallback's seccomp notification) must go through the
    /// same funnel, or this fails.
    #[test]
    fn every_observer_path_records_a_usage() {
        if !matches!(
            crate::backend::probe::probe(true).helper,
            crate::backend::probe::HelperStatus::Ready(_)
        ) {
            skip("no audit helper configured");
            return;
        }

        let policy = Policy::default();
        let (unconfined, trace) = AuditBackend {
            unconfined: true,
            isolate: false,
            observer: ObserverChoice::Auto,
        }
        .run_and_record(&policy, &target())
        .expect("an unconfined run of /bin/true");
        assert_eq!(unconfined, 0);
        let usage = trace.usage.expect("the unconfined path records a usage");
        assert_eq!(usage.memory_peak_bytes, None);
        assert!(
            usage
                .unmeasured
                .iter()
                .all(|reason| reason.contains("unconfined run, no cgroup"))
        );

        let (_, trace) = AuditBackend::default()
            .run_and_record(&policy, &target())
            .expect("a confined run of /bin/true");
        let usage = trace
            .usage
            .expect("the confined observer path records a usage");
        // Measured where the cgroup carried the peaks, explained where it did
        // not; never absent.
        assert!(
            usage.memory_peak_bytes.is_some() || !usage.unmeasured.is_empty(),
            "each peak is either measured or explained: {usage:?}"
        );
    }
}
