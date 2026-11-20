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

use std::path::{Path, PathBuf};

use crate::backend::enforce::{self, EnforceBackend};
use crate::backend::{BackendError, Target, audit_helper};
use crate::event::Trace;
use crate::policy::{Access, FsRule, Policy};

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
            eprintln!(
                "bailey: warning: auditing without confinement; the target runs \
                 with your full authority"
            );
            return audit_helper::run_unconfined(target);
        }

        let envelope = envelope(policy, target);
        report_envelope(&envelope, policy);

        let recorder = audit_helper::Recorder::start()?;
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
        };
        let confined = backend.spawn(&envelope, target)?;
        // `record` is the only funnel for a confined audit: it waits through
        // `wait_measured`, so its trace always carries the run's peaks,
        // measured or explained.
        audit_helper::record(recorder, confined)
    }
}

/// Widen `policy` enough for a target to run while being observed.
///
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
