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

        let mut recorder = audit_helper::Recorder::start()?;
        let backend = EnforceBackend {
            isolate: self.isolate,
            stop_before_exec: true,
            // The audit output is the point of the run; a layer summary on top
            // of it would bury the findings.
            summary: enforce::Summary::Quiet,
            // Scoping observation to a cgroup is race-free, so a run gets one
            // whether or not the policy sets limits.
            always_cgroup: true,
        };
        let confined = backend.spawn(&envelope, target)?;
        let code = audit_helper::record(&mut recorder, confined)?;
        Ok((code, recorder.finish()))
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
