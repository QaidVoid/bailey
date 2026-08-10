//! Audit backend.
//!
//! Runs the target permissively while recording its filesystem and network
//! access, producing a trace of [`AccessEvent`]s for reconciliation. The
//! recording itself is done by the privileged [`crate::backend::audit_helper`],
//! so the main tool stays unprivileged.

use crate::backend::{Backend, BackendError, Target, audit_helper};
use crate::event::AccessEvent;
use crate::policy::Policy;

/// Permissive-but-recording audit backend.
#[derive(Debug, Default)]
pub struct AuditBackend;

impl AuditBackend {
    /// Run `target` permissively while recording its access, returning the
    /// target's exit code and the recorded trace.
    pub fn run_and_record(
        &self,
        _policy: &Policy,
        target: &Target,
    ) -> Result<(i32, Vec<AccessEvent>), BackendError> {
        audit_helper::run(target)
    }
}

impl Backend for AuditBackend {
    fn run(&self, policy: &Policy, target: &Target) -> Result<i32, BackendError> {
        self.run_and_record(policy, target).map(|(code, _)| code)
    }
}
