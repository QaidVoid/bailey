//! Audit backend.
//!
//! Runs the target permissively while recording its filesystem and network
//! access through cgroup-scoped eBPF programs, producing a trace of
//! [`AccessEvent`]s for reconciliation. The eBPF machinery is added in a later
//! change; the recording entry point is defined here so the CLI can wire the
//! audit flow ahead of it.

use crate::backend::{Backend, BackendError, Target};
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
        #[cfg(feature = "ebpf")]
        {
            crate::backend::audit_ebpf::run(target)
        }
        #[cfg(not(feature = "ebpf"))]
        {
            let _ = target;
            Err(BackendError::Unimplemented(
                "audit backend (rebuild with --features ebpf)",
            ))
        }
    }
}

impl Backend for AuditBackend {
    fn run(&self, policy: &Policy, target: &Target) -> Result<i32, BackendError> {
        self.run_and_record(policy, target).map(|(code, _)| code)
    }
}
