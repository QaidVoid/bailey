//! Audit backend.
//!
//! Runs the target permissively while recording its filesystem and network
//! access through cgroup-scoped eBPF programs, emitting a structured event
//! stream for reconciliation. The eBPF machinery is added in a later change;
//! this module currently defines the backend type and its trait wiring.

use crate::backend::{Backend, BackendError, Target};
use crate::policy::Policy;

/// Permissive-but-recording audit backend.
#[derive(Debug, Default)]
pub struct AuditBackend;

impl Backend for AuditBackend {
    fn run(&self, _policy: &Policy, _target: &Target) -> Result<i32, BackendError> {
        Err(BackendError::Unimplemented("audit backend"))
    }
}
