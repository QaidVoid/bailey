//! Enforcement backend.
//!
//! Builds a deny-by-default world from a [`Policy`] using namespaces, Landlock
//! filesystem rules, a seccomp syscall filter, and cgroup resource limits. The
//! mechanisms are layered in a later change; this module currently defines the
//! backend type and its trait wiring.

use crate::backend::{Backend, BackendError, Target};
use crate::policy::Policy;

/// Deny-by-default enforcement backend.
#[derive(Debug, Default)]
pub struct EnforceBackend;

impl Backend for EnforceBackend {
    fn run(&self, _policy: &Policy, _target: &Target) -> Result<i32, BackendError> {
        Err(BackendError::Unimplemented("enforcement backend"))
    }
}
