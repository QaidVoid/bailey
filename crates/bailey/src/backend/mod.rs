//! Sandbox execution backends.
//!
//! Both the [`enforce`] and [`audit`] backends consume the same
//! [`crate::policy::Policy`]. Enforcement builds a deny-by-default world;
//! audit runs the target permissively while recording its access. The
//! [`probe`] module detects which kernel features are available.

pub mod audit;
pub mod audit_helper;
pub mod enforce;
pub mod isolation;
pub mod probe;

use std::path::PathBuf;

use crate::policy::Policy;

/// A program to run under a backend.
#[derive(Debug, Clone)]
pub struct Target {
    /// Path to the executable.
    pub program: PathBuf,
    /// Arguments passed to the executable.
    pub args: Vec<String>,
    /// Working directory, or `None` to inherit the current one.
    pub cwd: Option<PathBuf>,
}

/// An error produced while establishing a sandbox or running a target.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// The backend or a required feature is not yet implemented.
    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
    /// A required kernel feature is unavailable.
    #[error("required kernel feature unavailable: {0}")]
    Unsupported(String),
    /// An underlying I/O error occurred.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// A sandbox execution backend.
pub trait Backend {
    /// Run `target` confined by `policy`, returning the target's exit code.
    fn run(&self, policy: &Policy, target: &Target) -> Result<i32, BackendError>;
}
