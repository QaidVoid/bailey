//! The access event schema shared between the audit backend and reconciliation.
//!
//! The audit backend records one [`AccessEvent`] per observed access; the
//! [`crate::reconcile`] module diffs a trace of these against a policy.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The kind of access an event describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessKind {
    /// A filesystem read.
    Read,
    /// A filesystem write.
    Write,
    /// A filesystem execute.
    Execute,
    /// An outbound TCP connection.
    Connect,
    /// A TCP bind.
    Bind,
}

/// The resource an access targeted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    /// A filesystem path.
    Path(PathBuf),
    /// A network destination.
    Net {
        /// Destination host, if known (an address or hostname).
        host: Option<String>,
        /// Destination or bound TCP port.
        port: u16,
    },
}

/// A single observed access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessEvent {
    /// The kind of access.
    pub kind: AccessKind,
    /// The resource accessed.
    pub resource: Resource,
    /// PID of the accessing process.
    pub pid: u32,
    /// Monotonic timestamp of the access, in nanoseconds.
    pub timestamp_ns: u64,
}
