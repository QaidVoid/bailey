//! The access event schema shared between the audit backend and reconciliation.
//!
//! The audit backend records one [`AccessEvent`] per observed access, wrapped in
//! a [`Trace`] that carries what the run knows about its own completeness. A
//! trace that lost events says so, because a profile generated from a trace with
//! holes in it grants less than the program needs and looks no different.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Version of the saved trace format.
pub const TRACE_VERSION: u32 = 1;

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
    /// An outbound connection.
    Connect,
    /// A socket bind.
    Bind,
}

/// How an event's path was arrived at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// The program named an absolute path.
    Absolute,
    /// A relative path, resolved by the audit backend against the accessing
    /// process's working directory or directory descriptor.
    Userspace,
    /// A relative path that could not be resolved, usually because the process
    /// was gone before it could be read.
    Unresolved,
    /// Not a path.
    NotApplicable,
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
        /// Destination or bound port.
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
    /// How the path was resolved.
    #[serde(default = "not_applicable")]
    pub resolution: Resolution,
}

fn not_applicable() -> Resolution {
    Resolution::NotApplicable
}

/// A recorded session, with what the backend knows about its completeness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trace {
    /// Format version, so an older or newer file is rejected rather than
    /// misread.
    pub version: u32,
    /// Number of accesses the backend could not record.
    pub dropped: u64,
    /// The recorded accesses.
    pub events: Vec<AccessEvent>,
}

impl Trace {
    /// A complete trace of `events`.
    pub fn new(events: Vec<AccessEvent>, dropped: u64) -> Self {
        Self {
            version: TRACE_VERSION,
            dropped,
            events,
        }
    }

    /// Whether the trace is known to be missing events.
    pub fn is_truncated(&self) -> bool {
        self.dropped > 0
    }

    /// Check that a loaded trace is a format this build understands.
    pub fn check_version(&self) -> Result<(), String> {
        if self.version == TRACE_VERSION {
            return Ok(());
        }
        Err(format!(
            "trace format version {} is not supported by this build, which reads version {}",
            self.version, TRACE_VERSION
        ))
    }
}
