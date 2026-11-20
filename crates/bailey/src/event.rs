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

/// The resource peaks a run reported, where its cgroup carried the accounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Highest resident memory the run reached, in bytes, from `memory.peak`.
    pub memory_peak_bytes: Option<u64>,
    /// Highest number of tasks the run held at once, from `pids.peak`.
    pub tasks_peak: Option<u64>,
    /// Why each missing peak is missing, one short sentence per peak.
    pub unmeasured: Vec<String>,
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
    /// The run's resource peaks. `None` means the trace was written before
    /// traces carried measurement, and `profile generate` says so rather than
    /// suggesting limits from nothing.
    #[serde(default)]
    pub usage: Option<Usage>,
}

impl Trace {
    /// A complete trace of `events`, with no usage recorded yet. The backend
    /// fills `usage` in from the run's cgroup where one carried it.
    pub fn new(events: Vec<AccessEvent>, dropped: u64) -> Self {
        Self {
            version: TRACE_VERSION,
            dropped,
            events,
            usage: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A trace written before traces carried peaks has no `usage` key, and
    /// must still load and generate.
    #[test]
    fn a_version_1_trace_without_usage_loads() {
        let text = r#"{"version":1,"dropped":0,"events":[]}"#;
        let trace: Trace = serde_json::from_str(text).expect("an old trace still loads");
        assert!(trace.usage.is_none());
        assert!(trace.check_version().is_ok());
    }

    /// A trace with peaks round-trips through the format.
    #[test]
    fn a_trace_with_usage_round_trips() {
        let usage = Usage {
            memory_peak_bytes: Some(314_572_800),
            tasks_peak: Some(40),
            unmeasured: vec!["tasks: this kernel does not report pids.peak".into()],
        };
        let mut trace = Trace::new(Vec::new(), 0);
        trace.usage = Some(usage.clone());
        let text = serde_json::to_string(&trace).expect("a trace always serializes");
        let loaded: Trace = serde_json::from_str(&text).expect("and reads back");
        assert_eq!(loaded.usage, Some(usage));
    }

    /// Forward-compatibility guard, on purpose: `Trace` has no
    /// `deny_unknown_fields`, so a build older than a trace field ignores
    /// what it does not know instead of refusing the file. If someone adds
    /// `deny_unknown_fields` this breaks old builds reading new traces; this
    /// test is the reminder to think about the version instead.
    #[test]
    fn a_trace_with_an_unknown_top_level_key_still_loads() {
        let text = r#"{"version":1,"dropped":0,"events":[],"net_peaks":{}}"#;
        let trace: Trace = serde_json::from_str(text).expect("an unknown key is ignored");
        assert!(trace.check_version().is_ok());
    }
}
