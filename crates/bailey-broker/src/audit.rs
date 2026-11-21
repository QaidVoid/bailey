//! The decision log: one JSON line per decision, and the allowed and
//! refused counts the broker reports when it stops.

use std::fs::File;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// One decision, in the shape the log line carries.
pub struct AuditEntry<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub port: u16,
    /// The request path without its query, or the empty string for a
    /// CONNECT tunnel, whose target is host and port alone.
    pub path: &'a str,
    /// "allowed" or "refused".
    pub verdict: &'a str,
    /// The client-facing refusal text, or the empty string when allowed.
    pub reason: &'a str,
    /// "deny rule N in <source>" / "allow rule N in <source>", or empty
    /// when no rule decided.
    pub rule: &'a str,
    pub intercepted: bool,
    /// The upstream response status, when the decision got that far.
    pub status: Option<u16>,
}

/// The log and the running counts behind it. A missing or failing log
/// costs the line, never the decision.
pub struct AuditLog {
    file: Mutex<Option<File>>,
    allowed: AtomicU64,
    refused: AtomicU64,
}

impl AuditLog {
    /// Wraps the log descriptor, if the caller opened one.
    pub fn new(file: Option<File>) -> Self {
        Self {
            file: Mutex::new(file),
            allowed: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        }
    }

    /// Records one decision. The line is written in a single call, so
    /// concurrent decisions cannot interleave inside a line on the
    /// append-only descriptor.
    pub fn record(&self, entry: AuditEntry<'_>) {
        match entry.verdict {
            "allowed" => {
                self.allowed.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.refused.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut guard = self.file.lock().expect("the log lock is never poisoned");
        let Some(file) = guard.as_mut() else {
            return;
        };
        let time = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown".into());
        let mut line = serde_json::json!({
            "time": time,
            "method": entry.method,
            "host": entry.host,
            "port": entry.port,
            "path": entry.path,
            "verdict": entry.verdict,
            "reason": entry.reason,
            "rule": entry.rule,
            "intercepted": entry.intercepted,
        });
        if let Some(status) = entry.status {
            line["status"] = status.into();
        }
        let _ = writeln!(file, "{line}");
    }

    /// The counts line for the parent: the last thing the broker writes.
    pub fn counts_line(&self) -> String {
        serde_json::json!({
            "allowed": self.allowed.load(Ordering::Relaxed),
            "refused": self.refused.load(Ordering::Relaxed),
        })
        .to_string()
    }
}
