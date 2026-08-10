//! Runtime kernel capability detection.
//!
//! The probe reports which sandboxing features the running kernel offers so the
//! backends can adapt and report clearly rather than failing opaquely. The
//! precise Landlock ABI level is negotiated when the enforcement backend
//! creates its ruleset in best-effort mode, so it is not part of this probe.

use std::fs;
use std::path::Path;

/// Sandboxing-relevant features detected on the running kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// Whether the Landlock LSM is active.
    pub landlock: bool,
    /// Whether unprivileged user namespaces are permitted.
    pub unprivileged_userns: bool,
    /// Whether kernel BTF is available (required for the eBPF audit backend).
    pub btf: bool,
}

/// Probe the running kernel for sandboxing-relevant features.
pub fn probe() -> Capabilities {
    Capabilities {
        landlock: lsm_active("landlock"),
        unprivileged_userns: unprivileged_userns(),
        btf: Path::new("/sys/kernel/btf/vmlinux").exists(),
    }
}

fn lsm_active(name: &str) -> bool {
    fs::read_to_string("/sys/kernel/security/lsm")
        .map(|list| list.split(',').any(|item| item.trim() == name))
        .unwrap_or(false)
}

fn unprivileged_userns() -> bool {
    if let Ok(value) = fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        return value.trim() == "1";
    }
    fs::read_to_string("/proc/sys/user/max_user_namespaces")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|max| max > 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_does_not_panic() {
        let _ = probe();
    }
}
