//! Profile reconciliation.
//!
//! Diffs a recorded access trace against a [`Policy`], classifies the accesses
//! the policy does not already grant by risk, and generates a deny-by-default
//! profile from a chosen subset. High-risk access (network egress, credential
//! reads, access outside the target directory) is flagged and never included in
//! a generated profile unless the caller explicitly selects it, so auditing an
//! untrusted target never silently blesses its behavior.

use std::collections::BTreeSet;
use std::path::Path;

use crate::event::{AccessEvent, AccessKind, Resource};
use crate::policy::{Access, Egress, Policy};

/// The risk assigned to an ungranted access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Risk {
    /// Routine access that is safe to grant.
    Low,
    /// Sensitive access that must be reviewed before granting. The string is a
    /// human-readable reason.
    High(String),
}

impl Risk {
    /// Whether this risk is high.
    pub fn is_high(&self) -> bool {
        matches!(self, Risk::High(_))
    }
}

/// An access observed in the trace that the current policy does not grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The kind of access.
    pub kind: AccessKind,
    /// The resource accessed.
    pub resource: Resource,
    /// The assessed risk.
    pub risk: Risk,
}

/// Diff `trace` against `policy` and return the ungranted accesses, classified
/// by risk. Findings are deduplicated and sorted for a stable presentation.
pub fn reconcile(trace: &[AccessEvent], policy: &Policy, target_dir: &Path) -> Vec<Finding> {
    let mut seen = BTreeSet::new();
    let mut findings = Vec::new();

    for event in trace {
        if is_granted(event, policy) {
            continue;
        }
        let key = (event.kind, format!("{:?}", event.resource));
        if !seen.insert(key) {
            continue;
        }
        findings.push(Finding {
            kind: event.kind,
            resource: event.resource.clone(),
            risk: classify(&event.resource, target_dir),
        });
    }

    findings.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    findings
}

/// Generate a deny-by-default TOML profile granting exactly `findings`.
///
/// The caller decides which findings to include; nothing here is implicit. To
/// honor the never-auto-trust rule, callers should exclude high-risk findings
/// unless the user explicitly confirmed them.
pub fn generate_profile(findings: &[Finding]) -> String {
    let mut read = BTreeSet::new();
    let mut write = BTreeSet::new();
    let mut execute = BTreeSet::new();
    let mut connect_ports = BTreeSet::new();
    let mut bind_ports = BTreeSet::new();

    for finding in findings {
        match (&finding.kind, &finding.resource) {
            (AccessKind::Read, Resource::Path(path)) => {
                read.insert(display(path));
            }
            (AccessKind::Write, Resource::Path(path)) => {
                write.insert(display(path));
            }
            (AccessKind::Execute, Resource::Path(path)) => {
                execute.insert(display(path));
            }
            (AccessKind::Connect, Resource::Net { port, .. }) => {
                connect_ports.insert(*port);
            }
            (AccessKind::Bind, Resource::Net { port, .. }) => {
                bind_ports.insert(*port);
            }
            _ => {}
        }
    }

    let mut out = String::from("[filesystem]\n");
    out.push_str(&toml_string_array("read", &read));
    out.push_str(&toml_string_array("write", &write));
    out.push_str(&toml_string_array("execute", &execute));

    if !connect_ports.is_empty() || !bind_ports.is_empty() {
        out.push_str("\n[network]\n");
        if !connect_ports.is_empty() {
            out.push_str("egress = \"allow\"\n");
            out.push_str(&toml_egress_allow(&connect_ports));
        }
        if !bind_ports.is_empty() {
            out.push_str(&toml_port_array("bind_ports", &bind_ports));
        }
    }

    out
}

fn is_granted(event: &AccessEvent, policy: &Policy) -> bool {
    match (&event.kind, &event.resource) {
        (AccessKind::Read, Resource::Path(path)) => fs_granted(policy, path, Access::READ),
        (AccessKind::Write, Resource::Path(path)) => fs_granted(policy, path, Access::WRITE),
        (AccessKind::Execute, Resource::Path(path)) => fs_granted(policy, path, Access::EXECUTE),
        (AccessKind::Connect, Resource::Net { port, .. }) => match &policy.network.egress {
            Egress::AllowAll => true,
            Egress::DenyAll => false,
            Egress::Allow(rules) => rules.iter().any(|rule| rule.port == Some(*port)),
        },
        (AccessKind::Bind, Resource::Net { port, .. }) => policy.network.bind_ports.contains(port),
        _ => false,
    }
}

fn fs_granted(policy: &Policy, path: &Path, access: Access) -> bool {
    // Device grants share filesystem grant semantics, so both are considered.
    policy
        .filesystem
        .iter()
        .map(|rule| (&rule.path, rule.access))
        .chain(policy.devices.iter().map(|rule| (&rule.path, rule.access)))
        .any(|(rule_path, rule_access)| rule_access.contains(access) && path.starts_with(rule_path))
}

fn classify(resource: &Resource, target_dir: &Path) -> Risk {
    match resource {
        Resource::Net { .. } => Risk::High("network egress".into()),
        Resource::Path(path) => {
            if is_credential_path(path) {
                Risk::High("credential or secret path".into())
            } else if is_system_path(path) || path.starts_with(target_dir) {
                Risk::Low
            } else {
                Risk::High("access outside the target directory".into())
            }
        }
    }
}

fn is_system_path(path: &Path) -> bool {
    const SYSTEM_ROOTS: &[&str] = &[
        "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/sys", "/dev", "/run", "/opt",
        "/var",
    ];
    SYSTEM_ROOTS.iter().any(|root| path.starts_with(root))
}

fn is_credential_path(path: &Path) -> bool {
    const SECRET_COMPONENTS: &[&str] = &[
        ".ssh",
        ".gnupg",
        ".aws",
        ".config/gcloud",
        ".password-store",
        ".mozilla",
    ];
    const SECRET_NAMES: &[&str] = &[".netrc", ".git-credentials", "id_rsa", "id_ed25519"];

    let text = path.to_string_lossy();
    if SECRET_COMPONENTS.iter().any(|needle| text.contains(needle)) {
        return true;
    }
    path.file_name()
        .map(|name| SECRET_NAMES.contains(&name.to_string_lossy().as_ref()))
        .unwrap_or(false)
}

fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn toml_string_array(key: &str, values: &BTreeSet<String>) -> String {
    if values.is_empty() {
        return String::new();
    }
    let items = values
        .iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{key} = [{items}]\n")
}

fn toml_port_array(key: &str, values: &BTreeSet<u16>) -> String {
    let items = values
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("{key} = [{items}]\n")
}

fn toml_egress_allow(ports: &BTreeSet<u16>) -> String {
    let items = ports
        .iter()
        .map(|port| format!("{{ host = \"*\", port = {port} }}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("egress_allow = [{items}]\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::FsRule;
    use std::path::PathBuf;

    fn event(kind: AccessKind, path: &str) -> AccessEvent {
        AccessEvent {
            kind,
            resource: Resource::Path(PathBuf::from(path)),
            pid: 1,
            timestamp_ns: 0,
        }
    }

    fn net_event(kind: AccessKind, port: u16) -> AccessEvent {
        AccessEvent {
            kind,
            resource: Resource::Net { host: None, port },
            pid: 1,
            timestamp_ns: 0,
        }
    }

    #[test]
    fn granted_access_produces_no_finding() {
        let mut policy = Policy::default();
        policy.filesystem.push(FsRule {
            path: PathBuf::from("/game"),
            access: Access::READ,
        });
        let trace = [event(AccessKind::Read, "/game/data.pak")];
        let findings = reconcile(&trace, &policy, Path::new("/game"));
        assert!(findings.is_empty());
    }

    #[test]
    fn ungranted_access_is_reported_once() {
        let policy = Policy::default();
        let trace = [
            event(AccessKind::Read, "/game/data.pak"),
            event(AccessKind::Read, "/game/data.pak"),
        ];
        let findings = reconcile(&trace, &policy, Path::new("/game"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, Risk::Low);
    }

    #[test]
    fn credential_read_is_high_risk() {
        let policy = Policy::default();
        let trace = [event(AccessKind::Read, "/home/user/.ssh/id_rsa")];
        let findings = reconcile(&trace, &policy, Path::new("/game"));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].risk.is_high());
    }

    #[test]
    fn egress_is_high_risk() {
        let policy = Policy::default();
        let trace = [net_event(AccessKind::Connect, 443)];
        let findings = reconcile(&trace, &policy, Path::new("/game"));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].risk.is_high());
    }

    #[test]
    fn generated_profile_grants_only_given_findings() {
        let findings = vec![Finding {
            kind: AccessKind::Read,
            resource: Resource::Path(PathBuf::from("/game/data.pak")),
            risk: Risk::Low,
        }];
        let profile = generate_profile(&findings);
        assert!(profile.contains("read = [\"/game/data.pak\"]"));
        assert!(!profile.contains("egress"));
    }
}
