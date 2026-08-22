//! Profile reconciliation.
//!
//! Diffs a recorded access trace against a [`Policy`], classifies the accesses
//! the policy does not already grant by risk, and generates a deny-by-default
//! profile from a chosen subset. High-risk access (network egress, credential
//! reads, access outside the target directory) is flagged and never included in
//! a generated profile unless the caller explicitly selects it, so auditing an
//! untrusted target never silently blesses its behavior.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::backend::world;
use crate::event::{AccessEvent, AccessKind, Resolution, Resource};
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
    /// Whether the path could not be resolved to an absolute one, in which case
    /// it cannot be compared against policy paths or granted.
    pub unresolved: bool,
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
            unresolved: event.resolution == Resolution::Unresolved,
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
/// How many entries a directory needs before a grant names it rather than them.
const COALESCE_AT: usize = 3;

/// Replace many paths under one directory with the directory itself.
///
/// A trace of a real program is thousands of files: one run of a coding agent
/// read 1,760, of which 192 sat in a single directory of syntax definitions. A
/// grant per file is unreadable, and a policy nobody reads gets replaced by
/// something far wider. Bailey's grants are hierarchies, so the useful answer is
/// the directory.
///
/// This grants more than was observed, which is the trade: wide enough to read,
/// narrow enough to mean something. It stops where a directory has fewer than
/// [`COALESCE_AT`] entries, which is what keeps it from walking up to the home.
fn coalesce(paths: BTreeSet<String>) -> (BTreeSet<String>, bool) {
    let mut current: BTreeSet<PathBuf> = paths.iter().map(PathBuf::from).collect();
    let mut coalesced = false;

    loop {
        let mut by_parent: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
        for path in &current {
            match path.parent() {
                Some(parent) => by_parent
                    .entry(parent.to_path_buf())
                    .or_default()
                    .push(path.clone()),
                None => {
                    by_parent.entry(path.clone()).or_default();
                }
            }
        }

        let mut next = BTreeSet::new();
        let mut changed = false;
        for (parent, children) in by_parent {
            if children.len() >= COALESCE_AT && may_name(&parent) {
                next.insert(parent);
                changed = true;
            } else {
                next.extend(children);
            }
        }

        coalesced |= changed;
        if !changed {
            // A path already covered by a directory in the set adds nothing.
            let covered: Vec<PathBuf> = next
                .iter()
                .filter(|path| {
                    next.iter()
                        .any(|other| *other != **path && path.starts_with(other))
                })
                .cloned()
                .collect();
            for path in covered {
                next.remove(&path);
            }
            return (
                next.into_iter()
                    .map(|path| path.display().to_string())
                    .collect(),
                coalesced,
            );
        }
        current = next;
    }
}

/// Whether a directory is specific enough to name in a grant.
///
/// The home directory and anything above it are never the answer: a grant on the
/// home is the thing this tool exists to avoid, and arriving at one by
/// accumulation would be the worst way to get there.
fn may_name(dir: &Path) -> bool {
    if dir.components().count() < 3 {
        return false;
    }
    match std::env::var_os("HOME") {
        Some(home) => !Path::new(&home).starts_with(dir),
        None => true,
    }
}

pub fn generate_profile(findings: &[Finding]) -> String {
    let mut read = BTreeSet::new();
    let mut write = BTreeSet::new();
    let mut execute = BTreeSet::new();
    let mut connect_ports = BTreeSet::new();
    let mut bind_ports = BTreeSet::new();

    let mut skipped_terminal = false;
    for finding in findings {
        // A relative path that could not be resolved names nothing in
        // particular, so granting it would be guesswork.
        if finding.unresolved {
            continue;
        }
        // A pseudo-terminal is named per session: `/dev/pts/9` today is a
        // different number tomorrow, so a policy naming one is stale as soon as
        // the terminal closes. The sandbox provides the terminal it was started
        // from, so nothing needs to grant it. Findings still report the access;
        // it is only generating a grant from one that makes no sense.
        if let Resource::Path(path) = &finding.resource
            && path.starts_with("/dev/pts")
        {
            skipped_terminal = true;
            continue;
        }
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

    // A program that was executed from outside the sandbox `PATH` cannot be found
    // by name, and the environment is not otherwise generated: nothing in a trace
    // implies a variable. An execution is the exception, because the trace says
    // exactly where the thing that ran was.
    let interpreter_dirs: BTreeSet<String> = execute
        .iter()
        .filter_map(|path| Path::new(path).parent())
        .filter(|dir| {
            !world::SANDBOX_PATH
                .split(':')
                .any(|known| Path::new(known) == *dir)
        })
        .map(|dir| dir.display().to_string())
        .collect();

    let (read, read_coalesced) = coalesce(read);
    let (write, write_coalesced) = coalesce(write);
    let (execute, execute_coalesced) = coalesce(execute);

    let mut out = String::new();
    if read_coalesced || write_coalesced || execute_coalesced {
        out.push_str("# Directories, where many files under one were used: a grant per file\n");
        out.push_str("# is unreadable, and these are hierarchies. Narrow any that are wider\n");
        out.push_str("# than you want.\n");
    }
    if skipped_terminal {
        out.push_str("# The terminal is not granted: a pty is named per session, and the\n");
        out.push_str("# sandbox provides the one it was started from.\n");
    }
    out.push_str("[filesystem]\n");
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

    if !interpreter_dirs.is_empty() {
        let mut path: Vec<String> = interpreter_dirs.iter().cloned().collect();
        path.push(world::SANDBOX_PATH.to_owned());
        out.push_str("\n# Where the programs this ran were found. Without this they are not\n");
        out.push_str("# on PATH inside the sandbox, and a `#!/usr/bin/env` line finds\n");
        out.push_str("# nothing. The rest of the environment is never generated.\n");
        out.push_str("[env]\n");
        out.push_str(&format!("set = {{ PATH = \"{}\" }}\n", path.join(":")));
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
            resolution: Resolution::Absolute,
        }
    }

    fn net_event(kind: AccessKind, port: u16) -> AccessEvent {
        AccessEvent {
            kind,
            resource: Resource::Net { host: None, port },
            pid: 1,
            timestamp_ns: 0,
            resolution: Resolution::NotApplicable,
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
            unresolved: false,
        }];
        let profile = generate_profile(&findings);
        assert!(profile.contains("read = [\"/game/data.pak\"]"));
        assert!(!profile.contains("egress"));
    }
}
