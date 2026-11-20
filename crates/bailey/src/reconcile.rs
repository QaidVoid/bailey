//! Profile reconciliation.
//!
//! Diffs a recorded access trace against a [`Policy`], classifies the accesses
//! the policy does not already grant by risk, and generates a deny-by-default
//! profile from a chosen subset. High-risk access (network egress, credential
//! reads, access outside the target directory) is flagged and never included in
//! a generated profile unless the caller explicitly selects it, so auditing an
//! untrusted target never silently blesses its behavior.
//!
//! One tier sits above even that: paths a profile should never name whatever
//! the flags say (`/`, the home and its ancestors, credential paths), so no
//! flag combination can bless the whole home. And where the trace carries the
//! run's measured peaks, a commented-out resource block suggests limits from
//! them, since a profile that applies nothing is free and a live one derived
//! from a single run is a gamble.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use crate::backend::world;
use crate::event::{AccessEvent, AccessKind, Resolution, Resource, Usage};
use crate::policy::{Access, Egress, Policy, ResourceLimits};

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
/// unless the user explicitly confirmed them. On top of that choice, paths
/// [`never_generated`] matches are left out whatever their risk; they come
/// back alongside the profile text so the caller can name them. Callers
/// should also offer the resource block from [`suggest_resources`] where the
/// trace carries measured peaks.
pub fn generate_profile(findings: &[Finding]) -> (String, Vec<String>) {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    generate_profile_under_home(findings, home.as_deref())
}

fn generate_profile_under_home(findings: &[Finding], home: Option<&Path>) -> (String, Vec<String>) {
    let mut read = BTreeSet::new();
    let mut write = BTreeSet::new();
    let mut execute = BTreeSet::new();
    let mut connect_ports = BTreeSet::new();
    let mut bind_ports = BTreeSet::new();
    let mut withheld = Vec::new();

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
        // The never tier sits above every flag: no risk class, no include
        // switch, and no amount of coalescing arrives at one of these.
        if let Resource::Path(path) = &finding.resource
            && never_generated_under_home(path, home)
        {
            withheld.push(display(path));
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

    let (read, read_coalesced) = coalesce(read, home);
    let (write, write_coalesced) = coalesce(write, home);
    let (execute, execute_coalesced) = coalesce(execute, home);

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

    (out, withheld)
}

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
fn coalesce(paths: BTreeSet<String>, home: Option<&Path>) -> (BTreeSet<String>, bool) {
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
            if children.len() >= COALESCE_AT && may_name(&parent, home) {
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
/// accumulation would be the worst way to get there. [`never_generated`] is the
/// same rule the findings filter applies, so a direct finding and a merged one
/// cannot disagree.
fn may_name(dir: &Path, home: Option<&Path>) -> bool {
    if dir.components().count() < 3 {
        return false;
    }
    !never_generated_under_home(dir, home)
}

/// A MiB in bytes, the unit the suggestion speaks in.
const MIB: u64 = 1_048_576;

/// The floor under a suggested memory limit, in whole MiB.
const MEMORY_FLOOR_MIB: u64 = 64;

/// The floor under a suggested `pids_max`.
///
/// A peak of one or two tasks says almost nothing: the floors cover the short
/// run whose peak would otherwise suggest a `pids_max = 2` that breaks the
/// first shell the program spawns.
const TASKS_FLOOR: u64 = 32;

/// The resource limits the run's peaks suggest, as a block of TOML comments.
///
/// Memory is twice the peak with a [`MEMORY_FLOOR_MIB`] floor, rounded up to a
/// whole MiB and written the way `parse_size` reads it; `pids_max` is twice
/// the tasks peak with a [`TASKS_FLOOR`] floor. A limit the base policy
/// already sets is not suggested: the generated profile supplements that
/// policy, and doubling a limit the run already pushed against would quietly
/// widen it.
///
/// Every line is a comment, headed with the measured peaks and the rule. The
/// block applies nothing as written; uncommenting it is a choice a person
/// makes after reading it. `None` when there is nothing to suggest, either
/// because no peak was measured or because the base policy already limits
/// everything that was.
pub fn suggest_resources(usage: &Usage, base: &ResourceLimits) -> Option<String> {
    let memory_peak = usage
        .memory_peak_bytes
        .filter(|_| base.memory_bytes.is_none());
    let tasks_peak = usage.tasks_peak.filter(|_| base.pids_max.is_none());
    if memory_peak.is_none() && tasks_peak.is_none() {
        return None;
    }

    let memory_mib =
        memory_peak.map(|peak| peak.saturating_mul(2).div_ceil(MIB).max(MEMORY_FLOOR_MIB));
    let tasks = tasks_peak.map(|peak| peak.saturating_mul(2).max(TASKS_FLOOR));

    let mut out = String::new();
    out.push_str("# Resource limits, suggested from this run: one run is one sample, and a\n");
    out.push_str("# larger input routinely needs more. The rule is twice each measured\n");
    out.push_str("# peak, floored at 64 MiB of memory and 32 tasks. Uncomment to apply.\n");
    match (usage.memory_peak_bytes, base.memory_bytes.is_some()) {
        (Some(peak), true) => out.push_str(&format!(
            "#   memory peak: {} (not suggested: the base policy sets a limit)\n",
            mib_text(peak)
        )),
        (Some(peak), false) => out.push_str(&format!("#   memory peak: {}\n", mib_text(peak))),
        (None, _) => {
            out.push_str("#   memory peak: none recorded\n");
            for reason in &usage.unmeasured {
                if reason.starts_with("memory:") {
                    out.push_str(&format!("#   {reason}\n"));
                }
            }
        }
    }
    match (usage.tasks_peak, base.pids_max.is_some()) {
        (Some(peak), true) => out.push_str(&format!(
            "#   tasks peak: {peak} (not suggested: the base policy sets a limit)\n"
        )),
        (Some(peak), false) => out.push_str(&format!("#   tasks peak: {peak}\n")),
        (None, _) => {
            out.push_str("#   tasks peak: none recorded\n");
            for reason in &usage.unmeasured {
                if reason.starts_with("tasks:") {
                    out.push_str(&format!("#   {reason}\n"));
                }
            }
        }
    }
    if let Some(mib) = memory_mib {
        out.push_str("#[resources]\n");
        out.push_str(&format!("#memory = \"{mib}MiB\"\n"));
    }
    if let Some(tasks) = tasks {
        if memory_mib.is_none() {
            out.push_str("#[resources]\n");
        }
        out.push_str(&format!("#pids_max = {tasks}\n"));
    }
    Some(out)
}

/// A byte count as whole MiB, one decimal where it is not exact.
fn mib_text(bytes: u64) -> String {
    let whole = bytes / MIB;
    let rem = bytes % MIB;
    if rem == 0 {
        format!("{whole} MiB")
    } else {
        format!("{whole}.{}", rem * 10 / MIB)
    }
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

/// Credential locations the same substring rule [`is_credential_path`] and the
/// never tier match, shared so the two cannot drift apart.
const SECRET_COMPONENTS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".config/gcloud",
    ".password-store",
    ".mozilla",
];

const SECRET_NAMES: &[&str] = &[".netrc", ".git-credentials", "id_rsa", "id_ed25519"];

/// Whether a path is never written into a generated profile, whatever the
/// flags say.
///
/// This is `/`; the home directory and every ancestor of it; every ancestor of
/// a credential location under the home, which is where `~/.config` comes from
/// (`is_credential_path` matches `.config/gcloud` inside it, so the directory
/// itself never matched); and anything `is_credential_path` matches.
///
/// The rule holds whatever was accessed, because these are the grants a
/// generator has no business writing: `read = ["~"]` defeats the purpose of
/// auditing, and arriving at it by coalescing is only a slower way there. A
/// user who really wants one writes it by hand.
pub fn never_generated(path: &Path) -> bool {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    never_generated_under_home(path, home.as_deref())
}

fn never_generated_under_home(path: &Path, home: Option<&Path>) -> bool {
    // The tier judges the path the way the kernel resolves it, so a
    // lexical `..` cannot name a longer spelling to dodge the rule with.
    let path = &normalise(path);
    if path == Path::new("/") {
        return true;
    }
    if is_credential_path(path) {
        return true;
    }
    let Some(home) = home else {
        return false;
    };
    if path == home || home.starts_with(path) {
        return true;
    }
    SECRET_COMPONENTS
        .iter()
        .map(|component| home.join(component))
        .any(|location| location.starts_with(path))
}

/// A path without `.` or `..` components, resolved lexically. A `..` at the
/// root clamps the way the kernel resolves one; a relative path stays
/// relative.
fn normalise(path: &Path) -> PathBuf {
    let mut kept = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if let Some(Component::Normal(_)) = kept.last() {
                    kept.pop();
                }
            }
            other => kept.push(other),
        }
    }
    kept.into_iter().collect()
}

fn is_credential_path(path: &Path) -> bool {
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
    // Quoted, not pasted: a filename may hold a quote or a newline, and an
    // unescaped one would end the array and let the rest of the line stand
    // as whatever TOML it spelled.
    let items = values
        .iter()
        .map(|value| crate::strings::quoted(value))
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

    /// The tier reads the path the way the kernel resolves it, so a lexical
    /// `..` cannot hide the home behind a longer spelling.
    #[test]
    fn a_dotdot_spelling_is_judged_after_normalisation() {
        let home = Path::new("/home/user");
        assert!(
            never_generated_under_home(Path::new("/home/user/proj/.."), Some(home)),
            "/home/user/proj/.. is the home once the `..` resolves"
        );
        assert!(
            never_generated_under_home(Path::new("/home/user/proj/../.ssh"), Some(home)),
            "the credential path behind the `..` is still a credential path"
        );
    }

    /// A finding whose path carries `..` is granted nowhere: the tier judges
    /// the normalised path, so `/home/user/proj/..` comes back withheld
    /// rather than becoming a home-wide read in a generated profile.
    #[test]
    fn a_dotdot_path_is_withheld_like_the_path_it_names() {
        let home = Path::new("/home/user");
        let findings = vec![Finding {
            kind: AccessKind::Read,
            resource: Resource::Path(PathBuf::from("/home/user/proj/..")),
            risk: Risk::Low,
            unresolved: false,
        }];
        let (profile, withheld) = generate_profile_under_home(&findings, Some(home));
        assert!(
            !profile.contains("/home/user"),
            "the path normalises to the home, which is never granted: {profile}"
        );
        assert_eq!(withheld, vec!["/home/user/proj/..".to_owned()]);
    }

    #[test]
    fn granted_access_produces_no_finding() {
        let mut policy = Policy::default();
        policy.filesystem.push(FsRule {
            path: PathBuf::from("/game"),
            access: Access::READ,
            at: None,
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
        let (profile, withheld) = generate_profile_under_home(&findings, None);
        assert!(profile.contains("read = [\"/game/data.pak\"]"));
        assert!(!profile.contains("egress"));
        assert!(withheld.is_empty());
    }

    /// A filename may hold anything but `/` and NUL. One carrying a quote and
    /// a newline would have ended the array and stood as TOML of its own
    /// choosing, so the value is quoted in full and reads back as one path.
    #[test]
    fn a_finding_with_quotes_and_a_newline_round_trips_through_toml() {
        let hostile = "/dev/shm/x\";\n[hooks]\npre_launch = [\"id\"]\n#";
        let findings = vec![Finding {
            kind: AccessKind::Read,
            resource: Resource::Path(PathBuf::from(hostile)),
            risk: Risk::Low,
            unresolved: false,
        }];
        let (profile, _) = generate_profile_under_home(&findings, None);
        let parsed: toml::Table =
            toml::from_str(&profile).expect("a generated profile always parses as TOML");
        let granted = parsed
            .get("filesystem")
            .and_then(|filesystem| filesystem.get("read"))
            .and_then(toml::Value::as_array)
            .expect("a read array");
        assert_eq!(granted.len(), 1, "the hostile text must stay one entry");
        assert_eq!(granted[0].as_str(), Some(hostile));
    }

    /// The never tier, passed as direct findings: `/`, the home, and the
    /// ancestor of a credential location all stay out whatever their risk,
    /// and the caller is told what was left out.
    #[test]
    fn the_root_the_home_and_its_credential_ancestors_are_never_generated() {
        let home = Path::new("/users/tester");
        let paths = [
            "/",
            "/users",
            "/users/tester",
            "/users/tester/.config",
            "/users/tester/.ssh",
            "/users/tester/.ssh/id_ed25519",
        ];
        let findings: Vec<Finding> = paths
            .iter()
            .map(|path| Finding {
                kind: AccessKind::Read,
                resource: Resource::Path(PathBuf::from(path)),
                risk: Risk::Low,
                unresolved: false,
            })
            .collect();
        let (profile, withheld) = generate_profile_under_home(&findings, Some(home));
        for path in paths {
            assert!(
                !profile.contains(path),
                "{path} must never be generated: {profile}"
            );
        }
        assert_eq!(withheld, paths, "every withheld path is named");
    }

    /// An ordinary path inside the target still generates, next to the never
    /// tier: the filter is narrow, not a general suspicion of everything.
    #[test]
    fn an_ordinary_path_still_generates() {
        let home = Path::new("/users/tester");
        let findings = vec![Finding {
            kind: AccessKind::Read,
            resource: Resource::Path(PathBuf::from("/game/data.pak")),
            risk: Risk::Low,
            unresolved: false,
        }];
        let (profile, withheld) = generate_profile_under_home(&findings, Some(home));
        assert!(profile.contains("/game/data.pak"));
        assert!(withheld.is_empty());
    }

    /// Coalescing may not arrive at a never tier directory by merging its
    /// children: three reads under `~/.config` stay three entries, and the
    /// directory itself is never named.
    #[test]
    fn coalescing_never_arrives_at_a_never_generated_directory() {
        let home = Path::new("/users/tester");
        let findings: Vec<Finding> = ["a", "b", "c"]
            .iter()
            .map(|leaf| Finding {
                kind: AccessKind::Read,
                resource: Resource::Path(PathBuf::from(format!(
                    "/users/tester/.config/{leaf}/one"
                ))),
                risk: Risk::Low,
                unresolved: false,
            })
            .collect();
        let (profile, _) = generate_profile_under_home(&findings, Some(home));
        for leaf in ["a", "b", "c"] {
            assert!(
                profile.contains(&format!("/users/tester/.config/{leaf}")),
                "each leaf stays a grant: {profile}"
            );
        }
        assert!(
            !profile.contains("\"/users/tester/.config\""),
            "the coalesced directory must never be named: {profile}"
        );
    }

    fn usage(memory: Option<u64>, tasks: Option<u64>) -> Usage {
        Usage {
            memory_peak_bytes: memory,
            tasks_peak: tasks,
            unmeasured: Vec::new(),
        }
    }

    /// The rule on a real measurement: twice the peak, written commented out
    /// with the peaks and the rule above it.
    #[test]
    fn a_suggestion_is_twice_the_peaks_commented_out() {
        let base = ResourceLimits::default();
        let block =
            suggest_resources(&usage(Some(300 * MIB), Some(40)), &base).expect("peaks to suggest");
        assert!(block.contains("one run is one sample"), "{block}");
        assert!(block.contains("Uncomment to apply"), "{block}");
        assert!(block.contains("#   memory peak: 300 MiB"), "{block}");
        assert!(block.contains("#   tasks peak: 40"), "{block}");
        assert!(block.contains("#[resources]"), "{block}");
        assert!(block.contains("#memory = \"600MiB\""), "{block}");
        assert!(block.contains("#pids_max = 80"), "{block}");
        // Applies nothing as written: every line is a comment.
        let parsed: toml::Table =
            toml::from_str(&block).expect("a suggestion is valid TOML as comments");
        assert!(parsed.get("resources").is_none());
    }

    /// A short run whose peaks say little gets the floors, not a `pids_max`
    /// of 2 that breaks the first shell the program spawns.
    #[test]
    fn small_peaks_get_the_floors() {
        let base = ResourceLimits::default();
        let block = suggest_resources(&usage(Some(10 * MIB), Some(2)), &base).unwrap();
        assert!(block.contains("#memory = \"64MiB\""), "{block}");
        assert!(block.contains("#pids_max = 32"), "{block}");
    }

    /// A limit the base policy already sets is not suggested: doubling a
    /// limit the run already pushed against would quietly widen it.
    #[test]
    fn a_base_limit_is_not_suggested() {
        let base = ResourceLimits {
            memory_bytes: Some(256 * MIB),
            ..ResourceLimits::default()
        };
        let block = suggest_resources(&usage(Some(300 * MIB), Some(40)), &base).unwrap();
        assert!(!block.contains("#memory"), "{block}");
        assert!(
            block.contains("the base policy sets a limit"),
            "the header says why memory is missing: {block}"
        );
        assert!(block.contains("#pids_max = 80"), "{block}");
    }

    /// Twice a peak that is not a whole MiB is rounded up to one, so the
    /// suggestion parses and rounds the way `parse_size` reads it.
    #[test]
    fn a_suggestion_rounds_up_to_a_whole_mib() {
        let base = ResourceLimits::default();
        let block = suggest_resources(&usage(Some(100 * MIB + 1), None), &base).unwrap();
        assert!(block.contains("#memory = \"201MiB\""), "{block}");
    }

    /// No peak, no suggestion: the caller explains instead.
    #[test]
    fn no_peaks_gives_no_suggestion() {
        let base = ResourceLimits::default();
        assert!(suggest_resources(&usage(None, None), &base).is_none());
    }
}
