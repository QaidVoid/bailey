//! Cascading configuration discovery, merge, and resolution.
//!
//! Configuration is expressed in TOML across three layers of increasing
//! precedence:
//!
//! 1. a global config (`$XDG_CONFIG_HOME/bailey/config.toml`),
//! 2. zero or more per-directory `bailey.toml` files discovered by walking
//!    upward from the target, outermost first, and
//! 3. an optional explicit per-invocation config.
//!
//! Layers merge deterministically into a single [`Resolved`] value holding a
//! [`Policy`] and its [`Hooks`]. Filesystem and device grants accumulate
//! additively; a layer may clear accumulated filesystem grants with
//! `filesystem.reset = true`. A `filesystem.deny` entry retracts a grant of the
//! same path and records a denial, so that a path nested beneath a surviving
//! grant is still refused. Scalar settings from a later layer override earlier
//! ones.
//!
//! A per-directory file contributes only once the user has trusted it, since it
//! may have arrived with the code being confined. See [`crate::trust`].

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::hooks::Hooks;
use crate::policy::{
    Access, DeviceRule, Egress, EgressRule, EnvPolicy, FsRule, NetworkPolicy, Policy,
    ResourceLimits,
};
use crate::trust::{Rejected, Store};

/// Filename of a per-directory config layer.
const CONFIG_NAME: &str = "bailey.toml";

/// An error from discovering, parsing, or resolving configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A config file could not be read.
    #[error("failed to read config `{path}`: {source}")]
    Read {
        /// Path that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A config file could not be parsed as TOML.
    #[error("failed to parse config `{path}`: {source}")]
    Parse {
        /// Path that failed to parse.
        path: PathBuf,
        /// Underlying parse error.
        #[source]
        source: toml::de::Error,
    },
    /// A config file contained an invalid value.
    #[error("invalid config `{path}`: {reason}")]
    Invalid {
        /// Path that contained the invalid value.
        path: PathBuf,
        /// Human-readable reason.
        reason: String,
    },
    /// A single layer both granted and denied the same path.
    #[error("conflicting directives in `{path}` for `{target}`: {reason}")]
    Conflict {
        /// Path of the offending layer.
        path: PathBuf,
        /// The resource the directives disagree on.
        target: String,
        /// Human-readable reason.
        reason: String,
    },
}

/// A resolved policy together with its lifecycle hooks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolved {
    /// The merged, deny-by-default policy.
    pub policy: Policy,
    /// The merged lifecycle hooks.
    pub hooks: Hooks,
}

/// Resolve the effective configuration for `target`.
///
/// `explicit` is an optional highest-precedence config path, typically supplied
/// on the command line. Missing config files are skipped; only files that exist
/// contribute to the result.
pub fn resolve(target: &Path, explicit: Option<&Path>) -> Result<Resolved, ConfigError> {
    resolve_with_bases(&[], target, explicit)
}

/// Resolve configuration with `bases` applied as the lowest-precedence layers.
///
/// Each base is a `(label, toml)` pair, typically a bundled profile. Bases are
/// applied in order beneath all discovered config, so user config always
/// overrides them. The label is used only in error messages.
pub fn resolve_with_bases(
    bases: &[(&str, &str)],
    target: &Path,
    explicit: Option<&Path>,
) -> Result<Resolved, ConfigError> {
    let base_dir = target_dir(target);
    let mut layers = Vec::new();
    for (label, text) in bases {
        layers.push(parse_layer(label, text, &base_dir)?);
    }
    for source in discover(target, explicit) {
        if !source.applies() {
            continue;
        }
        layers.push(load_layer(&source.path)?);
    }
    merge(&layers)
}

/// List the config layers that contribute to `target`, lowest precedence first.
/// Bundled profile bases are not included.
pub fn sources(target: &Path, explicit: Option<&Path>) -> Vec<Source> {
    discover(target, explicit)
}

/// Which discovery rule found a config layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The global config.
    Global,
    /// Found walking up from the target executable's directory.
    Target,
    /// Found walking up from the working directory.
    WorkingDir,
    /// Named on the command line.
    Explicit,
}

impl Origin {
    /// A short label for display.
    pub fn label(self) -> &'static str {
        match self {
            Origin::Global => "global",
            Origin::Target => "target",
            Origin::WorkingDir => "working dir",
            Origin::Explicit => "explicit",
        }
    }
}

/// A discovered config layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// Path of the config file.
    pub path: PathBuf,
    /// How it was found.
    pub origin: Origin,
    /// Why this layer does not contribute, when it does not. A file the user
    /// supplied is never rejected; one found by an upward walk is, until it has
    /// been trusted.
    pub rejected: Option<Rejected>,
}

impl Source {
    /// Whether this layer contributes to the resolved policy.
    pub fn applies(&self) -> bool {
        self.rejected.is_none()
    }
}

/// A parsed config layer paired with the directory its relative paths resolve
/// against.
struct Layer {
    path: PathBuf,
    base: PathBuf,
    raw: RawLayer,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLayer {
    #[serde(default)]
    filesystem: RawFs,
    network: Option<RawNetwork>,
    #[serde(default)]
    device: Vec<RawDevice>,
    resources: Option<RawResources>,
    hooks: Option<RawHooks>,
    env: Option<RawEnv>,
    home: Option<String>,
    /// Which targets a profile claims. Parsed only so that a profile carrying
    /// the key is still a valid config layer; the value is read by
    /// `profiles::for_target`, from the file rather than from here.
    #[serde(default)]
    #[allow(dead_code)]
    applies_to: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnv {
    #[serde(default)]
    reset: bool,
    #[serde(default)]
    pass: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
    #[serde(default)]
    set: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFs {
    #[serde(default)]
    reset: bool,
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    write: Vec<String>,
    #[serde(default)]
    execute: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
    #[serde(default)]
    read_only: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetwork {
    egress: Option<String>,
    #[serde(default)]
    egress_allow: Vec<RawEgressRule>,
    #[serde(default)]
    bind_ports: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEgressRule {
    host: String,
    port: Option<u16>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDevice {
    path: String,
    access: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResources {
    memory: Option<String>,
    pids_max: Option<u64>,
    cpu_percent: Option<u32>,
    tmp_size: Option<String>,
    shm_size: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHooks {
    #[serde(default)]
    pre_launch: Vec<String>,
    #[serde(default)]
    post_exit: Vec<String>,
    /// Accepted so an existing config gets an explanation rather than a parse
    /// error. The hook was removed because nothing could ever trigger it.
    #[serde(default)]
    on_violation: Vec<String>,
}

#[derive(Default)]
struct Accumulator {
    filesystem: BTreeMap<PathBuf, Access>,
    denied: BTreeSet<PathBuf>,
    read_only: BTreeSet<PathBuf>,
    egress: Option<Egress>,
    bind_ports: Vec<u16>,
    devices: BTreeMap<PathBuf, Access>,
    resources: ResourceLimits,
    hooks: Hooks,
    env: EnvPolicy,
    home: Option<PathBuf>,
}

/// Discover the config layers for `target`, lowest precedence first.
///
/// Per-directory files are collected by walking up from both the target's
/// directory and the working directory, because the target's directory alone is
/// useless when the target is an interpreter under a system path. The union is
/// ordered by path depth so that a more specific directory always wins, and a
/// file found by both walks contributes once.
///
/// A file found by a walk arrived with whatever is in that directory, so it
/// carries the trust decision the user made about it, and contributes nothing
/// until they have made one. The global config and an explicit `--config` are
/// the user's own, and need no record.
fn discover(target: &Path, explicit: Option<&Path>) -> Vec<Source> {
    let mut sources = Vec::new();

    if let Some(global) = global_config_path()
        && global.is_file()
    {
        sources.push(Source {
            path: global,
            origin: Origin::Global,
            rejected: None,
        });
    }

    let mut walked: Vec<(usize, u8, PathBuf, Origin)> = Vec::new();
    let mut chains = vec![(target_dir(target), Origin::Target)];
    if let Ok(cwd) = std::env::current_dir() {
        chains.push((cwd, Origin::WorkingDir));
    }
    for (start, origin) in chains {
        // Later chains win ties at equal depth.
        let tiebreak = u8::from(origin == Origin::WorkingDir);
        for dir in start.ancestors() {
            let candidate = dir.join(CONFIG_NAME);
            if candidate.is_file() {
                walked.push((dir.components().count(), tiebreak, candidate, origin));
            }
        }
    }
    walked.sort_by_key(|entry| (entry.0, entry.1));

    let mut seen = BTreeSet::new();
    let mut store = None;
    for (_, _, path, origin) in walked {
        if seen.insert(path.clone()) {
            let store = store.get_or_insert_with(Store::load);
            let rejected = store.check(&path);
            sources.push(Source {
                path,
                origin,
                rejected,
            });
        }
    }

    if let Some(explicit) = explicit {
        sources.push(Source {
            path: absolute(explicit),
            origin: Origin::Explicit,
            rejected: None,
        });
    }

    sources
}

fn merge(layers: &[Layer]) -> Result<Resolved, ConfigError> {
    let mut acc = Accumulator::default();
    for layer in layers {
        apply_layer(&mut acc, layer)?;
    }
    Ok(finalize(acc))
}

fn apply_layer(acc: &mut Accumulator, layer: &Layer) -> Result<(), ConfigError> {
    let fs = &layer.raw.filesystem;

    let grants = [
        (fs.read.as_slice(), Access::READ),
        (fs.write.as_slice(), Access::WRITE),
        (fs.execute.as_slice(), Access::EXECUTE),
    ];

    let mut granted: BTreeMap<PathBuf, Access> = BTreeMap::new();
    for (paths, access) in grants {
        for raw in paths {
            *granted
                .entry(resolve_path(raw, &layer.base))
                .or_insert(Access::empty()) |= access;
        }
    }

    for raw in &fs.deny {
        let path = resolve_path(raw, &layer.base);
        if granted.contains_key(&path) {
            return Err(ConfigError::Conflict {
                path: layer.path.clone(),
                target: path.display().to_string(),
                reason: "path is both granted and denied in the same layer".into(),
            });
        }
    }

    if fs.reset {
        acc.filesystem.clear();
        acc.denied.clear();
        acc.read_only.clear();
    }
    for (path, access) in granted {
        // A grant in this layer overrides a denial from a lower one.
        acc.denied.remove(&path);
        *acc.filesystem.entry(path).or_insert(Access::empty()) |= access;
    }
    for raw in &fs.deny {
        let path = resolve_path(raw, &layer.base);
        acc.filesystem.remove(&path);
        acc.denied.insert(path);
    }
    for raw in &fs.read_only {
        acc.read_only.insert(resolve_path(raw, &layer.base));
    }

    if let Some(network) = &layer.raw.network {
        if network.egress.is_some() || !network.egress_allow.is_empty() {
            acc.egress = Some(build_egress(network, &layer.path)?);
        }
        for port in &network.bind_ports {
            if !acc.bind_ports.contains(port) {
                acc.bind_ports.push(*port);
            }
        }
    }

    for device in &layer.raw.device {
        let access = parse_access(&device.access).map_err(|reason| ConfigError::Invalid {
            path: layer.path.clone(),
            reason,
        })?;
        *acc.devices
            .entry(resolve_path(&device.path, &layer.base))
            .or_insert(Access::empty()) |= access;
    }

    if let Some(resources) = &layer.raw.resources {
        if let Some(memory) = &resources.memory {
            acc.resources.memory_bytes =
                Some(parse_size(memory).map_err(|reason| ConfigError::Invalid {
                    path: layer.path.clone(),
                    reason,
                })?);
        }
        if let Some(pids) = resources.pids_max {
            acc.resources.pids_max = Some(pids);
        }
        if let Some(cpu) = resources.cpu_percent {
            acc.resources.cpu_percent = Some(cpu);
        }
        if let Some(size) = &resources.tmp_size {
            acc.resources.tmp_bytes = Some(size_value(size, &layer.path)?);
        }
        if let Some(size) = &resources.shm_size {
            acc.resources.shm_bytes = Some(size_value(size, &layer.path)?);
        }
    }

    if let Some(env) = &layer.raw.env {
        if env.reset {
            acc.env = EnvPolicy::default();
        }
        for name in &env.pass {
            if !acc.env.pass.contains(name) {
                acc.env.pass.push(name.clone());
            }
        }
        for (name, value) in &env.set {
            acc.env.set.insert(name.clone(), expand_value(value));
        }
        for name in &env.deny {
            acc.env.pass.retain(|passed| passed != name);
            acc.env.set.remove(name);
            if !acc.env.deny.contains(name) {
                acc.env.deny.push(name.clone());
            }
        }
    }

    if let Some(home) = &layer.raw.home {
        acc.home = Some(resolve_path(home, &layer.base));
    }

    if let Some(hooks) = &layer.raw.hooks {
        acc.hooks
            .pre_launch
            .extend(hooks.pre_launch.iter().cloned());
        acc.hooks.post_exit.extend(hooks.post_exit.iter().cloned());
        if !hooks.on_violation.is_empty() {
            eprintln!(
                "bailey: warning: `hooks.on_violation` in {} is ignored; it was \
                 removed because Landlock denies silently and no signal reaches \
                 bailey to trigger it. Use `bailey audit` to see what a program \
                 wanted.",
                layer.path.display()
            );
        }
    }

    Ok(())
}

fn finalize(acc: Accumulator) -> Resolved {
    let filesystem = acc
        .filesystem
        .into_iter()
        .map(|(path, access)| FsRule { path, access })
        .collect();
    let devices = acc
        .devices
        .into_iter()
        .map(|(path, access)| DeviceRule { path, access })
        .collect();

    Resolved {
        policy: Policy {
            filesystem,
            denied: acc.denied.into_iter().collect(),
            read_only: acc.read_only.into_iter().collect(),
            network: NetworkPolicy {
                egress: acc.egress.unwrap_or(Egress::DenyAll),
                bind_ports: acc.bind_ports,
            },
            devices,
            resources: acc.resources,
            env: acc.env,
            home: acc.home,
        },
        hooks: acc.hooks,
    }
}

/// Build the egress intent for a layer.
///
/// An `egress_allow` entry without a port is rejected rather than dropped: the
/// only mechanism available matches on TCP port, so silently ignoring the rule
/// would resolve "allow this destination" into a full deny.
fn build_egress(network: &RawNetwork, path: &Path) -> Result<Egress, ConfigError> {
    if !network.egress_allow.is_empty() {
        let mut rules = Vec::with_capacity(network.egress_allow.len());
        for rule in &network.egress_allow {
            let Some(port) = rule.port else {
                return Err(ConfigError::Invalid {
                    path: path.to_path_buf(),
                    reason: format!(
                        "egress_allow entry for host `{}` has no port; \
                         outbound rules are matched by TCP port, so a port is required",
                        rule.host
                    ),
                });
            };
            rules.push(EgressRule {
                host: rule.host.clone(),
                port: Some(port),
            });
        }
        Ok(Egress::Allow(rules))
    } else if network.egress.as_deref() == Some("allow") {
        Ok(Egress::AllowAll)
    } else {
        Ok(Egress::DenyAll)
    }
}

fn parse_layer(label: &str, text: &str, base: &Path) -> Result<Layer, ConfigError> {
    let path = PathBuf::from(label);
    let raw: RawLayer = toml::from_str(text).map_err(|source| ConfigError::Parse {
        path: path.clone(),
        source,
    })?;
    Ok(Layer {
        path,
        base: base.to_path_buf(),
        raw,
    })
}

fn load_layer(path: &Path) -> Result<Layer, ConfigError> {
    let path = absolute(path);
    let text = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
        path: path.clone(),
        source,
    })?;
    let raw: RawLayer = toml::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path.clone(),
        source,
    })?;
    let base = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));
    Ok(Layer { path, base, raw })
}

fn parse_access(spec: &str) -> Result<Access, String> {
    let mut access = Access::empty();
    for ch in spec.chars() {
        match ch {
            'r' => access |= Access::READ,
            'w' => access |= Access::WRITE,
            'x' => access |= Access::EXECUTE,
            other => return Err(format!("unknown access character `{other}` in `{spec}`")),
        }
    }
    if access.is_empty() {
        return Err(format!("empty access specifier `{spec}`"));
    }
    Ok(access)
}

fn size_value(spec: &str, path: &Path) -> Result<u64, ConfigError> {
    parse_size(spec).map_err(|reason| ConfigError::Invalid {
        path: path.to_path_buf(),
        reason,
    })
}

fn parse_size(spec: &str) -> Result<u64, String> {
    let spec = spec.trim();
    let split = spec
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(spec.len());
    let (number, suffix) = spec.split_at(split);
    let number: f64 = number
        .trim()
        .parse()
        .map_err(|_| format!("invalid size `{spec}`"))?;
    let multiplier: f64 = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1_000.0,
        "kib" => 1_024.0,
        "m" | "mb" => 1_000_000.0,
        "mib" => 1_048_576.0,
        "g" | "gb" => 1_000_000_000.0,
        "gib" => 1_073_741_824.0,
        "t" | "tb" => 1_000_000_000_000.0,
        "tib" => 1_099_511_627_776.0,
        other => return Err(format!("unknown size suffix `{other}` in `{spec}`")),
    };
    Ok((number * multiplier) as u64)
}

fn resolve_path(raw: &str, base: &Path) -> PathBuf {
    let raw = expand_variables(raw);
    let expanded = expand_tilde(&raw);
    let joined = if expanded.is_absolute() {
        expanded
    } else {
        base.join(expanded)
    };
    normalize_lexical(&joined)
}

/// Collapse `.` and `..` components without touching the filesystem, so that
/// equivalent spellings of a path resolve to the same key during merge.
fn normalize_lexical(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// Expand `${VAR}` references against the environment.
///
/// Paths such as the session runtime directory cannot be written literally in a
/// shared profile, because they contain the user's own id. An unset variable
/// expands to nothing, which leaves a path that matches nothing rather than one
/// that matches something unintended.
fn expand_variables(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let name = &after[..end];
        match std::env::var_os(name) {
            Some(value) => out.push_str(&value.to_string_lossy()),
            // `${PWD}` names the directory the run was launched from, which is
            // how a profile grants "wherever I am" without a file in every
            // project. The shell usually exports it; fall back to asking the
            // kernel so it works when something else invoked bailey.
            None if name == "PWD" => {
                if let Ok(cwd) = std::env::current_dir() {
                    out.push_str(&cwd.to_string_lossy());
                }
            }
            None => {}
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Expand a value written in config the way a path written in config is.
///
/// Most of what people set here is a path: `PATH`, `LD_LIBRARY_PATH`, a cache
/// directory. Writing `${HOME}/...` in one and having it arrive verbatim, while
/// the same text in `[filesystem]` resolves, is a trap: it looks right and
/// silently is not. A leading `~` is expanded too, though `${HOME}` is what
/// works for the later entries of a list like `PATH`.
fn expand_value(raw: &str) -> String {
    let expanded = expand_variables(raw);
    match expanded.strip_prefix("~/") {
        Some(rest) => match std::env::var_os("HOME") {
            Some(home) => format!("{}/{rest}", home.to_string_lossy()),
            None => expanded,
        },
        None => expanded,
    }
}

fn expand_tilde(raw: &str) -> PathBuf {
    if raw == "~"
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home);
    }
    if let Some(rest) = raw.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return Path::new(&home).join(rest);
    }
    PathBuf::from(raw)
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

fn target_dir(target: &Path) -> PathBuf {
    let target = absolute(target);
    target
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn global_config_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return Some(Path::new(&xdg).join("bailey").join("config.toml"));
    }
    std::env::var_os("HOME").map(|home| {
        Path::new(&home)
            .join(".config")
            .join("bailey")
            .join("config.toml")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(base: &str, toml_src: &str) -> Layer {
        Layer {
            path: PathBuf::from(base).join(CONFIG_NAME),
            base: PathBuf::from(base),
            raw: toml::from_str(toml_src).expect("valid test config"),
        }
    }

    #[test]
    fn additive_merge_across_layers() {
        let layers = [
            layer("/base", "[filesystem]\nread = [\"/a\"]"),
            layer("/base", "[filesystem]\nread = [\"/b\"]"),
        ];
        let resolved = merge(&layers).unwrap();
        let paths: Vec<_> = resolved
            .policy
            .filesystem
            .iter()
            .map(|rule| rule.path.clone())
            .collect();
        assert_eq!(paths, vec![PathBuf::from("/a"), PathBuf::from("/b")]);
    }

    #[test]
    fn later_layer_deny_removes_earlier_grant() {
        let layers = [
            layer("/base", "[filesystem]\nread = [\"/a\"]"),
            layer("/base", "[filesystem]\ndeny = [\"/a\"]"),
        ];
        let resolved = merge(&layers).unwrap();
        assert!(resolved.policy.filesystem.is_empty());
        assert_eq!(resolved.policy.denied, vec![PathBuf::from("/a")]);
    }

    #[test]
    fn nested_deny_survives_a_granted_parent() {
        let layers = [
            layer("/base", "[filesystem]\nread = [\"/a\"]"),
            layer("/base", "[filesystem]\ndeny = [\"/a/secret\"]"),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.filesystem.len(), 1);
        assert_eq!(resolved.policy.filesystem[0].path, PathBuf::from("/a"));
        assert_eq!(resolved.policy.denied, vec![PathBuf::from("/a/secret")]);
    }

    #[test]
    fn later_grant_overrides_an_earlier_denial() {
        let layers = [
            layer("/base", "[filesystem]\ndeny = [\"/a\"]"),
            layer("/base", "[filesystem]\nread = [\"/a\"]"),
        ];
        let resolved = merge(&layers).unwrap();
        assert!(resolved.policy.denied.is_empty());
        assert_eq!(resolved.policy.filesystem[0].path, PathBuf::from("/a"));
    }

    #[test]
    fn reset_clears_denials_too() {
        let layers = [
            layer("/base", "[filesystem]\ndeny = [\"/a/secret\"]"),
            layer("/base", "[filesystem]\nreset = true\nread = [\"/a\"]"),
        ];
        let resolved = merge(&layers).unwrap();
        assert!(resolved.policy.denied.is_empty());
    }

    #[test]
    fn reset_clears_prior_grants() {
        let layers = [
            layer("/base", "[filesystem]\nread = [\"/a\"]"),
            layer("/base", "[filesystem]\nreset = true\nread = [\"/b\"]"),
        ];
        let resolved = merge(&layers).unwrap();
        let paths: Vec<_> = resolved
            .policy
            .filesystem
            .iter()
            .map(|rule| rule.path.clone())
            .collect();
        assert_eq!(paths, vec![PathBuf::from("/b")]);
    }

    #[test]
    fn same_layer_grant_and_deny_conflicts() {
        let layers = [layer(
            "/base",
            "[filesystem]\nread = [\"/a\"]\ndeny = [\"/a\"]",
        )];
        assert!(matches!(merge(&layers), Err(ConfigError::Conflict { .. })));
    }

    #[test]
    fn combined_access_flags_merge() {
        let layers = [
            layer("/base", "[filesystem]\nread = [\"/a\"]"),
            layer("/base", "[filesystem]\nwrite = [\"/a\"]"),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.filesystem.len(), 1);
        assert_eq!(
            resolved.policy.filesystem[0].access,
            Access::READ | Access::WRITE
        );
    }

    #[test]
    fn relative_paths_resolve_against_layer_base() {
        let layers = [layer("/base", "[filesystem]\nread = [\"assets\"]")];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved.policy.filesystem[0].path,
            PathBuf::from("/base/assets")
        );
    }

    #[test]
    fn egress_override_and_bind_ports_accumulate() {
        let layers = [
            layer("/base", "[network]\negress = \"deny\"\nbind_ports = [1]"),
            layer("/base", "[network]\negress = \"allow\"\nbind_ports = [2]"),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.network.egress, Egress::AllowAll);
        assert_eq!(resolved.policy.network.bind_ports, vec![1, 2]);
    }

    #[test]
    fn portless_egress_rule_is_rejected() {
        let layers = [layer(
            "/base",
            "[network]\negress_allow = [{ host = \"example.com\" }]",
        )];
        let err = merge(&layers).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }));
        assert!(err.to_string().contains("example.com"));
    }

    #[test]
    fn egress_rule_with_port_resolves() {
        let layers = [layer(
            "/base",
            "[network]\negress_allow = [{ host = \"*\", port = 443 }]",
        )];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved.policy.network.egress,
            Egress::Allow(vec![EgressRule {
                host: "*".into(),
                port: Some(443),
            }])
        );
    }

    #[test]
    fn variables_expand_in_paths() {
        unsafe { std::env::set_var("BAILEY_TEST_DIR", "/run/user/4242") };
        let layers = [layer(
            "/base",
            "[filesystem]\nread = [\"${BAILEY_TEST_DIR}/wayland-0\"]",
        )];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved.policy.filesystem[0].path,
            PathBuf::from("/run/user/4242/wayland-0")
        );
    }

    #[test]
    fn pwd_expands_to_the_invocation_directory() {
        // A profile grants "wherever I am" with ${PWD}, which is what lets a
        // per-program policy work without a config file in every project.
        unsafe { std::env::remove_var("PWD") };
        let layers = [layer("/base", "[filesystem]\nread = [\"${PWD}\"]")];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved.policy.filesystem[0].path,
            std::env::current_dir().unwrap()
        );
    }

    #[test]
    fn a_read_only_path_is_carried_into_the_policy() {
        let layers = [layer(
            "/base",
            "[filesystem]\nwrite = [\"/work\"]\nread_only = [\"/work/keep\"]",
        )];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.read_only, vec![PathBuf::from("/work/keep")]);
        assert_eq!(resolved.policy.nested_read_only().count(), 1);
    }

    #[test]
    fn an_unset_variable_expands_to_nothing() {
        let layers = [layer(
            "/base",
            "[filesystem]\nread = [\"${BAILEY_TEST_UNSET}/thing\"]",
        )];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.filesystem[0].path, PathBuf::from("/thing"));
    }

    #[test]
    fn env_values_expand_like_paths_do() {
        unsafe { std::env::set_var("BAILEY_TEST_BIN", "/opt/toolchain/bin") };
        let layers = [layer(
            "/base",
            "[env]\nset = { PATH = \"${BAILEY_TEST_BIN}:/usr/bin\", PLAIN = \"literal\" }",
        )];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved.policy.env.set.get("PATH").map(String::as_str),
            Some("/opt/toolchain/bin:/usr/bin"),
            "a path written in env is a path"
        );
        assert_eq!(
            resolved.policy.env.set.get("PLAIN").map(String::as_str),
            Some("literal"),
            "and a value with nothing to expand is left alone"
        );
    }

    #[test]
    fn size_parsing() {
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size("2GiB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1 MB").unwrap(), 1_000_000);
        assert!(parse_size("2Gigs").is_err());
    }
}
