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
//! `filesystem.reset = true`, and may remove specific paths with a
//! `filesystem.deny` list. Scalar settings from a later layer override earlier
//! ones.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::hooks::Hooks;
use crate::policy::{
    Access, DeviceRule, Egress, EgressRule, FsRule, NetworkPolicy, Policy, ResourceLimits,
};

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
    for path in discover(target, explicit) {
        layers.push(load_layer(&path)?);
    }
    merge(&layers)
}

/// List the config file paths that contribute to `target`, lowest precedence
/// first. Bundled profile bases are not included.
pub fn sources(target: &Path, explicit: Option<&Path>) -> Vec<PathBuf> {
    discover(target, explicit)
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
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHooks {
    #[serde(default)]
    pre_launch: Vec<String>,
    #[serde(default)]
    post_exit: Vec<String>,
    #[serde(default)]
    on_violation: Vec<String>,
}

#[derive(Default)]
struct Accumulator {
    filesystem: BTreeMap<PathBuf, Access>,
    egress: Option<Egress>,
    bind_ports: Vec<u16>,
    devices: BTreeMap<PathBuf, Access>,
    resources: ResourceLimits,
    hooks: Hooks,
}

fn discover(target: &Path, explicit: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(global) = global_config_path() {
        if global.is_file() {
            paths.push(global);
        }
    }

    let start = target_dir(target);
    let mut directory: Vec<PathBuf> = start
        .ancestors()
        .map(|dir| dir.join(CONFIG_NAME))
        .filter(|candidate| candidate.is_file())
        .collect();
    directory.reverse();
    paths.extend(directory);

    if let Some(explicit) = explicit {
        paths.push(absolute(explicit));
    }

    paths
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
    }
    for (path, access) in granted {
        *acc.filesystem.entry(path).or_insert(Access::empty()) |= access;
    }
    for raw in &fs.deny {
        acc.filesystem.remove(&resolve_path(raw, &layer.base));
    }

    if let Some(network) = &layer.raw.network {
        if network.egress.is_some() || !network.egress_allow.is_empty() {
            acc.egress = Some(build_egress(network));
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
    }

    if let Some(hooks) = &layer.raw.hooks {
        acc.hooks
            .pre_launch
            .extend(hooks.pre_launch.iter().cloned());
        acc.hooks.post_exit.extend(hooks.post_exit.iter().cloned());
        acc.hooks
            .on_violation
            .extend(hooks.on_violation.iter().cloned());
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
            network: NetworkPolicy {
                egress: acc.egress.unwrap_or(Egress::DenyAll),
                bind_ports: acc.bind_ports,
            },
            devices,
            resources: acc.resources,
        },
        hooks: acc.hooks,
    }
}

fn build_egress(network: &RawNetwork) -> Egress {
    if !network.egress_allow.is_empty() {
        Egress::Allow(
            network
                .egress_allow
                .iter()
                .map(|rule| EgressRule {
                    host: rule.host.clone(),
                    port: rule.port,
                })
                .collect(),
        )
    } else if network.egress.as_deref() == Some("allow") {
        Egress::AllowAll
    } else {
        Egress::DenyAll
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
    let expanded = expand_tilde(raw);
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

fn expand_tilde(raw: &str) -> PathBuf {
    if raw == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return Path::new(&home).join(rest);
        }
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
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(Path::new(&xdg).join("bailey").join("config.toml"));
        }
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
    fn size_parsing() {
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size("2GiB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1 MB").unwrap(), 1_000_000);
        assert!(parse_size("2Gigs").is_err());
    }
}
