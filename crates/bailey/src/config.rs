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
    Access, DeviceRule, Egress, EgressRule, EnvPolicy, FsRule, FuseMount, NetworkPolicy, Policy,
    PortForward, ResourceLimits, SocketRelay,
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
    resolve_with_bases(&[], target, explicit, &[])
}

/// Resolve configuration with `bases` applied as the lowest-precedence layers.
///
/// Each base is a `(label, toml)` pair, typically a bundled profile. Bases are
/// applied in order beneath all discovered config, so user config always
/// overrides them. The label is used only in error messages.
///
/// `overrides` are `(label, toml)` pairs applied above everything, discovered
/// config included. They carry what a caller asked for on the command line,
/// which stands above every file for the same reason `explicit` is never
/// trust-gated: the user typed it, at the moment they typed it.
pub fn resolve_with_bases(
    bases: &[(&str, &str)],
    target: &Path,
    explicit: Option<&Path>,
    overrides: &[(&str, &str)],
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
        layers.push(load_verified_layer(&source)?);
    }
    for (label, text) in overrides {
        layers.push(parse_layer(label, text, &base_dir)?);
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
    /// The bytes the trust decision was made against, when the layer
    /// contributes. Applied rather than read again, so the policy is built from
    /// what was verified.
    verified: Option<Vec<u8>>,
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
    #[serde(default)]
    fuse: Vec<RawFuse>,
    /// The self-serve FUSE switch. A top-level key, since [[fuse]] owns the
    /// table name for its entries.
    #[serde(default)]
    self_fuse: Option<bool>,
    #[serde(default)]
    socket: Vec<RawSocket>,
    #[serde(default)]
    forward: Vec<RawForward>,
    /// Which targets a profile claims. Parsed only so that a profile carrying
    /// the key is still a valid config layer; the value is read by
    /// `profiles::for_target`, from the file rather than from here.
    #[serde(default)]
    #[allow(dead_code)]
    applies_to: Vec<String>,
}

/// One FUSE mount bailey performs itself, placed at `at` for the target.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFuse {
    /// Shell command that performs the mount, run as the caller with
    /// `BAILEY_MOUNTPOINT` naming the host directory to mount onto.
    mount: String,
    /// Where the mount appears to the target.
    at: String,
}

/// One desktop service socket relayed into the sandbox.
///
/// Either a named `service` or an explicit `host` and `at`, never both: a
/// service's paths are chosen by bailey, and a custom socket's are chosen by
/// the config.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSocket {
    /// A named service: `wayland`, `x11`, `pulse`, or `dbus`.
    service: Option<String>,
    /// The host socket to relay, when naming a custom one.
    host: Option<String>,
    /// Where the target sees it, when naming a custom one. Defaults to the
    /// host path, since a custom socket usually keeps its own name.
    at: Option<String>,
}

/// One host TCP port the target may reach on loopback.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawForward {
    /// The port the target dials inside the sandbox.
    port: u16,
    /// The host port the connection lands on. Defaults to `port`.
    host_port: Option<u16>,
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

/// One entry in a grant list.
///
/// Written as a plain path, or as a table naming where the path should appear
/// to the target: `{ path = "/srv/project", at = "/workspace" }`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RawGrant {
    Path(String),
    Relocated { path: String, at: String },
}

impl RawGrant {
    fn path(&self) -> &str {
        match self {
            RawGrant::Path(path) => path,
            RawGrant::Relocated { path, .. } => path,
        }
    }

    fn at(&self) -> Option<&str> {
        match self {
            RawGrant::Path(_) => None,
            RawGrant::Relocated { at, .. } => Some(at),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFs {
    #[serde(default)]
    reset: bool,
    #[serde(default)]
    read: Vec<RawGrant>,
    #[serde(default)]
    write: Vec<RawGrant>,
    #[serde(default)]
    execute: Vec<RawGrant>,
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
    file_max: Option<String>,
    tmp_size: Option<String>,
    shm_size: Option<String>,
    tmp_dir: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHooks {
    /// Retracts every hook a lower layer contributed, before this layer's
    /// own are added.
    #[serde(default)]
    reset: bool,
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
    /// Where a granted path appears to the target, for the few that are moved.
    relocated: BTreeMap<PathBuf, PathBuf>,
    denied: BTreeSet<PathBuf>,
    read_only: BTreeSet<PathBuf>,
    /// The egress allowance, with the path of the layer that set it, for the
    /// same reason as `self_fuse` above.
    egress: Option<(Egress, PathBuf)>,
    bind_ports: Vec<u16>,
    devices: BTreeMap<PathBuf, Access>,
    resources: ResourceLimits,
    hooks: Hooks,
    env: EnvPolicy,
    home: Option<PathBuf>,
    fuse: Vec<FuseMount>,
    /// The self-serve FUSE switch, with the path of the layer that set it,
    /// so a conflicting policy can name where the switch came from.
    self_fuse: Option<(bool, PathBuf)>,
    sockets: Vec<SocketRelay>,
    forwards: Vec<PortForward>,
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

    // Inside a sandbox, HOME is the private home the confined target writes
    // to, so a config found there was planted by the thing being confined.
    // Its hooks would run here, as the caller, before any confinement exists.
    // The trust store makes the same refusal.
    let global = if crate::backend::world::inside_sandbox() {
        None
    } else {
        global_config_path().filter(|global| global.is_file())
    };
    if let Some(global) = global {
        // No trust record is needed for a file in your own config directory,
        // but that argument is about who wrote it, and says nothing about who
        // can write it now. The exposure check refuses one the caller does
        // not own, or that anyone else can write.
        let rejected = crate::trust::exposure_of(&global);
        sources.push(Source {
            path: global,
            origin: Origin::Global,
            rejected,
            verified: None,
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
            let (rejected, verified) = store.check_read(&path);
            let verified = rejected.is_none().then_some(verified);
            sources.push(Source {
                path,
                origin,
                rejected,
                verified,
            });
        }
    }

    if let Some(explicit) = explicit {
        sources.push(Source {
            path: absolute(explicit),
            origin: Origin::Explicit,
            rejected: None,
            verified: None,
        });
    }

    sources
}

fn merge(layers: &[Layer]) -> Result<Resolved, ConfigError> {
    let mut acc = Accumulator::default();
    for layer in layers {
        apply_layer(&mut acc, layer)?;
    }
    finalize(acc)
}

fn apply_layer(acc: &mut Accumulator, layer: &Layer) -> Result<(), ConfigError> {
    let fs = &layer.raw.filesystem;

    let grants = [
        (fs.read.as_slice(), Access::READ),
        (fs.write.as_slice(), Access::WRITE),
        (fs.execute.as_slice(), Access::EXECUTE),
    ];

    let mut granted: BTreeMap<PathBuf, Access> = BTreeMap::new();
    let mut relocated: BTreeMap<PathBuf, PathBuf> = BTreeMap::new();
    for (paths, access) in grants {
        for raw in paths {
            let Some(path) = resolve_path(raw.path(), &layer.base) else {
                continue;
            };
            if let Some(raw_at) = raw.at() {
                let Some(at) = resolve_path(raw_at, &layer.base) else {
                    return Err(ConfigError::Invalid {
                        path: layer.path.clone(),
                        reason: format!("at must be an absolute path, got {raw_at}"),
                    });
                };
                // Two hierarchies at one location would leave whichever is
                // mounted second covering the first, granting access to a path
                // the target cannot reach.
                if let Some(existing) = relocated.get(&at)
                    && existing != &path
                {
                    return Err(ConfigError::Conflict {
                        path: layer.path.clone(),
                        target: at.display().to_string(),
                        reason: "two different paths are placed at the same location".into(),
                    });
                }
                relocated.insert(at, path.clone());
            }
            *granted.entry(path).or_insert(Access::empty()) |= access;
        }
    }
    for raw in &fs.deny {
        let Some(path) = resolve_path(raw, &layer.base) else {
            continue;
        };
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
        // Relocations are applied to every rule with a matching path when the
        // policy is finalized, so one left behind would place a later plain
        // grant at an `at` the resetting layer never mentions.
        acc.relocated.clear();
        // Devices are grants like any other, carried in their own list only
        // because they name nodes rather than trees. A profile that means to
        // be the whole of what a run can reach is not, if a lower profile's
        // device nodes come along with it.
        acc.devices.clear();
        // FUSE mounts run commands as the caller, so one left behind from a
        // lower layer is exactly the kind of inheritance a reset exists to
        // refuse.
        acc.fuse.clear();
        // Same standing: a socket relay is a promise to carry a host service
        // in, and one inherited from below would do it silently.
        acc.sockets.clear();
        // A port forward is the same kind of promise, made about a TCP port.
        acc.forwards.clear();
    }
    // After the reset, with this layer's grants: a layer that resets and
    // relocates in one breath means to keep its own placement, and clearing
    // after inserting would drop the relocation it just declared.
    for (at, source) in relocated {
        acc.relocated.insert(source, at);
    }
    for (path, access) in granted {
        // A grant in this layer overrides a denial from a lower one.
        acc.denied.remove(&path);
        *acc.filesystem.entry(path).or_insert(Access::empty()) |= access;
    }
    for raw in &fs.deny {
        let Some(path) = resolve_path(raw, &layer.base) else {
            continue;
        };
        acc.filesystem.remove(&path);
        acc.denied.insert(path);
    }
    for raw in &fs.read_only {
        if let Some(path) = resolve_path(raw, &layer.base) {
            acc.read_only.insert(path);
        }
    }

    if let Some(network) = &layer.raw.network {
        if network.egress.is_some() || !network.egress_allow.is_empty() {
            acc.egress = Some((build_egress(network, &layer.path)?, layer.path.clone()));
        }
        for port in &network.bind_ports {
            if !acc.bind_ports.contains(port) {
                acc.bind_ports.push(*port);
            }
        }
    }

    if let Some(self_fuse) = layer.raw.self_fuse {
        acc.self_fuse = Some((self_fuse, layer.path.clone()));
    }

    for device in &layer.raw.device {
        let access = parse_access(&device.access).map_err(|reason| ConfigError::Invalid {
            path: layer.path.clone(),
            reason,
        })?;
        let Some(path) = resolve_path(&device.path, &layer.base) else {
            continue;
        };
        *acc.devices.entry(path).or_insert(Access::empty()) |= access;
    }

    for fuse in &layer.raw.fuse {
        let Some(at) = resolve_path(&fuse.at, &layer.base) else {
            return Err(ConfigError::Invalid {
                path: layer.path.clone(),
                reason: format!("fuse mount at `{}` resolves to nothing", fuse.at),
            });
        };
        acc.fuse.push(FuseMount {
            command: fuse.mount.clone(),
            at,
        });
    }

    for socket in &layer.raw.socket {
        acc.sockets
            .push(build_socket(socket, &layer.path, &layer.base)?);
    }

    let mut forward_ports = std::collections::BTreeSet::new();
    for forward in &layer.raw.forward {
        if forward.port == 0 {
            return Err(ConfigError::Invalid {
                path: layer.path.clone(),
                reason: "a forward on port 0 would mean any port, so a real \
                         port is required"
                    .into(),
            });
        }
        if !forward_ports.insert(forward.port) {
            return Err(ConfigError::Conflict {
                path: layer.path.clone(),
                target: forward.port.to_string(),
                reason: "two forwards for the same port in one layer".into(),
            });
        }
        acc.forwards.push(PortForward {
            port: forward.port,
            host_port: forward.host_port.unwrap_or(forward.port),
        });
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
        if let Some(size) = &resources.file_max {
            acc.resources.file_bytes = Some(size_value(size, &layer.path)?);
        }
        if let Some(size) = &resources.tmp_size {
            acc.resources.tmp_bytes = Some(size_value(size, &layer.path)?);
        }
        if let Some(size) = &resources.shm_size {
            acc.resources.shm_bytes = Some(size_value(size, &layer.path)?);
        }
        if let Some(dir) = &resources.tmp_dir {
            acc.resources.tmp_dir = Some(std::path::PathBuf::from(dir));
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

    if let Some(home) = &layer.raw.home
        && let Some(path) = resolve_path(home, &layer.base)
    {
        acc.home = Some(path);
    }

    if let Some(hooks) = &layer.raw.hooks {
        if hooks.reset {
            // Hooks run as the caller before the target is confined, so a
            // layer that means to start clean has to be able to retract what
            // a lower layer left, not only add to it.
            acc.hooks = Hooks::default();
        }
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

/// Build one socket relay from a config entry.
///
/// A named `service` gets bailey's paths for it, taken from the session the
/// run is launched from. An explicit entry names both ends itself, and the
/// two spellings are refused together: a service's paths are bailey's to
/// know, and a custom socket's are the config's.
fn build_socket(raw: &RawSocket, path: &Path, base: &Path) -> Result<SocketRelay, ConfigError> {
    if let Some(service) = &raw.service {
        if raw.host.is_some() || raw.at.is_some() {
            return Err(ConfigError::Invalid {
                path: path.to_path_buf(),
                reason: format!(
                    "socket service `{service}` chooses its own paths; name \
                     either a service or a host and at, not both"
                ),
            });
        }
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".runtime")));
        let invalid = |reason: String| ConfigError::Invalid {
            path: path.to_path_buf(),
            reason,
        };
        return match service.as_str() {
            "wayland" => {
                let dir = runtime.ok_or_else(|| {
                    invalid("service `wayland` needs XDG_RUNTIME_DIR, which is not set".into())
                })?;
                Ok(SocketRelay {
                    host: dir.join("wayland-0"),
                    at: dir.join("wayland-0"),
                    service: Some(service.clone()),
                })
            }
            "pulse" => {
                let dir = runtime.ok_or_else(|| {
                    invalid("service `pulse` needs XDG_RUNTIME_DIR, which is not set".into())
                })?;
                Ok(SocketRelay {
                    host: dir.join("pulse").join("native"),
                    at: dir.join("pulse").join("native"),
                    service: Some(service.clone()),
                })
            }
            "dbus" => {
                let dir = runtime.ok_or_else(|| {
                    invalid("service `dbus` needs XDG_RUNTIME_DIR, which is not set".into())
                })?;
                Ok(SocketRelay {
                    host: dir.join("bus"),
                    at: dir.join("bus"),
                    service: Some(service.clone()),
                })
            }
            "x11" => {
                // The display number is the socket's name: `:1` means X1.
                let number = std::env::var("DISPLAY")
                    .ok()
                    .and_then(|display| {
                        display
                            .split(':')
                            .next_back()
                            .and_then(|rest| rest.split('.').next().map(str::to_owned))
                    })
                    .unwrap_or_else(|| "0".into());
                let valid = !number.is_empty() && number.chars().all(|ch| ch.is_ascii_digit());
                if !valid {
                    return Err(invalid(format!(
                        "service `x11` could not read a display number from \
                         DISPLAY `{}`",
                        std::env::var("DISPLAY").unwrap_or_default()
                    )));
                }
                let socket = PathBuf::from(format!("/tmp/.X11-unix/X{number}"));
                Ok(SocketRelay {
                    at: socket.clone(),
                    host: socket.clone(),
                    service: Some(service.clone()),
                })
            }
            "url-open" => {
                let dir = runtime.ok_or_else(|| {
                    invalid("service `url-open` needs XDG_RUNTIME_DIR, which is not set".into())
                })?;
                // The socket is bailey's own: the host side of this relay is
                // the broker, not another program, so the host path is the
                // same path and never used.
                let at = dir.join("url-open");
                Ok(SocketRelay {
                    host: at.clone(),
                    at,
                    service: Some(service.clone()),
                })
            }
            other => Err(invalid(format!(
                "unknown socket service `{other}`; the known ones are wayland, \
                 x11, pulse, dbus, and url-open"
            ))),
        };
    }
    let Some(host) = &raw.host else {
        return Err(ConfigError::Invalid {
            path: path.to_path_buf(),
            reason: "a [[socket]] entry needs either a `service` or a `host`".into(),
        });
    };
    let Some(host) = resolve_path(host, base) else {
        return Err(ConfigError::Invalid {
            path: path.to_path_buf(),
            reason: format!("socket host `{host}` resolves to nothing"),
        });
    };
    let at = match &raw.at {
        Some(at) => resolve_path(at, base).ok_or_else(|| ConfigError::Invalid {
            path: path.to_path_buf(),
            reason: format!("socket at `{at}` resolves to nothing"),
        })?,
        None => host.clone(),
    };
    Ok(SocketRelay {
        host,
        at,
        service: None,
    })
}

fn finalize(mut acc: Accumulator) -> Result<Resolved, ConfigError> {
    // Self-serve FUSE hands the target mount power over the run's whole
    // namespace, and two guarantees are enforced by mounts the target could
    // then take down: a read-only island is a read-only bind the target could
    // remount writable, and a denial beneath a grant is an empty mount
    // covering the path, which the parent grant would expose. Refuse the
    // combination rather than promise less than the policy says.
    if let Some((true, source)) = &acc.self_fuse {
        let island = acc.read_only.first();
        let conceal = acc.denied.iter().find(|denied| {
            acc.filesystem
                .keys()
                .any(|granted| denied.starts_with(granted) && denied.as_path() != granted)
        });
        if let Some(path) = island.or(conceal) {
            let kind = if island.is_some() {
                "a read-only island"
            } else {
                "a denial beneath a grant"
            };
            let why = if island.is_some() {
                "remount writable"
            } else {
                "unmount"
            };
            return Err(ConfigError::Conflict {
                path: source.clone(),
                target: "self_fuse".into(),
                reason: format!(
                    "`{}` is {kind}, enforced by a mount the target could \
                     {why} with the power self_fuse hands it. Clear \
                     `self_fuse`, or drop {kind} from the policy",
                    path.display()
                ),
            });
        }
        // The egress port rules are Landlock rules, and Landlock is the half of
        // confinement this switch gives up: the ruleset that would carry them
        // is built and then not applied, so an allowance would promise a
        // restriction nothing in the run makes. A denial is not in that
        // position, because it is held by the run's own network namespace.
        if let Some((Egress::Allow(_), egress_source)) = &acc.egress {
            return Err(ConfigError::Conflict {
                path: source.clone(),
                target: "self_fuse".into(),
                reason: format!(
                    "`{}` is a partial egress allowance, enforced only by the \
                     Landlock ruleset that self_fuse drops. Clear `self_fuse`, \
                     or drop the egress allowance",
                    egress_source.display()
                ),
            });
        }
        // A FUSE mount needs the device node, and a switch that promises
        // full use should not also demand the boilerplate.
        acc.devices
            .entry(PathBuf::from("/dev/fuse"))
            .or_insert(Access::READ | Access::WRITE);
    }

    let relocated = acc.relocated;
    let filesystem = acc
        .filesystem
        .into_iter()
        .map(|(path, access)| {
            let at = relocated.get(&path).cloned();
            FsRule { path, access, at }
        })
        .collect();
    let devices = acc
        .devices
        .into_iter()
        .map(|(path, access)| DeviceRule { path, access })
        .collect();

    Ok(Resolved {
        policy: Policy {
            filesystem,
            denied: acc.denied.into_iter().collect(),
            read_only: acc.read_only.into_iter().collect(),
            network: NetworkPolicy {
                egress: acc
                    .egress
                    .map(|(egress, _)| egress)
                    .unwrap_or(Egress::DenyAll),
                bind_ports: acc.bind_ports,
            },
            devices,
            resources: acc.resources,
            env: acc.env,
            home: acc.home,
            self_fuse: matches!(acc.self_fuse, Some((true, _))),
            fuse: acc.fuse,
            sockets: acc.sockets,
            forwards: acc.forwards,
        },
        hooks: acc.hooks,
    })
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

/// Parse a discovered layer from the bytes its trust decision was made against.
///
/// A file the user supplied on the command line was never trust-checked, so it
/// has no verified bytes and is read here instead.
fn load_verified_layer(source: &Source) -> Result<Layer, ConfigError> {
    match &source.verified {
        Some(bytes) => parse_layer_bytes(&source.path, bytes),
        None => load_layer(&source.path),
    }
}

/// Parse `text` as a layer attributed to `path`.
fn parse_layer_bytes(path: &Path, text: &[u8]) -> Result<Layer, ConfigError> {
    let text = String::from_utf8_lossy(text);
    let raw: RawLayer = toml::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    let base = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));
    Ok(Layer {
        path: path.to_path_buf(),
        base,
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
    // A negative or infinite size casts to a wrapped value rather than
    // failing, and the strictest possible limit is what a typo would produce:
    // `memory = "-1"` would mean every allocation fails, which reads as a bug
    // in the program rather than in the policy.
    if !number.is_finite() || number.is_sign_negative() {
        return Err(format!("size `{spec}` must be zero or more"));
    }
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
    let bytes = number * multiplier;
    if bytes > u64::MAX as f64 {
        return Err(format!("size `{spec}` is larger than this can express"));
    }
    Ok(bytes as u64)
}

fn resolve_path(raw: &str, base: &Path) -> Option<PathBuf> {
    let raw = expand_variables(raw);
    if raw.trim().is_empty() {
        return None;
    }
    let expanded = expand_tilde(&raw);
    let joined = if expanded.is_absolute() {
        expanded
    } else {
        base.join(expanded)
    };
    Some(normalize_lexical(&joined))
}

/// Resolve a path written in a quick-grant command-line flag the way a path
/// written in config is: `${VAR}` and a leading `~` expand, then the result is
/// made absolute against the working directory and lexically normalized.
///
/// Unlike a grant in a config file, an unset variable is an error rather than a
/// grant that quietly matches nothing. A flag names exactly one path, and one
/// dropped in expansion would leave the run narrower than the command line
/// says, which is the kind of silence this tool exists to refuse.
pub fn expand_flag_path(raw: &str) -> Result<PathBuf, String> {
    let (expanded, had_unset) = expand_variables_tracked(raw);
    if expanded.trim().is_empty() {
        return Err(format!(
            "`{raw}` expands to nothing, and an unset ${{VAR}} in a quick grant is an error"
        ));
    }
    if had_unset {
        return Err(format!(
            "`{raw}` names a variable that is not set, and a quick grant must name a real path"
        ));
    }
    let expanded = expand_tilde(&expanded);
    let joined = if expanded.is_absolute() {
        expanded
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(expanded),
            Err(_) => expanded,
        }
    };
    Ok(normalize_lexical(&joined))
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
    expand_variables_tracked(raw).0
}

/// The same expansion, reporting whether any named variable was unset.
///
/// A config grant that matches nothing is a documented silence; a flag grant
/// that silently names a different path is a lie on the command line, so
/// [`expand_flag_path`] refuses where this would drop.
fn expand_variables_tracked(raw: &str) -> (String, bool) {
    let mut out = String::with_capacity(raw.len());
    let mut had_unset = false;
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[start..]);
            return (out, had_unset);
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
            None => had_unset = true,
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    (out, had_unset)
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

    /// `host_port` defaults to the sandbox port, which is what nearly every
    /// local daemon case wants: the target dials the port it knows.
    #[test]
    fn a_forward_defaults_to_the_same_port_on_the_host() {
        let layers = [layer("/base", "[[forward]]\nport = 9876")];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved.policy.forwards,
            vec![PortForward {
                port: 9876,
                host_port: 9876
            }]
        );
    }

    #[test]
    fn a_forward_may_land_on_a_different_host_port() {
        let layers = [layer(
            "/base",
            "[[forward]]\nport = 5432\nhost_port = 15432",
        )];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.forwards[0].host_port, 15432);
    }

    /// Port 0 would bind an arbitrary port, which the target cannot dial by
    /// number, so the forward could never be used as written.
    #[test]
    fn a_forward_on_port_zero_is_refused() {
        let layers = [layer("/base", "[[forward]]\nport = 0")];
        assert!(merge(&layers).is_err());
    }

    #[test]
    fn two_forwards_on_one_port_in_a_layer_are_refused() {
        let layers = [layer(
            "/base",
            "[[forward]]\nport = 8080\nhost_port = 80\n[[forward]]\nport = 8080\nhost_port = 81",
        )];
        assert!(merge(&layers).is_err());
    }

    #[test]
    fn a_reset_clears_forwards() {
        // The filesystem reset is the layer-level one: fuse mounts, socket
        // relays and forwards all clear with it, since inheriting any of them
        // from below would carry a promise the profile never made.
        let layers = [
            layer("/base", "[[forward]]\nport = 9876"),
            layer(
                "/base",
                "[filesystem]\nreset = true\n[[forward]]\nport = 6379",
            ),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved
                .policy
                .forwards
                .iter()
                .map(|f| f.port)
                .collect::<Vec<_>>(),
            vec![6379]
        );
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
    fn a_tmp_dir_backs_tmp_with_disk_instead_of_a_tmpfs() {
        let layers = [layer(
            "/base",
            "[resources]\ntmp_dir = \"/scratch/tmp\"\ntmp_size = \"512m\"",
        )];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved.policy.resources.tmp_dir,
            Some(PathBuf::from("/scratch/tmp"))
        );
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

    /// A layer that resets and relocates in one breath keeps its own
    /// placement. Clearing after inserting dropped it, which left a relocated
    /// grant applied at its host path: the target then had no `/workspace` and
    /// no `/state` at all.
    #[test]
    fn a_reset_keeps_the_resetting_layer_s_own_relocation() {
        let layers = [
            layer("/base", "[filesystem]\nwrite = [\"/lower\"]"),
            layer(
                "/base",
                "[filesystem]\nreset = true\nwrite = [{ path = \"/a\", at = \"/workspace\" }]",
            ),
        ];
        let resolved = merge(&layers).unwrap();
        let rule = resolved
            .policy
            .filesystem
            .iter()
            .find(|rule| rule.path == Path::new("/a"))
            .expect("the relocated grant survives its own reset");
        assert_eq!(rule.at, Some(PathBuf::from("/workspace")));
    }

    #[test]
    fn a_reset_clears_relocations_too() {
        // `path` is the host path and `at` is where the target sees it, so a
        // relocation surviving a reset places a later plain grant somewhere
        // the resetting layer never named.
        let layers = [
            layer(
                "/base",
                "[filesystem]\nwrite = [{ path = \"/a\", at = \"/x\" }]",
            ),
            layer("/base", "[filesystem]\nreset = true\nwrite = [\"/a\"]"),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.filesystem[0].at, None);
    }

    #[test]
    fn a_negative_or_unrepresentable_size_is_refused() {
        // These reached the run as the strictest possible limit, which reads
        // as a broken program rather than a broken policy.
        assert!(parse_size("-1").is_err());
        assert!(parse_size("-5m").is_err());
        assert!(parse_size("1e30").is_err());
        assert!(parse_size("-0.5g").is_err());

        assert_eq!(parse_size("0"), Ok(0));
        assert_eq!(parse_size("4g"), Ok(4_000_000_000));
        assert_eq!(parse_size("1kib"), Ok(1_024));
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

    /// Devices are grants carried in a list of their own, so a reset that
    /// left them would hand every device a profile named to a layer that
    /// meant to start from nothing.
    #[test]
    fn a_reset_clears_device_grants_too() {
        let layers = [
            layer(
                "/base",
                "[filesystem]\nread = [\"/a\"]\n[[device]]\npath = \"/dev/tty\"\naccess = \"rw\"",
            ),
            layer("/base", "[filesystem]\nreset = true\nread = [\"/a\"]"),
        ];
        let resolved = merge(&layers).unwrap();
        assert!(resolved.policy.devices.is_empty());
    }

    /// Hooks run as the caller before the target is confined, so a layer
    /// that means to start clean has to be able to retract what a lower
    /// layer left rather than only add to it.
    #[test]
    fn a_hook_reset_retracts_lower_layers_hooks() {
        let layers = [
            layer(
                "/base",
                "[hooks]\npre_launch = [\"lower\"]\npost_exit = [\"lower-exit\"]",
            ),
            layer("/base", "[hooks]\nreset = true\npre_launch = [\"upper\"]"),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.hooks.pre_launch, vec!["upper".to_owned()]);
        assert!(resolved.hooks.post_exit.is_empty());
    }

    /// The global config is read from HOME, and inside a sandbox HOME is the
    /// private home the confined target writes to. A config planted there
    /// would run its hooks as the caller before any confinement exists, so
    /// the layer is refused outright, the way the trust store is.
    ///
    /// Only the refusal is asserted: a concurrent test touching the same
    /// variables can only ever take a source away, so an absence holds either
    /// way, while asserting the layer's presence outside a sandbox would race
    /// with them.
    #[test]
    fn the_global_config_is_not_read_inside_a_sandbox() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("bailey").join("config.toml");
        std::fs::create_dir_all(global.parent().unwrap()).unwrap();
        std::fs::write(&global, "[filesystem]\nread = [\"/a\"]").unwrap();
        unsafe { std::env::set_var("XDG_CONFIG_HOME", dir.path()) };
        unsafe { std::env::set_var("BAILEY_SANDBOX", "1") };

        let sources = discover(Path::new("/bin/true"), None);
        unsafe { std::env::remove_var("BAILEY_SANDBOX") };
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };

        assert!(
            !sources.iter().any(|source| source.origin == Origin::Global),
            "a planted global config must not become a layer inside a sandbox"
        );
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
    fn a_grant_an_unset_variable_emptied_is_dropped() {
        unsafe { std::env::remove_var("BAILEY_TEST_EMPTY_GRANT") };
        let layers = [layer(
            "/base",
            "[filesystem]\nread = [\"${BAILEY_TEST_EMPTY_GRANT}\"]",
        )];
        let resolved = merge(&layers).unwrap();
        assert!(
            resolved.policy.filesystem.is_empty(),
            "an empty expansion must not fall back to the config's own directory"
        );
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

    /// A discovered layer is applied from the bytes its trust decision was made
    /// against, not from a second read. The seam is `load_verified_layer`: given
    /// a source that carries the bytes it was checked against, those are what
    /// gets parsed, whatever the file says now.
    #[test]
    fn a_verified_layer_is_parsed_from_the_bytes_it_was_checked_against() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bailey.toml");
        std::fs::write(&path, "[filesystem]\nread = [\"/swapped-in\"]\n").unwrap();
        let verified = b"[filesystem]\nread = [\"/accepted\"]\n".to_vec();

        let source = Source {
            path: path.clone(),
            origin: Origin::WorkingDir,
            rejected: None,
            verified: Some(verified),
        };
        let layer = load_verified_layer(&source).unwrap();
        let paths: Vec<&str> = layer
            .raw
            .filesystem
            .read
            .iter()
            .map(RawGrant::path)
            .collect();
        assert_eq!(
            paths,
            vec!["/accepted"],
            "the layer must come from the verified bytes, not the file"
        );
    }

    /// A layer the user supplied on the command line was never trust-checked, so
    /// it has no verified bytes and is read from disk as before.
    #[test]
    fn an_unchecked_layer_is_read_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("given.toml");
        std::fs::write(&path, "[filesystem]\nread = [\"/given\"]\n").unwrap();
        let source = Source {
            path: path.clone(),
            origin: Origin::Explicit,
            rejected: None,
            verified: None,
        };
        let layer = load_verified_layer(&source).unwrap();
        let paths: Vec<&str> = layer
            .raw
            .filesystem
            .read
            .iter()
            .map(RawGrant::path)
            .collect();
        assert_eq!(paths, vec!["/given"]);
    }

    #[test]
    fn size_parsing() {
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size("2GiB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1 MB").unwrap(), 1_000_000);
        assert!(parse_size("2Gigs").is_err());
    }

    /// Command-line grants sit above every file, `--config` included, which is
    /// the whole point of typing them: the caller narrows or widens a policy
    /// for one run without editing anything.
    #[test]
    fn an_override_deny_retracts_an_explicit_config_grant() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("given.toml");
        std::fs::write(&config, "[filesystem]\nread = [\"/granted\"]").unwrap();
        let resolved = resolve_with_bases(
            &[],
            Path::new("/bin/true"),
            Some(&config),
            &[("command-line grants", "[filesystem]\ndeny = [\"/granted\"]")],
        )
        .unwrap();
        assert!(
            resolved.policy.filesystem.is_empty(),
            "the override retracts the file's grant"
        );
        assert_eq!(resolved.policy.denied, vec![PathBuf::from("/granted")]);
    }

    #[test]
    fn an_override_grant_overrides_an_explicit_config_denial() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("given.toml");
        std::fs::write(&config, "[filesystem]\ndeny = [\"/kept-out\"]").unwrap();
        let resolved = resolve_with_bases(
            &[],
            Path::new("/bin/true"),
            Some(&config),
            &[(
                "command-line grants",
                "[filesystem]\nread = [\"/kept-out\"]",
            )],
        )
        .unwrap();
        assert!(resolved.policy.denied.is_empty());
        assert_eq!(
            resolved.policy.filesystem[0].path,
            PathBuf::from("/kept-out")
        );
    }

    /// Egress is a scalar where later layers replace earlier ones, so a
    /// `--allow-net` flag replaces whatever a file chose. That is the
    /// documented precedence, not an accident to preserve.
    #[test]
    fn an_override_replaces_the_config_s_egress_choice() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("given.toml");
        std::fs::write(&config, "[network]\negress = \"allow\"").unwrap();
        let resolved = resolve_with_bases(
            &[],
            Path::new("/bin/true"),
            Some(&config),
            &[(
                "command-line grants",
                "[network]\negress_allow = [{ host = \"*\", port = 443 }]",
            )],
        )
        .unwrap();
        assert_eq!(
            resolved.policy.network.egress,
            Egress::Allow(vec![EgressRule {
                host: "*".into(),
                port: Some(443)
            }])
        );
    }

    #[test]
    fn flag_paths_resolve_against_the_working_directory() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            expand_flag_path("assets").unwrap(),
            normalize_lexical(&cwd.join("assets"))
        );
        assert_eq!(
            expand_flag_path("/absolute/path").unwrap(),
            PathBuf::from("/absolute/path")
        );
    }

    #[test]
    fn flag_paths_expand_variables() {
        unsafe { std::env::set_var("BAILEY_TEST_FLAG_PATH", "/opt/flag") };
        assert_eq!(
            expand_flag_path("${BAILEY_TEST_FLAG_PATH}/bin").unwrap(),
            PathBuf::from("/opt/flag/bin")
        );
    }

    /// A flag names exactly one path, so a variable that is unset is refused
    /// rather than left to point the grant somewhere else.
    #[test]
    fn a_flag_path_with_an_unset_variable_is_refused() {
        let err = expand_flag_path("${BAILEY_TEST_UNSET_VAR}/bin").unwrap_err();
        assert!(err.contains("is not set"), "{err}");
        let err = expand_flag_path("${BAILEY_TEST_UNSET_VAR}").unwrap_err();
        assert!(err.contains("expands to nothing"), "{err}");
        assert!(expand_flag_path("").is_err());
    }

    #[test]
    fn flag_paths_expand_a_leading_tilde() {
        let _env = crate::test_support::env_lock();
        unsafe { std::env::set_var("HOME", "/home/tester") };
        assert_eq!(
            expand_flag_path("~/notes").unwrap(),
            PathBuf::from("/home/tester/notes")
        );
    }

    #[test]
    fn fuse_mounts_accumulate_and_resolve_at() {
        let layers = [
            layer("/base", "[[fuse]]\nmount = \"one\"\nat = \"/mnt/a\""),
            layer("/base", "[[fuse]]\nmount = \"two\"\nat = \"rel\""),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.fuse.len(), 2);
        assert_eq!(resolved.policy.fuse[0].at, PathBuf::from("/mnt/a"));
        assert_eq!(resolved.policy.fuse[1].at, PathBuf::from("/base/rel"));
    }

    /// FUSE mounts run commands as the caller, so one left behind from a lower
    /// layer is exactly the inheritance a reset exists to refuse.
    #[test]
    fn a_reset_clears_fuse_mounts_too() {
        let layers = [
            layer("/base", "[[fuse]]\nmount = \"one\"\nat = \"/mnt/a\""),
            layer(
                "/base",
                "[filesystem]\nreset = true\nread = [\"/a\"]\n[[fuse]]\nmount = \"two\"\nat = \"/mnt/b\"",
            ),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.fuse.len(), 1);
        assert_eq!(resolved.policy.fuse[0].command, "two");
    }

    #[test]
    fn unknown_fuse_keys_are_refused() {
        // The refusal happens at deserialize, before any merging.
        let parsed: Result<RawLayer, _> =
            toml::from_str("[[fuse]]\nmount = \"one\"\nat = \"/mnt/a\"\nextra = \"x\"");
        assert!(parsed.is_err());
    }

    #[test]
    fn self_fuse_reaches_the_policy_and_brings_the_device() {
        let resolved = merge(&[layer(
            "/base",
            "self_fuse = true\n[filesystem]\nread = [\"/a\"]",
        )])
        .unwrap();
        assert!(resolved.policy.self_fuse);
        assert!(
            resolved
                .policy
                .devices
                .iter()
                .any(|rule| rule.path == *"/dev/fuse"
                    && rule.access.contains(Access::READ | Access::WRITE))
        );
    }

    /// The switch means "nearest layer that sets it", the same standing an
    /// `egress` setting has, so a project can turn off what a profile turned
    /// on.
    #[test]
    fn self_fuse_follows_the_nearest_layer() {
        let on_then_off = [
            layer("/base", "self_fuse = true"),
            layer("/base", "self_fuse = false"),
        ];
        assert!(!merge(&on_then_off).unwrap().policy.self_fuse);
        let off_then_on = [
            layer("/base", "self_fuse = false"),
            layer("/base", "self_fuse = true"),
        ];
        assert!(merge(&off_then_on).unwrap().policy.self_fuse);
    }

    /// The read-only guarantee is a mount the target could unmount with the
    /// power self_fuse hands it, so the two are refused together.
    #[test]
    fn self_fuse_with_a_read_only_island_is_refused() {
        let layers = [layer(
            "/base",
            "self_fuse = true\n[filesystem]\nwrite = [\"/a\"]\nread_only = [\"/a/keep\"]",
        )];
        assert!(merge(&layers).is_err());
    }

    /// A denial beneath a grant is enforced by an empty mount over the path,
    /// which the parent grant would expose again once the target can unmount.
    #[test]
    fn self_fuse_with_a_denial_beneath_a_grant_is_refused() {
        let layers = [layer(
            "/base",
            "self_fuse = true\n[filesystem]\nread = [\"/a\"]\ndeny = [\"/a/secret\"]",
        )];
        assert!(merge(&layers).is_err());
    }

    /// A read-only island is a read-only bind wherever it sits: with mount
    /// power the target could remount it writable, so even one no grant
    /// reaches is refused.
    #[test]
    fn self_fuse_with_an_unnested_read_only_island_is_refused() {
        let layers = [layer(
            "/base",
            "self_fuse = true\n[filesystem]\nread = [\"/a\"]\nread_only = [\"/c/keep\"]",
        )];
        assert!(merge(&layers).is_err());
    }

    /// A denial no grant reaches needs no mount to enforce, so it costs
    /// nothing and is left alone.
    #[test]
    fn self_fuse_with_an_unnested_denial_is_accepted() {
        let layers = [layer(
            "/base",
            "self_fuse = true\n[filesystem]\nread = [\"/a\"]\ndeny = [\"/b/secret\"]",
        )];
        let resolved = merge(&layers).unwrap();
        assert!(resolved.policy.self_fuse);
        assert!(resolved.policy.read_only.is_empty());
        assert_eq!(resolved.policy.denied.len(), 1);
    }

    /// The egress port rules are Landlock rules, and Landlock is the half a
    /// self_fuse run gives up. An allowance therefore promises a restriction
    /// nothing in that run makes, so it is refused rather than quietly dropped.
    #[test]
    fn self_fuse_with_an_egress_allowance_is_refused() {
        let layers = [layer(
            "/base",
            "self_fuse = true\n[network]\negress_allow = [{ host = \"*\", port = 443 }]",
        )];
        let error = merge(&layers).unwrap_err().to_string();
        assert!(
            error.contains("self_fuse") && error.contains("egress allowance"),
            "the refusal names both things to change: {error}"
        );
    }

    /// The two directives usually reach each other from different files, and
    /// the advice is only actionable if it names both of them.
    #[test]
    fn self_fuse_and_an_egress_allowance_refused_across_layers() {
        let layers = [
            layer("/over", "self_fuse = true"),
            layer(
                "/deep",
                "[network]\negress_allow = [{ host = \"*\", port = 443 }]",
            ),
        ];
        let error = merge(&layers).unwrap_err().to_string();
        assert!(
            error.contains("/over/bailey.toml") && error.contains("/deep/bailey.toml"),
            "both layers are named: {error}"
        );
    }

    /// An allowance absent altogether leaves the denial to the network
    /// namespace, which self_fuse does not touch.
    #[test]
    fn self_fuse_without_an_egress_allowance_is_unchanged() {
        let layers = [layer(
            "/base",
            "self_fuse = true\n[filesystem]\nread = [\"/a\"]",
        )];
        let resolved = merge(&layers).unwrap();
        assert!(resolved.policy.self_fuse);
        assert_eq!(resolved.policy.network.egress, Egress::DenyAll);
    }

    /// Allow-everything promises no restriction, so there is nothing for a
    /// dropped Landlock ruleset to have been enforcing. This assumes no bound
    /// port: a bound port is restricted by that same ruleset, and that
    /// restriction is dropped too.
    #[test]
    fn self_fuse_with_egress_allow_all_is_unchanged() {
        let layers = [
            layer("/base", "self_fuse = true\n[filesystem]\nread = [\"/a\"]"),
            layer("/base", "[network]\negress = \"allow\""),
        ];
        let resolved = merge(&layers).unwrap();
        assert!(resolved.policy.self_fuse);
        assert_eq!(resolved.policy.network.egress, Egress::AllowAll);
    }

    /// A denial is held by the network namespace rather than by Landlock, so
    /// self_fuse costs it nothing.
    #[test]
    fn self_fuse_with_egress_denied_is_unchanged() {
        let layers = [
            layer("/base", "self_fuse = true\n[filesystem]\nread = [\"/a\"]"),
            layer("/base", "[network]\negress = \"deny\""),
        ];
        let resolved = merge(&layers).unwrap();
        assert!(resolved.policy.self_fuse);
        assert_eq!(resolved.policy.network.egress, Egress::DenyAll);
    }
}
