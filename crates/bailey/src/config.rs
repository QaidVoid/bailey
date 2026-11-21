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
    Access, DenyRule, Destination, DeviceRule, Egress, EgressRule, EnvPolicy, FsRule, FuseMount,
    NetworkPolicy, Policy, PortForward, ResourceLimits, SocketRelay,
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
    /// HTTP-level rules for the built-in egress broker.
    #[serde(default)]
    http: RawHttp,
    /// Which targets a profile claims. Parsed only so that a profile carrying
    /// the key is still a valid config layer; the value is read by
    /// `profiles::for_target`, from the file rather than from here.
    #[serde(default)]
    #[allow(dead_code)]
    applies_to: Vec<String>,
}

/// The `[http]` table: interception, rules, credential bindings and the audit
/// log for the built-in egress broker.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHttp {
    /// Hosts the broker intercepts: exact names or `*.suffix`.
    #[serde(default)]
    intercept: Vec<String>,
    #[serde(default)]
    allow: Vec<RawHttpRule>,
    #[serde(default)]
    deny: Vec<RawHttpRule>,
    #[serde(default)]
    credential: Vec<RawCredential>,
    /// The append-only JSONL audit log. Caller's own config only, which
    /// resolution enforces rather than the parser.
    log: Option<String>,
}

/// One `[[http.allow]]` or `[[http.deny]]` entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHttpRule {
    host: String,
    port: Option<u16>,
    #[serde(default)]
    methods: Vec<String>,
    path: Option<String>,
}

/// One `[[http.credential]]` entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredential {
    host: String,
    /// `bearer`, or `header:NAME` naming the header the value goes in.
    auth: String,
    /// `env:NAME`, `file:PATH` or `fd:N`.
    source: String,
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
    /// Pathname UNIX sockets, or literal directories of them, the target may
    /// connect to. Expanded more strictly than the other grants, because a
    /// widened result here is a door into another program.
    #[serde(default)]
    connect: Vec<String>,
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
    egress_deny: Vec<RawDenyRule>,
    /// Whether the run may ask DNS questions: auto, allow, or deny.
    dns: Option<String>,
    /// How a run with allowed egress picks its namespace.
    mode: Option<String>,
    /// The egress broker a run is held to, as `ADDR:PORT`.
    broker: Option<String>,
    #[serde(default)]
    bind_ports: Vec<u16>,
    #[serde(default)]
    publish_ports: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEgressRule {
    host: String,
    port: Option<u16>,
    /// `tcp` or `udp`, defaulting to `tcp`.
    protocol: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDenyRule {
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
    address_space: Option<String>,
    pids_max: Option<u64>,
    open_files: Option<u64>,
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
    /// The egress choice from `egress = "allow" | "deny"`, with the path of
    /// the layer that set it, for the same reason as `self_fuse` above. A
    /// layer that sets only `egress_allow` does not touch it.
    egress_all: Option<(bool, PathBuf)>,
    /// The egress allowances, each with the path of the layer that set it,
    /// so a later error can name where the rule came from. The list
    /// accumulates across layers.
    egress_rules: Vec<(crate::policy::EgressRule, PathBuf)>,
    /// The egress denials, accumulated across layers with their layer paths.
    egress_denies: Vec<(crate::policy::DenyRule, PathBuf)>,
    /// Whether the run may ask DNS questions, with the layer that set it.
    dns: Option<(crate::policy::DnsSetting, PathBuf)>,
    /// How the run picks a namespace when egress is allowed, with the layer
    /// that set it, so the summary and `show` can name the source.
    mode: Option<(crate::policy::NetworkMode, PathBuf)>,
    /// The egress broker a run is held to, with the layer that set it.
    broker: Option<(crate::policy::Broker, PathBuf)>,
    bind_ports: Vec<u16>,
    publish_ports: Vec<u16>,
    devices: BTreeMap<PathBuf, Access>,
    resources: ResourceLimits,
    /// The layer that set the address-space fallback, so the error that
    /// refuses a fallback without a memory limit can name where the key came
    /// from.
    address_space_source: Option<PathBuf>,
    hooks: Hooks,
    env: EnvPolicy,
    home: Option<PathBuf>,
    fuse: Vec<FuseMount>,
    /// The self-serve FUSE switch, with the path of the layer that set it,
    /// so a conflicting policy can name where the switch came from.
    self_fuse: Option<(bool, PathBuf)>,
    sockets: Vec<SocketRelay>,
    forwards: Vec<PortForward>,
    /// HTTP interception, rules, bindings and the log for the built-in egress
    /// broker, accumulated across layers, each with the layer path that
    /// contributed it so a refusal can name the layer and the rule.
    http_intercept: Vec<(crate::policy::HttpHost, PathBuf)>,
    http_allow: Vec<(crate::policy::HttpRule, PathBuf)>,
    http_deny: Vec<(crate::policy::HttpRule, PathBuf)>,
    http_credentials: Vec<(crate::policy::CredentialBinding, PathBuf)>,
    http_log: Option<(PathBuf, PathBuf)>,
    /// Where the first HTTP rule or binding came from, so a refusal outside
    /// the parser can name the layer that asked for it.
    http_source: Option<PathBuf>,
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
    for raw in &fs.connect {
        match expand_connect_entry(raw, &layer.base) {
            Ok(path) => {
                *granted.entry(path).or_insert(Access::empty()) |= Access::CONNECT;
            }
            Err(reason) => {
                // A dropped entry is a warning rather than an error: a
                // missing display variable, common under ssh or on a TTY
                // login, must not turn a profile that does not need the
                // display for its work into a refused run.
                eprintln!("bailey: warning: dropping `connect` entry `{raw}`: {reason}");
            }
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
        acc.publish_ports.clear();
        // A broker is the same kind of promise made about the whole egress
        // path: a run held to one inherits it silently unless the reset
        // clears it, which is what a reset means here too.
        acc.broker = None;
        // HTTP rules are the same kind of promise made about what may cross
        // the broker, and credentials are a stronger one still.
        acc.http_intercept.clear();
        acc.http_allow.clear();
        acc.http_deny.clear();
        acc.http_credentials.clear();
        acc.http_log = None;
        acc.http_source = None;
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
            let (all, rules) = build_egress(network, &layer.path)?;
            if let Some(all) = all {
                acc.egress_all = Some((all, layer.path.clone()));
            }
            acc.egress_rules
                .extend(rules.into_iter().map(|rule| (rule, layer.path.clone())));
        }
        if !network.egress_deny.is_empty() {
            let denies = build_egress_deny(network, &layer.path)?;
            acc.egress_denies
                .extend(denies.into_iter().map(|rule| (rule, layer.path.clone())));
        }
        if let Some(dns) = &network.dns {
            let Some(dns) = crate::policy::DnsSetting::parse(dns) else {
                return Err(ConfigError::Invalid {
                    path: layer.path.clone(),
                    reason: format!("network dns `{dns}` is not one of auto, allow, deny"),
                });
            };
            acc.dns = Some((dns, layer.path.clone()));
        }
        if let Some(mode) = &network.mode {
            let Some(mode) = crate::policy::NetworkMode::parse(mode) else {
                return Err(ConfigError::Invalid {
                    path: layer.path.clone(),
                    reason: format!("network mode `{mode}` is not one of auto, private, host"),
                });
            };
            acc.mode = Some((mode, layer.path.clone()));
        }
        if let Some(broker) = &network.broker {
            let broker = parse_broker(broker).map_err(|err| ConfigError::Invalid {
                path: layer.path.clone(),
                reason: format!("network broker: {err}"),
            })?;
            acc.broker = Some((broker, layer.path.clone()));
        }
        for port in &network.bind_ports {
            if !acc.bind_ports.contains(port) {
                acc.bind_ports.push(*port);
            }
        }
        for port in &network.publish_ports {
            if *port == 0 {
                return Err(ConfigError::Invalid {
                    path: layer.path.clone(),
                    reason: "a published port must be a real port, not 0".into(),
                });
            }
            if !acc.publish_ports.contains(port) {
                acc.publish_ports.push(*port);
            }
        }
    }

    apply_http(acc, layer)?;

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
        if let Some(open_files) = resources.open_files {
            if open_files == 0 {
                return Err(ConfigError::Invalid {
                    path: layer.path.clone(),
                    reason: "`open_files = 0` would refuse the target's first \
                             open; name a count the target can live with, or \
                             remove the key"
                        .to_owned(),
                });
            }
            acc.resources.open_files = Some(open_files);
        }
        if let Some(spec) = &resources.address_space {
            acc.resources.address_space_bytes = Some(size_value(spec, &layer.path)?);
            acc.address_space_source = Some(layer.path.clone());
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
    // The HTTP rule set is checked and assembled before the rest of the
    // policy is taken apart field by field, so it can borrow `acc` freely.
    let http_intercept = std::mem::take(&mut acc.http_intercept);
    let http_allow = std::mem::take(&mut acc.http_allow);
    let http_deny = std::mem::take(&mut acc.http_deny);
    let http_credentials = std::mem::take(&mut acc.http_credentials);
    let http_log = acc.http_log.take();
    let http_source = acc.http_source.clone();
    check_http(&http_intercept, &http_allow, &http_deny, &http_credentials)?;
    let http = crate::policy::HttpPolicy {
        intercept: http_intercept
            .iter()
            .map(|(host, _)| host.clone())
            .collect(),
        allow: http_allow.iter().map(|(rule, _)| rule.clone()).collect(),
        deny: http_deny.iter().map(|(rule, _)| rule.clone()).collect(),
        credentials: http_credentials
            .iter()
            .map(|(binding, _)| binding.clone())
            .collect(),
        log: http_log.as_ref().map(|(path, _)| path.clone()),
        source: http_source.as_ref().map(|path| path.display().to_string()),
    };
    // Self-serve FUSE hands the target mount power over the run's whole
    // namespace, and two guarantees are enforced by mounts the target could
    // then take down: a read-only island is a read-only bind the target could
    // remount writable, and a denial beneath a grant is an empty mount
    // covering the path, which the parent grant would expose. Refuse the
    // combination rather than promise less than the policy says.
    if let Some((true, source)) = &acc.self_fuse {
        let island = acc.read_only.first();
        // A relocation moves where the target sees a grant, so a denial can
        // name that grant from either the host or the visible spelling.
        let conceal = acc.denied.iter().find(|denied| {
            acc.filesystem.keys().any(|granted| {
                beneath(granted, denied)
                    || acc
                        .relocated
                        .get(granted)
                        .is_some_and(|at| beneath(at, denied))
            })
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
        // restriction nothing in the run makes. Allow-everything promises no
        // restriction, and a denial is held by the run's own network
        // namespace, so neither is in that position.
        if let Some((_, rule_source)) = acc.egress_rules.first() {
            return Err(ConfigError::Conflict {
                path: source.clone(),
                target: "self_fuse".into(),
                reason: format!(
                    "`{}` is a partial egress allowance, enforced only by \
                     the Landlock ruleset that self_fuse drops. Clear \
                     `self_fuse`, or drop the egress allowance",
                    rule_source.display()
                ),
            });
        }
        // A FUSE mount needs the device node, and a switch that promises
        // full use should not also demand the boilerplate.
        acc.devices
            .entry(PathBuf::from("/dev/fuse"))
            .or_insert(Access::READ | Access::WRITE);
    }

    // The address-space fallback exists to stand in for `memory` where no
    // cgroup can carry it. Without a memory limit in the policy there is
    // nothing for it to stand in for, and it would never apply on any host,
    // so a config carrying one is a mistake to name rather than a key to
    // ignore.
    if let Some(source) = &acc.address_space_source
        && acc.resources.memory_bytes.is_none()
    {
        return Err(ConfigError::Invalid {
            path: source.clone(),
            reason: "`address_space` is a fallback for `memory`, and no \
                     layer sets `memory`, so it could never apply. Set \
                     `memory`, or drop `address_space`"
                .to_owned(),
        });
    }

    let network = {
        let mode = acc.mode.as_ref().map(|(mode, _)| *mode).unwrap_or_default();
        refuse_unenforceable_network_rules(&acc, mode)?;
        NetworkPolicy {
            egress: if !acc.egress_rules.is_empty() {
                Egress::Allow(
                    acc.egress_rules
                        .iter()
                        .map(|(rule, _)| rule.clone())
                        .collect(),
                )
            } else if acc.egress_all.as_ref().is_some_and(|(all, _)| *all) {
                Egress::AllowAll
            } else {
                Egress::DenyAll
            },
            mode,
            broker: acc.broker.as_ref().map(|(broker, _)| *broker),
            bind_ports: acc.bind_ports.clone(),
            publish_ports: acc.publish_ports.clone(),
            mode_source: acc
                .mode
                .as_ref()
                .map(|(_, path)| format!("{}", path.display()))
                .unwrap_or_else(|| "the default (auto)".to_owned()),
            broker_source: acc
                .broker
                .as_ref()
                .map(|(_, path)| path.display().to_string()),
            deny: acc
                .egress_denies
                .iter()
                .map(|(rule, _)| rule.clone())
                .collect(),
            dns: acc.dns.map(|(dns, _)| dns).unwrap_or_default(),
        }
    };
    let relocated = acc.relocated.clone();
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
            network,
            devices,
            resources: acc.resources,
            env: acc.env,
            home: acc.home,
            self_fuse: matches!(acc.self_fuse, Some((true, _))),
            fuse: acc.fuse,
            sockets: acc.sockets,
            forwards: acc.forwards,
            http,
        },
        hooks: acc.hooks,
    })
}

/// Refuse network rules no mechanism can enforce.
///
/// The host namespace offers only Landlock's TCP port rules, so a rule that
/// names a destination, allows UDP, or denies DNS would resolve into a policy
/// that means something else. Where the resolved mode is `host`, such a rule
/// is refused, naming the layer that set it. Under `auto` or `private` the
/// namespace decision makes the private namespace required instead.
fn refuse_unenforceable_network_rules(
    acc: &Accumulator,
    mode: crate::policy::NetworkMode,
) -> Result<(), ConfigError> {
    if mode != crate::policy::NetworkMode::Host {
        return Ok(());
    }
    for (rule, layer) in &acc.egress_rules {
        if !rule.host.is_any() || rule.protocol == crate::policy::Protocol::Udp {
            let what = if rule.host.is_any() {
                "a UDP allowance".to_owned()
            } else {
                format!("an egress_allow entry for host `{}`", rule.host)
            };
            return Err(ConfigError::Invalid {
                path: layer.clone(),
                reason: format!(
                    "{what} needs the private network namespace, which \
                     `mode = \"host\"` does not provide; drop `mode = \"host\"` \
                     or set the rule's host to `*` with protocol `tcp`"
                ),
            });
        }
    }
    if let Some((rule, layer)) = acc.egress_denies.first() {
        return Err(ConfigError::Invalid {
            path: layer.clone(),
            reason: format!(
                "an egress_deny entry for host `{}` needs the private \
                 network namespace, which `mode = \"host\"` does not provide",
                rule.host
            ),
        });
    }
    if let Some((crate::policy::DnsSetting::Deny, layer)) = &acc.dns {
        return Err(ConfigError::Invalid {
            path: layer.clone(),
            reason: "a DNS denial needs the private network namespace, which \
                     `mode = \"host\"` does not provide"
                .to_owned(),
        });
    }
    Ok(())
}

/// Build the egress intent for a layer.
///
/// Returns the `egress = "allow" | "deny"` choice, when the layer set one,
/// and the layer's parsed allowances. An `egress_allow` entry without a port
/// is rejected rather than dropped: silently ignoring the rule would resolve
/// "allow this destination" into a full deny.
/// Parse the value `[network] broker` and `--egress-proxy` accept: the
/// built-in broker, or one address.
fn parse_broker(value: &str) -> Result<crate::policy::Broker, String> {
    if value == "builtin" {
        return Ok(crate::policy::Broker::Builtin);
    }
    crate::cli::parse_egress_proxy(value)
        .map(|(addr, port)| crate::policy::Broker::External(addr, port))
        .map_err(|err| err.to_string())
}

/// Whether a string is an RFC 9110 token, which is what a method and a
/// header name must be.
fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Build one `[[http.allow]]` or `[[http.deny]]` rule, with the error naming
/// the layer and the rule's host.
fn build_http_rule(
    raw: &RawHttpRule,
    path: &Path,
    list: &str,
) -> Result<crate::policy::HttpRule, ConfigError> {
    let invalid = |reason: String| ConfigError::Invalid {
        path: path.to_path_buf(),
        reason: format!("http {list} rule for `{}`: {reason}", raw.host),
    };
    let Some(host) = crate::policy::HttpHost::parse(&raw.host) else {
        return Err(invalid(
            "the host is not a name, `*.suffix`, `*` or an address".into(),
        ));
    };
    for method in &raw.methods {
        if !is_token(method) || *method != method.to_uppercase() {
            return Err(invalid(format!(
                "method `{method}` is not an uppercase token"
            )));
        }
    }
    let path_rule = match &raw.path {
        None => None,
        Some(path) => Some(
            crate::policy::HttpPath::parse(path)
                .ok_or_else(|| invalid("`path` must be an exact path or a `prefix*`".into()))?,
        ),
    };
    Ok(crate::policy::HttpRule {
        host,
        port: raw.port,
        methods: raw.methods.clone(),
        path: path_rule,
    })
}

/// Build one `[[http.credential]]` binding.
fn build_credential(
    raw: &RawCredential,
    path: &Path,
) -> Result<crate::policy::CredentialBinding, ConfigError> {
    let invalid = |reason: String| ConfigError::Invalid {
        path: path.to_path_buf(),
        reason: format!("http credential for `{}`: {reason}", raw.host),
    };
    let Some(host) = crate::policy::HttpHost::parse(&raw.host) else {
        return Err(invalid(
            "the host is not a name, `*.suffix`, `*` or an address".into(),
        ));
    };
    let auth = if raw.auth == "bearer" {
        crate::policy::AuthShape::Bearer
    } else if let Some(name) = raw.auth.strip_prefix("header:") {
        if !is_token(name) {
            return Err(invalid(format!("auth `{}` is not a header name", raw.auth)));
        }
        crate::policy::AuthShape::Header(name.to_owned())
    } else {
        return Err(invalid("auth must be `bearer` or `header:NAME`".into()));
    };
    let source = if let Some(name) = raw.source.strip_prefix("env:") {
        if name.is_empty() {
            return Err(invalid("`env:` needs a variable name".into()));
        }
        crate::policy::CredentialSource::Env(name.to_owned())
    } else if let Some(file) = raw.source.strip_prefix("file:") {
        if file.is_empty() {
            return Err(invalid("`file:` needs a path".into()));
        }
        crate::policy::CredentialSource::File(PathBuf::from(file))
    } else if let Some(fd) = raw.source.strip_prefix("fd:") {
        let fd = fd
            .parse::<u32>()
            .map_err(|_| invalid(format!("`fd:` needs a descriptor number, got {fd:?}")))?;
        crate::policy::CredentialSource::Fd(fd)
    } else {
        return Err(invalid(
            "source must be `env:NAME`, `file:PATH` or `fd:N`".into(),
        ));
    };
    Ok(crate::policy::CredentialBinding { host, auth, source })
}

/// Accumulate one layer's `[http]` tables into the broker's rule set.
///
/// The lists accumulate across layers; `[filesystem] reset = true` cleared
/// them before this runs. What resolution refuses instead of the parser
/// (credentials and log entries from layers a target could have written, a
/// rule no intercept entry covers, `*` in the intercept list) is 2.4 and
/// 2.5's business, not the parser's.
fn apply_http(acc: &mut Accumulator, layer: &Layer) -> Result<(), ConfigError> {
    let http = &layer.raw.http;
    for listed in &http.intercept {
        let Some(host) = crate::policy::HttpHost::parse(listed) else {
            return Err(ConfigError::Invalid {
                path: layer.path.clone(),
                reason: format!(
                    "http intercept `{listed}` is not a name, `*.suffix` or an address"
                ),
            });
        };
        if !acc.http_intercept.iter().any(|(known, _)| known == &host) {
            acc.http_intercept.push((host, layer.path.clone()));
        }
    }
    for raw in &http.allow {
        acc.http_allow.push((
            build_http_rule(raw, &layer.path, "allow")?,
            layer.path.clone(),
        ));
    }
    for raw in &http.deny {
        acc.http_deny.push((
            build_http_rule(raw, &layer.path, "deny")?,
            layer.path.clone(),
        ));
    }
    for raw in &http.credential {
        acc.http_credentials
            .push((build_credential(raw, &layer.path)?, layer.path.clone()));
    }
    if let Some(log) = &http.log {
        let Some(resolved) = resolve_path(log, &layer.base) else {
            return Err(ConfigError::Invalid {
                path: layer.path.clone(),
                reason: format!("http log `{log}` must be an absolute path"),
            });
        };
        acc.http_log = Some((resolved, layer.path.clone()));
    }
    let carried_anything = !http.intercept.is_empty()
        || !http.allow.is_empty()
        || !http.deny.is_empty()
        || !http.credential.is_empty()
        || http.log.is_some();
    if carried_anything {
        acc.http_source.get_or_insert_with(|| layer.path.clone());
    }
    Ok(())
}

/// Header names a credential may not bind to: the ones the broker strips as
/// hop-by-hop or owns itself, where an attached value would be dropped,
/// misframed, or would contradict a header the broker writes.
const FORBIDDEN_CREDENTIAL_HEADERS: [&str; 10] = [
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Refuse HTTP rules the accumulated layers cannot all honour, whatever the
/// enforcement does later. Every error names the layer and the rule.
///
/// Checked here, where the whole merged rule set is in hand, rather than per
/// layer: a rule written before any intercept entry may be covered by one a
/// later layer adds.
fn check_http(
    http_intercept: &[(crate::policy::HttpHost, PathBuf)],
    http_allow: &[(crate::policy::HttpRule, PathBuf)],
    http_deny: &[(crate::policy::HttpRule, PathBuf)],
    http_credentials: &[(crate::policy::CredentialBinding, PathBuf)],
) -> Result<(), ConfigError> {
    for (listed, path) in http_intercept {
        if *listed == crate::policy::HttpHost::Any {
            return Err(ConfigError::Invalid {
                path: path.clone(),
                reason: "http intercept `*` would intercept every host; name \
                         the hosts instead"
                    .into(),
            });
        }
    }

    // A rule that bounds the method or the path, and every credential, is
    // only enforceable on a host the broker intercepts: that is where the
    // request is visible and the rule can be applied. A bare host rule is a
    // tunnel, and needs no interception.
    let covered = |host: &crate::policy::HttpHost| {
        http_intercept
            .iter()
            .any(|(listed, _)| host_covered_by(host, listed))
    };
    for (rule, path) in http_allow.iter().chain(http_deny) {
        if rule.methods.is_empty() && rule.path.is_none() {
            continue;
        }
        if !covered(&rule.host) {
            return Err(ConfigError::Invalid {
                path: path.clone(),
                reason: format!(
                    "http rule for `{}` bounds a method or a path, which needs \
                     it in the [http] intercept list",
                    rule.host
                ),
            });
        }
    }
    for (credential, path) in http_credentials {
        if !covered(&credential.host) {
            return Err(ConfigError::Invalid {
                path: path.clone(),
                reason: format!(
                    "http credential for `{}` needs it in the [http] \
                     intercept list",
                    credential.host
                ),
            });
        }
        if let crate::policy::AuthShape::Header(name) = &credential.auth {
            let lowered = name.to_ascii_lowercase();
            if FORBIDDEN_CREDENTIAL_HEADERS.contains(&lowered.as_str()) {
                return Err(ConfigError::Invalid {
                    path: path.clone(),
                    reason: format!(
                        "http credential header `{name}` is a framing or \
                         hop-by-hop name the broker owns"
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Whether an intercept entry covers a rule's host: an exact entry matches
/// itself, a `*.suffix` entry covers every subdomain of the suffix it names.
fn host_covered_by(host: &crate::policy::HttpHost, listed: &crate::policy::HttpHost) -> bool {
    use crate::policy::HttpHost;
    match (host, listed) {
        (HttpHost::Any, _) => true,
        (HttpHost::Exact(name), listed) => listed.matches(name),
        (HttpHost::Wildcard(suffix), HttpHost::Wildcard(listed_suffix)) => suffix == listed_suffix,
        (HttpHost::Address(addr), listed) => listed.matches(&addr.to_string()),
        (HttpHost::Wildcard(_), _) => false,
    }
}

/// The refusal for HTTP rules that can never be enforced, checked after the
/// flags are mapped on so a `--egress-proxy builtin` on the command line
/// satisfies rules written in config.
///
/// With egress allowed and no broker there is nothing that could enforce the
/// rules, so the run is refused. Under an external broker the rules are not
/// enforced and the caller is warned, which keeps an invocation that carries
/// a global config with rules working.
pub(crate) fn check_http_broker(policy: &Policy) -> anyhow::Result<()> {
    let http = &policy.http;
    let Some(source) = http.source.as_deref() else {
        return Ok(());
    };
    let denied = matches!(policy.network.egress, crate::policy::Egress::DenyAll);
    match policy.network.broker {
        Some(crate::policy::Broker::Builtin) => Ok(()),
        Some(crate::policy::Broker::External(addr, port)) => {
            eprintln!(
                "bailey: warning: the HTTP rules from {source} are not \
                 enforced: egress goes through the external broker at \
                 {addr}:{port}, which applies none of them"
            );
            Ok(())
        }
        None if denied => {
            eprintln!(
                "bailey: warning: the HTTP rules from {source} are not in \
                 force: egress is denied, so no broker runs"
            );
            Ok(())
        }
        None => anyhow::bail!(
            "HTTP rules from {source} need the built-in egress broker: set \
             [network] broker = \"builtin\" or pass --egress-proxy builtin, \
             or remove the rules"
        ),
    }
}

fn build_egress(
    network: &RawNetwork,
    path: &Path,
) -> Result<(Option<bool>, Vec<EgressRule>), ConfigError> {
    let mut rules = Vec::with_capacity(network.egress_allow.len());
    for rule in &network.egress_allow {
        let Some(port) = rule.port else {
            return Err(ConfigError::Invalid {
                path: path.to_path_buf(),
                reason: format!(
                    "egress_allow entry for host `{}` has no port; \
                     outbound rules are matched by port, so a port is required",
                    rule.host
                ),
            });
        };
        if port == 53 {
            return Err(ConfigError::Invalid {
                path: path.to_path_buf(),
                reason: format!(
                    "egress_allow entry for host `{}` names port 53; DNS is \
                     decided by the `dns` setting, not by an egress rule",
                    rule.host
                ),
            });
        }
        let host = parse_destination(&rule.host).map_err(|reason| ConfigError::Invalid {
            path: path.to_path_buf(),
            reason: format!("egress_allow entry for host `{}`: {reason}", rule.host),
        })?;
        let protocol = match rule.protocol.as_deref() {
            None => crate::policy::Protocol::Tcp,
            Some(value) => {
                let Some(protocol) = crate::policy::Protocol::parse(value) else {
                    return Err(ConfigError::Invalid {
                        path: path.to_path_buf(),
                        reason: format!(
                            "egress_allow entry for host `{}` names protocol \
                             `{value}`; the accepted values are tcp and udp",
                            rule.host
                        ),
                    });
                };
                protocol
            }
        };
        rules.push(EgressRule {
            host,
            port: Some(port),
            protocol,
        });
    }
    let all = match network.egress.as_deref() {
        Some("allow") => Some(true),
        Some(other) if other != "deny" => {
            return Err(ConfigError::Invalid {
                path: path.to_path_buf(),
                reason: format!("network egress `{other}` is not one of allow, deny"),
            });
        }
        _ => None,
    };
    Ok((all, rules))
}

/// Build a layer's egress denials.
///
/// A deny naming loopback is rejected: loopback inside the namespace is
/// governed by forwards and publications, and a deny there would contradict a
/// forward of the same port.
fn build_egress_deny(network: &RawNetwork, path: &Path) -> Result<Vec<DenyRule>, ConfigError> {
    let mut denies = Vec::with_capacity(network.egress_deny.len());
    for rule in &network.egress_deny {
        let host = parse_destination(&rule.host).map_err(|reason| ConfigError::Invalid {
            path: path.to_path_buf(),
            reason: format!("egress_deny entry for host `{}`: {reason}", rule.host),
        })?;
        if host.covers_loopback() {
            return Err(ConfigError::Invalid {
                path: path.to_path_buf(),
                reason: format!(
                    "egress_deny entry names loopback ({}); loopback is \
                     governed by forwards and publications, not by egress rules",
                    rule.host
                ),
            });
        }
        denies.push(DenyRule {
            host,
            port: rule.port,
        });
    }
    Ok(denies)
}

/// Parse the `host` value of an egress or deny rule.
///
/// `*` means any destination. An address or `address/prefix` is parsed as
/// such; everything else is a hostname, which a later step resolves and
/// pins. A wildcard anywhere but alone is rejected now rather than at start,
/// because a wildcard name cannot be pinned to addresses.
fn parse_destination(raw: &str) -> Result<Destination, String> {
    if raw == "*" {
        return Ok(Destination::Any);
    }
    if raw.contains('*') {
        return Err(
            "a wildcard name cannot be pinned to addresses; name the hosts \
             or address blocks you need"
                .to_owned(),
        );
    }
    if let Ok(addr) = raw.parse::<std::net::IpAddr>() {
        return Ok(Destination::Address(addr));
    }
    if let Some((addr, prefix)) = raw.rsplit_once('/') {
        let Ok(addr) = addr.parse::<std::net::IpAddr>() else {
            return Err(format!(
                "`{addr}` in `{raw}` is neither an address nor a hostname"
            ));
        };
        let Ok(prefix) = prefix.parse::<u8>() else {
            return Err(format!("`{prefix}` in `{raw}` is not a prefix length"));
        };
        let width = match addr {
            std::net::IpAddr::V4(_) => 32,
            std::net::IpAddr::V6(_) => 128,
        };
        if prefix > width {
            return Err(format!(
                "prefix /{prefix} is too long for {addr}; the longest is /{width}"
            ));
        }
        return Ok(Destination::Block(addr, prefix));
    }
    let plausible = !raw.is_empty()
        && !raw.contains(['/', ' ', '\t', ':', '$'])
        && raw.len() <= 253
        && raw.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        });
    if !plausible {
        return Err(format!(
            "`{raw}` is neither an address, a CIDR block, `*`, nor a plausible hostname"
        ));
    }
    Ok(Destination::Name(raw.to_owned()))
}

/// Resolve one `connect` entry, under the stricter rules a socket grant needs.
///
/// A widened `connect` entry is a door into another program, so this is
/// deliberately narrower than [`resolve_path`]:
/// - A variable that is unset, or set to the empty string, is an error rather
///   than a path that matches nothing.
/// - A variable whose value is absolute replaces everything to its left, the
///   way joining an absolute component does. Wayland defines an absolute
///   `WAYLAND_DISPLAY`, so the profile templates stay correct for a
///   compositor that sets one.
/// - An entry that used a variable and resolves to an existing directory is
///   an error: the variable was meant to name a socket, and a directory there
///   would make every socket beneath it connectable.
/// - An entry that resolves to the session runtime directory, to an ancestor
///   of it, or to `/` is an error whether or not it used a variable. Those
///   are the directories whose sockets the connect list exists to separate.
///
/// A literal directory entry is fine and covers every socket beneath it, and
/// a path that does not exist yet is kept, to be skipped at enforcement like
/// any missing grant. The directory check is a `stat` against the host now.
pub(crate) fn expand_connect_entry(raw: &str, base: &Path) -> Result<PathBuf, String> {
    let mut out = String::new();
    let mut rest = raw;
    let mut used_variable = false;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[start..]);
            break;
        };
        let name = &after[..end];
        let value = match std::env::var_os(name) {
            Some(value) => value.to_string_lossy().into_owned(),
            // `${PWD}` names the directory the run was launched from, for the
            // same reason resolve_path falls back to asking the kernel.
            None if name == "PWD" => match std::env::current_dir() {
                Ok(cwd) => cwd.to_string_lossy().into_owned(),
                Err(_) => {
                    return Err(format!("variable `${{{name}}}` is not set"));
                }
            },
            None => {
                return Err(format!(
                    "variable `${{{name}}}` is not set, and a connect entry \
                     must name a socket"
                ));
            }
        };
        if value.is_empty() {
            return Err(format!(
                "variable `${{{name}}}` is empty, and a connect entry must \
                 name a socket"
            ));
        }
        used_variable = true;
        if value.starts_with('/') {
            out.clear();
        }
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    if out.trim().is_empty() {
        return Err("expands to nothing".to_owned());
    }
    let expanded = expand_tilde(&out);
    let joined = if expanded.is_absolute() {
        expanded
    } else {
        base.join(expanded)
    };
    let path = normalize_lexical(&joined);
    if used_variable && path.is_dir() {
        return Err(format!(
            "resolves to the directory {}, and a variable there is meant to \
             name a socket; a directory would make every socket beneath it \
             connectable",
            path.display()
        ));
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR")
        && Path::new(&runtime).is_absolute()
        && Path::new(&runtime).starts_with(&path)
    {
        return Err(
            "would make the session runtime directory, or an ancestor of it, \
             connectable; connect there is granted socket by socket"
                .to_owned(),
        );
    }
    Ok(path)
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
///
/// A `..` above the root is dropped, because an absolute path has nothing above
/// `/`, and a key that kept one would match no rule. A relative path that pops
/// past its own start keeps the `..`, because collapsing it to nothing would
/// produce the empty path, which is a prefix of every path and so matches
/// every rule.
fn normalize_lexical(path: &Path) -> PathBuf {
    use std::path::Component;

    let absolute = path.is_absolute();
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() && !absolute {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// True when `child` lies strictly beneath `parent`, component for component.
fn beneath(parent: &Path, child: &Path) -> bool {
    child.starts_with(parent) && child != parent
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

/// Where the global config lives, or `None` when the environment names no
/// directory bailey is willing to read it from.
///
/// A relative value is refused rather than resolved: it would be read from the
/// working directory, so the project a run is launched from would supply a
/// layer discovery applies with no trust record. `$XDG_CONFIG_HOME` is ignored
/// rather than treated as unset, per the XDG spec, so a relative value names no
/// global config at all instead of falling back to `$HOME/.config`.
fn global_config_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        let dir = Path::new(&xdg);
        if !dir.is_absolute() {
            eprintln!(
                "bailey: warning: ignoring a relative XDG_CONFIG_HOME `{}`: a relative \
                 path would be read from the working directory, which the project being \
                 run controls",
                dir.display()
            );
            return None;
        }
        return Some(dir.join("bailey").join("config.toml"));
    }
    let home = std::env::var_os("HOME")?;
    if !Path::new(&home).is_absolute() {
        eprintln!(
            "bailey: warning: ignoring a relative HOME `{}`: a relative path would be \
             read from the working directory, which the project being run controls",
            Path::new(&home).display()
        );
        return None;
    }
    Some(
        Path::new(&home)
            .join(".config")
            .join("bailey")
            .join("config.toml"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{DnsSetting, NetworkMode, Protocol};

    fn layer(base: &str, toml_src: &str) -> Layer {
        Layer {
            path: PathBuf::from(base).join(CONFIG_NAME),
            base: PathBuf::from(base),
            raw: toml::from_str(toml_src).expect("valid test config"),
        }
    }

    /// A layer whose TOML may not parse, for tests that expect a parse
    /// error rather than a merge error. The error text is all the test sees.
    fn raw_layer(toml_src: &str) -> Result<(), String> {
        toml::from_str::<RawLayer>(toml_src)
            .map(|_| ())
            .map_err(|err| err.to_string())
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

    /// Resource keys follow the nearest layer that sets them, exactly as the
    /// other per-key merges do.
    #[test]
    fn an_open_file_limit_follows_the_nearest_layer() {
        let on_then_off = [
            layer("/base", "[resources]\nopen_files = 256"),
            layer("/base", "[resources]\nopen_files = 1024"),
        ];
        let resolved = merge(&on_then_off).unwrap();
        assert_eq!(resolved.policy.resources.open_files, Some(1024));
    }

    #[test]
    fn a_zero_open_file_limit_is_refused() {
        let layers = [layer("/base", "[resources]\nopen_files = 0")];
        let error = merge(&layers).unwrap_err();
        assert!(
            error.to_string().contains("open_files"),
            "the refusal must name the key: {error}"
        );
        assert!(
            error.to_string().contains("/base"),
            "the refusal must name the layer: {error}"
        );
    }

    #[test]
    fn an_address_space_fallback_without_memory_is_refused() {
        let layers = [layer("/base", "[resources]\naddress_space = \"8GiB\"")];
        let error = merge(&layers).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("address_space"),
            "the refusal must name the key: {message}"
        );
        assert!(
            message.contains("fallback for `memory`"),
            "the refusal must say what the key stands in for: {message}"
        );
        assert!(
            message.contains("/base"),
            "the refusal must name the layer that set it: {message}"
        );
    }

    #[test]
    fn a_fallback_and_memory_from_different_layers_carry_both() {
        let layers = [
            layer("/global", "[resources]\nmemory = \"2GiB\""),
            layer("/project", "[resources]\naddress_space = \"8GiB\""),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved.policy.resources.memory_bytes,
            Some(2 * 1024 * 1024 * 1024)
        );
        assert_eq!(
            resolved.policy.resources.address_space_bytes,
            Some(8 * 1024 * 1024 * 1024)
        );
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

    /// A misspelled key is an error rather than a rule that quietly does
    /// nothing, which is the promise `deny_unknown_fields` makes.
    #[test]
    fn an_unknown_network_key_is_refused() {
        assert!(toml::from_str::<RawLayer>("[network]\npublish_port = [3800]").is_err());
    }

    #[test]
    fn publish_ports_accumulate_and_deduplicate() {
        let layers = [
            layer("/base", "[network]\npublish_ports = [3800, 4000]"),
            layer("/base", "[network]\npublish_ports = [4000, 4567]"),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved.policy.network.publish_ports,
            vec![3800, 4000, 4567]
        );
    }

    #[test]
    fn publish_port_zero_is_refused() {
        let layers = [layer("/base", "[network]\npublish_ports = [0]")];
        assert!(merge(&layers).is_err());
    }

    #[test]
    fn a_reset_clears_published_ports() {
        let layers = [
            layer("/base", "[network]\npublish_ports = [3800]"),
            layer(
                "/base",
                "[filesystem]\nreset = true\n[network]\npublish_ports = [4000]",
            ),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.network.publish_ports, vec![4000]);
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

    /// A `connect` entry is its own grant: read on a directory never reads as
    /// the right to talk to the sockets in it.
    #[test]
    fn a_connect_entry_grants_the_connect_right_alone() {
        let layers = [layer(
            "/base",
            "[filesystem]\nconnect = [\"/tmp/srv.sock\"]",
        )];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.filesystem.len(), 1);
        assert_eq!(
            resolved.policy.filesystem[0].path,
            PathBuf::from("/tmp/srv.sock")
        );
        assert_eq!(resolved.policy.filesystem[0].access, Access::CONNECT);
    }

    #[test]
    fn a_path_written_and_connectable_carries_both_bits() {
        let layers = [layer(
            "/base",
            "[filesystem]\nwrite = [\"/x\"]\nconnect = [\"/x\"]",
        )];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.filesystem.len(), 1);
        assert_eq!(
            resolved.policy.filesystem[0].access,
            Access::WRITE | Access::CONNECT
        );
    }

    #[test]
    fn an_exact_deny_retracts_a_connect_grant() {
        let layers = [
            layer("/base", "[filesystem]\nconnect = [\"/s\"]"),
            layer("/base", "[filesystem]\ndeny = [\"/s\"]"),
        ];
        let resolved = merge(&layers).unwrap();
        assert!(resolved.policy.filesystem.is_empty());
    }

    #[test]
    fn a_reset_clears_connect_grants() {
        let layers = [
            layer("/base", "[filesystem]\nconnect = [\"/s\"]"),
            layer("/base", "[filesystem]\nreset = true\nread = [\"/keep\"]"),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved
                .policy
                .filesystem
                .iter()
                .map(|rule| rule.path.clone())
                .collect::<Vec<_>>(),
            vec![PathBuf::from("/keep")]
        );
    }

    #[test]
    fn a_connect_entry_on_a_relative_path_resolves_against_the_layer() {
        let layers = [layer("/base", "[filesystem]\nconnect = [\"run.sock\"]")];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved.policy.filesystem[0].path,
            PathBuf::from("/base/run.sock")
        );
    }

    #[test]
    fn a_connect_entry_in_the_same_layer_as_its_deny_is_refused() {
        let layers = [layer(
            "/base",
            "[filesystem]\nconnect = [\"/s\"]\ndeny = [\"/s\"]",
        )];
        assert!(merge(&layers).is_err());
    }

    /// The Wayland template is the entry every shared profile will carry, so
    /// every shape the compositor's environment can give it must end in a
    /// grant that names the socket, never the runtime directory or anything
    /// above it. An unset or empty variable, an absolute value, and a name
    /// that turns out to be a directory are all shapes a real session has.
    #[test]
    fn the_wayland_template_never_grants_above_the_socket() {
        let runtime = tempfile::tempdir().unwrap();
        let rt = runtime.path();
        fs::create_dir(rt.join("sub")).unwrap();
        // SAFETY: test-only process-global state; no other test in this
        // binary reads these two names.
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", rt) };

        let cases: [(&str, Option<&str>); 5] = [
            ("unset", None),
            ("empty", Some("")),
            ("a socket name", Some("wayland-1")),
            ("an absolute path", Some("/elsewhere/absolute-wayland-1")),
            ("a directory name", Some("sub")),
        ];
        for (what, display) in cases {
            match display {
                Some(value) => unsafe { std::env::set_var("WAYLAND_DISPLAY", value) },
                None => unsafe { std::env::remove_var("WAYLAND_DISPLAY") },
            }
            let layers = [layer(
                "/base",
                "[filesystem]\nconnect = [\"${XDG_RUNTIME_DIR}/${WAYLAND_DISPLAY}\"]",
            )];
            let resolved = merge(&layers).unwrap();

            // Whatever the entry became, the runtime directory itself and
            // every directory above it are never among the grants. The socket
            // sits inside the runtime directory, so grants beneath it are the
            // point.
            for rule in &resolved.policy.filesystem {
                assert_ne!(
                    rule.path, rt,
                    "{what}: the runtime directory itself must not be connectable"
                );
                assert!(
                    !rt.starts_with(&rule.path),
                    "{what}: a grant reached above the socket: {}",
                    rule.path.display()
                );
                assert_ne!(
                    rule.path,
                    rt.join("sub"),
                    "{what}: the variable named a directory and a grant was made on it"
                );
            }
            match display {
                // A dropped entry grants nothing: the run proceeds without the
                // display rather than with everything around it.
                None | Some("") | Some("sub") => {
                    assert!(
                        resolved.policy.filesystem.is_empty(),
                        "{what}: the entry must be dropped, not widened: {:?}",
                        resolved.policy.filesystem
                    );
                }
                Some("wayland-1") => {
                    assert_eq!(
                        resolved.policy.filesystem[0].path,
                        rt.join("wayland-1"),
                        "{what}: the socket path is what gets the grant"
                    );
                    assert_eq!(resolved.policy.filesystem[0].access, Access::CONNECT);
                }
                Some("/elsewhere/absolute-wayland-1") => {
                    assert_eq!(
                        resolved.policy.filesystem[0].path,
                        PathBuf::from("/elsewhere/absolute-wayland-1"),
                        "{what}: an absolute value replaces the runtime prefix"
                    );
                }
                other => unreachable!("unhandled case {other:?}"),
            }
        }
        unsafe { std::env::remove_var("WAYLAND_DISPLAY") };
        unsafe { std::env::remove_var("XDG_RUNTIME_DIR") };
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

    /// A `..` that walks above the root lands on the root, so a deny spelled
    /// with one still retracts the grant it names. A literal `..` surviving
    /// normalisation would leave the deny keyed at a path no rule holds.
    #[test]
    fn a_deny_that_pops_above_the_root_still_names_its_grant() {
        let layers = [
            layer("/base", "[filesystem]\nread = [\"/a/granted\"]"),
            layer(
                "/base",
                "[filesystem]\ndeny = [\"/a/granted/../../../a/granted\"]",
            ),
        ];
        let resolved = merge(&layers).unwrap();
        assert!(resolved.policy.filesystem.is_empty());
        assert_eq!(resolved.policy.denied, vec![PathBuf::from("/a/granted")]);
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

    /// A relative `XDG_CONFIG_HOME` resolves against the working
    /// directory, so the project a run is launched from would supply the global
    /// layer, which discovery applies with no trust record. It names no global
    /// config instead, and a relative `HOME` is refused the same way.
    ///
    /// Only the returned path is asserted. The warning is written to stderr,
    /// which libtest captures per thread rather than at the descriptor, so a
    /// test cannot read it; the naming is covered by running the binary.
    #[test]
    fn a_relative_xdg_config_home_names_no_global_config() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("bailey")).unwrap();
        std::fs::write(
            dir.path().join("bailey").join("config.toml"),
            "[filesystem]\nread = [\"/planted\"]",
        )
        .unwrap();

        unsafe { std::env::set_var("XDG_CONFIG_HOME", dir.path()) };
        let absolute = global_config_path();

        unsafe { std::env::set_var("XDG_CONFIG_HOME", "./relative") };
        let relative = global_config_path();

        unsafe { std::env::set_var("XDG_CONFIG_HOME", "/nonexistent-absolute") };
        let other_absolute = global_config_path();

        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        unsafe { std::env::set_var("HOME", "relative-home") };
        let relative_home = global_config_path();
        unsafe { std::env::remove_var("HOME") };

        assert_eq!(
            absolute.as_deref(),
            Some(dir.path().join("bailey").join("config.toml").as_path()),
            "an absolute XDG_CONFIG_HOME still names the global config"
        );
        assert_eq!(
            relative, None,
            "a relative XDG_CONFIG_HOME names no global config at all"
        );
        assert_eq!(
            other_absolute.as_deref(),
            Some(Path::new("/nonexistent-absolute/bailey/config.toml")),
            "an absolute value pointing nowhere is still the path it names"
        );
        assert_eq!(
            relative_home, None,
            "a relative HOME names no global config either"
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
    fn nearest_layer_wins_for_mode_and_broker() {
        let layers = [
            layer(
                "/global",
                "[network]\nmode = \"host\"\nbroker = \"169.254.169.1:8443\"",
            ),
            layer(
                "/project",
                "[network]\nmode = \"private\"\nbroker = \"169.254.169.2:9000\"",
            ),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.network.mode, NetworkMode::Private);
        assert_eq!(
            resolved.policy.network.broker,
            Some(crate::policy::Broker::External(
                "169.254.169.2".parse().unwrap(),
                9000
            ))
        );
        assert_eq!(resolved.policy.network.mode_source, "/project/bailey.toml");
        assert_eq!(
            resolved.policy.network.broker_source.as_deref(),
            Some("/project/bailey.toml")
        );
    }

    #[test]
    fn mode_defaults_to_auto_with_a_named_source() {
        let resolved = merge(&[layer("/base", "[filesystem]\nread = [\"/a\"]")]).unwrap();
        assert_eq!(resolved.policy.network.mode, NetworkMode::Auto);
        assert_eq!(resolved.policy.network.mode_source, "the default (auto)");
        assert_eq!(resolved.policy.network.broker, None);
        assert_eq!(resolved.policy.network.broker_source, None);
    }

    #[test]
    fn builtin_is_a_broker_value_and_beats_an_address_below() {
        let layers = [
            layer("/global", "[network]\nbroker = \"169.254.169.1:8443\""),
            layer("/project", "[network]\nbroker = \"builtin\""),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved.policy.network.broker,
            Some(crate::policy::Broker::Builtin)
        );

        let reversed = [
            layer("/project", "[network]\nbroker = \"builtin\""),
            layer("/global", "[network]\nbroker = \"169.254.169.1:8443\""),
        ];
        let resolved = merge(&reversed).unwrap();
        assert_eq!(
            resolved.policy.network.broker,
            Some(crate::policy::Broker::External(
                "169.254.169.1".parse().unwrap(),
                8443
            ))
        );
    }

    #[test]
    fn a_bad_broker_value_is_rejected_naming_the_layer() {
        let err = merge(&[layer("/base", "[network]\nbroker = \"nope\"")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("/base"), "{err}");
        assert!(err.contains("broker"), "{err}");
    }

    #[test]
    fn http_rules_accumulate_across_layers() {
        let layers = [
            layer(
                "/global",
                "[http]\nintercept = [\"api.anthropic.com\"]\n\n[[http.allow]]\nhost = \"registry.npmjs.org\"",
            ),
            layer(
                "/project",
                "[http]\nintercept = [\"api.github.com\"]\n\n[[http.allow]]\nhost = \"api.github.com\"\nmethods = [\"GET\"]\npath = \"/repos/myorg/*\"\n\n[[http.deny]]\nhost = \"api.github.com\"\npath = \"/repos/myorg/secrets*\"",
            ),
        ];
        let resolved = merge(&layers).unwrap();
        let http = &resolved.policy.http;
        assert_eq!(
            http.intercept,
            vec![
                crate::policy::HttpHost::parse("api.anthropic.com").unwrap(),
                crate::policy::HttpHost::parse("api.github.com").unwrap(),
            ]
        );
        assert_eq!(http.allow.len(), 2);
        assert_eq!(
            http.allow[0].host,
            crate::policy::HttpHost::parse("registry.npmjs.org").unwrap()
        );
        assert_eq!(http.allow[1].methods, vec!["GET"]);
        assert_eq!(
            http.allow[1].path,
            Some(crate::policy::HttpPath::parse("/repos/myorg/*").unwrap())
        );
        assert_eq!(http.deny.len(), 1);
        assert_eq!(http.credentials, Vec::new());
        assert_eq!(http.log, None);
    }

    #[test]
    fn a_filesystem_reset_clears_the_http_rules() {
        let layers = [
            layer(
                "/global",
                "[http]\nintercept = [\"api.anthropic.com\"]\nlog = \"/var/log/bailey-http.jsonl\"\n\n[[http.allow]]\nhost = \"registry.npmjs.org\"\n\n[[http.credential]]\nhost = \"api.anthropic.com\"\nauth = \"header:x-api-key\"\nsource = \"env:ANTHROPIC_API_KEY\"",
            ),
            layer(
                "/project",
                "[filesystem]\nreset = true\n\n[http]\nintercept = [\"api.github.com\"]",
            ),
        ];
        let resolved = merge(&layers).unwrap();
        let http = &resolved.policy.http;
        assert_eq!(
            http.intercept,
            vec![crate::policy::HttpHost::parse("api.github.com").unwrap()]
        );
        assert_eq!(http.allow, Vec::new());
        assert_eq!(http.deny, Vec::new());
        assert_eq!(http.credentials, Vec::new());
        assert_eq!(http.log, None);
    }

    #[test]
    fn a_credential_binding_parses_all_three_sources() {
        let layers = [layer(
            "/caller",
            "[http]\nintercept = [\"api.anthropic.com\", \"api.github.com\", \"api.openai.com\"]\n\n[[http.credential]]\nhost = \"api.anthropic.com\"\nauth = \"bearer\"\nsource = \"env:KEY\"\n\n[[http.credential]]\nhost = \"api.github.com\"\nauth = \"header:x-api-key\"\nsource = \"file:/run/secrets/key\"\n\n[[http.credential]]\nhost = \"api.openai.com\"\nauth = \"bearer\"\nsource = \"fd:7\"",
        )];
        let resolved = merge(&layers).unwrap();
        let creds = &resolved.policy.http.credentials;
        assert_eq!(creds.len(), 3);
        assert_eq!(creds[0].auth, crate::policy::AuthShape::Bearer);
        assert_eq!(
            creds[1].auth,
            crate::policy::AuthShape::Header("x-api-key".into())
        );
        assert_eq!(creds[2].source, crate::policy::CredentialSource::Fd(7));
    }

    #[test]
    fn a_method_or_path_rule_needs_an_intercept_entry() {
        let err = merge(&[layer(
            "/base",
            "[[http.allow]]\nhost = \"api.github.com\"\nmethods = [\"GET\"]\npath = \"/repos/*\"",
        )])
        .unwrap_err()
        .to_string();
        assert!(err.contains("/base"), "{err}");
        assert!(err.contains("api.github.com"), "{err}");
        assert!(err.contains("intercept"), "{err}");

        // A wildcard intercept entry covers the subdomains a rule names.
        let resolved = merge(&[layer(
            "/base",
            "[http]\nintercept = [\"*.github.com\"]\n\n[[http.allow]]\nhost = \"api.github.com\"\nmethods = [\"GET\"]",
        )])
        .unwrap();
        assert_eq!(resolved.policy.http.allow.len(), 1);

        // A bare host rule needs no interception.
        let resolved = merge(&[layer(
            "/base",
            "[[http.allow]]\nhost = \"registry.npmjs.org\"",
        )])
        .unwrap();
        assert_eq!(resolved.policy.http.allow.len(), 1);
    }

    #[test]
    fn a_star_in_the_intercept_list_is_refused() {
        let err = merge(&[layer("/base", "[http]\nintercept = [\"*\"]")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("/base"), "{err}");
        assert!(err.contains("intercept"), "{err}");
    }

    #[test]
    fn a_credential_for_an_uncovered_host_is_refused() {
        let err = merge(&[layer(
            "/base",
            "[http]\nintercept = [\"api.anthropic.com\"]\n\n[[http.credential]]\nhost = \"api.openai.com\"\nauth = \"bearer\"\nsource = \"env:KEY\"",
        )])
        .unwrap_err()
        .to_string();
        assert!(err.contains("/base"), "{err}");
        assert!(err.contains("api.openai.com"), "{err}");
    }

    #[test]
    fn a_credential_on_a_framing_or_hop_by_hop_header_is_refused() {
        for header in [
            "transfer-encoding",
            "content-length",
            "connection",
            "TE",
            "host",
        ] {
            let err = merge(&[layer(
                "/base",
                &format!(
                    "[http]\nintercept = [\"api.anthropic.com\"]\n\n[[http.credential]]\nhost = \"api.anthropic.com\"\nauth = \"header:{header}\"\nsource = \"env:KEY\""
                ),
            )])
            .unwrap_err()
            .to_string();
            assert!(err.contains(header), "{header}: {err}");
        }
    }

    #[test]
    fn http_rules_with_allowed_egress_and_no_broker_are_refused() {
        let policy_with_rules = |broker: Option<crate::policy::Broker>| {
            let mut policy = Policy::default();
            policy.network.egress = Egress::AllowAll;
            policy.http.source = Some("/caller/bailey.toml".to_owned());
            policy.http.allow.push(crate::policy::HttpRule {
                host: crate::policy::HttpHost::parse("api.anthropic.com").unwrap(),
                port: None,
                methods: Vec::new(),
                path: None,
            });
            policy.network.broker = broker;
            policy
        };

        let err = crate::config::check_http_broker(&policy_with_rules(None)).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("/caller/bailey.toml"), "{text}");
        assert!(text.contains("builtin"), "{text}");

        // The builtin broker satisfies the rules.
        crate::config::check_http_broker(&policy_with_rules(Some(crate::policy::Broker::Builtin)))
            .unwrap();

        // An external broker warns rather than refusing.
        crate::config::check_http_broker(&policy_with_rules(Some(
            crate::policy::Broker::External("169.254.169.1".parse().unwrap(), 8443),
        )))
        .unwrap();
    }

    #[test]
    fn http_rules_with_denied_egress_and_no_broker_warn_only() {
        let mut policy = Policy::default();
        policy.network.egress = Egress::DenyAll;
        policy.http.source = Some("/caller/bailey.toml".to_owned());
        crate::config::check_http_broker(&policy).unwrap();
    }

    #[test]
    fn a_bad_http_rule_is_rejected_naming_the_layer_and_rule() {
        let err = merge(&[layer(
            "/base",
            "[[http.allow]]\nhost = \"api.github.com\"\nmethods = [\"get\"]",
        )])
        .unwrap_err()
        .to_string();
        assert!(err.contains("/base"), "{err}");
        assert!(err.contains("api.github.com"), "{err}");
        assert!(err.contains("uppercase"), "{err}");

        let err = merge(&[layer(
            "/base",
            "[[http.credential]]\nhost = \"api.anthropic.com\"\nauth = \"cookie\"\nsource = \"env:KEY\"",
        )])
        .unwrap_err()
        .to_string();
        assert!(err.contains("/base"), "{err}");
        assert!(err.contains("auth"), "{err}");

        let err = merge(&[layer(
            "/base",
            "[[http.credential]]\nhost = \"api.anthropic.com\"\nauth = \"bearer\"\nsource = \"keyring:KEY\"",
        )])
        .unwrap_err()
        .to_string();
        assert!(err.contains("source"), "{err}");

        let err = merge(&[layer("/base", "[http]\nintercept = [\"bücher.example\"]")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("intercept"), "{err}");
    }

    #[test]
    fn unknown_http_keys_are_rejected() {
        let err = raw_layer("[http]\ncache = true").unwrap_err();
        assert!(err.contains("cache"), "{err}");

        let err = raw_layer("[[http.allow]]\nhost = \"a.example\"\nheaders = []").unwrap_err();
        assert!(err.contains("headers"), "{err}");

        let err = raw_layer(
            "[[http.credential]]\nhost = \"a.example\"\nauth = \"bearer\"\nsource = \"env:K\"\nttl = 5",
        )
        .unwrap_err();
        assert!(err.contains("ttl"), "{err}");
    }

    #[test]
    fn unknown_mode_is_rejected_naming_the_layer_and_values() {
        let layers = [layer("/base", "[network]\nmode = \"vpn\"")];
        let err = merge(&layers).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }));
        let text = err.to_string();
        assert!(text.contains("/base"), "the layer is named: {text}");
        assert!(
            text.contains("auto"),
            "the accepted values are named: {text}"
        );
    }

    #[test]
    fn malformed_broker_is_rejected_naming_the_layer() {
        let layers = [layer("/base", "[network]\nbroker = \"localhost\"")];
        let err = merge(&layers).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }));
        let text = err.to_string();
        assert!(text.contains("/base"), "the layer is named: {text}");
        assert!(
            text.contains("ADDR:PORT"),
            "the expected form is named: {text}"
        );
    }

    /// The host namespace has nothing that carries a destination rule, a UDP
    /// allowance, an egress denial, or a DNS denial, so a policy naming any
    /// of them beside an explicit `mode = "host"` is refused at resolution,
    /// naming the layer that set each side.
    #[test]
    fn host_mode_with_a_destination_rule_is_refused() {
        let layers = [
            layer("/global", "[network]\nmode = \"host\""),
            layer(
                "/project",
                "[network]\negress_allow = [{ host = \"api.example.com\", port = 443 }]",
            ),
        ];
        let err = merge(&layers).unwrap_err().to_string();
        assert!(err.contains("api.example.com"), "{err}");
        assert!(err.contains("/project/bailey.toml"), "{err}");
    }

    #[test]
    fn host_mode_with_a_udp_rule_is_refused() {
        let layers = [layer(
            "/base",
            "[network]\nmode = \"host\"\negress_allow = [{ host = \"*\", port = 27015, protocol = \"udp\" }]",
        )];
        let err = merge(&layers).unwrap_err().to_string();
        assert!(err.contains("UDP allowance"), "{err}");
    }

    #[test]
    fn host_mode_with_a_deny_rule_is_refused() {
        let layers = [layer(
            "/base",
            "[network]\nmode = \"host\"\negress_deny = [{ host = \"169.254.169.254\" }]",
        )];
        let err = merge(&layers).unwrap_err().to_string();
        assert!(err.contains("169.254.169.254"), "{err}");
    }

    #[test]
    fn host_mode_with_a_dns_denial_is_refused() {
        let layers = [layer("/base", "[network]\nmode = \"host\"\ndns = \"deny\"")];
        let err = merge(&layers).unwrap_err().to_string();
        assert!(err.contains("DNS denial"), "{err}");
    }

    /// A port-only TCP allowance is exactly what Landlock enforces, so host
    /// mode beside one stays coherent.
    #[test]
    fn host_mode_with_a_port_only_rule_is_unchanged() {
        let layers = [layer(
            "/base",
            "[network]\nmode = \"host\"\negress_allow = [{ host = \"*\", port = 443 }]",
        )];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.network.mode, NetworkMode::Host);
    }

    #[test]
    fn reset_clears_an_inherited_broker() {
        let layers = [
            layer("/global", "[network]\nbroker = \"169.254.169.1:8443\""),
            layer("/project", "[filesystem]\nreset = true"),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.network.broker, None);
        assert_eq!(resolved.policy.network.broker_source, None);
    }

    #[test]
    fn reset_does_not_clear_the_mode() {
        let layers = [
            layer("/global", "[network]\nmode = \"private\""),
            layer("/project", "[filesystem]\nreset = true"),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.network.mode, NetworkMode::Private);
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
                host: Destination::Any,
                protocol: Protocol::Tcp,
                port: Some(443),
            }])
        );
    }

    /// The protocol names are few on purpose; anything else is a typo to
    /// catch, not a transport to guess at.
    #[test]
    fn an_unknown_protocol_is_rejected() {
        let layers = [layer(
            "/base",
            "[network]\negress_allow = [{ host = \"*\", port = 443, protocol = \"sctp\" }]",
        )];
        let err = merge(&layers).unwrap_err().to_string();
        assert!(err.contains("sctp"), "{err}");
        assert!(err.contains("tcp") && err.contains("udp"), "{err}");
    }

    #[test]
    fn a_udp_rule_resolves_with_its_protocol() {
        let layers = [layer(
            "/base",
            "[network]\negress_allow = [{ host = \"*\", port = 27015, protocol = \"udp\" }]",
        )];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved.policy.network.egress,
            Egress::Allow(vec![EgressRule {
                host: Destination::Any,
                protocol: Protocol::Udp,
                port: Some(27015),
            }])
        );
    }

    /// A prefix longer than the address has no addresses in it, and a name
    /// with a slash is not a name the resolver can be asked for.
    #[test]
    fn a_malformed_cidr_is_rejected() {
        let layers = [layer(
            "/base",
            "[network]\negress_allow = [{ host = \"203.0.113.0/33\", port = 443 }]",
        )];
        let err = merge(&layers).unwrap_err().to_string();
        assert!(err.contains("prefix"), "{err}");

        let layers = [layer(
            "/base",
            "[network]\negress_allow = [{ host = \"example.com/24\", port = 443 }]",
        )];
        let err = merge(&layers).unwrap_err().to_string();
        assert!(err.contains("neither an address"), "{err}");
    }

    #[test]
    fn a_cidr_rule_resolves_to_a_block() {
        let layers = [layer(
            "/base",
            "[network]\negress_allow = [{ host = \"203.0.113.0/24\", port = 443 }]",
        )];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved.policy.network.egress,
            Egress::Allow(vec![EgressRule {
                host: Destination::Block("203.0.113.0".parse().unwrap(), 24),
                protocol: Protocol::Tcp,
                port: Some(443),
            }])
        );
    }

    /// A wildcard name cannot be pinned to addresses, so `*.example.com` is
    /// refused rather than silently read as one fixed host.
    #[test]
    fn a_wildcard_subdomain_is_rejected() {
        let layers = [layer(
            "/base",
            "[network]\negress_allow = [{ host = \"*.example.com\", port = 443 }]",
        )];
        let err = merge(&layers).unwrap_err().to_string();
        assert!(err.contains("wildcard"), "{err}");
    }

    /// Port 53 is DNS, and DNS is decided by the `dns` setting alone; an
    /// egress rule naming it would read as a second way to allow DNS.
    #[test]
    fn an_egress_rule_for_port_53_is_rejected() {
        let layers = [layer(
            "/base",
            "[network]\negress_allow = [{ host = \"*\", port = 53 }]",
        )];
        let err = merge(&layers).unwrap_err().to_string();
        assert!(err.contains("port 53") && err.contains("dns"), "{err}");
    }

    /// Loopback inside the namespace is governed by forwards and
    /// publications; a deny there would contradict a forward of the same
    /// port.
    #[test]
    fn a_deny_rule_for_loopback_is_rejected() {
        let layers = [layer(
            "/base",
            "[network]\negress_deny = [{ host = \"127.0.0.1\" }]",
        )];
        let err = merge(&layers).unwrap_err().to_string();
        assert!(err.contains("loopback"), "{err}");

        // A range that contains loopback is refused too.
        let layers = [layer(
            "/base",
            "[network]\negress_deny = [{ host = \"127.0.0.0/8\" }]",
        )];
        let err = merge(&layers).unwrap_err().to_string();
        assert!(err.contains("loopback"), "{err}");
    }

    #[test]
    fn a_deny_rule_resolves_and_accumulates_across_layers() {
        let layers = [
            layer(
                "/base",
                "[network]\negress_deny = [{ host = \"169.254.169.254\" }]",
            ),
            layer(
                "/project",
                "[network]\negress_deny = [{ host = \"169.254.170.2\", port = 80 }]",
            ),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(
            resolved.policy.network.deny,
            vec![
                DenyRule {
                    host: Destination::Address("169.254.169.254".parse().unwrap()),
                    port: None,
                },
                DenyRule {
                    host: Destination::Address("169.254.170.2".parse().unwrap()),
                    port: Some(80),
                },
            ]
        );
    }

    /// A deny list works under full egress too: `egress = "allow"` plus
    /// `egress_deny` is the usual "everything except" shape.
    #[test]
    fn a_deny_list_under_full_egress_resolves() {
        let layers = [layer(
            "/base",
            "[network]\negress = \"allow\"\negress_deny = [{ host = \"169.254.169.254\" }]",
        )];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.network.egress, Egress::AllowAll);
        assert_eq!(resolved.policy.network.deny.len(), 1);
    }

    #[test]
    fn dns_merges_as_a_scalar() {
        let layers = [
            layer("/base", "[network]\ndns = \"allow\""),
            layer("/project", "[network]\ndns = \"deny\""),
        ];
        let resolved = merge(&layers).unwrap();
        assert_eq!(resolved.policy.network.dns, DnsSetting::Deny);
    }

    #[test]
    fn an_unknown_dns_value_is_rejected_naming_the_layer() {
        let layers = [layer("/deep", "[network]\ndns = \"proxy\"")];
        let err = merge(&layers).unwrap_err().to_string();
        assert!(err.contains("/deep/bailey.toml"), "{err}");
        assert!(err.contains("proxy"), "{err}");
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
                host: Destination::Any,
                protocol: Protocol::Tcp,
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

    /// A `..` above the root names the root, so no normalised path carries a
    /// parent component for a key to trip over.
    #[test]
    fn normalize_lexical_drops_a_parent_above_the_root() {
        assert_eq!(
            normalize_lexical(Path::new("/a/granted/../../../a/granted")),
            PathBuf::from("/a/granted")
        );
        assert_eq!(normalize_lexical(Path::new("/..")), PathBuf::from("/"));
        assert_eq!(
            normalize_lexical(Path::new("/a/./b")),
            PathBuf::from("/a/b")
        );
        // A relative path that pops past its own start keeps its `..`, because
        // the empty path is a prefix of everything and would match every rule.
        assert_eq!(normalize_lexical(Path::new("..")), PathBuf::from(".."));
        assert_eq!(normalize_lexical(Path::new("a/../..")), PathBuf::from(".."));
        assert_eq!(
            normalize_lexical(Path::new("a/b/../../..")),
            PathBuf::from("..")
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

    /// The visible spelling is where the target acts, so a denial written
    /// there is enforced by a mount just as much as the host spelling is.
    #[test]
    fn a_relocated_visible_deny_is_recognised() {
        let layers = [layer(
            "/base",
            "self_fuse = true\n[filesystem]\nread = [{ path = \"/a\", at = \"/v\" }]\ndeny = [\"/v/secret\"]",
        )];
        let error = merge(&layers).unwrap_err().to_string();
        assert!(
            error.contains("self_fuse") && error.contains("/v/secret"),
            "the refusal names the denial: {error}"
        );
    }

    /// The host spelling of the same denial was always caught, and stays so.
    #[test]
    fn a_relocated_host_deny_is_still_refused() {
        let layers = [layer(
            "/base",
            "self_fuse = true\n[filesystem]\nread = [{ path = \"/a\", at = \"/v\" }]\ndeny = [\"/a/secret\"]",
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
