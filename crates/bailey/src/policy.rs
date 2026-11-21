//! Mechanism-independent sandbox policy model.
//!
//! A [`Policy`] expresses the intent of a sandbox: which filesystem paths,
//! network destinations, and devices a target may reach, and what resource
//! limits apply. It is deliberately independent of any enforcement mechanism so
//! that the enforcement and audit backends can each interpret the same value.

use std::collections::BTreeMap;
use std::path::PathBuf;

use bitflags::bitflags;

bitflags! {
    /// Access rights granted on a filesystem path hierarchy or device node.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Access: u8 {
        /// Permission to read.
        const READ = 0b001;
        /// Permission to write.
        const WRITE = 0b010;
        /// Permission to execute.
        const EXECUTE = 0b100;
        /// Permission to connect to a pathname UNIX socket.
        ///
        /// It is its own grant, never implied by `READ` or `WRITE`: a
        /// pathname socket is a door into another program, and reaching a
        /// directory is not the same as being allowed to knock on every door
        /// in it. Nothing grants it except a `connect` entry, a relay bailey
        /// sets up, or a literal directory entry naming a directory of
        /// sockets.
        const CONNECT = 0b1000;
    }
}

/// A single filesystem grant: a path hierarchy and the rights allowed on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsRule {
    /// The path hierarchy the grant applies to, as the host has it.
    pub path: PathBuf,
    /// The rights granted on the hierarchy.
    pub access: Access,
    /// Where the hierarchy appears to the target, when that is not its own path.
    ///
    /// Paths are otherwise preserved exactly, because a program that resolves
    /// anything relative to its own location breaks when moved. Relocating is
    /// worth it for a path whose name is itself the thing to withhold: a
    /// directory named after the operator tells a target who is running it and
    /// how the host is laid out, which no amount of access control takes back.
    ///
    /// Only meaningful under isolation. Without a reconstructed root there is
    /// nowhere else for a path to be.
    pub at: Option<PathBuf>,
}

impl FsRule {
    /// The path the target sees, which is what a rule must be attached to.
    ///
    /// Landlock is applied after the pivot, so a rule naming the host path
    /// would name something that no longer exists and be silently skipped.
    pub fn visible(&self) -> &PathBuf {
        self.at.as_ref().unwrap_or(&self.path)
    }
}

/// Network egress intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Egress {
    /// Deny all outbound connections.
    DenyAll,
    /// Allow all outbound connections.
    AllowAll,
    /// Allow only the listed destinations.
    Allow(Vec<EgressRule>),
}

/// A permitted egress destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRule {
    /// Who may be reached: any host, one pinned name, one address, or a
    /// block.
    pub host: Destination,
    /// Destination port, or `None` for any port.
    pub port: Option<u16>,
    /// The transport the rule allows.
    pub protocol: Protocol,
}

/// Where an egress rule's traffic may go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// Any destination: the rule bounds the port and protocol only.
    Any,
    /// A hostname, resolved once when the run starts and pinned to the
    /// addresses it answered with.
    Name(String),
    /// One address.
    Address(std::net::IpAddr),
    /// A block of addresses, written as CIDR. The address is the block's
    /// base as written; the ruleset masks it to the prefix.
    Block(std::net::IpAddr, u8),
}

impl Destination {
    /// Whether the rule bounds only the port and protocol.
    pub fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }

    /// Whether the rule names a block that contains the loopback addresses.
    /// A deny naming them would contradict a forward or publication of the
    /// same port, so resolution refuses it.
    pub fn covers_loopback(&self) -> bool {
        match self {
            Self::Address(addr) => addr.is_loopback(),
            Self::Block(addr, prefix) => match addr {
                std::net::IpAddr::V4(v4) => {
                    let bits = u32::from(*v4);
                    let loopback = u32::from(std::net::Ipv4Addr::LOCALHOST) & mask(*prefix, 32);
                    bits & mask(*prefix, 32) == loopback
                }
                std::net::IpAddr::V6(v6) => {
                    let bits = u128::from(*v6);
                    let loopback = u128::from(std::net::Ipv6Addr::LOCALHOST) & mask6(*prefix);
                    bits & mask6(*prefix) == loopback
                }
            },
            Self::Any | Self::Name(_) => false,
        }
    }
}

/// The address bits kept by a CIDR prefix of the given width.
fn mask(prefix: u8, width: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (width - prefix)
    }
}

/// The address bits kept by a CIDR prefix, for IPv6.
fn mask6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => write!(f, "*"),
            Self::Name(name) => write!(f, "{name}"),
            Self::Address(addr) => write!(f, "{addr}"),
            Self::Block(addr, prefix) => write!(f, "{addr}/{prefix}"),
        }
    }
}

/// The transport an egress rule allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Outbound TCP connections.
    Tcp,
    /// Outbound UDP datagrams.
    Udp,
}

impl Protocol {
    /// Parse the value a config file writes, or `None` for anything else.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }

    /// The name a config file writes, for messages.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// A destination whose traffic is dropped whatever the allowances say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyRule {
    /// Who may not be reached: one pinned name, one address, or a block.
    pub host: Destination,
    /// Destination port, or `None` for every port.
    pub port: Option<u16>,
}

/// Whether the run may ask DNS questions, and who answers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsSetting {
    /// Allowed exactly when a rule needs names resolved: an allow rule whose
    /// host is any address.
    #[default]
    Auto,
    /// Allowed, to the namespace's forwarder only.
    Allow,
    /// Dropped, whatever the allow rules say.
    Deny,
}

impl DnsSetting {
    /// Parse the value a config file writes, or `None` for anything else.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }

    /// The name a config file writes, for messages.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// How a run with allowed egress picks its network namespace.
///
/// A policy that denies egress is unaffected by this setting: it always gets
/// the loopback-only namespace, which is the only way to deny every protocol
/// at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkMode {
    /// Use the private namespace whenever the host can provide it. Fall back
    /// to the host namespace with a warning when it cannot, unless the policy
    /// needs the private namespace, in which case the run is refused.
    #[default]
    Auto,
    /// Always use the private namespace, and refuse the run when the host
    /// cannot provide it.
    Private,
    /// Keep the host's network namespace, where Landlock's TCP port rules are
    /// the only restriction.
    Host,
}

impl NetworkMode {
    /// Parse the value a config file writes, or `None` for anything else.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "private" => Some(Self::Private),
            "host" => Some(Self::Host),
            _ => None,
        }
    }
}

/// The egress broker a run is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broker {
    /// The built-in broker bailey spawns outside the target's namespace and
    /// confines itself. Written `builtin`.
    Builtin,
    /// An external broker the caller runs, at one address.
    External(std::net::Ipv4Addr, u16),
}

impl Broker {
    /// The host and port an external broker listens on.
    pub fn external(self) -> Option<(std::net::Ipv4Addr, u16)> {
        match self {
            Self::Builtin => None,
            Self::External(addr, port) => Some((addr, port)),
        }
    }
}

/// Network access intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    /// Outbound connection policy.
    pub egress: Egress,
    /// How the run picks a namespace when egress is allowed.
    pub mode: NetworkMode,
    /// The egress broker a run is held to. Implies the private namespace,
    /// whatever `mode` says.
    pub broker: Option<Broker>,
    /// TCP ports the target is allowed to bind.
    pub bind_ports: Vec<u16>,
    /// TCP ports on which the host may reach a service bound inside the
    /// sandbox. Each is published on host loopback only, and only when the run
    /// uses a private network namespace.
    pub publish_ports: Vec<u16>,
    /// The config layer or flag that set [`NetworkPolicy::mode`], for the
    /// summary and `bailey show` to name.
    pub mode_source: String,
    /// The config layer or flag that set [`NetworkPolicy::broker`], when one
    /// is set.
    pub broker_source: Option<String>,
    /// Destinations dropped ahead of every allowance, in the private
    /// namespace's netfilter rules.
    pub deny: Vec<DenyRule>,
    /// Whether the run may ask DNS questions, and who answers them.
    pub dns: DnsSetting,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            egress: Egress::DenyAll,
            mode: NetworkMode::Auto,
            broker: None,
            bind_ports: Vec::new(),
            publish_ports: Vec::new(),
            mode_source: "the default (auto)".to_owned(),
            broker_source: None,
            deny: Vec::new(),
            dns: DnsSetting::Auto,
        }
    }
}

impl NetworkPolicy {
    /// Whether any egress rule needs more than Landlock's TCP port rules.
    ///
    /// A rule naming a destination, a UDP allowance, an egress denial, and a
    /// DNS denial are all enforced in the private namespace's netfilter
    /// rules; the host's namespace has nothing that carries them.
    pub fn needs_egress_namespace(&self) -> bool {
        self.dns == DnsSetting::Deny || !self.deny.is_empty() || self.egress_rules_need_namespace()
    }

    /// Whether an allow rule names a destination or protocol Landlock
    /// cannot match.
    fn egress_rules_need_namespace(&self) -> bool {
        match &self.egress {
            Egress::Allow(rules) => rules
                .iter()
                .any(|rule| !rule.host.is_any() || rule.protocol == Protocol::Udp),
            Egress::DenyAll | Egress::AllowAll => false,
        }
    }

    /// Whether any rule names a hostname, which resolution must turn into
    /// pinned addresses and a generated `/etc/hosts`.
    pub fn needs_pinning(&self) -> bool {
        let allow_names = match &self.egress {
            Egress::Allow(rules) => rules
                .iter()
                .any(|rule| matches!(rule.host, Destination::Name(_))),
            Egress::DenyAll | Egress::AllowAll => false,
        };
        allow_names
            || self
                .deny
                .iter()
                .any(|rule| matches!(rule.host, Destination::Name(_)))
    }

    /// Whether DNS questions are answered for this policy.
    ///
    /// An explicit `dns` setting decides. `auto` allows DNS exactly when a
    /// rule names any host, since a rule that reaches every address is
    /// useless without resolution, and drops it otherwise, leaving the
    /// pinned `/etc/hosts` to answer.
    pub fn dns_allowed(&self) -> bool {
        match self.dns {
            DnsSetting::Allow => true,
            DnsSetting::Deny => false,
            DnsSetting::Auto => match &self.egress {
                Egress::Allow(rules) => rules.iter().any(|rule| rule.host.is_any()),
                Egress::AllowAll => true,
                Egress::DenyAll => false,
            },
        }
    }
}

/// A device access grant, typically a node under `/dev`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRule {
    /// Path to the device node.
    pub path: PathBuf,
    /// Rights granted on the device.
    pub access: Access,
}

/// Resource limits applied to a run.
///
/// Most are applied via cgroups and need a delegated one to have any effect.
/// `file_bytes` is the exception: it is an rlimit, so it holds on any host,
/// with or without cgroups.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Maximum resident memory in bytes.
    pub memory_bytes: Option<u64>,
    /// Per-process address space in bytes, the explicit fallback for
    /// `memory_bytes` on a run where no cgroup could carry the memory limit.
    ///
    /// This bounds what a process may map, not what it may keep resident, and
    /// it bounds one process rather than the run. Runtimes that reserve large
    /// ranges (the JVM, node) need a number well above their resident size,
    /// which is why the policy must set it by name and a cgroup, where one
    /// exists, remains the memory bound.
    pub address_space_bytes: Option<u64>,
    /// Maximum number of processes and threads.
    pub pids_max: Option<u64>,
    /// Largest descriptor number a process may newly open.
    ///
    /// Applied as `RLIMIT_NOFILE` and holds without a cgroup. Descriptors the
    /// process inherited above the number stay open; new ones are refused
    /// once the numbers below it are spent.
    pub open_files: Option<u64>,
    /// CPU quota as a percentage of a single core (100 = one full core).
    pub cpu_percent: Option<u32>,
    /// Largest single file the target may create, in bytes.
    ///
    /// This bounds one file rather than total usage, because Linux offers no
    /// rootless way to cap what a process tree writes in aggregate: cgroups
    /// have no disk controller, and a sized filesystem needs a mount. It stops
    /// a runaway log or dump, which is the common way a sandbox fills a disk.
    pub file_bytes: Option<u64>,
    /// Size of the private `/tmp`, in bytes.
    pub tmp_bytes: Option<u64>,
    /// Size of the private `/dev/shm`, in bytes.
    pub shm_bytes: Option<u64>,
    /// A host directory to back the private `/tmp` with, instead of a tmpfs.
    ///
    /// When set, `/tmp` is a bind of this directory rather than a memory-backed
    /// tmpfs, so a build's scratch is bounded by the disk it sits on rather
    /// than by memory. It still masks the host's `/tmp`: a bind over `/tmp`
    /// covers whatever was there, exactly as the tmpfs did.
    pub tmp_dir: Option<std::path::PathBuf>,
}

/// Which environment variables reach the target.
///
/// The target's environment is built rather than inherited: it starts empty, a
/// reconstructed base set is added, and only the variables named here cross from
/// the caller. Anything a shell exports, including credentials such as
/// `SSH_AUTH_SOCK` or an API token, stays behind unless it is named.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvPolicy {
    /// Names to forward from the caller. A trailing `*` matches by prefix.
    pub pass: Vec<String>,
    /// Variables set to a literal value, overriding anything passed.
    pub set: BTreeMap<String, String>,
    /// Names to remove from the final environment, including the base set. A
    /// trailing `*` matches by prefix.
    pub deny: Vec<String>,
}

impl EnvPolicy {
    /// Whether `name` is forwarded from the caller.
    pub fn passes(&self, name: &str) -> bool {
        self.pass.iter().any(|pattern| matches_name(pattern, name))
    }

    /// Whether `name` is denied outright.
    pub fn denies(&self, name: &str) -> bool {
        self.deny.iter().any(|pattern| matches_name(pattern, name))
    }
}

/// Match a variable name against a pattern, where a trailing `*` is a prefix.
fn matches_name(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

/// A FUSE filesystem bailey mounts itself, so the target can use one without
/// ever holding the power to mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuseMount {
    /// Shell command that performs the mount. It runs as the caller before any
    /// confinement exists, with `BAILEY_MOUNTPOINT` naming the host directory
    /// to mount onto, exactly the standing a `pre_launch` hook has.
    pub command: String,
    /// Where the mount appears to the target.
    pub at: PathBuf,
}

/// One desktop service socket carried into the sandbox by a host-side relay.
///
/// The relay is what makes a single service grantable: the sandbox sees a
/// socket at the service's usual path, backed by bailey, and the directory
/// holding the real socket stays out of reach along with everything beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketRelay {
    /// The host socket the relay forwards to.
    pub host: PathBuf,
    /// Where the target sees the socket.
    pub at: PathBuf,
    /// The named service this is, when the config named one. Custom relays
    /// carry `None` and set up their own environment.
    pub service: Option<String>,
}

/// A host an HTTP rule names.
///
/// Written as an exact name, `*.suffix` for subdomains only, `*` for any
/// host, or an IP literal. Compared in lowercase without a trailing dot.
/// Names must be ASCII, so internationalised names are written in their
/// `xn--` form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpHost {
    /// Any host: written `*`.
    Any,
    /// Subdomains of a suffix at any depth, written `*.suffix`. The bare
    /// suffix itself is not matched.
    Wildcard(String),
    /// One exact name.
    Exact(String),
    /// One address literal.
    Address(std::net::IpAddr),
}

impl HttpHost {
    /// Parse the value a config file or flag writes, or `None` for anything
    /// else, which resolution reports as a bad rule.
    pub fn parse(value: &str) -> Option<Self> {
        let lowered = value.to_ascii_lowercase();
        if !value.is_ascii() {
            return None;
        }
        match lowered.as_str() {
            "*" => return Some(Self::Any),
            // `*.` and a bare dot name nothing.
            "" | "*." => return None,
            _ => {}
        }
        let lowered = lowered.strip_suffix('.').unwrap_or(&lowered);
        if let Some(suffix) = lowered.strip_prefix("*.") {
            if suffix.is_empty() || suffix.contains('*') {
                return None;
            }
            return Some(Self::Wildcard(suffix.to_owned()));
        }
        if lowered.contains('*') {
            return None;
        }
        if let Ok(addr) = lowered.parse() {
            return Some(Self::Address(addr));
        }
        Some(Self::Exact(lowered.to_owned()))
    }

    /// Whether the host a request names, already lowercase with any trailing
    /// dot stripped, is covered.
    pub(crate) fn matches(&self, host: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(name) => name == host,
            Self::Wildcard(suffix) => {
                host != suffix.as_str()
                    && host
                        .strip_suffix(suffix.as_str())
                        .is_some_and(|rest| rest.ends_with('.'))
            }
            Self::Address(addr) => host
                .parse()
                .is_ok_and(|parsed: std::net::IpAddr| parsed == *addr),
        }
    }
}

impl std::fmt::Display for HttpHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => write!(f, "*"),
            Self::Wildcard(suffix) => write!(f, "*.{suffix}"),
            Self::Exact(name) => write!(f, "{name}"),
            Self::Address(addr) => write!(f, "{addr}"),
        }
    }
}

/// The request path a rule bounds: exact, or a prefix when written with a
/// trailing `*`. No other wildcard. Matched against the path without the
/// query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpPath {
    /// The whole path, byte for byte.
    Exact(String),
    /// Everything that starts with this prefix, written `prefix*`.
    Prefix(String),
}

impl HttpPath {
    /// Parse the value a config file or flag writes, or `None` for anything
    /// else. A `*` is only ever the last character.
    pub fn parse(value: &str) -> Option<Self> {
        match value.strip_suffix('*') {
            Some(prefix) => (!prefix.contains('*')).then(|| Self::Prefix(prefix.to_owned())),
            None => (!value.contains('*')).then(|| Self::Exact(value.to_owned())),
        }
    }

    /// Whether a request path, with the query already stripped, is covered.
    fn matches(&self, path: &str) -> bool {
        match self {
            Self::Exact(exact) => exact == path,
            Self::Prefix(prefix) => path.starts_with(prefix.as_str()),
        }
    }
}

impl std::fmt::Display for HttpPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact(exact) => write!(f, "{exact}"),
            Self::Prefix(prefix) => write!(f, "{prefix}*"),
        }
    }
}

/// A permitted or dropped HTTP request.
///
/// A rule bounds its host always, and the port, the methods and the path only
/// when it names them: an unset port is any port, an empty method list is any
/// method, and no path is any path. Methods are written and matched in
/// uppercase, so a request whose method is anything else never matches an
/// allow rule and lands in the default refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRule {
    /// Who the rule names.
    pub host: HttpHost,
    /// Destination port, or `None` for any port. The broker applies the
    /// port defaults before it matches: 443 for a CONNECT, 80 for a
    /// cleartext request.
    pub port: Option<u16>,
    /// Methods the rule bounds, uppercase, or empty for any.
    pub methods: Vec<String>,
    /// The path the rule bounds, or `None` for any.
    pub path: Option<HttpPath>,
}

impl HttpRule {
    /// Whether a request is covered.
    fn matches(&self, req: &HttpRequest<'_>) -> bool {
        if !self.host.matches(req.host) {
            return false;
        }
        if self.port.is_some_and(|port| port != req.port) {
            return false;
        }
        if !self.methods.is_empty() && !self.methods.iter().any(|m| m == req.method) {
            return false;
        }
        match &self.path {
            None => true,
            Some(path) => path.matches(req.path),
        }
    }
}

/// A request the broker matches, with the port defaults applied and the
/// query already stripped from the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpRequest<'a> {
    /// The host the request names, lowercase, without a trailing dot.
    pub host: &'a str,
    /// The port the request names, after the defaults.
    pub port: u16,
    /// The method, uppercase.
    pub method: &'a str,
    /// The path, without the query.
    pub path: &'a str,
}

/// What the broker decided about one request, and which rule decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision<'a> {
    /// A deny rule matched.
    Denied(&'a HttpRule),
    /// An allow rule matched.
    Allowed(&'a HttpRule),
    /// No rule matched: refused, because nothing is allowed that no rule
    /// allows.
    Refused,
}

/// The shape of an attached credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthShape {
    /// `Authorization: Bearer <value>`.
    Bearer,
    /// A named header carrying the value raw.
    Header(String),
}

/// Where a credential value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialSource {
    /// An environment variable of the caller, read before the sandbox is
    /// made.
    Env(String),
    /// A file of the caller, read before the sandbox is made.
    File(PathBuf),
    /// A descriptor bailey already holds, read once.
    Fd(u32),
}

/// A credential the broker attaches to requests on an intercepted host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialBinding {
    /// The host it binds to, covered by an intercept entry.
    pub host: HttpHost,
    /// The request shape the value is attached as.
    pub auth: AuthShape,
    /// Where the value comes from.
    pub source: CredentialSource,
}

/// HTTP-level policy the built-in egress broker enforces.
///
/// The broker refuses a request unless an allow rule matches it, and drops
/// it when a deny rule matches, whatever the allowances say.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpPolicy {
    /// Hosts the broker intercepts: it terminates TLS for them, and decides
    /// every request inside the tunnel on its own. Written as exact names or
    /// `*.suffix`; `*` is refused at resolution.
    pub intercept: Vec<HttpHost>,
    /// Requests allowed, in order.
    pub allow: Vec<HttpRule>,
    /// Requests dropped ahead of every allowance, in order.
    pub deny: Vec<HttpRule>,
    /// Credentials bound to intercepted hosts.
    pub credentials: Vec<CredentialBinding>,
    /// The append-only JSONL audit log, or `None`. Caller's own config only.
    pub log: Option<PathBuf>,
    /// The config layer or flag that contributed the first HTTP rule, for
    /// the summary and refusals to name.
    pub source: Option<String>,
}

impl HttpPolicy {
    /// The decision for one request, and the rule that made it.
    pub fn decide(&self, req: &HttpRequest<'_>) -> Decision<'_> {
        if let Some(rule) = self.deny.iter().find(|rule| rule.matches(req)) {
            return Decision::Denied(rule);
        }
        if let Some(rule) = self.allow.iter().find(|rule| rule.matches(req)) {
            return Decision::Allowed(rule);
        }
        Decision::Refused
    }

    /// Whether the broker terminates TLS for a host.
    pub fn is_intercepted(&self, host: &str) -> bool {
        self.intercept.iter().any(|listed| listed.matches(host))
    }
}

/// The host a request may be matched on: lowercase, ASCII, and without a
/// trailing dot. `None` for anything else, which the broker refuses. A
/// trailing dot is refused rather than stripped, because a request that names
/// the DNS root is not a request any rule is written for.
pub fn request_host(value: &str) -> Option<String> {
    if value.is_empty() || !value.is_ascii() || value.ends_with('.') {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

/// Whether a request path is canonical: it
/// starts with `/`, contains no empty or dot segments, no backslash, no
/// semicolon, no control character, no malformed escape, and no escape of a
/// character (`/`, `\`, `.`, `;` or an unreserved one) that could let a
/// different path pass the rule a canonical one passes. Ordinary escapes
/// such as `%20` are left untouched. The query is never part of the path the
/// broker matches, so it is not considered here.
pub fn is_canonical_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    if path.contains("//") || path.contains('\\') {
        return false;
    }
    if rest
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return false;
    }
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let Some(escape) = bytes
                    .get(index + 1..index + 3)
                    .and_then(|hex| std::str::from_utf8(hex).ok())
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                else {
                    return false;
                };
                // Escapes of the characters RFC 3986 calls equivalent to
                // themselves, and of the separators a refusal turns on, would
                // let a path pass a rule and reach a different one upstream.
                if escape.is_ascii_alphanumeric()
                    || matches!(escape, b'-' | b'.' | b'_' | b'~' | b'/' | b'\\' | b';')
                {
                    return false;
                }
                index += 3;
            }
            b';' => return false,
            byte if byte < 0x20 || byte == 0x7f => return false,
            _ => index += 1,
        }
    }
    true
}

/// A host TCP service the target may reach on loopback, one port at a time.
///
/// The target dials `127.0.0.1:port` inside its own network namespace, and
/// bailey carries the connection to `127.0.0.1:host_port` on the host. Nothing
/// else crosses: the namespace stays routeless, so UDP, DNS, and every other
/// port stay dead, and the host's addressing stays invisible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortForward {
    /// The port the target dials.
    pub port: u16,
    /// The host port the connection lands on.
    pub host_port: u16,
}

/// A fully resolved, deny-by-default sandbox policy.
///
/// Any access not explicitly granted here is denied. This is the single value
/// consumed by both the enforcement and audit backends.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Filesystem grants, sorted by path.
    pub filesystem: Vec<FsRule>,
    /// Paths made read-only inside a writable parent, sorted by path.
    ///
    /// Landlock rules only add rights, so a read-only island in a granted
    /// hierarchy cannot be expressed as a rule. It is enforced by mounting the
    /// path over itself read-only, which the VFS honours regardless of Landlock,
    /// and therefore only works under the isolation layer.
    pub read_only: Vec<PathBuf>,
    /// Paths denied outright, sorted by path.
    ///
    /// A denial is total: no access is permitted to the path or anything under
    /// it, even where a grant covers a directory containing it. Denials that
    /// name a path no grant reaches are redundant, since anything ungranted is
    /// denied already.
    pub denied: Vec<PathBuf>,
    /// Network access policy.
    pub network: NetworkPolicy,
    /// Device grants, sorted by path.
    pub devices: Vec<DeviceRule>,
    /// Resource limits.
    pub resources: ResourceLimits,
    /// Which environment variables reach the target.
    pub env: EnvPolicy,
    /// Host directory to use as the target's private home, overriding the
    /// derived one.
    pub home: Option<PathBuf>,
    /// Whether the target may mount and unmount its own filesystems.
    ///
    /// Keeps `CAP_SYS_ADMIN` in the run's user namespace and allows the mount
    /// syscall family through seccomp, so the target can mount its own FUSE
    /// filesystems inside the sandbox. What it mounts lives and dies inside
    /// the run's mount namespace. The same power reaches every mount the run
    /// already holds, and two guarantees are enforced by mounts: a read-only
    /// island is a read-only mount, and a denial beneath a grant is an empty
    /// read-only mount covering the path. A partial egress allowance is
    /// enforced by the Landlock ruleset rather than by a mount, which this
    /// switch also gives up. Resolution therefore refuses a policy that asks
    /// for this and any of those at once.
    pub self_fuse: bool,
    /// FUSE mounts bailey performs before the target starts, in order.
    pub fuse: Vec<FuseMount>,
    /// Desktop service sockets relayed into the sandbox, in order.
    pub sockets: Vec<SocketRelay>,
    /// Host TCP ports the target may reach on loopback, in order.
    pub forwards: Vec<PortForward>,
    /// HTTP-level policy the built-in egress broker enforces.
    pub http: HttpPolicy,
}

impl Policy {
    /// Read-only paths that sit beneath a grant allowing writes.
    pub fn nested_read_only(&self) -> impl Iterator<Item = &PathBuf> {
        self.read_only.iter().filter(|path| {
            self.filesystem
                .iter()
                .any(|rule| rule.access.contains(Access::WRITE) && path.starts_with(&rule.path))
        })
    }

    /// Denials that sit beneath a grant which still covers them.
    ///
    /// These need a mechanism that can take access away, which Landlock rules
    /// cannot: access resolution walks up from the accessed path, so an ancestor
    /// grant satisfies it. Only the isolation layer can enforce these, by
    /// covering the path over.
    pub fn nested_denials(&self) -> impl Iterator<Item = &PathBuf> {
        self.denied.iter().filter(|denied| {
            self.filesystem
                .iter()
                .any(|rule| denied.starts_with(&rule.path) && **denied != rule.path)
        })
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;

    fn rule(host: &str) -> HttpRule {
        HttpRule {
            host: HttpHost::parse(host).unwrap(),
            port: None,
            methods: Vec::new(),
            path: None,
        }
    }

    fn check(path: &str) -> HttpRequest<'_> {
        HttpRequest {
            host: "api.github.com",
            port: 443,
            method: "GET",
            path,
        }
    }

    #[test]
    fn nothing_is_allowed_without_rules() {
        let policy = HttpPolicy::default();
        assert_eq!(policy.decide(&check("/x")), Decision::Refused);
    }

    #[test]
    fn a_deny_rule_wins_over_an_allow_rule() {
        let mut policy = HttpPolicy::default();
        policy.allow.push(rule("api.github.com"));
        policy.deny.push(rule("*"));
        assert!(matches!(policy.decide(&check("/x")), Decision::Denied(_)));
    }

    #[test]
    fn a_deny_rule_wins_over_a_later_allow_rule() {
        let mut policy = HttpPolicy::default();
        policy.deny.push(rule("*"));
        policy.allow.push(rule("api.github.com"));
        assert!(matches!(policy.decide(&check("/x")), Decision::Denied(_)));
    }

    #[test]
    fn a_wildcard_suffix_matches_subdomains_but_not_the_bare_suffix() {
        let host = HttpHost::parse("*.github.com").unwrap();
        assert!(host.matches("api.github.com"));
        assert!(host.matches("a.b.github.com"));
        assert!(!host.matches("github.com"));
        assert!(!host.matches("notgithub.com"));
    }

    #[test]
    fn an_exact_host_ignores_a_trailing_dot_and_case() {
        let host = HttpHost::parse("API.GitHub.com.").unwrap();
        assert_eq!(host, HttpHost::Exact("api.github.com".into()));
        assert!(host.matches("api.github.com"));
    }

    #[test]
    fn a_trailing_star_is_a_prefix() {
        let mut policy = HttpPolicy::default();
        let mut allow = rule("api.github.com");
        allow.path = HttpPath::parse("/repos/myorg/*");
        policy.allow.push(allow);
        assert!(matches!(
            policy.decide(&check("/repos/myorg/x")),
            Decision::Allowed(_)
        ));
        assert!(matches!(
            policy.decide(&check("/repos/myorg/x/y")),
            Decision::Allowed(_)
        ));
        assert_eq!(
            policy.decide(&check("/repos/myorgification")),
            Decision::Refused
        );
        assert_eq!(policy.decide(&check("/repos/other/x")), Decision::Refused);
    }

    #[test]
    fn an_exact_path_takes_no_wildcard() {
        assert_eq!(HttpPath::parse("/repos/*/x"), None);
        assert_eq!(HttpPath::parse("/re*pos"), None);
        let exact = HttpPath::parse("/repos").unwrap();
        assert_eq!(exact, HttpPath::Exact("/repos".into()));
    }

    #[test]
    fn a_query_is_never_part_of_the_path() {
        // The codec strips the query before it matches; the
        // matcher itself must not match through one either way.
        let mut policy = HttpPolicy::default();
        let mut allow = rule("api.github.com");
        allow.path = HttpPath::parse("/repos");
        policy.allow.push(allow);
        assert!(matches!(
            policy.decide(&check("/repos")),
            Decision::Allowed(_)
        ));
        assert_eq!(policy.decide(&check("/repos?x=1")), Decision::Refused);
        assert_eq!(policy.decide(&check("/reposbing")), Decision::Refused);
    }

    #[test]
    fn an_unset_port_matches_every_port_and_a_named_port_only_itself() {
        let mut policy = HttpPolicy::default();
        policy.allow.push(rule("api.github.com"));
        assert!(matches!(policy.decide(&check("/x")), Decision::Allowed(_)));
        let any_port = HttpRequest {
            port: 8443,
            ..check("/x")
        };
        assert!(matches!(policy.decide(&any_port), Decision::Allowed(_)));

        let mut policy = HttpPolicy::default();
        let mut pinned = rule("api.github.com");
        pinned.port = Some(8443);
        policy.allow.push(pinned);
        assert!(matches!(policy.decide(&any_port), Decision::Allowed(_)));
        assert_eq!(policy.decide(&check("/x")), Decision::Refused);
    }

    #[test]
    fn a_lowercase_method_never_matches_an_uppercase_rule() {
        let mut policy = HttpPolicy::default();
        let mut allow = rule("api.github.com");
        allow.methods = vec!["DELETE".into()];
        policy.allow.push(allow);
        let lower = HttpRequest {
            method: "delete",
            ..check("/x")
        };
        assert_eq!(policy.decide(&lower), Decision::Refused);
        let mixed = HttpRequest {
            method: "Delete",
            ..check("/x")
        };
        assert_eq!(policy.decide(&mixed), Decision::Refused);
        let upper = HttpRequest {
            method: "DELETE",
            ..check("/x")
        };
        assert!(matches!(policy.decide(&upper), Decision::Allowed(_)));
    }

    #[test]
    fn a_star_host_covers_everything_and_an_address_matches_a_literal() {
        let mut policy = HttpPolicy::default();
        policy.allow.push(rule("*"));
        let other = HttpRequest {
            host: "example.org",
            ..check("/x")
        };
        assert!(matches!(policy.decide(&other), Decision::Allowed(_)));

        let mut policy = HttpPolicy::default();
        let mut by_addr = rule("127.0.0.1");
        by_addr.port = Some(8080);
        policy.allow.push(by_addr);
        let literal = HttpRequest {
            host: "127.0.0.1",
            port: 8080,
            ..check("/x")
        };
        assert!(matches!(policy.decide(&literal), Decision::Allowed(_)));
        assert_eq!(policy.decide(&check("/x")), Decision::Refused);
    }

    #[test]
    fn host_parse_rejects_non_ascii_and_mid_globs() {
        assert_eq!(
            HttpHost::parse("*.example.com"),
            Some(HttpHost::Wildcard("example.com".into()))
        );
        assert_eq!(HttpHost::parse("*"), Some(HttpHost::Any));
        assert_eq!(
            HttpHost::parse("10.0.0.1"),
            Some(HttpHost::Address("10.0.0.1".parse().unwrap()))
        );
        assert_eq!(HttpHost::parse("bücher.example"), None);
        assert_eq!(HttpHost::parse("a*b.example"), None);
        assert_eq!(HttpHost::parse("*."), None);
        assert_eq!(HttpHost::parse(""), None);
    }

    #[test]
    fn interception_matches_the_same_host_forms() {
        let policy = HttpPolicy {
            intercept: HttpHost::parse("*.anthropic.com").into_iter().collect(),
            ..Default::default()
        };
        assert!(policy.is_intercepted("api.anthropic.com"));
        assert!(!policy.is_intercepted("anthropic.com"));
    }

    #[test]
    fn request_hosts_are_lowercased_and_trailing_dots_are_refused() {
        assert_eq!(
            request_host("API.GitHub.com"),
            Some("api.github.com".to_owned())
        );
        assert_eq!(request_host("api.github.com."), None);
        assert_eq!(request_host("."), None);
        assert_eq!(request_host(""), None);
        assert_eq!(request_host("bücher.example"), None);
        assert_eq!(request_host("10.0.0.1"), Some("10.0.0.1".to_owned()));
    }

    /// One row per input, with what the broker must answer: accepted paths
    /// are canonical, refused paths are not.
    #[test]
    fn canonical_path_table() {
        let accepted = [
            "/",
            "/repos",
            "/repos/",
            "/repos/myorg/x",
            "/repos/myorg/x%20y",
            "/repos/myorg/x?q=1", // the query is the codec's business, not a defect
            "/v1/deep/path/with/many/segments",
            "/repos/myorg/x/Y",
            "/control%1f", // a control character is refused raw, not escaped
        ];
        for path in accepted {
            assert!(super::is_canonical_path(path), "{path} should be canonical");
        }

        let refused = [
            "relative/path",     // no leading slash
            "",                  // empty
            "/double//slash",    // empty segment
            "/trailing/slash//", // empty segment at the end
            "/dot/.",            // a dot segment
            "/dot/../up",        // a dotdot segment
            "/%2e/hidden",       // escaped dot segment
            "/%2e%2e/up",        // escaped dotdot segment
            "/slash%2Fedit",     // an escaped separator
            "/back\\slash",      // a backslash
            "/back%5Cslash",     // an escaped backslash
            "/escape%61dmin",    // an escaped unreserved character
            "/escape%41dmin",    // an escaped unreserved character, upper
            "/tilde%7Ehome",     // an escaped unreserved character
            "/malformed%",       // a bare percent
            "/malformed%2",      // a truncated escape
            "/malformed%zz",     // not hex
            "/control\x01char",  // a control character
            "/a;b",              // a path parameter separator
            "/dot..;/up",        // a dotdot segment behind parameters
            "/..;/admin",        // a parameterised dotdot segment
            "/seg%3Btail",       // an escaped semicolon
        ];
        for path in refused {
            assert!(
                !super::is_canonical_path(path),
                "{path:?} should be refused"
            );
        }
    }

    #[test]
    fn ordinary_api_paths_pass_unchanged() {
        assert!(super::is_canonical_path("/v1/messages"));
        assert!(super::is_canonical_path(
            "/v1/messages/a-long-id-with-hyphens-and-numbers-42"
        ));
        assert!(super::is_canonical_path("/static/css/site.css"));
        assert!(super::is_canonical_path("/api/v2/items?limit=50&offset=0"));
    }
}
