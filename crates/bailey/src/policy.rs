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
                    let loopback = u32::from(std::net::Ipv4Addr::LOCALHOST)
                        & mask(*prefix, 32);
                    bits & mask(*prefix, 32) == loopback
                }
                std::net::IpAddr::V6(v6) => {
                    let bits = u128::from(*v6);
                    let loopback = u128::from(std::net::Ipv6Addr::LOCALHOST)
                        & mask6(*prefix);
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

/// Network access intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    /// Outbound connection policy.
    pub egress: Egress,
    /// How the run picks a namespace when egress is allowed.
    pub mode: NetworkMode,
    /// The egress broker a run is held to, as `ADDR:PORT`. Implies the private
    /// namespace, whatever `mode` says.
    pub broker: Option<(std::net::Ipv4Addr, u16)>,
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
        self.dns == DnsSetting::Deny
            || !self.deny.is_empty()
            || self.egress_rules_need_namespace()
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
