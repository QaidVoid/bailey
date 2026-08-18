//! Mechanism-independent sandbox policy model.
//!
//! A [`Policy`] expresses the intent of a sandbox: which filesystem paths,
//! network destinations, and devices a target may reach, and what resource
//! limits apply. It is deliberately independent of any enforcement mechanism so
//! that the enforcement and audit backends can each interpret the same value.

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
    }
}

/// A single filesystem grant: a path hierarchy and the rights allowed on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsRule {
    /// The path hierarchy the grant applies to.
    pub path: PathBuf,
    /// The rights granted on the hierarchy.
    pub access: Access,
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
    /// Destination hostname or CIDR block.
    pub host: String,
    /// Destination port, or `None` for any port.
    pub port: Option<u16>,
}

/// Network access intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    /// Outbound connection policy.
    pub egress: Egress,
    /// TCP ports the target is allowed to bind.
    pub bind_ports: Vec<u16>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            egress: Egress::DenyAll,
            bind_ports: Vec::new(),
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

/// Resource limits applied via cgroups.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Maximum resident memory in bytes.
    pub memory_bytes: Option<u64>,
    /// Maximum number of processes and threads.
    pub pids_max: Option<u64>,
    /// CPU quota as a percentage of a single core (100 = one full core).
    pub cpu_percent: Option<u32>,
}

/// A fully resolved, deny-by-default sandbox policy.
///
/// Any access not explicitly granted here is denied. This is the single value
/// consumed by both the enforcement and audit backends.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Filesystem grants, sorted by path.
    pub filesystem: Vec<FsRule>,
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
}

impl Policy {
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
