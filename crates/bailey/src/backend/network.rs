//! Network confinement.
//!
//! Landlock's network rules cover TCP connect and bind, and nothing else, so a
//! policy that denies egress still lets UDP, QUIC, DNS, and ICMP off the host.
//! Where the policy denies egress outright, the target is instead placed in its
//! own network namespace with only a loopback interface, which has no route
//! anywhere and therefore denies every protocol at once. That also removes the
//! host's abstract UNIX socket namespace from reach, since it is per network
//! namespace.
//!
//! A policy that allows egress can have the same namespace behind pasta, which
//! copies no host address into it: the resolved policy's network mode decides
//! through [`decide`], with automatic mode preferring the namespace wherever
//! the host provides it. Without the namespace, or where the mode asks for the
//! host's, Landlock's port rules are the only restriction and the run reports
//! what that does not cover.
//!
//! A run given an egress broker is the exception: it is already in a namespace
//! of its own whose netfilter rule admits only the broker, so every other
//! destination and protocol is dropped there rather than left to Landlock.

use std::fs;
use std::io;

use nix::sched::{CloneFlags, unshare};

use crate::backend::isolation::{create_guard_namespace, set_user_namespace_limit};
use crate::policy::{Egress, Policy, PortForward};

/// How a run's network access is confined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Own network namespace with only loopback. Nothing leaves the host, at any
    /// protocol.
    Isolated,
    /// Own namespace behind pasta, with connectivity for allowed egress. The
    /// host's address, MAC, and loopback services stay out of reach.
    Private,
    /// Host network namespace, with Landlock rules over TCP ports. Other
    /// protocols are unrestricted.
    LandlockOnly,
    /// Own network namespace whose netfilter rule admits TCP to one broker and
    /// drops everything else: every other host and port, UDP, DNS, ICMP, and
    /// all of IPv6. Landlock's port rules apply on top.
    Brokered,
}

impl NetworkMode {
    /// A short description of what this mode enforces.
    pub fn describe(self) -> &'static str {
        match self {
            NetworkMode::Isolated => {
                "isolated (own namespace, loopback only, no route off the host)"
            }
            NetworkMode::Private => {
                "private (own namespace behind pasta; the host's address, MAC, and \
                 loopback services are not visible)"
            }
            NetworkMode::LandlockOnly => "landlock only (TCP ports; other protocols unrestricted)",
            NetworkMode::Brokered => {
                "brokered (own namespace, TCP to the broker only; UDP, DNS, ICMP dropped)"
            }
        }
    }

    /// The name a run's summary and `bailey show` report the mode by.
    pub fn name(self) -> &'static str {
        match self {
            NetworkMode::Isolated => "isolated",
            NetworkMode::Private => "private",
            NetworkMode::LandlockOnly => "host",
            NetworkMode::Brokered => "brokered",
        }
    }
}

/// What the host can provide for a network decision.
#[derive(Debug, Clone, Copy)]
pub struct HostCapabilities {
    /// Whether unprivileged user namespaces work, which both the denied-egress
    /// and the private namespace are built through.
    pub user_namespaces: bool,
    /// Whether pasta is available in a trusted location.
    pub pasta: bool,
    /// Whether `nft` is available in a trusted location, which the broker's
    /// lockdown rule needs.
    pub nft: bool,
}

/// The mode a run will get, with what chose it and why.
#[derive(Debug, Clone)]
pub struct NetworkDecision {
    /// The mode in force.
    pub mode: NetworkMode,
    /// The config layer or flag that chose the setting, or what automatic
    /// selection fell back to.
    pub source: String,
    /// Why this mode for this run: the automatic choice, or the fallback that
    /// downgraded it.
    pub reason: String,
}

/// Whether the policy cannot be honoured without the private namespace.
///
/// A forward under allowed egress needs pasta to carry it, a published port
/// needs a namespace the host can dial into, and a broker needs a namespace
/// its netfilter rule can hold. So does every rule that names a destination,
/// allows UDP, denies a destination, or denies DNS: netfilter in that
/// namespace is the only mechanism that carries them. Under automatic mode
/// their presence turns a fallback into a refusal; a feature forming a
/// boundary is never silently dropped.
pub fn needs_private_namespace(
    policy: &Policy,
    forwards: &[PortForward],
    publishes: &[u16],
) -> bool {
    let egress_allowed = !matches!(policy.network.egress, Egress::DenyAll);
    policy.network.needs_egress_namespace()
        || (egress_allowed && !forwards.is_empty())
        || !publishes.is_empty()
        || policy.network.broker.is_some()
}

/// Choose the confinement mode for `policy` on a host with `caps`, naming what
/// chose it and why.
///
/// A policy that denies egress keeps the loopback-only namespace in every mode:
/// the namespace is the only way to deny every protocol at once, and no mode
/// setting asks to give that up. A broker is honoured in every mode too, since
/// a boundary the policy names is not quietly dropped. For allowed egress
/// without a broker, the resolved mode decides, with automatic mode preferring
/// the private namespace wherever the host provides it.
pub fn decide(
    policy: &Policy,
    caps: &HostCapabilities,
    nested: bool,
    forwards: &[PortForward],
    publishes: &[u16],
) -> anyhow::Result<NetworkDecision> {
    // Inside a sandbox, `unshare` is refused by the outer filter, so the inner
    // run can build neither a namespace nor a netfilter rule. It enforces what
    // it can apply itself, Landlock's TCP port rules, and refuses a policy
    // that needs more: whatever the outer run provides is the outer policy's,
    // not this one's.
    if nested {
        if policy.network.broker.is_some() {
            anyhow::bail!(
                "a nested run cannot establish a broker, so the policy's \
                 broker ({}) cannot be honoured; run it outside the sandbox",
                policy.network.broker_source.as_deref().unwrap_or("unknown")
            );
        }
        if !publishes.is_empty() {
            anyhow::bail!(
                "a nested run cannot publish ports, which need a network \
                 namespace of the run's own"
            );
        }
        if policy.network.mode == crate::policy::NetworkMode::Private {
            anyhow::bail!(
                "a nested run cannot create a network namespace, so the \
                 policy's private mode ({}) cannot be honoured",
                policy.network.mode_source
            );
        }
        if !forwards.is_empty() {
            anyhow::bail!(
                "a nested run cannot create a network namespace of its own, so \
                 the policy's forwards cannot be carried"
            );
        }
        if policy.network.needs_egress_namespace() {
            anyhow::bail!(
                "a nested run cannot carry the policy's destination, UDP, deny \
                 and DNS rules, which are enforced in the private namespace's \
                 netfilter rules, and that namespace is one a nested run \
                 cannot build; run it outside the sandbox"
            );
        }
        return Ok(NetworkDecision {
            mode: NetworkMode::LandlockOnly,
            source: "nested run".to_owned(),
            reason: "inherits the network of the sandbox it runs in, and only \
                     the Landlock port rules are its own"
                .to_owned(),
        });
    }

    if let Some((addr, port)) = policy.network.broker {
        let source = policy.network.broker_source.as_deref().unwrap_or("unknown");
        if !caps.user_namespaces || !caps.pasta {
            anyhow::bail!(
                "the broker at {addr}:{port} ({source}) needs the private \
                 namespace, which needs {} ; the run is refused",
                if caps.user_namespaces {
                    "pasta, which is not in a trusted location"
                } else {
                    "user namespaces, which are unavailable"
                }
            );
        }
        if !caps.nft {
            anyhow::bail!(
                "the broker at {addr}:{port} ({source}) needs nft, which is \
                 not in a trusted location; the run is refused"
            );
        }
        // The broker's namespace is built for the broker alone, so
        // per-host destination rules have nothing to attach to: say so
        // where the mode is reported instead of silently carrying a
        // policy that does not apply.
        let mut reason = format!("egress is held to the broker at {addr}:{port}");
        if policy.network.needs_egress_namespace() {
            reason.push_str(
                "; the destination rules and DNS setting are \
                             superseded by the broker",
            );
        }
        return Ok(NetworkDecision {
            mode: NetworkMode::Brokered,
            source: source.to_owned(),
            reason,
        });
    }

    // A policy that denies egress keeps the private namespace whether or not it
    // binds a port. The namespace has loopback up, so a bound port is reachable
    // from inside the sandbox, which is what a policy that refuses every
    // outbound connection can coherently have meant. Falling back to the host's
    // namespace to publish the port would hand the run UDP, QUIC, DNS and ICMP
    // as well, none of which Landlock gates: the port would be served at the
    // cost of everything else being unrestricted.
    if matches!(policy.network.egress, Egress::DenyAll) {
        if caps.user_namespaces {
            return Ok(NetworkDecision {
                mode: NetworkMode::Isolated,
                source: "the policy denies egress".to_owned(),
                reason: "an own namespace is the only way to deny every \
                         protocol at once"
                    .to_owned(),
            });
        }
        if policy.network.needs_egress_namespace() {
            anyhow::bail!(
                "the policy's deny rules or DNS denial are enforced in the \
                 private namespace, which needs unprivileged user \
                 namespaces, which are unavailable; the run is refused"
            );
        }
        return Ok(NetworkDecision {
            mode: NetworkMode::LandlockOnly,
            source: "the policy denies egress".to_owned(),
            reason: "unprivileged user namespaces are unavailable, so only \
                     Landlock's TCP rules could be applied"
                .to_owned(),
        });
    }

    let setting = policy.network.mode;
    let source = policy.network.mode_source.clone();
    if setting == crate::policy::NetworkMode::Host {
        return Ok(NetworkDecision {
            mode: NetworkMode::LandlockOnly,
            source,
            reason: "the host's namespace, where Landlock's TCP port rules \
                     are the only restriction"
                .to_owned(),
        });
    }
    if setting == crate::policy::NetworkMode::Private {
        if !caps.user_namespaces || !caps.pasta {
            anyhow::bail!(
                "the policy's private mode ({source}) needs {}, which this \
                 host cannot provide; the run is refused",
                if caps.user_namespaces {
                    "pasta, which is not in a trusted location"
                } else {
                    "unprivileged user namespaces, which are unavailable"
                }
            );
        }
        require_nft_for_allowed_egress(policy, caps, &source)?;
        return Ok(NetworkDecision {
            mode: NetworkMode::Private,
            source,
            reason: "the policy asks for the private namespace".to_owned(),
        });
    }

    // Automatic mode: the private namespace wherever the host provides it
    // and can enforce the rules that make it the boundary. Without `nft` a
    // policy that needs nothing the namespace alone provides falls back to
    // the host's namespace below, which confines more than a tableless
    // private one would, and one that needs the namespace is refused,
    // naming `nft` as what is missing.
    if caps.user_namespaces && caps.pasta {
        if caps.nft {
            return Ok(NetworkDecision {
                mode: NetworkMode::Private,
                source,
                reason: "the host provides the private namespace, which automatic \
                         mode prefers"
                    .to_owned(),
            });
        }
        if needs_private_namespace(policy, forwards, publishes) {
            anyhow::bail!(
                "the egress rules are enforced by netfilter in the private \
                 namespace, which needs nft, which is not in a trusted \
                 location; the run is refused (mode {source})"
            );
        }
    }
    if needs_private_namespace(policy, forwards, publishes) {
        let missing = if !caps.user_namespaces {
            "unprivileged user namespaces, which are unavailable"
        } else if !caps.pasta {
            "pasta, which is not in a trusted location"
        } else {
            "nft, which is not in a trusted location"
        };
        let needed = if !publishes.is_empty() {
            "the published ports"
        } else if !forwards.is_empty() {
            "the port forwards"
        } else if policy.network.needs_egress_namespace() {
            "the policy's destination, UDP and deny rules"
        } else {
            "the policy"
        };
        anyhow::bail!(
            "{needed} need the private namespace, which needs {missing}; \
             the run is refused"
        );
    }
    let missing = if !caps.user_namespaces {
        "unprivileged user namespaces are unavailable"
    } else if !caps.pasta {
        "pasta is not in a trusted location"
    } else {
        "nft is not in a trusted location"
    };
    Ok(NetworkDecision {
        mode: NetworkMode::LandlockOnly,
        source,
        reason: format!(
            "automatic mode fell back to the host's namespace because \
             {missing}, so the host's address and loopback are visible and \
             only TCP ports are restricted"
        ),
    })
}

/// Require `nft` where the private namespace carries the egress rules.
///
/// Landlock's port rules bound TCP before netfilter did, so an egress-allowed
/// private run could once survive without `nft`. With destination rules and
/// the DNS setting in the table, the netfilter rules are the boundary
/// itself: a table that cannot be installed would leave the run wider than
/// the policy, so the run is refused instead.
fn require_nft_for_allowed_egress(
    policy: &Policy,
    caps: &HostCapabilities,
    source: &str,
) -> anyhow::Result<()> {
    if !matches!(policy.network.egress, Egress::DenyAll) && !caps.nft {
        anyhow::bail!(
            "the egress rules are enforced by netfilter in the private \
             namespace, which needs nft, which is not in a trusted \
             location; the run is refused (mode {source})"
        );
    }
    Ok(())
}

/// Whether a bound port will only be reachable from inside the sandbox.
///
/// Worth saying out loud: the policy names a port, and in this mode nothing
/// outside can connect to it.
pub fn bind_is_loopback_only(policy: &Policy, mode: NetworkMode) -> bool {
    mode == NetworkMode::Isolated
        && !policy.network.bind_ports.is_empty()
        && policy.network.publish_ports.is_empty()
}

/// The mode a run confined by [`crate::backend::audit`] reports, which is the
/// shape of answer the pre-mode summary gave.
///
/// Audit runs in the host namespace by design, so it never selects the private
/// namespace for allowed egress: a policy that denies egress and can build a
/// namespace still gets the loopback-only one, because Landlock alone would
/// leave UDP open. The decision [`decide`] makes for a run carries more, and
/// audit reports what the policy's mode would have done instead of applying it.
pub fn select(policy: &Policy, userns: bool) -> NetworkMode {
    if userns && matches!(policy.network.egress, Egress::DenyAll) {
        NetworkMode::Isolated
    } else {
        NetworkMode::LandlockOnly
    }
}

/// Report the confinement that is actually in force, when it is weaker than the
/// policy reads.
///
/// What network an outer bailey run has already put this process in.
///
/// A run inside a sandbox cannot create a namespace of its own, because the
/// outer seccomp filter denies `unshare`, so what it has is whatever it
/// inherited. Guessing is not good enough in either direction: claiming UDP is
/// unrestricted when there is no route to send it on is as wrong as staying
/// silent when there is one. The outer run says which it built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inherited {
    /// Not inside another sandbox.
    None,
    /// Inside one with a namespace of its own and no route off the host.
    IsolatedNamespace,
    /// Inside one behind pasta, with connectivity for allowed egress.
    PrivateNamespace,
    /// Inside one that shares the host's network namespace.
    HostNamespace,
    /// Inside one whose egress is held to a single broker.
    Brokered,
}

impl Inherited {
    /// Read what the outer run published in this process's environment.
    pub fn detect() -> Self {
        Self::read(std::env::var("BAILEY_SANDBOX_NET").ok().as_deref())
    }

    fn read(published: Option<&str>) -> Self {
        match published {
            Some("isolated") => Inherited::IsolatedNamespace,
            Some("private") => Inherited::PrivateNamespace,
            Some("broker") => Inherited::Brokered,
            Some(_) => Inherited::HostNamespace,
            None => Inherited::None,
        }
    }

    /// The value an outer run publishes for the mode it established.
    pub fn publish(mode: NetworkMode) -> &'static str {
        match mode {
            NetworkMode::Isolated => "isolated",
            NetworkMode::Private => "private",
            NetworkMode::LandlockOnly => "host",
            NetworkMode::Brokered => "broker",
        }
    }
}

/// Report the confinement that is actually in force, when it differs from what
/// the policy reads.
///
/// A run that fully denies the network says nothing, in keeping with the rest of
/// the tool: output means something needs attention.
///
/// Private mode stays in scope on purpose: its namespace carries allowed egress,
/// but the run's own rules still gate TCP ports only, so a partial allowance
/// leaves every other protocol free to leave through pasta.
pub fn report(mode: NetworkMode, policy: &Policy, inherited: Inherited) {
    if matches!(mode, NetworkMode::Isolated | NetworkMode::Brokered) {
        return;
    }
    if inherited == Inherited::Brokered {
        if !matches!(policy.network.egress, Egress::DenyAll) {
            eprintln!(
                "bailey: note: the sandbox this run is inside holds egress to a \
                 single broker, so only connections through it will succeed; \
                 UDP, DNS, and ICMP are dropped"
            );
        }
        return;
    }
    if inherited == Inherited::IsolatedNamespace {
        // The inherited namespace has no route, so this policy cannot be weaker
        // than it reads. It can be stronger than it reads, which is worth
        // saying: an outbound connection that the policy allows will still fail.
        if !matches!(policy.network.egress, Egress::DenyAll) {
            eprintln!(
                "bailey: note: this policy allows outbound access, but the \
                 sandbox this run is inside has no route off the host, so \
                 nothing will connect"
            );
        }
        return;
    }
    if inherited == Inherited::PrivateNamespace {
        // The inherited namespace is behind pasta, so the host's address and
        // loopback are out of reach, and what leaves travels the same path the
        // outer run's traffic does. This run's own rules still only cover TCP.
        match &policy.network.egress {
            Egress::DenyAll => eprintln!(
                "bailey: warning: egress is denied, but only TCP is blocked by \
                 this run's rules, so UDP, QUIC, and DNS still leave through \
                 the sandbox it is inside"
            ),
            Egress::Allow(_) | Egress::AllowAll => eprintln!(
                "bailey: note: this run inherits the private network of the \
                 sandbox it is inside, so the host's address and loopback \
                 services are not visible, and its own rules restrict TCP \
                 ports only"
            ),
        }
        return;
    }
    match &policy.network.egress {
        Egress::DenyAll => eprintln!(
            "bailey: warning: egress is denied but no network namespace could be \
             created, so only TCP is blocked; UDP, QUIC, and DNS are not"
        ),
        Egress::Allow(_) => eprintln!(
            "bailey: warning: outbound access is restricted by TCP port only; \
             non-TCP protocols such as UDP, QUIC, SCTP, and DNS are not restricted"
        ),
        Egress::AllowAll => {}
    }
}

/// Enter a network namespace of our own, via a user namespace so it needs no
/// privilege.
///
/// The uid mapping is the identity, unlike the isolation layer's mapping to
/// root: nothing here needs privileged operations beyond creating the namespace,
/// and keeping the uid unchanged keeps file ownership looking the same to the
/// target.
/// Create the network namespace an egress proxy is bounded by.
///
/// Mapped to root inside, where the target's own namespace is mapped to the
/// caller's uid. The lockdown rule is installed by running `nft`, and a process
/// that is not uid 0 in its user namespace loses its capabilities on `execve`,
/// so the helper would arrive without the one capability it needs over the
/// namespace it was started for. pasta mapped to root for the same reason when
/// it was the one creating this namespace.
///
/// The target is unaffected: the isolation layer builds its own user namespace
/// nested in this one and maps the caller's uid there, which is what a program
/// that refuses to run as root, or authenticates over D-Bus, needs to see.
pub fn enter_proxy_namespace(limit: u32) -> io::Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // Before the unshare, while getuid still answers with the host's numbers:
    // the map below makes this namespace's caller 0, and the namespaces built
    // beneath it must present the host identity, not that 0.
    crate::backend::isolation::capture_host_identity();

    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWIPC)
        .map_err(errno)?;
    fs::write("/proc/self/setgroups", "deny")?;
    fs::write("/proc/self/gid_map", format!("0 {gid} 1"))?;
    fs::write("/proc/self/uid_map", format!("0 {uid} 1"))?;

    // The proxy namespace is the run's guard: the isolation layer nests the
    // run's own user namespace inside it, and the limit says whether anything
    // may be created beneath it at all. pasta, which joins the namespace, does
    // not create one.
    set_user_namespace_limit(limit)?;

    bring_loopback_up()
}

pub fn enter_isolated(create_guard: bool) -> io::Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // Before the unshare, while getuid still answers with the host's numbers.
    crate::backend::isolation::capture_host_identity();
    if create_guard {
        create_guard_namespace(1)?;
    }

    // The IPC namespace comes along here too: SysV and POSIX IPC objects are
    // not files, so nothing in the filesystem policy can withhold them.
    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWIPC)
        .map_err(errno)?;
    // The shared writer presents the host identity: from inside a proxy
    // namespace, getuid answers 0, and mapping that straight back would make
    // the target root.
    crate::backend::isolation::write_identity_map(uid, gid)?;

    bring_loopback_up()
}

/// Bring the loopback interface up inside the current network namespace.
///
/// A fresh namespace starts with loopback down, so a target that binds a local
/// port for its own use would fail. Loopback here reaches nothing but the
/// sandbox itself.
pub fn bring_loopback_up() -> io::Result<()> {
    // `libc::Ioctl` rather than a fixed integer type: the request argument is
    // `c_ulong` against glibc and `c_int` against musl, and hard-coding either
    // makes the crate build for only one of them.
    const SIOCGIFFLAGS: libc::Ioctl = 0x8913;
    const SIOCSIFFLAGS: libc::Ioctl = 0x8914;

    // The kernel's `ifreq`: a name and a union of same-sized members. Only the
    // flags member is used here, so the rest is padding.
    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IF_NAMESIZE],
        flags: libc::c_short,
        _padding: [u8; 22],
    }

    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut request = IfReq {
        name: [0; libc::IF_NAMESIZE],
        flags: 0,
        _padding: [0; 22],
    };
    request.name[0] = b'l' as libc::c_char;
    request.name[1] = b'o' as libc::c_char;

    let mut result = unsafe { libc::ioctl(socket, SIOCGIFFLAGS, &mut request as *mut IfReq) };
    if result >= 0 {
        request.flags |= libc::IFF_UP as libc::c_short;
        result = unsafe { libc::ioctl(socket, SIOCSIFFLAGS, &mut request as *mut IfReq) };
    }
    unsafe { libc::close(socket) };

    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn errno(err: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(err as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Destination, EgressRule, NetworkPolicy, Protocol};

    fn policy_with(network: NetworkPolicy) -> Policy {
        Policy {
            network,
            ..Policy::default()
        }
    }

    fn caps(pasta: bool, user_namespaces: bool, nft: bool) -> HostCapabilities {
        HostCapabilities {
            user_namespaces,
            pasta,
            nft,
        }
    }

    #[test]
    fn denied_egress_selects_the_namespace() {
        let policy = policy_with(NetworkPolicy::default());
        assert_eq!(select(&policy, true), NetworkMode::Isolated);
    }

    #[test]
    fn without_user_namespaces_it_falls_back() {
        let policy = policy_with(NetworkPolicy::default());
        assert_eq!(select(&policy, false), NetworkMode::LandlockOnly);
    }

    #[test]
    fn allowed_egress_stays_on_landlock() {
        let policy = policy_with(NetworkPolicy {
            egress: Egress::Allow(vec![EgressRule {
                host: Destination::Any,
                protocol: Protocol::Tcp,
                port: Some(443),
            }]),
            ..NetworkPolicy::default()
        });
        assert_eq!(select(&policy, true), NetworkMode::LandlockOnly);
    }

    /// A rule naming a destination, a UDP rule, a deny rule and a DNS denial
    /// are all netfilter work: under automatic mode they make the private
    /// namespace required, so a host without it refuses the run instead of
    /// silently dropping the boundary the policy names.
    #[test]
    fn destination_rules_require_the_private_namespace() {
        let no_caps = caps(false, false, false);
        let full = caps(true, true, true);

        let named = policy_with(NetworkPolicy {
            egress: Egress::Allow(vec![EgressRule {
                host: Destination::Name("api.example.com".to_owned()),
                protocol: Protocol::Tcp,
                port: Some(443),
            }]),
            ..NetworkPolicy::default()
        });
        assert_eq!(
            decide(&named, &full, false, &[], &[]).unwrap().mode,
            NetworkMode::Private
        );
        let err = decide(&named, &no_caps, false, &[], &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("destination, UDP and deny rules"), "{err}");

        let udp = policy_with(NetworkPolicy {
            egress: Egress::Allow(vec![EgressRule {
                host: Destination::Any,
                protocol: Protocol::Udp,
                port: Some(27015),
            }]),
            ..NetworkPolicy::default()
        });
        assert!(decide(&udp, &no_caps, false, &[], &[]).is_err());

        let denied = policy_with(NetworkPolicy {
            egress: Egress::AllowAll,
            deny: vec![crate::policy::DenyRule {
                host: Destination::Address("169.254.169.254".parse().unwrap()),
                port: None,
            }],
            ..NetworkPolicy::default()
        });
        assert_eq!(
            decide(&denied, &full, false, &[], &[]).unwrap().mode,
            NetworkMode::Private
        );
        assert!(decide(&denied, &no_caps, false, &[], &[]).is_err());

        let no_dns = policy_with(NetworkPolicy {
            egress: Egress::AllowAll,
            dns: crate::policy::DnsSetting::Deny,
            ..NetworkPolicy::default()
        });
        assert_eq!(
            decide(&no_dns, &full, false, &[], &[]).unwrap().mode,
            NetworkMode::Private
        );
        assert!(decide(&no_dns, &no_caps, false, &[], &[]).is_err());
    }

    /// Automatic mode falls back to the host's namespace when `nft` is
    /// missing and nothing needs the private one: a tableless private
    /// namespace would enforce less than the fallback does, so the fallback
    /// is the answer. A policy that needs the namespace is still refused,
    /// naming `nft` as what is missing.
    #[test]
    fn a_missing_nft_falls_back_when_nothing_needs_the_namespace() {
        let no_nft = caps(true, true, false);

        // A plain allowance needs no namespace: the fallback bounds TCP by
        // port, which a tableless namespace would not.
        let plain = policy_with(NetworkPolicy {
            egress: Egress::AllowAll,
            ..NetworkPolicy::default()
        });
        let decision = decide(&plain, &no_nft, false, &[], &[]).unwrap();
        assert_eq!(decision.mode, NetworkMode::LandlockOnly);
        assert!(decision.reason.contains("nft"), "{decision:?}");

        // Destination rules are netfilter work: they are refused, not
        // silently dropped on the fallback.
        let named = policy_with(NetworkPolicy {
            egress: Egress::Allow(vec![EgressRule {
                host: Destination::Name("api.example.com".to_owned()),
                protocol: Protocol::Tcp,
                port: Some(443),
            }]),
            ..NetworkPolicy::default()
        });
        let err = decide(&named, &no_nft, false, &[], &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("nft"), "{err}");
    }

    /// A deny rule or DNS denial beside denied egress still needs the
    /// namespace: the Landlock-only fallback denies TCP by port rules but
    /// leaves DNS and UDP open, which would drop the boundary those name.
    #[test]
    fn a_deny_or_dns_denial_under_denied_egress_requires_the_namespace() {
        let no_userns = caps(true, false, false);

        let denied_dns = policy_with(NetworkPolicy {
            dns: crate::policy::DnsSetting::Deny,
            ..NetworkPolicy::default()
        });
        let err = decide(&denied_dns, &no_userns, false, &[], &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("DNS denial"), "{err}");
        assert_eq!(
            decide(&denied_dns, &caps(true, true, true), false, &[], &[])
                .unwrap()
                .mode,
            NetworkMode::Isolated
        );

        let denied_dest = policy_with(NetworkPolicy {
            deny: vec![crate::policy::DenyRule {
                host: Destination::Address("169.254.169.254".parse().unwrap()),
                port: None,
            }],
            ..NetworkPolicy::default()
        });
        assert!(decide(&denied_dest, &no_userns, false, &[], &[]).is_err());

        // Without either, denied egress degrades to the port rules as before.
        let plain = NetworkPolicy::default();
        assert_eq!(
            decide(&policy_with(plain), &no_userns, false, &[], &[])
                .unwrap()
                .mode,
            NetworkMode::LandlockOnly
        );
    }

    /// Publishing a bound port used to cost the whole namespace, which handed
    /// the run UDP, QUIC, DNS and ICMP as well: a policy that denied egress
    /// could still send a UDP packet to the internet.
    #[test]
    fn a_bound_port_keeps_the_private_namespace() {
        let policy = policy_with(NetworkPolicy {
            egress: Egress::DenyAll,
            bind_ports: vec![27015],
            publish_ports: Vec::new(),
            ..NetworkPolicy::default()
        });
        assert_eq!(select(&policy, true), NetworkMode::Isolated);
        assert!(bind_is_loopback_only(&policy, NetworkMode::Isolated));

        // Without user namespaces there is no private namespace to keep.
        assert_eq!(select(&policy, false), NetworkMode::LandlockOnly);
        assert!(!bind_is_loopback_only(&policy, NetworkMode::LandlockOnly));
    }

    /// A proxied run makes its own network namespace before the backend is
    /// reached, so the backend must not make a second one and throw away the
    /// one pasta configured. The backend is told the run is brokered and skips
    /// the selection, but the policy it is given would not select a namespace
    /// either, so losing that flag would still keep the egress rule.
    #[test]
    fn a_proxied_run_is_not_given_a_second_network_namespace() {
        // What `permit_broker_port` leaves behind for a brokered run.
        let policy = policy_with(NetworkPolicy {
            egress: Egress::Allow(vec![EgressRule {
                host: Destination::Any,
                protocol: Protocol::Tcp,
                port: Some(8443),
            }]),
            bind_ports: Vec::new(),
            publish_ports: Vec::new(),
            ..NetworkPolicy::default()
        });
        assert_eq!(select(&policy, true), NetworkMode::LandlockOnly);
    }

    /// A nested run inside a brokered session used to read it as the host's
    /// network and warn that UDP was open, when the broker's rule drops it.
    #[test]
    fn a_nested_run_reads_back_what_the_outer_run_published() {
        assert_eq!(
            Inherited::read(Some(Inherited::publish(NetworkMode::Isolated))),
            Inherited::IsolatedNamespace
        );
        assert_eq!(
            Inherited::read(Some(Inherited::publish(NetworkMode::Private))),
            Inherited::PrivateNamespace
        );
        assert_eq!(
            Inherited::read(Some(Inherited::publish(NetworkMode::LandlockOnly))),
            Inherited::HostNamespace
        );
        assert_eq!(
            Inherited::read(Some(Inherited::publish(NetworkMode::Brokered))),
            Inherited::Brokered
        );
        assert_eq!(Inherited::read(None), Inherited::None);
    }

    /// A policy that allows egress still needs the host's network.
    #[test]
    fn allowing_egress_still_uses_the_host_network() {
        let policy = policy_with(NetworkPolicy {
            egress: Egress::Allow(vec![]),
            bind_ports: vec![27015],
            publish_ports: Vec::new(),
            ..NetworkPolicy::default()
        });
        assert_eq!(select(&policy, true), NetworkMode::LandlockOnly);
    }

    /// Every row of the sandbox-network delta, decided exactly as written.
    /// The mode setting and the broker ride in the policy, the host's
    /// capabilities in `caps`, and forwards and published ports travel beside
    /// the policy the way the caller collects them.
    #[test]
    fn the_mode_delta_rows_decide_as_specified() {
        let full = caps(true, true, true);
        let no_pasta = caps(false, true, true);
        let no_userns = caps(true, false, true);

        // A project config selects the private namespace.
        let private = policy_with(NetworkPolicy {
            egress: Egress::Allow(vec![EgressRule {
                host: Destination::Any,
                protocol: Protocol::Tcp,
                port: Some(443),
            }]),
            mode: crate::policy::NetworkMode::Private,
            mode_source: "/project/bailey.toml".to_owned(),
            ..NetworkPolicy::default()
        });
        let decision = decide(&private, &full, false, &[], &[]).unwrap();
        assert_eq!(decision.mode, NetworkMode::Private);
        assert_eq!(decision.source, "/project/bailey.toml");

        // Denied egress is unaffected by mode.
        let denied_host = policy_with(NetworkPolicy {
            mode: crate::policy::NetworkMode::Host,
            ..NetworkPolicy::default()
        });
        assert_eq!(
            decide(&denied_host, &full, false, &[], &[]).unwrap().mode,
            NetworkMode::Isolated
        );

        // A broker in policy is brokered in every mode, refused where nft or
        // the namespace is missing.
        let mut brokered = private.clone();
        brokered.network.broker = Some(("169.254.169.1".parse().unwrap(), 8443));
        brokered.network.broker_source = Some("/project/bailey.toml".to_owned());
        assert_eq!(
            decide(&brokered, &full, false, &[], &[]).unwrap().mode,
            NetworkMode::Brokered
        );
        let refused = decide(&brokered, &no_pasta, false, &[], &[])
            .unwrap_err()
            .to_string();
        assert!(refused.contains("pasta"), "{refused}");
        assert!(refused.contains("/project/bailey.toml"), "{refused}");
        let refused = decide(&brokered, &caps(true, true, false), false, &[], &[])
            .unwrap_err()
            .to_string();
        assert!(refused.contains("nft"), "{refused}");

        // Automatic mode prefers the private namespace where the host
        // provides it, and continues on the host's network where it does not,
        // unless the policy needs the namespace.
        let auto = policy_with(NetworkPolicy {
            egress: Egress::AllowAll,
            ..NetworkPolicy::default()
        });
        let decision = decide(&auto, &full, false, &[], &[]).unwrap();
        assert_eq!(decision.mode, NetworkMode::Private);
        let decision = decide(&auto, &no_pasta, false, &[], &[]).unwrap();
        assert_eq!(decision.mode, NetworkMode::LandlockOnly);
        assert!(decision.reason.contains("pasta"), "{}", decision.reason);

        let forward = PortForward {
            port: 8080,
            host_port: 8080,
        };
        let forwards = [forward];
        let refused = decide(&auto, &no_pasta, false, &forwards, &[])
            .unwrap_err()
            .to_string();
        assert!(refused.contains("pasta"), "{refused}");
        assert!(refused.contains("forward"), "{refused}");

        // Explicit private mode refuses rather than degrades, whatever asked
        // for it, a config layer or a flag.
        for source in ["/project/bailey.toml", "flag --proxy-net"] {
            let mut explicit = auto.clone();
            explicit.network.mode = crate::policy::NetworkMode::Private;
            explicit.network.mode_source = source.to_owned();
            let refused = decide(&explicit, &no_pasta, false, &[], &[])
                .unwrap_err()
                .to_string();
            assert!(refused.contains("pasta"), "{refused}");
            assert!(refused.contains(source), "{refused}");
            let refused = decide(&explicit, &no_userns, false, &[], &[])
                .unwrap_err()
                .to_string();
            assert!(refused.contains("user namespaces"), "{refused}");
        }

        // Host mode keeps the host namespace, and a nested run refuses what
        // it cannot enforce while inheriting the outer run's network.
        let host = policy_with(NetworkPolicy {
            egress: Egress::AllowAll,
            mode: crate::policy::NetworkMode::Host,
            mode_source: "/project/bailey.toml".to_owned(),
            ..NetworkPolicy::default()
        });
        assert_eq!(
            decide(&host, &full, false, &[], &[]).unwrap().mode,
            NetworkMode::LandlockOnly
        );
        let nested = decide(&host, &full, true, &[], &[]).unwrap();
        assert_eq!(nested.mode, NetworkMode::LandlockOnly);
        assert_eq!(nested.source, "nested run");
        let refused = decide(&brokered, &full, true, &[], &[])
            .unwrap_err()
            .to_string();
        assert!(refused.contains("nested"), "{refused}");
        let refused = decide(&private, &full, true, &[], &[])
            .unwrap_err()
            .to_string();
        assert!(refused.contains("nested"), "{refused}");
        let refused = decide(&host, &full, true, &forwards, &[])
            .unwrap_err()
            .to_string();
        assert!(refused.contains("nested"), "{refused}");
    }

    /// The names the summary reports the modes by.
    #[test]
    fn modes_report_their_names() {
        assert_eq!(NetworkMode::Isolated.name(), "isolated");
        assert_eq!(NetworkMode::Private.name(), "private");
        assert_eq!(NetworkMode::LandlockOnly.name(), "host");
        assert_eq!(NetworkMode::Brokered.name(), "brokered");
    }
}
