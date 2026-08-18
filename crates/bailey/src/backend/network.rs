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
//! Where the policy allows some egress, the namespace cannot be used without
//! also providing connectivity into it, so enforcement falls back to Landlock's
//! port rules and the run reports what that does not cover.

use std::fs;
use std::io;

use nix::sched::{CloneFlags, unshare};

use crate::policy::{Egress, Policy};

/// How a run's network access is confined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Own network namespace with only loopback. Nothing leaves the host, at any
    /// protocol.
    Isolated,
    /// Host network namespace, with Landlock rules over TCP ports. Other
    /// protocols are unrestricted.
    LandlockOnly,
}

impl NetworkMode {
    /// A short description of what this mode enforces.
    pub fn describe(self) -> &'static str {
        match self {
            NetworkMode::Isolated => {
                "isolated (own namespace, loopback only, no route off the host)"
            }
            NetworkMode::LandlockOnly => "landlock only (TCP ports; other protocols unrestricted)",
        }
    }
}

/// Choose the confinement mode for `policy` on a host where user namespaces are
/// or are not available.
///
/// The namespace is only usable where the policy needs no connectivity at all:
/// a namespace with no route cannot serve a policy that allows egress or binds a
/// port, so those fall back to Landlock's port rules.
pub fn select(policy: &Policy, userns_available: bool) -> NetworkMode {
    let needs_no_network =
        matches!(policy.network.egress, Egress::DenyAll) && policy.network.bind_ports.is_empty();
    if needs_no_network && userns_available {
        NetworkMode::Isolated
    } else {
        NetworkMode::LandlockOnly
    }
}

/// Report the confinement that is actually in force, when it is weaker than the
/// policy reads.
///
/// A run that fully denies the network says nothing, in keeping with the rest of
/// the tool: output means something needs attention.
pub fn report(mode: NetworkMode, policy: &Policy) {
    if mode == NetworkMode::Isolated {
        return;
    }
    match &policy.network.egress {
        Egress::DenyAll => eprintln!(
            "bailey: warning: egress is denied but no network namespace could be \
             created, so only TCP is blocked; UDP, QUIC, and DNS are not"
        ),
        Egress::Allow(_) => eprintln!(
            "bailey: warning: outbound access is restricted by TCP port only; \
             UDP, QUIC, and DNS are not restricted"
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
pub fn enter_isolated() -> io::Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET).map_err(errno)?;
    fs::write("/proc/self/setgroups", "deny")?;
    fs::write("/proc/self/gid_map", format!("{gid} {gid} 1"))?;
    fs::write("/proc/self/uid_map", format!("{uid} {uid} 1"))?;

    bring_loopback_up()
}

/// Bring the loopback interface up inside the current network namespace.
///
/// A fresh namespace starts with loopback down, so a target that binds a local
/// port for its own use would fail. Loopback here reaches nothing but the
/// sandbox itself.
pub fn bring_loopback_up() -> io::Result<()> {
    const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
    const SIOCSIFFLAGS: libc::c_ulong = 0x8914;

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
    use crate::policy::{EgressRule, NetworkPolicy};

    fn policy_with(network: NetworkPolicy) -> Policy {
        Policy {
            network,
            ..Policy::default()
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
                host: "*".into(),
                port: Some(443),
            }]),
            bind_ports: Vec::new(),
        });
        assert_eq!(select(&policy, true), NetworkMode::LandlockOnly);
    }

    #[test]
    fn a_bound_port_stays_on_landlock() {
        let policy = policy_with(NetworkPolicy {
            egress: Egress::DenyAll,
            bind_ports: vec![27015],
        });
        assert_eq!(select(&policy, true), NetworkMode::LandlockOnly);
    }
}
