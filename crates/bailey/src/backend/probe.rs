//! Runtime kernel capability detection.
//!
//! The probe reports which sandboxing features the running kernel offers, and
//! what each missing one costs, so a user can find out what a run will actually
//! enforce before running anything rather than after a program mysteriously
//! fails.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::backend::isolation;

/// `landlock_create_ruleset`, which reports the supported ABI when asked for the
/// version. The number is the same across the architectures bailey supports;
/// libc only exposes the constant for Android targets.
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

/// Landlock ABI level at which network rules became available.
const ABI_NETWORK: u32 = 4;
/// Landlock ABI level at which scoping became available.
const ABI_SCOPE: u32 = 6;
/// Landlock ABI level at which the kernel logs denials.
const ABI_LOGGING: u32 = 7;

/// Whether the privileged audit helper is usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperStatus {
    /// The helper loaded its programs, so audit will work.
    Ready(PathBuf),
    /// The helper was found but could not load, almost always missing
    /// capabilities.
    NotPermitted(PathBuf),
    /// No helper binary was found.
    Missing,
}

/// Sandboxing-relevant features detected on the running kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// Landlock ABI level the kernel supports, or `None` when Landlock is
    /// unavailable.
    pub landlock_abi: Option<u32>,
    /// Whether unprivileged user namespaces can actually be created here.
    pub unprivileged_userns: bool,
    /// Whether kernel BTF is available, which the audit programs need.
    pub btf: bool,
    /// Whether a cgroup can be created for a run, which resource limits need.
    pub cgroup_delegated: bool,
    /// Whether bailey could read the kernel's denial records, which violation
    /// hooks would need.
    pub denial_log_readable: bool,
    /// Whether the audit helper is present and permitted.
    pub helper: HelperStatus,
}

impl Capabilities {
    /// Whether Landlock can enforce network policy.
    pub fn landlock_network(&self) -> bool {
        self.landlock_abi.is_some_and(|abi| abi >= ABI_NETWORK)
    }

    /// Whether Landlock can scope the target away from abstract sockets and
    /// signals.
    pub fn landlock_scope(&self) -> bool {
        self.landlock_abi.is_some_and(|abi| abi >= ABI_SCOPE)
    }

    /// Whether the kernel records Landlock denials at all.
    pub fn landlock_logs_denials(&self) -> bool {
        self.landlock_abi.is_some_and(|abi| abi >= ABI_LOGGING)
    }

    /// Whether `on_violation` hooks can fire: the kernel has to record denials
    /// and bailey has to be able to read them.
    pub fn violation_hooks_possible(&self) -> bool {
        self.landlock_logs_denials() && self.denial_log_readable
    }
}

/// Whether `on_violation` hooks could ever fire on this host.
///
/// Cheap enough to call on every run that configures such a hook: it asks the
/// kernel for its Landlock ABI and tries to open the kernel log.
pub fn violation_signal_available() -> bool {
    landlock_abi().is_some_and(|abi| abi >= ABI_LOGGING) && denial_log_readable()
}

/// Probe the running kernel for sandboxing-relevant features.
///
/// `deep` also starts the audit helper to find out whether it can really load
/// its programs, which costs a process spawn and is only worth it when the
/// caller is reporting to a person.
pub fn probe(deep: bool) -> Capabilities {
    Capabilities {
        landlock_abi: landlock_abi(),
        unprivileged_userns: isolation::available(),
        btf: Path::new("/sys/kernel/btf/vmlinux").exists(),
        cgroup_delegated: cgroup_delegated(),
        denial_log_readable: denial_log_readable(),
        helper: if deep {
            helper_status()
        } else {
            HelperStatus::Missing
        },
    }
}

/// Ask the kernel which Landlock ABI it implements.
fn landlock_abi() -> Option<u32> {
    let version = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    (version > 0).then_some(version as u32)
}

/// Whether a run could create its own cgroup, which is what resource limits
/// need. Session managers that do not delegate a cgroup leave limits
/// unenforceable.
fn cgroup_delegated() -> bool {
    let Some(base) = current_cgroup() else {
        return false;
    };
    let probe = base.join(format!("bailey.probe.{}", std::process::id()));
    let created = fs::create_dir(&probe).is_ok();
    if created {
        let _ = fs::remove_dir(&probe);
    }
    created
}

fn current_cgroup() -> Option<PathBuf> {
    let content = fs::read_to_string("/proc/self/cgroup").ok()?;
    let relative = content.lines().find_map(|line| line.strip_prefix("0::"))?;
    let relative = relative.trim().strip_prefix('/').unwrap_or("");
    Some(Path::new("/sys/fs/cgroup").join(relative))
}

/// Whether the kernel's log of denied accesses is readable here.
///
/// Landlock records denials from ABI 7 onwards, but reading them needs either a
/// readable kernel log or the audit subsystem, both of which are commonly
/// restricted.
fn denial_log_readable() -> bool {
    fs::File::open("/dev/kmsg").is_ok()
}

/// Start the audit helper and see whether it can load its programs.
fn helper_status() -> HelperStatus {
    let Some(path) = locate_helper() else {
        return HelperStatus::Missing;
    };

    let Ok(mut child) = Command::new(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return HelperStatus::Missing;
    };

    let mut hello = [0u8; 2];
    let loaded = child
        .stdout
        .as_mut()
        .is_some_and(|out| std::io::Read::read_exact(out, &mut hello).is_ok());

    // Closing stdin ends the helper, which is still waiting for a target.
    drop(child.stdin.take());
    let _ = child.wait();

    if loaded && hello[0] == bailey_common::HELLO {
        HelperStatus::Ready(path)
    } else {
        HelperStatus::NotPermitted(path)
    }
}

fn locate_helper() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("BAILEY_BPF_HELPER") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("bailey-bpf-helper");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_does_not_panic() {
        let _ = probe(false);
    }

    #[test]
    fn abi_thresholds_follow_the_reported_level() {
        let with = |abi| Capabilities {
            landlock_abi: abi,
            unprivileged_userns: false,
            btf: false,
            cgroup_delegated: false,
            denial_log_readable: true,
            helper: HelperStatus::Missing,
        };

        assert!(!with(None).landlock_network());
        assert!(!with(Some(3)).landlock_network());
        assert!(with(Some(4)).landlock_network());
        assert!(!with(Some(5)).landlock_scope());
        assert!(with(Some(6)).landlock_scope());
        assert!(!with(Some(6)).violation_hooks_possible());
        assert!(with(Some(7)).violation_hooks_possible());
    }
}
