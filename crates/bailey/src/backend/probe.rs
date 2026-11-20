//! Runtime kernel capability detection.
//!
//! The probe reports which sandboxing features the running kernel offers, and
//! what each missing one costs, so a user can find out what a run will actually
//! enforce before running anything rather than after a program mysteriously
//! fails.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::backend::audit_notify;
use crate::backend::cgroup;
use crate::backend::fdpass;
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

/// Name of the privileged helper binary.
pub const HELPER_BIN: &str = "bailey-bpf-helper";

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
    /// The controllers a cgroup for a run would carry, which resource limits
    /// need. Empty when no cgroup can host a run.
    pub cgroup_delegated: Vec<&'static str>,
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
        helper: if deep {
            helper_status()
        } else {
            HelperStatus::Missing
        },
    }
}

/// Ask the kernel which Landlock ABI it implements.
pub fn landlock_abi() -> Option<u32> {
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

/// The uid an unmapped host uid reads as inside a user namespace.
///
/// Inside a user namespace a file owned by host root has no id here and reads
/// as the overflow uid. An owner this namespace cannot name is one nothing in
/// it could have written, which is the property that matters when deciding
/// whether a program may be run with the caller's authority.
pub fn overflow_uid() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(65534)
}

/// Whether a file is one the caller may run with its own authority.
///
/// Owned by root, by the caller, or by a host id this namespace cannot name,
/// and with no group or other write bit: one only the system or the caller
/// could have put there. Anything else is refused by name rather than run.
pub fn runnable_as_caller(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let caller = unsafe { libc::geteuid() };
    let owner_ok = meta.uid() == 0 || meta.uid() == caller || meta.uid() == overflow_uid();
    owner_ok && meta.permissions().mode() & 0o022 == 0
}

/// The controllers a run could be given limits through.
///
/// Asked exactly the way the run asks it, per controller, because a host that
/// delegates one controller serves a policy that needs only that one. Each
/// controller goes through [`cgroup::usable_root`], which answers the
/// override variable and the search alike, so the answer is the set a run
/// asking for all three would actually get, join permission included: a root
/// the target could not join must not read as delegated.
pub(crate) fn cgroup_delegated() -> Vec<&'static str> {
    CONTROLLERS
        .into_iter()
        .filter(|controller| cgroup::usable_root(&[*controller]).is_some())
        .collect()
}

/// The controllers a run may be given limits through.
const CONTROLLERS: [&str; 3] = ["memory", "pids", "cpu"];

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

/// Find the audit helper: the path named in the environment, then one beside
/// this executable, then one on `PATH`.
///
/// Both the probe and the audit backend resolve it through here. They used to
/// look separately, and disagreed: the backend fell back to the bare name, which
/// `Command` resolves on `PATH`, while the probe gave up before that and had
/// `doctor` report a helper missing that a run would have found and used.
///
/// The helper is run by bailey with the caller's authority, so every candidate
/// is held to the same standard [`runnable_as_caller`] states, wherever it was
/// found. One that fails it is skipped like one that is not there.
pub fn locate_helper() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("BAILEY_BPF_HELPER") {
        let path = PathBuf::from(path);
        if helper_is_trusted(&path) {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(HELPER_BIN);
        if helper_is_trusted(&candidate) {
            return Some(candidate);
        }
    }
    // An installed helper is the ordinary case for anyone who did not build
    // from source, and `cargo install` puts it on `PATH` rather than beside
    // bailey.
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(HELPER_BIN))
        .find(|candidate| helper_is_trusted(candidate))
}

/// Whether a helper candidate is a file the caller may run with its authority.
fn helper_is_trusted(candidate: &Path) -> bool {
    std::fs::metadata(candidate)
        .map(|meta| meta.is_file() && runnable_as_caller(&meta))
        .unwrap_or(false)
}

/// Whether the seccomp notification fallback observer can run on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackStatus {
    /// The whole mechanism works: the listener arms, hands over, and the
    /// supervisor can read the target's memory.
    Available,
    /// A listener already watches this process, so a second cannot exist.
    /// A fallback audit nested inside one, or any sandbox that installed its
    /// own listener, lands here.
    Busy,
    /// The kernel has no user notification, so it is older than 5.0.
    NoUserNotif,
    /// The kernel has no `CONTINUE`, so it is older than 5.5.
    NoContinue,
    /// The supervisor cannot read target memory, usually a hardened Yama
    /// `ptrace_scope`.
    MemoryRead(String),
    /// Some other reason, carried in the text.
    Unavailable(String),
}

impl FallbackStatus {
    /// Why the fallback is unavailable, when it is.
    pub fn reason(&self) -> Option<String> {
        match self {
            FallbackStatus::Available => None,
            FallbackStatus::Busy => Some(
                "a seccomp listener already observes this process, and a \
                 fallback audit cannot run nested"
                    .to_owned(),
            ),
            FallbackStatus::NoUserNotif => {
                Some("this kernel has no seccomp user notification (needs Linux 5.5)".to_owned())
            }
            FallbackStatus::NoContinue => {
                Some("this kernel cannot continue a notified syscall (needs Linux 5.5)".to_owned())
            }
            FallbackStatus::MemoryRead(reason) => Some(reason.clone()),
            FallbackStatus::Unavailable(reason) => Some(reason.clone()),
        }
    }

    /// Whether the fallback observer can record.
    pub fn is_available(&self) -> bool {
        matches!(self, FallbackStatus::Available)
    }
}

/// Run the fallback mechanism for real, in a throwaway child, and report
/// what happened.
///
/// The child arms a listener over `openat` through the same install and
/// handover the audit uses, then opens `/`. The parent plays the supervisor
/// once: it reads the path from the child's memory and continues the
/// syscall. The probe informs `doctor`; `auto` selection asks the helper
/// directly instead, so this never gates a run.
pub fn fallback_status() -> FallbackStatus {
    let (parent_end, child_end) = match UnixStream::pair() {
        Ok(ends) => ends,
        Err(err) => return FallbackStatus::Unavailable(format!("no socketpair: {err}")),
    };
    // The handover must not wait forever: a kernel that accepts the install
    // but never delivers the listener would hang the caller.
    if let Err(err) = parent_end.set_read_timeout(Some(Duration::from_secs(2))) {
        return FallbackStatus::Unavailable(format!("no socket timeout: {err}"));
    }
    let handover = child_end.as_raw_fd();
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return FallbackStatus::Unavailable(format!("no fork: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        // In the probe child. Exit codes distinguish the install failures:
        // 4 for EBUSY, 5 for EINVAL, 3 for anything else.
        drop(parent_end);
        // Installing a filter needs either this or CAP_SYS_ADMIN, exactly as
        // it does in the audit's own pre-exec.
        let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        let status = if nnp != 0 {
            3
        } else {
            match audit_notify::arm(handover) {
                Ok(()) => 0,
                Err(err) => match err.raw_os_error() {
                    Some(libc::EBUSY) => 4,
                    Some(libc::EINVAL) => 5,
                    _ => 3,
                },
            }
        };
        if status == 0 {
            let path = CString::new("/").expect("a path without NUL");
            unsafe {
                libc::openat(libc::AT_FDCWD, path.as_ptr(), libc::O_PATH);
            }
        }
        unsafe { libc::_exit(status) };
    }
    drop(child_end);
    let outcome = probe_from_parent(parent_end, pid as u32);
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    outcome
}

/// The parent half of the probe: serve one notification like the supervisor
/// would, and classify whatever goes wrong.
fn probe_from_parent(parent_end: UnixStream, pid: u32) -> FallbackStatus {
    let listener = match fdpass::recv_fds(&parent_end, 1, "probe listener") {
        Ok(fds) => unsafe { OwnedFd::from_raw_fd(fds[0]) },
        Err(_) => {
            return match wait_status(pid) {
                4 => FallbackStatus::Busy,
                5 => FallbackStatus::NoUserNotif,
                code => FallbackStatus::Unavailable(format!(
                    "the probe child could not arm a listener (exit {code})"
                )),
            };
        }
    };
    let (notif_size, resp_size) = match audit_notify::notif_sizes() {
        Ok(sizes) => sizes,
        Err(err) => return unavailable_after(pid, listener, err),
    };
    let mut notif = vec![0u8; notif_size];
    let mut resp = vec![0u8; resp_size];
    // The notification sits on the listener until it is read or the child
    // dies; bound the wait so the probe can never hang.
    let mut pollfd = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut pollfd, 1, 2000) };
    if ready <= 0 {
        return unavailable_after(
            pid,
            listener,
            io::Error::other("the probe notification never arrived"),
        );
    }
    loop {
        match audit_notify::recv_notification(listener.as_raw_fd(), &mut notif) {
            Ok(()) => break,
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(err) => return unavailable_after(pid, listener, err),
        }
    }
    let notification: libc::seccomp_notif =
        unsafe { std::ptr::read_unaligned(notif.as_ptr().cast()) };
    let path_pointer = notification.data.args[1];
    if let Err(err) = audit_notify::read_memory_now(pid, path_pointer, 2) {
        return FallbackStatus::MemoryRead(format!(
            "target memory could not be read ({err}); check the Yama ptrace_scope policy"
        ));
    }
    if let Err(err) = audit_notify::reply_continue(listener.as_raw_fd(), notification.id, &mut resp)
    {
        return match err.raw_os_error() {
            Some(libc::EINVAL) => FallbackStatus::NoContinue,
            _ => unavailable_after(pid, listener, err),
        };
    }
    FallbackStatus::Available
}

/// Close the listener so the held probe syscall fails, then say why.
fn unavailable_after(pid: u32, listener: OwnedFd, err: io::Error) -> FallbackStatus {
    drop(listener);
    let _ = wait_status(pid);
    FallbackStatus::Unavailable(format!("the probe run failed: {err}"))
}

/// The probe child's exit code, 0 when it cannot be read.
fn wait_status(pid: u32) -> i32 {
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        0
    }
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
            cgroup_delegated: Vec::new(),
            helper: HelperStatus::Missing,
        };

        assert!(!with(None).landlock_network());
        assert!(!with(Some(3)).landlock_network());
        assert!(with(Some(4)).landlock_network());
        assert!(!with(Some(5)).landlock_scope());
        assert!(with(Some(6)).landlock_scope());
    }

    /// A named root answers for the controllers a child of it would carry.
    ///
    /// The tree is temporary: the host's own cgroup hierarchy is never touched.
    /// A root that does not exist answers nothing, which is one of the two ways
    /// the probe used to claim a controller the run would then refuse to use.
    #[test]
    fn a_named_root_answers_with_the_controllers_it_carries() {
        let _env = crate::test_support::env_lock();

        unsafe { std::env::set_var(cgroup::ROOT_OVERRIDE, "/nonexistent/cgroup/root") };
        let missing = cgroup_delegated();
        unsafe { std::env::remove_var(cgroup::ROOT_OVERRIDE) };
        assert!(
            missing.is_empty(),
            "a root that does not exist must answer nothing: {missing:?}"
        );
    }

    /// The probe answers the question the run asks, so it may never claim a
    /// controller a run could not actually use.
    ///
    /// A plain directory holding the controller filenames carries them because
    /// something delegated them to *it*, which says nothing about what it may
    /// hand to a child. The run asks by creating a child and looking there, so
    /// a directory that is not a cgroup at all must answer nothing rather than
    /// advertise every controller.
    #[test]
    fn the_probe_never_claims_a_controller_the_run_cannot_use() {
        let _env = crate::test_support::env_lock();

        let not_a_cgroup = tempfile::tempdir().unwrap();
        for file in ["cgroup.procs", "memory.max", "pids.max", "cpu.max"] {
            std::fs::write(not_a_cgroup.path().join(file), "").unwrap();
        }
        unsafe { std::env::set_var(cgroup::ROOT_OVERRIDE, not_a_cgroup.path()) };

        let claimed = cgroup_delegated();
        // The same question, asked the way `try_create_cgroup` asks it.
        let usable = cgroup::usable_root(&["memory", "pids", "cpu"]).is_some();
        unsafe { std::env::remove_var(cgroup::ROOT_OVERRIDE) };

        assert!(
            claimed.is_empty(),
            "a directory that cannot host a run must answer nothing: {claimed:?}"
        );
        assert!(
            !usable,
            "and the run's own search must refuse it too, or the two disagree"
        );
    }
}
