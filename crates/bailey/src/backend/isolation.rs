//! Namespace-based world reconstruction, layered under Landlock enforcement.
//!
//! When enabled, the target runs in a fresh user, mount, and PID namespace with
//! a root rebuilt from the policy's granted paths, so ungranted paths are absent
//! rather than merely denied, and host processes are invisible. This runs inside
//! the enforcement `pre_exec`, before Landlock and seccomp are applied, and is
//! fully unprivileged via the user namespace.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{chdir, pivot_root};

/// A path to bind into the reconstructed root.
pub struct BindMount {
    /// Source path on the host.
    pub source: PathBuf,
    /// Whether the source is a directory (otherwise a file mountpoint is made).
    pub is_dir: bool,
}

/// The set of paths to reconstruct in the target's root.
pub struct IsolationPlan {
    /// Paths to bind into the new root.
    pub binds: Vec<BindMount>,
}

/// Whether namespace isolation actually works on this host.
///
/// This probes for real by attempting the core setup (user namespace, uid/gid
/// maps, mount namespace, and a tmpfs mount) in a throwaway child. A sysctl
/// alone is not enough: a host can report user namespaces as permitted while a
/// policy such as AppArmor still blocks `unshare(CLONE_NEWUSER)`. The caller
/// (the enforcement backend) is single-threaded when it calls this, so the fork
/// is safe.
pub fn available() -> bool {
    match unsafe { libc::fork() } {
        -1 => false,
        0 => {
            let code = i32::from(probe().is_err());
            unsafe { libc::_exit(code) }
        }
        pid => {
            let mut status: libc::c_int = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        }
    }
}

fn probe() -> io::Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    unshare(CloneFlags::CLONE_NEWUSER).map_err(errno)?;
    fs::write("/proc/self/setgroups", "deny")?;
    fs::write("/proc/self/gid_map", format!("0 {gid} 1"))?;
    fs::write("/proc/self/uid_map", format!("0 {uid} 1"))?;
    unshare(CloneFlags::CLONE_NEWNS).map_err(errno)?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(errno)?;

    let dir = PathBuf::from(format!("/tmp/.bailey-probe.{}", unsafe { libc::getpid() }));
    fs::create_dir_all(&dir)?;
    let mounted = mount(
        Some("tmpfs"),
        &dir,
        Some("tmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(errno);
    let _ = umount2(&dir, MntFlags::MNT_DETACH);
    let _ = fs::remove_dir(&dir);
    mounted
}

/// Enter the isolation namespaces and reconstruct the root.
///
/// Returns `Ok` only in the child that will exec the target (PID 1 in the new
/// PID namespace). The intermediate parent waits for that child and exits with
/// its status, so it never returns.
pub fn enter(plan: &IsolationPlan) -> io::Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    unshare(CloneFlags::CLONE_NEWUSER).map_err(errno)?;
    fs::write("/proc/self/setgroups", "deny")?;
    fs::write("/proc/self/gid_map", format!("0 {gid} 1"))?;
    fs::write("/proc/self/uid_map", format!("0 {uid} 1"))?;

    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID).map_err(errno)?;

    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            // Child: PID 1 in the new PID namespace. It reconstructs the root
            // and then returns so the caller execs the target here.
            setup_root(plan)
        }
        pid => {
            // Parent: reap the target and exit with its status. Never returns.
            let mut status: libc::c_int = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                1
            };
            unsafe { libc::_exit(code) }
        }
    }
}

fn setup_root(plan: &IsolationPlan) -> io::Result<()> {
    // Make the whole tree private so our mount changes do not propagate.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(errno)?;

    let new_root = PathBuf::from(format!("/tmp/.bailey-root.{}", unsafe { libc::getpid() }));
    fs::create_dir_all(&new_root)?;
    mount(
        Some("tmpfs"),
        &new_root,
        Some("tmpfs"),
        MsFlags::empty(),
        Some("mode=0755"),
    )
    .map_err(errno)?;

    for bind in &plan.binds {
        bind_into(&new_root, bind)?;
    }

    // A fresh /proc, meaningful because we are in a new PID namespace.
    let proc_dir = new_root.join("proc");
    fs::create_dir_all(&proc_dir)?;
    mount(
        Some("proc"),
        &proc_dir,
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(errno)?;

    let old_root = new_root.join(".oldroot");
    fs::create_dir_all(&old_root)?;
    pivot_root(&new_root, &old_root).map_err(errno)?;
    chdir("/").map_err(errno)?;
    umount2("/.oldroot", MntFlags::MNT_DETACH).map_err(errno)?;
    let _ = fs::remove_dir("/.oldroot");
    Ok(())
}

fn bind_into(new_root: &Path, bind: &BindMount) -> io::Result<()> {
    let relative = bind.source.strip_prefix("/").unwrap_or(&bind.source);
    let target = new_root.join(relative);

    if bind.is_dir {
        fs::create_dir_all(&target)?;
    } else {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        // A bind mount needs an existing mountpoint of a matching kind.
        let _ = fs::File::create(&target);
    }

    mount(
        Some(&bind.source),
        &target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(errno)
}

fn errno(err: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(err as i32)
}
