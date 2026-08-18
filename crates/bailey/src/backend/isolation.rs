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

/// A path to conceal inside the reconstructed root.
///
/// Concealment is how a denial is enforced beneath a granted parent. Landlock
/// rules can only add access, so a denied path that arrives with its parent's
/// bind mount is covered over instead: an empty read-only filesystem in its
/// place, leaving nothing to read and nothing to write.
pub struct Conceal {
    /// Absolute path to cover, as it appears in the new root.
    pub path: PathBuf,
    /// Whether the path is a directory.
    pub is_dir: bool,
}

/// The set of paths to reconstruct in the target's root.
pub struct IsolationPlan {
    /// Paths to bind into the new root.
    pub binds: Vec<BindMount>,
    /// Paths to cover over after binding.
    pub conceal: Vec<Conceal>,
    /// Whether to also take the target out of the host's network namespace.
    pub network: bool,
    /// The private home: where it lives on the host, and where it appears
    /// inside.
    pub home: Option<(PathBuf, PathBuf)>,
    /// Whether to give the target a private `/tmp`.
    pub private_tmp: bool,
    /// Size of the private `/tmp`, in bytes.
    pub tmp_bytes: u64,
    /// Whether to give the target a private `/dev/shm`.
    pub private_shm: bool,
    /// Size of the private `/dev/shm`, in bytes.
    pub shm_bytes: u64,
    /// Directory to start the target in, once the new root is in place.
    pub cwd: PathBuf,
    /// Host directory the new root is staged in, removed by the parent after the
    /// run.
    pub staging: PathBuf,
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

    let mut flags = CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID;
    if plan.network {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    unshare(flags).map_err(errno)?;
    if plan.network {
        crate::backend::network::bring_loopback_up()?;
    }

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

    // Staged at a path the parent chose, since the PID here is 1 in the new
    // namespace and would collide between concurrent runs.
    let new_root = plan.staging.clone();
    fs::create_dir_all(&new_root)?;
    mount(
        Some("tmpfs"),
        &new_root,
        Some("tmpfs"),
        MsFlags::empty(),
        Some("mode=0755"),
    )
    .map_err(errno)?;

    // The private /tmp goes first: a shared /tmp is a channel between every
    // program on the machine, so the target gets its own, discarded with the
    // namespace. It must precede the binds, because a granted path *under* /tmp
    // has to land inside this tmpfs rather than be covered by it.
    if plan.private_tmp {
        mount_tmpfs(&new_root.join("tmp"), plan.tmp_bytes, "mode=1777")?;
    }

    for bind in &plan.binds {
        bind_into(&new_root, bind)?;
    }

    // After the binds, so that a bind covering /dev does not hide it.
    if plan.private_shm {
        mount_tmpfs(&new_root.join("dev/shm"), plan.shm_bytes, "mode=1777")?;
    }

    // The private home is bound at the path the real home would have, so a
    // program that hard-codes its home still writes inside the sandbox.
    if let Some((host, inside)) = &plan.home {
        let target = new_root.join(inside.strip_prefix("/").unwrap_or(inside));
        fs::create_dir_all(&target)?;
        mount(
            Some(host),
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(errno)?;
    }

    conceal_all(&new_root, &plan.conceal)?;

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

    // Back into the directory the target was invoked from, so relative paths
    // resolve the way they do outside the sandbox.
    if chdir(&plan.cwd).is_err() {
        chdir("/").map_err(errno)?;
    }
    Ok(())
}

/// Mount a fresh tmpfs, creating the mountpoint first.
fn mount_tmpfs(target: &Path, size_bytes: u64, mode: &str) -> io::Result<()> {
    fs::create_dir_all(target)?;
    mount(
        Some("tmpfs"),
        target,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(format!("size={size_bytes},{mode}").as_str()),
    )
    .map_err(errno)
}

/// Cover each denied path that survived into the new root.
///
/// Directories are replaced by an empty read-only tmpfs. Files are covered by a
/// bind of an empty placeholder, which is unlinked once the binds hold a
/// reference to it. Read-only is enforced by the mount rather than by the mode
/// bits, which the target could otherwise bypass as root inside its own user
/// namespace.
fn conceal_all(new_root: &Path, conceal: &[Conceal]) -> io::Result<()> {
    let placeholder = new_root.join(".bailey-empty");
    let needs_placeholder = conceal.iter().any(|item| !item.is_dir);
    if needs_placeholder {
        fs::File::create(&placeholder)?;
    }

    for item in conceal {
        let relative = item.path.strip_prefix("/").unwrap_or(&item.path);
        let target = new_root.join(relative);
        if !target.exists() {
            continue;
        }
        if item.is_dir {
            mount(
                Some("tmpfs"),
                &target,
                Some("tmpfs"),
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                Some("mode=0000"),
            )
            .map_err(errno)?;
        } else {
            mount(
                Some(&placeholder),
                &target,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(errno)?;
            mount(
                None::<&str>,
                &target,
                None::<&str>,
                MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                None::<&str>,
            )
            .map_err(errno)?;
        }
    }

    if needs_placeholder {
        let _ = fs::remove_file(&placeholder);
    }
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
