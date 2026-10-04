//! FUSE mounts bailey performs itself.
//!
//! A FUSE filesystem the target may use is mounted by bailey before the target
//! starts and unmounted when it ends, by any path that reaches teardown. The
//! target itself never holds the power to mount: the seccomp filter denies the
//! mount syscalls and the capability drop leaves nothing to mount with, which
//! is the point. A mount command runs as the caller before any confinement
//! exists, exactly the standing a `pre_launch` hook has, and a config carrying
//! one is trusted the way a config carrying hooks is.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::BackendError;
use crate::policy::{Access, FsRule, FuseMount};

/// The prefix of the per-run directories holding mountpoints.
const PREFIX: &str = ".bailey-fuse.";

/// The environment variable naming the host directory a mount command mounts
/// onto.
const MOUNTPOINT_VAR: &str = "BAILEY_MOUNTPOINT";

/// One mount bailey performed.
#[derive(Debug, Clone)]
pub(crate) struct Mounted {
    /// The host directory the filesystem was mounted on.
    host: PathBuf,
    /// Where the target sees it.
    at: PathBuf,
}

impl Mounted {
    /// Where the target sees the mount.
    pub(crate) fn at(&self) -> &Path {
        &self.at
    }

    /// The grant that carries the mount into the sandbox at its place.
    ///
    /// The grant covers read, write, and execute: the config has no other way
    /// to name the host side of the mount, since the staging directory is
    /// bailey's, so a narrower grant here could never be widened later.
    pub(crate) fn rule(&self) -> FsRule {
        FsRule {
            path: self.host.clone(),
            access: Access::READ | Access::WRITE | Access::EXECUTE,
            at: Some(self.at.clone()),
        }
    }
}

/// The mounts of one run, unmounted when the guard drops.
#[derive(Debug, Default)]
pub(crate) struct FuseGuard {
    run_dir: PathBuf,
    mounts: Vec<Mounted>,
}

impl FuseGuard {
    /// Take over what [`mount_all`] performed under `run_dir`.
    pub(crate) fn new(run_dir: PathBuf, mounts: Vec<Mounted>) -> Self {
        Self { run_dir, mounts }
    }

    /// Unmount everything this run mounted, then remove the run directory.
    ///
    /// Best-effort, because a mount that will not go leaves the filesystem
    /// alive on the host rather than inside a sandbox, which is the honest
    /// state to say out loud rather than fail the run's exit status over. The
    /// mountpoint is removed with a plain `remove_dir`, which refuses a
    /// directory that is still a mountpoint, so a failed unmount can never
    /// take the mounted tree's contents with it.
    fn unmount_all(&self) {
        for mount in &self.mounts {
            let status = Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "fusermount3 -u -- \"{mp}\" 2>/dev/null || umount -- \"{mp}\"",
                    mp = shell_quote(&mount.host),
                ))
                .status();
            match status {
                Ok(status) if status.success() => {}
                Ok(status) => eprintln!(
                    "bailey: warning: the mount on {} did not unmount (status {}); \
                     it is still mounted on the host",
                    mount.host.display(),
                    status.code().unwrap_or(-1),
                ),
                Err(err) => eprintln!(
                    "bailey: warning: the mount on {} could not be unmounted: {err}",
                    mount.host.display(),
                ),
            }
            let _ = std::fs::remove_dir(&mount.host);
        }
        let _ = std::fs::remove_dir(&self.run_dir);
    }
}

impl Drop for FuseGuard {
    fn drop(&mut self) {
        self.unmount_all();
    }
}

/// Quote a path for a shell double-quoted context.
///
/// Mountpoints are bailey's own, so the characters needing care are the ones a
/// path can legitimately hold, not an attacker's choice: a quote or a dollar
/// here would otherwise reach the shell.
fn shell_quote(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
}

/// Mount every mount in `mounts`, in order, under `run_dir`.
///
/// The mountpoints are staged under a per-run directory so the sweep below can
/// tell one run's leftovers from another's. A failing mount command refuses
/// the run: a policy that names a mount which is not there would otherwise
/// start the target narrower than the policy says.
pub(crate) fn mount_all(
    mounts: &[FuseMount],
    run_dir: &Path,
) -> Result<Vec<Mounted>, BackendError> {
    let mut mounted = Vec::new();
    for (index, mount) in mounts.iter().enumerate() {
        let host = run_dir.join(index.to_string());
        std::fs::create_dir_all(&host).map_err(BackendError::Io)?;
        let status = Command::new("sh")
            .arg("-c")
            .arg(&mount.command)
            .env(MOUNTPOINT_VAR, &host)
            .env("BAILEY_AT", &mount.at)
            .status()
            .map_err(|source| {
                BackendError::Command(format!(
                    "the fuse mount command `{}` could not be run: {source}",
                    mount.command
                ))
            })?;
        if !status.success() {
            return Err(BackendError::Command(format!(
                "the fuse mount command `{}` exited with status {}; the run is \
                 refused rather than started without the mount it names",
                mount.command,
                status.code().unwrap_or(-1),
            )));
        }
        mounted.push(Mounted {
            host,
            at: mount.at.clone(),
        });
    }
    Ok(mounted)
}

/// The per-run directory holding this run's mountpoints.
pub(crate) fn run_dir() -> PathBuf {
    PathBuf::from(format!("/tmp/{PREFIX}{}", std::process::id()))
}

/// Remove the run directory of runs that are over.
///
/// A mount itself is left alone: it belongs to its FUSE daemon and the user's
/// hand, a leftover is visible on the host where it can be seen, and
/// unmounting it here could pull a filesystem out from under a process that
/// outlived the run and kept it open. The directory removal is best-effort for
/// the same reason the staging sweep is.
pub(crate) fn sweep_stale() {
    let Ok(entries) = std::fs::read_dir("/tmp") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(owner) = name
            .to_str()
            .and_then(|name| name.strip_prefix(PREFIX))
            .and_then(|owner| owner.parse::<u32>().ok())
        else {
            continue;
        };
        // A directory whose owner is still running belongs to a run in
        // progress, which may well be a concurrent one.
        if Path::new("/proc").join(owner.to_string()).exists() {
            continue;
        }
        let _ = std::fs::remove_dir(entry.path());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mount command runs with the mountpoint named, and whatever it leaves
    /// there is what the grant names. A real FUSE mount is not needed to prove
    /// the wiring: a command that fills the directory stands in for one.
    #[test]
    fn a_mount_command_sees_its_mountpoint() {
        let dir = tempfile::tempdir().unwrap();
        let run_dir = dir.path().join("run");
        let mounts = [FuseMount {
            command: "mkdir -p \"$BAILEY_MOUNTPOINT/data\" && echo mounted > \
                      \"$BAILEY_MOUNTPOINT/data/ready\""
                .into(),
            at: "/mnt/data".into(),
        }];
        let mounted = mount_all(&mounts, &run_dir).unwrap();

        assert_eq!(mounted.len(), 1);
        let rule = mounted[0].rule();
        assert_eq!(rule.at, Some(PathBuf::from("/mnt/data")));
        assert!(rule.path.starts_with(&run_dir));
        let ready = rule.path.join("data/ready");
        assert_eq!(std::fs::read_to_string(&ready).unwrap(), "mounted\n");
    }

    /// A failing mount command refuses the run instead of starting the target
    /// without the mount its policy names.
    #[test]
    fn a_failing_mount_command_refuses_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let mounts = [FuseMount {
            command: "exit 3".into(),
            at: "/mnt/data".into(),
        }];
        let err = mount_all(&mounts, &dir.path().join("run")).unwrap_err();
        assert!(err.to_string().contains("exited with status 3"), "{err}");
    }

    /// A mount command that cannot be run at all names the command rather
    /// than surfacing as a bare spawn error.
    #[test]
    fn an_unrunnable_mount_command_names_itself() {
        let dir = tempfile::tempdir().unwrap();
        let mounts = [FuseMount {
            command: "bailey-no-such-command-ever".into(),
            at: "/mnt/data".into(),
        }];
        let err = mount_all(&mounts, &dir.path().join("run")).unwrap_err();
        assert!(
            err.to_string().contains("bailey-no-such-command-ever"),
            "{err}"
        );
    }

    /// A guard tears down the mountpoints and the run directory. With nothing
    /// actually mounted, the unmount command fails and the guard says so on
    /// stderr without failing, which is the same path teardown takes under a
    /// mount that will not go.
    #[test]
    fn a_guard_tears_down_its_run_directory() {
        let dir = tempfile::tempdir().unwrap();
        let run_dir = dir.path().join("run");
        let mounts = [FuseMount {
            command: "mkdir -p \"$BAILEY_MOUNTPOINT\"".into(),
            at: "/mnt/data".into(),
        }];
        let mounted = mount_all(&mounts, &run_dir).unwrap();
        drop(FuseGuard::new(run_dir.clone(), mounted));
        assert!(
            !run_dir.exists(),
            "the guard removes the run directory it was given"
        );
    }
}
