//! Finding a cgroup a run can actually be limited in.
//!
//! Resource limits need a cgroup that bailey may create, and whose children get
//! the controller files (`memory.max` and friends) written into them. A cgroup
//! only gets those files when its parent lists the controller in
//! `cgroup.subtree_control`, and the kernel refuses to enable a controller on a
//! cgroup that has processes of its own.
//!
//! That rules out the obvious approach of creating the run's cgroup as a child
//! of bailey's own, because bailey's own cgroup always contains bailey. The run
//! is therefore created as a *sibling*, in the nearest ancestor that is
//! delegated to this user, which is the same shape systemd uses for a scope.
//! Delegation containment adds one more question: the target joins the run's
//! cgroup by writing itself into its `cgroup.procs`, and the kernel demands
//! write access to the common ancestor's file too, so a subtree is only usable
//! when bailey itself lives under it.

use std::fs;
use std::path::{Path, PathBuf};

use crate::policy::ResourceLimits;

/// Where the unified hierarchy is mounted.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Environment variable naming the cgroup to create runs in, for when the search
/// below picks the wrong one.
pub(crate) const ROOT_OVERRIDE: &str = "BAILEY_CGROUP_ROOT";

/// The controllers a set of limits needs.
pub fn needed_controllers(limits: &ResourceLimits) -> Vec<&'static str> {
    let mut needed = Vec::new();
    if limits.memory_bytes.is_some() {
        needed.push("memory");
    }
    if limits.pids_max.is_some() {
        needed.push("pids");
    }
    if limits.cpu_percent.is_some() {
        needed.push("cpu");
    }
    needed
}

/// The cgroup bailey itself is in.
pub fn own() -> Option<PathBuf> {
    let content = fs::read_to_string("/proc/self/cgroup").ok()?;
    let relative = content.lines().find_map(|line| line.strip_prefix("0::"))?;
    let relative = relative.trim().strip_prefix('/').unwrap_or("");
    Some(Path::new(CGROUP_ROOT).join(relative))
}

/// Find a cgroup that runs can be created in, with `needed` controllers
/// available to their children, and that this process can actually move
/// itself into.
///
/// Walks up from bailey's own cgroup, because the delegated subtree is normally
/// an ancestor: the session manager hands the user a directory and the user's
/// processes live in a leaf of it. Creation alone is not enough; the kernel's
/// delegation containment (see [`caller_may_join`]) also decides whether the
/// target can join what it creates, and a root that answers no there is not
/// usable however well it delegates.
pub fn usable_root(needed: &[&'static str]) -> Option<PathBuf> {
    let own = own()?;
    if let Some(path) = std::env::var_os(ROOT_OVERRIDE) {
        let path = PathBuf::from(path);
        return (can_host_runs(&path, needed) && caller_may_join(&own, &path)).then_some(path);
    }

    let root = Path::new(CGROUP_ROOT);
    // Bailey's own cgroup is skipped: it contains bailey, so its controllers
    // cannot be delegated to children.
    for candidate in own.ancestors().skip(1) {
        if !candidate.starts_with(root) {
            break;
        }
        if can_host_runs(candidate, needed) && caller_may_join(&own, candidate) {
            return Some(candidate.to_path_buf());
        }
        if candidate == root {
            break;
        }
    }
    None
}

/// Whether a run's cgroup could be created under `dir` and actually carry
/// limits.
pub(crate) fn can_host_runs(dir: &Path, needed: &[&'static str]) -> bool {
    carries_all(dir, needed).len() == needed.len()
}

/// Whether a process in `own` may move itself into a cgroup under `base`.
///
/// The kernel's delegation containment names two write requirements for a
/// non-root process migration: the writer must have write access to the
/// destination's `cgroup.procs`, and to the `cgroup.procs` of the source and
/// destination's common ancestor. The first is guaranteed, because the run's
/// cgroup is created by this very user; the second is what decides usability.
/// A caller sitting outside the delegated subtree, in a cgroup whose files it
/// does not own (the hierarchy root, a system slice owned by root), can create
/// the run's cgroup but the target's join would be denied, which used to kill
/// the run at spawn with a bare permission error. Asking here keeps limits
/// best-effort: they are skipped with a warning instead.
fn caller_may_join(own: &Path, base: &Path) -> bool {
    let ancestor = common_ancestor(own, base);
    std::fs::OpenOptions::new()
        .write(true)
        .open(ancestor.join("cgroup.procs"))
        .is_ok()
}

/// The longest directory both paths live under, the kernel's permission
/// boundary for moving a process between two cgroups.
fn common_ancestor(a: &Path, b: &Path) -> PathBuf {
    let mut ancestor = PathBuf::new();
    for (left, right) in a.iter().zip(b.iter()) {
        if left != right {
            break;
        }
        ancestor.push(left);
    }
    if ancestor.as_os_str().is_empty() {
        ancestor.push("/");
    }
    ancestor
}

/// Which of `needed` a child created under `dir` would carry.
///
/// A controller reaches a child only once `dir` delegates it, so a child is
/// created and asked rather than `dir`'s own listing, which reflects what
/// `dir`'s parent delegated to `dir` and says nothing about what `dir` may hand
/// on. A controller `dir` may delegate but has not yet is enabled, which is
/// what a run needs and what [`usable_root`] has always done.
pub(crate) fn carries_all(dir: &Path, needed: &[&'static str]) -> Vec<&'static str> {
    if !dir.is_dir() {
        return Vec::new();
    }
    let Some(probe) = make_probe_dir(dir) else {
        return Vec::new();
    };
    let missing: Vec<&'static str> = needed
        .iter()
        .copied()
        .filter(|controller| !probe.join(control_file(controller)).exists())
        .collect();
    let _ = fs::remove_dir(&probe);

    if missing.is_empty() {
        return needed.to_vec();
    }
    // Not delegated yet. Enabling is allowed only when this cgroup has no
    // processes of its own, which is exactly the case for a delegated root.
    if enable(dir, &missing).is_err() {
        return Vec::new();
    }
    let Some(probe) = make_probe_dir(dir) else {
        return Vec::new();
    };
    let carried: Vec<&'static str> = needed
        .iter()
        .copied()
        .filter(|controller| probe.join(control_file(controller)).exists())
        .collect();
    let _ = fs::remove_dir(&probe);
    carried
}

/// Create a probe child of `dir`, named uniquely for this call.
///
/// Two questions asked at once, as concurrent tests of one process do, used to
/// race on a probe named for the pid alone: the second `create_dir` saw the
/// first's and read that as `dir` refusing children, which made a usable
/// delegation answer unusable depending on timing. A sequence number past the
/// pid keeps each call's probe its own.
fn make_probe_dir(dir: &Path) -> Option<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    for _ in 0..2 {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let probe = dir.join(format!("bailey.probe.{}.{seq}", std::process::id()));
        match fs::create_dir(&probe) {
            Ok(()) => return Some(probe),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                // A leftover of a dead caller with a recycled pid. Its
                // contents are not ours to trust, so it is replaced.
                let _ = fs::remove_dir_all(&probe);
            }
            Err(_) => return None,
        }
    }
    None
}

fn enable(dir: &Path, controllers: &[&str]) -> std::io::Result<()> {
    let request: Vec<String> = controllers
        .iter()
        .map(|controller| format!("+{controller}"))
        .collect();
    fs::write(dir.join("cgroup.subtree_control"), request.join(" "))
}

/// The file a controller writes its limit to, used to tell whether the
/// controller reached a child.
pub(crate) fn control_file(controller: &str) -> &'static str {
    match controller {
        "memory" => "memory.max",
        "pids" => "pids.max",
        "cpu" => "cpu.max",
        _ => "cgroup.procs",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controllers_follow_the_limits_that_are_set() {
        let limits = ResourceLimits {
            memory_bytes: Some(1),
            ..ResourceLimits::default()
        };
        assert_eq!(needed_controllers(&limits), vec!["memory"]);

        let all = ResourceLimits {
            memory_bytes: Some(1),
            pids_max: Some(2),
            cpu_percent: Some(3),
            ..ResourceLimits::default()
        };
        assert_eq!(needed_controllers(&all), vec!["memory", "pids", "cpu"]);
        assert!(needed_controllers(&ResourceLimits::default()).is_empty());
    }

    #[test]
    fn the_search_does_not_escape_the_hierarchy() {
        // Whatever this host provides, a returned root is always inside the
        // unified hierarchy.
        if let Some(root) = usable_root(&["memory"]) {
            assert!(root.starts_with(CGROUP_ROOT));
        }
    }

    #[test]
    fn the_ancestor_of_a_subtree_is_the_shared_prefix() {
        let own = Path::new("/sys/fs/cgroup/ci/session");
        let run = Path::new("/sys/fs/cgroup/ci/bailey.9");
        assert_eq!(
            common_ancestor(own, run),
            PathBuf::from("/sys/fs/cgroup/ci")
        );
    }

    #[test]
    fn cgroups_sharing_nothing_meet_at_the_hierarchy_root() {
        let own = Path::new("/sys/fs/cgroup/one/leaf");
        let other = Path::new("/sys/fs/cgroup/two");
        assert_eq!(common_ancestor(own, other), PathBuf::from("/sys/fs/cgroup"));
    }

    #[test]
    fn a_cgroup_is_its_own_ancestor() {
        let own = Path::new("/sys/fs/cgroup/ci/session");
        assert_eq!(
            common_ancestor(own, own),
            PathBuf::from("/sys/fs/cgroup/ci/session")
        );
    }
}
