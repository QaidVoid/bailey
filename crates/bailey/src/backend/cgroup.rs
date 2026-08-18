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

use std::fs;
use std::path::{Path, PathBuf};

use crate::policy::ResourceLimits;

/// Where the unified hierarchy is mounted.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Environment variable naming the cgroup to create runs in, for when the search
/// below picks the wrong one.
const ROOT_OVERRIDE: &str = "BAILEY_CGROUP_ROOT";

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
/// available to their children.
///
/// Walks up from bailey's own cgroup, because the delegated subtree is normally
/// an ancestor: the session manager hands the user a directory and the user's
/// processes live in a leaf of it.
pub fn usable_root(needed: &[&str]) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(ROOT_OVERRIDE) {
        let path = PathBuf::from(path);
        return can_host_runs(&path, needed).then_some(path);
    }

    let own = own()?;
    let root = Path::new(CGROUP_ROOT);
    // Bailey's own cgroup is skipped: it contains bailey, so its controllers
    // cannot be delegated to children.
    for candidate in own.ancestors().skip(1) {
        if !candidate.starts_with(root) {
            break;
        }
        if can_host_runs(candidate, needed) {
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
fn can_host_runs(dir: &Path, needed: &[&str]) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let probe = dir.join(format!("bailey.probe.{}", std::process::id()));
    if fs::create_dir(&probe).is_err() {
        return false;
    }
    // The controller files only appear in the child once the parent delegates
    // them, so ask the child rather than trusting the parent's listing.
    let missing: Vec<_> = needed
        .iter()
        .filter(|controller| !probe.join(control_file(controller)).exists())
        .copied()
        .collect();
    let _ = fs::remove_dir(&probe);

    if missing.is_empty() {
        return true;
    }
    // Not delegated yet. Enabling is allowed only when this cgroup has no
    // processes of its own, which is exactly the case for a delegated root.
    if enable(dir, &missing).is_err() {
        return false;
    }
    let probe = dir.join(format!("bailey.probe.{}", std::process::id()));
    if fs::create_dir(&probe).is_err() {
        return false;
    }
    let ok = needed
        .iter()
        .all(|controller| probe.join(control_file(controller)).exists());
    let _ = fs::remove_dir(&probe);
    ok
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
fn control_file(controller: &str) -> &'static str {
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
}
