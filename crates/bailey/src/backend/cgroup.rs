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
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::backend::{dbus, random_suffix};
use crate::policy::ResourceLimits;

/// Where the unified hierarchy is mounted.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Environment variable naming the cgroup to create runs in, for when the search
/// below picks the wrong one.
pub(crate) const ROOT_OVERRIDE: &str = "BAILEY_CGROUP_ROOT";

/// How `sd_booted()` recognises a host systemd runs as init on: a directory
/// systemd creates at boot and nothing else does.
const SYSTEMD_RUN_DIR: &str = "/run/systemd/system";

/// Where logind records users whose service manager runs without any session.
const LINGER_DIR: &str = "/var/lib/systemd/linger";

/// The user manager's bus-less endpoint, relative to `XDG_RUNTIME_DIR`; the
/// socket `systemctl --user` itself speaks to.
const MANAGER_SOCKET: &str = "systemd/private";

/// How long the manager gets to answer, and to start the scope it accepted.
const MANAGER_TIMEOUT: Duration = Duration::from_secs(2);

/// How often the confirmation looks at `/proc/self/cgroup` within
/// [`MANAGER_TIMEOUT`].
const CONFIRM_INTERVAL: Duration = Duration::from_millis(5);

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

/// The controllers a set of limits needs, plus the ones measuring a run's
/// peaks needs.
///
/// `memory` and `pids` are what `memory.peak` and `pids.peak` live behind, so
/// an audit asks for them even when the limits name neither. Duplicated names
/// would be harmless, but the order below keeps the list readable.
pub fn measuring_controllers(needed: &[&'static str]) -> Vec<&'static str> {
    let mut wanted: Vec<&'static str> = needed.to_vec();
    for controller in ["memory", "pids"] {
        if !wanted.contains(&controller) {
            wanted.push(controller);
        }
    }
    wanted
}

/// The controller lists a run's cgroup search tries, best first.
///
/// The measuring controllers come first, so the peaks are kept wherever the
/// delegation carries them. A run that enforces nothing through its cgroup,
/// an audit, tries the limits' controllers alone as a second step: the
/// scoping is kept and the peaks are explained, rather than the scoping
/// being lost with them. An enforcing run has one list, since what it wants
/// is what it needs.
pub(crate) fn controller_searches(
    even_without_limits: bool,
    wanted: &[&'static str],
    needed: &[&'static str],
) -> Vec<Vec<&'static str>> {
    let mut lists = vec![wanted.to_vec()];
    if even_without_limits && wanted != needed {
        lists.push(needed.to_vec());
    }
    lists
}

/// The run's resource peaks, read from a cgroup before it is removed.
///
/// Each peak is read only where the cgroup carries its controller, and every
/// missing peak says why: no cgroup at all, a delegation without the
/// controller, or a kernel too old to keep the high-water mark.
pub(crate) fn read_peaks(dir: &Path) -> crate::event::Usage {
    let controllers = fs::read_to_string(dir.join("cgroup.controllers"))
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let memory_peak_bytes = if !controllers.iter().any(|c| c == "memory") {
        None
    } else {
        match fs::read_to_string(dir.join("memory.peak")) {
            Ok(text) => text.trim().parse::<u64>().ok(),
            Err(_) => None,
        }
    };
    let tasks_peak = if !controllers.iter().any(|c| c == "pids") {
        None
    } else {
        match fs::read_to_string(dir.join("pids.peak")) {
            Ok(text) => text.trim().parse::<u64>().ok(),
            Err(_) => None,
        }
    };

    let mut unmeasured = Vec::new();
    if memory_peak_bytes.is_none() {
        unmeasured.push(if controllers.iter().any(|c| c == "memory") {
            "memory: this kernel does not report memory.peak (needs Linux 5.19)".to_owned()
        } else {
            "memory: the run's cgroup has no memory controller".to_owned()
        });
    }
    if tasks_peak.is_none() {
        unmeasured.push(if controllers.iter().any(|c| c == "pids") {
            "tasks: this kernel does not report pids.peak (needs Linux 6.1)".to_owned()
        } else {
            "tasks: the run's cgroup has no pids controller".to_owned()
        });
    }

    crate::event::Usage {
        memory_peak_bytes,
        tasks_peak,
        unmeasured,
    }
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

/// What asking the user manager for a delegated scope ended in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UserScope {
    /// A gate stopped the request before anything was sent. The reason is
    /// what `bailey doctor` reports; a run keeps its own reason unchanged.
    Unavailable(String),
    /// The request was sent and the manager refused it, or the scope it
    /// accepted never appeared. The reason joins the run's skipped reason.
    Refused(String),
    /// The scope exists and bailey sits in a leaf of it.
    Granted(String),
}

/// Ask the user manager for a delegated scope holding bailey, and move into a
/// leaf of it so the ordinary search finds a delegated root.
///
/// Bailey is never named by a process id: the `PIDs` property holds a single
/// zero, which the manager resolves through the connection's peer credentials.
/// A pid is only meaningful in a PID namespace, and bailey cannot know which
/// namespace the manager behind a socket lives in; the kernel's translation
/// of its own credentials needs no such knowledge. The socket must belong to
/// the caller and be served by the caller's uid, so the manager asked is the
/// caller's own.
pub(crate) fn request_user_scope() -> UserScope {
    if let Some(reason) = scope_gate_stop() {
        return UserScope::Unavailable(reason);
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").unwrap_or_default();
    let path = Path::new(&runtime).join(MANAGER_SOCKET);
    let Ok(mut stream) = UnixStream::connect(&path) else {
        let reason = std::io::Error::last_os_error();
        return UserScope::Refused(format!("cannot connect to {}: {reason}", path.display()));
    };
    let caller = caller_uid();
    match peer_uid(&stream) {
        Ok(uid) if uid == caller => {}
        Ok(uid) => {
            return UserScope::Refused(format!(
                "{} is served by uid {uid}, not this user",
                path.display()
            ));
        }
        Err(error) => {
            return UserScope::Refused(format!(
                "the peer credentials of {} cannot be read: {error}",
                path.display()
            ));
        }
    }
    let _ = stream.set_read_timeout(Some(MANAGER_TIMEOUT));
    let _ = stream.set_write_timeout(Some(MANAGER_TIMEOUT));
    if let Err(reason) = dbus::authenticate(&mut stream, caller) {
        return UserScope::Refused(format!("the user manager handshake failed: {reason}"));
    }
    let unit = format!("bailey-{}.{}.scope", std::process::id(), random_suffix());
    if let Err(reason) = dbus::start_transient_unit(&mut stream, &unit) {
        return UserScope::Refused(format!("the user manager refused the scope: {reason}"));
    }
    // StartTransientUnit returns once the job is queued, not when the scope
    // has started, so the move is confirmed by reading it back.
    if !confirm_scope(&unit) {
        return UserScope::Refused(
            "the user manager accepted the request, but the scope never appeared \
             under /proc/self/cgroup"
                .to_owned(),
        );
    }
    if let Err(error) = enter_supervisor_leaf() {
        return UserScope::Refused(format!(
            "the scope exists but bailey could not move into a leaf of it: {error}"
        ));
    }
    UserScope::Granted(unit)
}

/// The first gate that stops a scope request, cheapest first.
///
/// The order is the order of cost: two environment lookups, two stat calls,
/// then the socket's metadata. Gates three and onward are also what keeps
/// hosts without systemd paying nothing: the run stops there after one stat.
fn scope_gate_stop() -> Option<String> {
    if std::env::var_os(ROOT_OVERRIDE).is_some() {
        return Some(
            "BAILEY_CGROUP_ROOT is set, and the cgroup it names answers instead".to_owned(),
        );
    }
    if crate::backend::world::inside_sandbox() {
        return Some(
            "this run is inside a bailey sandbox, and the manager outside it must \
             not be asked to move anything"
                .to_owned(),
        );
    }
    systemd_init_reason()
        .or_else(linger_reason)
        .or_else(socket_reason)
}

fn systemd_init_reason() -> Option<String> {
    (!Path::new(SYSTEMD_RUN_DIR).is_dir())
        .then(|| "systemd is not init; there is no user manager to ask".to_owned())
}

fn linger_reason() -> Option<String> {
    let user = login_name().unwrap_or_else(|| caller_uid().to_string());
    (!Path::new(LINGER_DIR).join(&user).exists()).then(|| {
        "the user manager does not linger, so a scope it serves would be torn down \
         at the last logout, taking detached runs with it; opt in with: \
         loginctl enable-linger"
            .to_owned()
    })
}

fn socket_reason() -> Option<String> {
    let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") else {
        return Some(
            "XDG_RUNTIME_DIR is not set, so the user manager's socket is unknown".to_owned(),
        );
    };
    let path = Path::new(&runtime).join(MANAGER_SOCKET);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(_) => return Some(format!("no user manager socket at {}", path.display())),
    };
    socket_meta_reason(&meta.file_type(), meta.uid(), caller_uid())
        .map(|reason| format!("{}: {}", path.display(), reason))
}

/// Whether a socket file with this type and owner is the caller's own
/// manager's. Pure over the metadata so a socket owned by another uid is
/// testable without privileges.
fn socket_meta_reason(kind: &fs::FileType, uid: u32, caller: u32) -> Option<&'static str> {
    if !kind.is_socket() {
        return Some("is not a socket");
    }
    (uid != caller).then_some("is not owned by this user")
}

/// The login name the linger marker is filed under: `USER` when the caller's
/// environment says so, else a scan of `/etc/passwd`. An unfindable name is
/// read as the uid string, which misses the marker and leaves the feature
/// off; a run is never weakened by a name this lookup fails on.
fn login_name() -> Option<String> {
    if let Some(user) = std::env::var_os("USER").filter(|user| !user.is_empty()) {
        return Some(user.to_string_lossy().into_owned());
    }
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    let uid = caller_uid();
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?.to_owned();
        let _group = fields.next()?;
        let owner: u32 = fields.next()?.parse().ok()?;
        (owner == uid).then_some(name)
    })
}

/// The uid the kernel recorded for the socket's peer at `connect()`.
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut creds = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut creds as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(creds.uid)
}

fn caller_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Whether a line of `/proc/self/cgroup` names `unit`: the line's path must
/// end in the unit's full name, so a path that merely begins with the same
/// text reads as no match.
fn cgroup_line_names(line: &str, unit: &str) -> bool {
    line.trim().ends_with(unit)
}

/// Wait for the scope to appear as bailey's own cgroup.
fn confirm_scope(unit: &str) -> bool {
    for _ in 0..(MANAGER_TIMEOUT.as_millis() / CONFIRM_INTERVAL.as_millis()) {
        if let Ok(content) = fs::read_to_string("/proc/self/cgroup")
            && content.lines().any(|line| cgroup_line_names(line, unit))
        {
            return true;
        }
        std::thread::sleep(CONFIRM_INTERVAL);
    }
    false
}

/// Move bailey into a leaf of its new scope.
///
/// A delegated scope starts with bailey as its only process, and the kernel
/// refuses to enable controllers for the children of a cgroup that holds
/// processes. The leaf is what makes the scope usable: writing zero to the
/// leaf's `cgroup.procs` moves the whole process, every thread included, and
/// the ordinary walk up from the leaf then finds the scope.
fn enter_supervisor_leaf() -> io::Result<()> {
    let scope = own().ok_or_else(|| io::Error::other("no unified-hierarchy cgroup"))?;
    let leaf = scope.join("supervisor");
    fs::create_dir(&leaf)?;
    fs::write(leaf.join("cgroup.procs"), "0")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

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

    /// A real listener socket is accepted for its owner and refused for any
    /// other uid.
    #[test]
    fn a_socket_for_another_uid_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let listener = std::os::unix::net::UnixListener::bind(dir.path().join("s")).unwrap();
        let meta = fs::symlink_metadata(dir.path().join("s")).unwrap();
        let caller = meta.uid();
        assert!(listener.local_addr().is_ok());
        assert_eq!(socket_meta_reason(&meta.file_type(), caller, caller), None);
        assert_eq!(
            socket_meta_reason(&meta.file_type(), caller + 1, caller),
            Some("is not owned by this user")
        );
    }

    /// A regular file where the socket should be is refused whatever it is
    /// owned by, which is what a stopped or masked manager leaves behind.
    #[test]
    fn a_regular_file_in_the_sockets_place_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-socket");
        fs::write(&file, "").unwrap();
        let meta = fs::symlink_metadata(&file).unwrap();
        let caller = meta.uid();
        assert_eq!(
            socket_meta_reason(&meta.file_type(), caller, caller),
            Some("is not a socket")
        );
    }

    /// The confirmation matches a cgroup path that ends in the unit's name
    /// and nothing shorter: a prefix of the name, or the same text inside a
    /// longer component, is a different cgroup.
    #[test]
    fn the_confirmation_matches_the_whole_unit_name() {
        let unit = "bailey-42-abcdef0123456789.scope";
        assert!(cgroup_line_names(
            "0::/user.slice/user-1000.slice/user@1000.service/bailey-42-abcdef0123456789.scope",
            unit
        ));
        assert!(!cgroup_line_names("0::/user.slice/user-1000/bailey", unit));
        assert!(!cgroup_line_names(
            "0::/user.slice/user-1000.slice/user@1000.service/bailey-42-abcdef0123456789.scope2",
            unit
        ));
        // The leaf entered after the match does not read as the scope again.
        assert!(!cgroup_line_names(
            "0::/user.slice/user-1000.slice/user@1000.service/bailey-42-abcdef0123456789.scope/supervisor",
            unit
        ));
    }

    /// Lay out a directory as a cgroup leaf: its controller list and, where a
    /// controller is delegated, a peak file.
    fn fake_cgroup(dir: &Path, controllers: &[&str], peaks: &[(&str, u64)]) {
        fs::write(dir.join("cgroup.controllers"), controllers.join(" ")).unwrap();
        for (name, value) in peaks {
            fs::write(dir.join(name), value.to_string()).unwrap();
        }
    }

    /// Both peaks read where the cgroup carries both controllers.
    #[test]
    fn both_peaks_read_where_the_cgroup_carries_them() {
        let dir = tempfile::tempdir().unwrap();
        fake_cgroup(
            dir.path(),
            &["memory", "pids"],
            &[("memory.peak", 314_572_800), ("pids.peak", 40)],
        );
        let usage = read_peaks(dir.path());
        assert_eq!(usage.memory_peak_bytes, Some(314_572_800));
        assert_eq!(usage.tasks_peak, Some(40));
        assert!(usage.unmeasured.is_empty());
    }

    /// A delegation without the memory controller is the reason, not a
    /// kernel complaint: the controller file decides what is missing and why.
    #[test]
    fn a_missing_controller_says_the_delegation_lacks_it() {
        let dir = tempfile::tempdir().unwrap();
        fake_cgroup(dir.path(), &["pids"], &[("pids.peak", 3)]);
        let usage = read_peaks(dir.path());
        assert_eq!(usage.memory_peak_bytes, None);
        assert_eq!(usage.tasks_peak, Some(3));
        assert_eq!(
            usage.unmeasured,
            vec!["memory: the run's cgroup has no memory controller"]
        );
    }

    /// Where the controller is delegated but the peak file is absent, the
    /// kernel is too old to have kept the high-water mark.
    #[test]
    fn a_missing_peak_file_names_the_kernel() {
        let dir = tempfile::tempdir().unwrap();
        fake_cgroup(dir.path(), &["memory", "pids"], &[]);
        let usage = read_peaks(dir.path());
        assert_eq!(usage.memory_peak_bytes, None);
        assert_eq!(usage.tasks_peak, None);
        assert_eq!(
            usage.unmeasured,
            vec![
                "memory: this kernel does not report memory.peak (needs Linux 5.19)",
                "tasks: this kernel does not report pids.peak (needs Linux 6.1)",
            ]
        );
    }

    /// An audit asks for the limits' controllers plus the measuring ones,
    /// without duplicating a controller the limits already need.
    #[test]
    fn measuring_controllers_extend_the_limits_ones() {
        assert_eq!(measuring_controllers(&[]), vec!["memory", "pids"]);
        assert_eq!(measuring_controllers(&["memory"]), vec!["memory", "pids"]);
        assert_eq!(
            measuring_controllers(&["memory", "pids", "cpu"]),
            vec!["memory", "pids", "cpu"]
        );
    }

    /// A delegation without the memory controller cannot host the measuring
    /// list, but still hosts the limits' list, which for a limit-free audit
    /// run is empty: the scoping cgroup is there, and only the peaks go.
    #[test]
    fn a_partial_delegation_hosts_the_limits_list_but_not_the_measuring_one() {
        let dir = tempfile::tempdir().unwrap();
        fake_cgroup(dir.path(), &["pids"], &[]);
        assert!(!can_host_runs(dir.path(), &["memory", "pids"]));
        assert!(can_host_runs(dir.path(), &[]));
    }

    /// An audit's search falls back to the limits' controllers, and an
    /// enforcing run's search does not widen past its own list.
    #[test]
    fn an_audit_run_falls_back_to_the_limits_controllers() {
        assert_eq!(
            controller_searches(true, &["memory", "pids"], &[]),
            vec![vec!["memory", "pids"], vec![]]
        );
        assert_eq!(
            controller_searches(false, &["memory"], &["memory"]),
            vec![vec!["memory"]]
        );
    }
}
