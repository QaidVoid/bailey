//! The world a target is placed in.
//!
//! Access control decides what a program may reach. This module decides what it
//! is handed before it starts: which environment variables cross the boundary,
//! where its home directory is, and which directory it starts in. Those are not
//! access-control questions, and getting them wrong leaks just as much: an
//! inherited `SSH_AUTH_SOCK` is a live credential no filesystem rule can take
//! back.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::backend::network::{Inherited, NetworkMode};
use crate::policy::Policy;

/// The `PATH` handed to a target, rather than the caller's, which commonly
/// includes directories the sandbox does not grant.
pub const SANDBOX_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Caller variables that carry locale and terminal settings. These are not
/// credentials, and a program without them behaves oddly enough to look broken.
const BASE_PASSTHROUGH: &[&str] = &[
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_TIME",
    "LC_NUMERIC",
    "LC_COLLATE",
    "LC_MESSAGES",
    "USER",
    "LOGNAME",
    "SHELL",
    "TZ",
];

/// Variables that only make sense when the session's runtime directory is
/// granted, which is what the compositor and audio sockets live in.
const RUNTIME_DIR_VARS: &[&str] = &[
    "XDG_RUNTIME_DIR",
    "WAYLAND_DISPLAY",
    "PULSE_SERVER",
    "XDG_SESSION_TYPE",
];

/// Variables that only make sense when the X11 socket directory is granted.
const X11_VARS: &[&str] = &["DISPLAY", "XAUTHORITY"];

/// Set in every confined environment, so a bailey run from inside a sandbox can
/// tell that one is already in force.
const SANDBOX_MARKER: &str = "BAILEY_SANDBOX";

/// Where the target's home, temporary storage, and working directory are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct World {
    /// The private home on the host, or `None` when the policy grants the real
    /// home and the target should use that instead.
    pub home_host: Option<PathBuf>,
    /// The path the home has from inside the sandbox.
    pub home_inside: PathBuf,
    /// Whether the target gets a private `/tmp`.
    pub private_tmp: bool,
    /// Whether the target gets a private `/dev/shm`.
    pub private_shm: bool,
    /// The directory the target starts in.
    pub cwd: PathBuf,
    /// Whether the invocation directory was granted and so kept as the working
    /// directory.
    pub kept_invocation_dir: bool,
    /// The terminal this run is attached to, when it has one.
    ///
    /// A pseudo-terminal is named after the session that owns it, so a policy
    /// cannot name one usefully: `/dev/pts/9` today is `/dev/pts/14` tomorrow.
    /// It is part of what the sandbox hands the target, like the home.
    pub terminal: Option<PathBuf>,
}

impl World {
    /// Work out the world for `target` under `policy`.
    ///
    /// `isolated` says whether the mount namespace will be built, which decides
    /// whether the private home can appear at the real home's path and whether
    /// temporary storage can be private.
    pub fn derive(target: &Path, policy: &Policy, isolated: bool) -> Self {
        let real_home = real_home();
        // Only a grant on the home itself, or on an ancestor of it, counts as
        // asking for the real home. A grant on something *inside* it does not:
        // the target executable is granted implicitly, and most programs live
        // under the home, so treating that as an opt-out would silently disable
        // the private home for nearly every run.
        let asked_for_real_home = covered_by_grant(policy, &real_home);

        let home_host = if asked_for_real_home {
            None
        } else {
            Some(policy.home.clone().unwrap_or_else(|| default_home(target)))
        };
        let home_inside = match (&home_host, isolated) {
            // Mounted where the real home would be, so a program that hard-codes
            // its own home path still lands inside the sandbox.
            (Some(_), true) => real_home.clone(),
            (Some(host), false) => host.clone(),
            (None, _) => real_home.clone(),
        };

        // The target keeps the directory it was invoked from. Outside isolation
        // that costs nothing: an ungranted directory is unreadable wherever the
        // program stands. Inside isolation the directory only exists if it was
        // granted, so an ungranted one falls back to the home.
        let invocation_dir = std::env::current_dir().unwrap_or_else(|_| home_inside.clone());
        let kept_invocation_dir = covered_by_grant(policy, &invocation_dir);
        let cwd = if !isolated {
            invocation_dir
        } else if kept_invocation_dir {
            // A relocated grant does not exist at its host path inside the
            // sandbox, so the directory to enter is where the grant was placed.
            // Entering the host path would fail and drop the target into its
            // home, which reads as the grant not having worked at all.
            relocated_dir(policy, &invocation_dir).unwrap_or(invocation_dir)
        } else {
            home_inside.clone()
        };

        // A private /tmp has to be granted read-write for the target to use it,
        // and Landlock rights only add, so that grant would widen any narrower
        // grant on a path that happens to live under /tmp. Where the policy says
        // anything about /tmp, in either direction, bailey leaves it alone.
        Self {
            home_host,
            home_inside,
            private_tmp: isolated && !policy_touches(policy, Path::new("/tmp")),
            private_shm: isolated && !policy_touches(policy, Path::new("/dev/shm")),
            cwd,
            kept_invocation_dir,
            terminal: controlling_terminal(),
        }
    }

    /// Create the private home on the host if it is not there yet, reporting the
    /// path the first time so the user can find what the target writes.
    ///
    /// `nested` says this run is itself inside a sandbox, in which case the path
    /// is one inside that sandbox rather than one on the host, and saying so
    /// keeps it from reading as though the real home was touched.
    pub fn prepare(&self, nested: bool) -> std::io::Result<()> {
        let Some(home) = &self.home_host else {
            return Ok(());
        };
        if !home.exists() {
            std::fs::create_dir_all(home)?;
            let where_ = if nested {
                " (inside the sandbox this run is in)"
            } else {
                ""
            };
            eprintln!("bailey: created private home at {}{where_}", home.display());
        }
        Ok(())
    }
}

/// The terminal this process is attached to, if any.
///
/// Found through the standard descriptors rather than by asking for a name, so
/// that a run with its output redirected reports nothing rather than the
/// terminal it inherited on another descriptor.
fn controlling_terminal() -> Option<PathBuf> {
    for fd in 0..3 {
        let Ok(path) = std::fs::read_link(format!("/proc/self/fd/{fd}")) else {
            continue;
        };
        if path.starts_with("/dev/pts/") || path.starts_with("/dev/tty") {
            return Some(path);
        }
    }
    None
}

/// Whether this process is already confined by an outer bailey run.
///
/// There is no way to ask the kernel "am I restricted by Landlock", and a
/// seccomp filter in `/proc/self/status` does not say whose it is, so the marker
/// bailey puts in every confined environment is what answers this.
pub fn inside_sandbox() -> bool {
    std::env::var_os(SANDBOX_MARKER).is_some()
}

/// Build the environment the target will receive.
///
/// The result is the whole environment: it is applied to a cleared environment,
/// so anything absent here does not reach the target.
pub fn environment(policy: &Policy, world: &World, network: NetworkMode) -> Vec<(String, String)> {
    let mut env: BTreeMap<String, String> = BTreeMap::new();

    env.insert("PATH".into(), SANDBOX_PATH.into());
    env.insert("HOME".into(), world.home_inside.display().to_string());
    // So that a bailey run from inside a sandbox knows one is already in force,
    // and can report what it inherited rather than what it could not build. A
    // program can tell it is confined by the shape of the world around it
    // anyway, so saying it plainly gives nothing away.
    env.insert(SANDBOX_MARKER.into(), "1".into());
    // Which network the inner run will inherit. A nested run cannot build its
    // own, so this is the difference between correctly saying nothing and
    // wrongly warning that UDP is unrestricted.
    env.insert(
        "BAILEY_SANDBOX_NET".into(),
        Inherited::publish(network).into(),
    );
    if world.private_tmp {
        env.insert("TMPDIR".into(), "/tmp".into());
    }
    for name in BASE_PASSTHROUGH {
        if let Ok(value) = std::env::var(name) {
            env.insert((*name).into(), value);
        }
    }

    // Display and audio variables follow the grants they depend on: the variable
    // without the socket is useless, and the socket without the variable is a
    // program that cannot find its display.
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    if let Some(dir) = &runtime_dir
        && covered_by_grant(policy, dir)
    {
        insert_from_caller(&mut env, RUNTIME_DIR_VARS);
    }
    if covered_by_grant(policy, Path::new("/tmp/.X11-unix")) {
        insert_from_caller(&mut env, X11_VARS);
    }

    for (name, value) in std::env::vars() {
        if policy.env.passes(&name) {
            env.insert(name, value);
        }
    }
    for (name, value) in &policy.env.set {
        env.insert(name.clone(), value.clone());
    }

    env.retain(|name, _| !policy.env.denies(name));
    env.into_iter().collect()
}

fn insert_from_caller(env: &mut BTreeMap<String, String>, names: &[&str]) {
    for name in names {
        if let Ok(value) = std::env::var(name) {
            env.insert((*name).into(), value);
        }
    }
}

/// Whether the policy grants anything that overlaps `path`, in either direction.
///
/// A grant on the home itself and a grant on something inside it both count as
/// the user having opinions about that hierarchy, so bailey stays out of it.
fn policy_touches(policy: &Policy, path: &Path) -> bool {
    policy
        .filesystem
        .iter()
        .map(|rule| &rule.path)
        .chain(policy.devices.iter().map(|rule| &rule.path))
        .any(|granted| granted.starts_with(path) || path.starts_with(granted))
}

/// Whether a grant covers `path` itself.
/// Where `path` ends up when the grant covering it was placed elsewhere.
///
/// Returns `None` when nothing covering it was moved, which is the ordinary
/// case and leaves the path exactly as the caller gave it.
fn relocated_dir(policy: &Policy, path: &Path) -> Option<PathBuf> {
    policy.filesystem.iter().find_map(|rule| {
        let at = rule.at.as_ref()?;
        let relative = path.strip_prefix(&rule.path).ok()?;
        Some(at.join(relative))
    })
}

fn covered_by_grant(policy: &Policy, path: &Path) -> bool {
    policy
        .filesystem
        .iter()
        .map(|rule| &rule.path)
        .chain(policy.devices.iter().map(|rule| &rule.path))
        .any(|granted| path.starts_with(granted))
}

fn real_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// `$XDG_DATA_HOME/bailey/<target>/home`, named after the target so the
/// directory is something a person can navigate to.
fn default_home(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "target".into());
    data_home().join("bailey").join(name).join("home")
}

/// The private home for a shell confined to `dir`.
///
/// Keyed on the directory rather than on the shell's file name, which would
/// collapse every project into one home called `bash`. The name is kept
/// navigable and disambiguated with a digest of the full path, since two
/// projects are often both called `app`.
pub fn directory_home(dir: &Path) -> PathBuf {
    let name = dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "root".into());
    let digest = short_digest(dir);
    data_home()
        .join("bailey")
        .join("shell")
        .join(format!("{name}-{digest}"))
        .join("home")
}

fn short_digest(path: &Path) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(path.as_os_str().as_encoded_bytes());
    hasher
        .finalize()
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn data_home() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME")
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    real_home().join(".local").join("share")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Access, FsRule};

    fn policy_granting(paths: &[&str]) -> Policy {
        Policy {
            filesystem: paths
                .iter()
                .map(|path| FsRule {
                    path: PathBuf::from(path),
                    access: Access::READ,
                    at: None,
                })
                .collect(),
            ..Policy::default()
        }
    }

    #[test]
    fn private_home_is_used_when_the_policy_says_nothing_about_home() {
        let policy = policy_granting(&["/usr"]);
        let world = World::derive(Path::new("/opt/game/game"), &policy, false);
        let home = world.home_host.expect("a private home");
        assert!(home.ends_with("bailey/game/home"), "{}", home.display());
        assert_eq!(world.home_inside, home);
    }

    #[test]
    fn isolation_puts_the_private_home_at_the_real_home_path() {
        let policy = policy_granting(&["/usr"]);
        let world = World::derive(Path::new("/opt/game/game"), &policy, true);
        assert!(world.home_host.is_some());
        assert_eq!(world.home_inside, real_home());
    }

    #[test]
    fn two_directories_of_the_same_name_get_different_homes() {
        let one = directory_home(Path::new("/home/you/work/one/app"));
        let two = directory_home(Path::new("/home/you/work/two/app"));
        assert_ne!(
            one, two,
            "a shared home would leak one project into another"
        );
        assert!(
            one.to_string_lossy().contains("app-"),
            "and the name stays navigable: {}",
            one.display()
        );
    }

    #[test]
    fn granting_the_real_home_opts_out() {
        let home = real_home();
        let policy = policy_granting(&[home.to_str().unwrap()]);
        let world = World::derive(Path::new("/opt/game/game"), &policy, true);
        assert!(world.home_host.is_none());
        assert_eq!(world.home_inside, home);
    }

    #[test]
    fn caller_secrets_do_not_reach_the_target() {
        unsafe { std::env::set_var("BAILEY_TEST_SECRET", "hunter2") };
        let policy = policy_granting(&["/usr"]);
        let world = World::derive(Path::new("/opt/game/game"), &policy, false);
        let env = environment(&policy, &world, NetworkMode::Isolated);
        assert!(!env.iter().any(|(name, _)| name == "BAILEY_TEST_SECRET"));
        assert!(env.iter().any(|(name, _)| name == "PATH"));
        assert!(env.iter().any(|(name, _)| name == "HOME"));
    }

    #[test]
    fn named_variables_are_passed_and_denied() {
        unsafe { std::env::set_var("BAILEY_TEST_PASSED", "yes") };
        unsafe { std::env::set_var("BAILEY_TEST_PREFIXED", "yes") };
        let mut policy = policy_granting(&["/usr"]);
        policy.env.pass = vec!["BAILEY_TEST_PASSED".into(), "BAILEY_TEST_PRE*".into()];
        policy.env.set.insert("EXPLICIT".into(), "value".into());
        policy.env.deny = vec!["TERM".into()];

        let world = World::derive(Path::new("/opt/game/game"), &policy, false);
        let env: BTreeMap<_, _> = environment(&policy, &world, NetworkMode::Isolated)
            .into_iter()
            .collect();

        assert_eq!(
            env.get("BAILEY_TEST_PASSED").map(String::as_str),
            Some("yes")
        );
        assert_eq!(
            env.get("BAILEY_TEST_PREFIXED").map(String::as_str),
            Some("yes")
        );
        assert_eq!(env.get("EXPLICIT").map(String::as_str), Some("value"));
        assert!(!env.contains_key("TERM"));
    }

    #[test]
    fn the_sandbox_marker_is_in_the_base_set_and_can_be_denied() {
        let policy = policy_granting(&["/usr"]);
        let world = World::derive(Path::new("/opt/game/game"), &policy, false);

        let env: BTreeMap<_, _> = environment(&policy, &world, NetworkMode::Isolated)
            .into_iter()
            .collect();
        assert_eq!(env.get(SANDBOX_MARKER).map(String::as_str), Some("1"));
        assert_eq!(
            env.get("BAILEY_SANDBOX_NET").map(String::as_str),
            Some("isolated"),
            "a nested run reads this rather than guessing what it inherited"
        );

        let host: BTreeMap<_, _> = environment(&policy, &world, NetworkMode::LandlockOnly)
            .into_iter()
            .collect();
        assert_eq!(
            host.get("BAILEY_SANDBOX_NET").map(String::as_str),
            Some("host")
        );

        let mut denied = policy.clone();
        denied.env.deny = vec![SANDBOX_MARKER.into()];
        let env: BTreeMap<_, _> = environment(&denied, &world, NetworkMode::Isolated)
            .into_iter()
            .collect();
        assert!(
            !env.contains_key(SANDBOX_MARKER),
            "it is an ordinary variable, removable like any other"
        );
    }

    #[test]
    fn display_variables_follow_their_grant() {
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "/run/user/4242") };
        unsafe { std::env::set_var("WAYLAND_DISPLAY", "wayland-0") };

        let without = policy_granting(&["/usr"]);
        let world = World::derive(Path::new("/opt/game/game"), &without, false);
        let env: BTreeMap<_, _> = environment(&without, &world, NetworkMode::Isolated)
            .into_iter()
            .collect();
        assert!(!env.contains_key("WAYLAND_DISPLAY"));

        let with = policy_granting(&["/usr", "/run/user/4242"]);
        let world = World::derive(Path::new("/opt/game/game"), &with, false);
        let env: BTreeMap<_, _> = environment(&with, &world, NetworkMode::Isolated)
            .into_iter()
            .collect();
        assert_eq!(
            env.get("WAYLAND_DISPLAY").map(String::as_str),
            Some("wayland-0")
        );
    }
}
