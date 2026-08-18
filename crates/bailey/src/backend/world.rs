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

use crate::policy::Policy;

/// The `PATH` handed to a target, rather than the caller's, which commonly
/// includes directories the sandbox does not grant.
const SANDBOX_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

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
}

impl World {
    /// Work out the world for `target` under `policy`.
    ///
    /// `isolated` says whether the mount namespace will be built, which decides
    /// whether the private home can appear at the real home's path and whether
    /// temporary storage can be private.
    pub fn derive(target: &Path, policy: &Policy, isolated: bool) -> Self {
        let real_home = real_home();
        let touches_home = policy_touches(policy, &real_home);

        let home_host = if touches_home {
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
        let cwd = if !isolated || kept_invocation_dir {
            invocation_dir
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
        }
    }

    /// Create the private home on the host if it is not there yet, reporting the
    /// path the first time so the user can find what the target writes.
    pub fn prepare(&self) -> std::io::Result<()> {
        let Some(home) = &self.home_host else {
            return Ok(());
        };
        if !home.exists() {
            std::fs::create_dir_all(home)?;
            eprintln!("bailey: created private home at {}", home.display());
        }
        Ok(())
    }
}

/// Build the environment the target will receive.
///
/// The result is the whole environment: it is applied to a cleared environment,
/// so anything absent here does not reach the target.
pub fn environment(policy: &Policy, world: &World) -> Vec<(String, String)> {
    let mut env: BTreeMap<String, String> = BTreeMap::new();

    env.insert("PATH".into(), SANDBOX_PATH.into());
    env.insert("HOME".into(), world.home_inside.display().to_string());
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
        let env = environment(&policy, &world);
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
        let env: BTreeMap<_, _> = environment(&policy, &world).into_iter().collect();

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
    fn display_variables_follow_their_grant() {
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "/run/user/4242") };
        unsafe { std::env::set_var("WAYLAND_DISPLAY", "wayland-0") };

        let without = policy_granting(&["/usr"]);
        let world = World::derive(Path::new("/opt/game/game"), &without, false);
        let env: BTreeMap<_, _> = environment(&without, &world).into_iter().collect();
        assert!(!env.contains_key("WAYLAND_DISPLAY"));

        let with = policy_granting(&["/usr", "/run/user/4242"]);
        let world = World::derive(Path::new("/opt/game/game"), &with, false);
        let env: BTreeMap<_, _> = environment(&with, &world).into_iter().collect();
        assert_eq!(
            env.get("WAYLAND_DISPLAY").map(String::as_str),
            Some("wayland-0")
        );
    }
}
