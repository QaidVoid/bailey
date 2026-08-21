//! Shell integration.
//!
//! A hook cannot confine the shell it runs in: Landlock restricts a process for
//! its lifetime, and by the time a shell can run anything it already exists with
//! the authority it was given. What a hook can do is notice that a directory has
//! a policy, say so, and start a confined shell when asked.
//!
//! The logic lives here rather than in the emitted snippets, which are shims
//! that print what [`notice`] returns. Discovery, trust, and wording would
//! otherwise be written once per shell dialect and drift apart.

use std::path::{Path, PathBuf};

use crate::backend::world;
use crate::profiles;
use crate::trust::{Rejected, Store};

/// Filename the hook looks for in the directory just entered.
const CONFIG_NAME: &str = "bailey.toml";

/// A shell the integration has been exercised on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// fish.
    Fish,
    /// bash.
    Bash,
}

/// What the hook should say, if anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// Nothing to report.
    Silent,
    /// A policy here is ready to be used, so entering a shell would apply it.
    /// This is the only state an asking hook offers to act on.
    Ready(String),
    /// Something worth saying, with nothing to offer.
    Info(String),
}

impl Notice {
    /// The machine-readable form the snippets consume: a state, a tab, and the
    /// message.
    pub fn porcelain(&self) -> String {
        match self {
            Notice::Silent => String::new(),
            Notice::Ready(message) => format!("ready\t{message}"),
            Notice::Info(message) => format!("info\t{message}"),
        }
    }

    /// The message on its own.
    pub fn message(&self) -> Option<&str> {
        match self {
            Notice::Silent => None,
            Notice::Ready(message) | Notice::Info(message) => Some(message),
        }
    }
}

/// What to say about the directory the shell has just entered.
pub fn notice() -> Notice {
    let Ok(cwd) = std::env::current_dir() else {
        return Notice::Silent;
    };

    // Inside a confined shell there is nothing to offer: the policy was fixed
    // when the shell started and a second one could only narrow it. The one
    // thing worth saying is that the ground has moved.
    if world::inside_sandbox() {
        return left_the_policy_directory(&cwd);
    }

    let config = cwd.join(CONFIG_NAME);
    if !config.is_file() {
        return Notice::Silent;
    }

    match Store::load().check(&config) {
        None => Notice::Ready(
            "bailey: this directory has a policy; `bailey shell` works under it".into(),
        ),
        Some(Rejected::Untrusted) => Notice::Info(format!(
            "bailey: this directory has a policy you have not accepted; review it, \
             then: bailey trust {}",
            display_relative(&config, &cwd)
        )),
        Some(Rejected::Changed) => Notice::Info(format!(
            "bailey: this directory's policy changed since you accepted it; review \
             it, then: bailey trust {}",
            display_relative(&config, &cwd)
        )),
        Some(other) => Notice::Info(format!(
            "bailey: this directory has a policy that will not apply: {}",
            other.reason()
        )),
    }
}

/// Report a working directory that has left the one the policy was resolved for.
///
/// The policy does not follow a `cd`. Without this, moving to another project
/// inside a confined shell produces failures that look like a broken tool.
fn left_the_policy_directory(cwd: &Path) -> Notice {
    let Some(dir) = std::env::var_os("BAILEY_SANDBOX_DIR") else {
        return Notice::Silent;
    };
    let dir = PathBuf::from(dir);
    if cwd.starts_with(&dir) {
        return Notice::Silent;
    }
    Notice::Info(format!(
        "bailey: this shell is confined to {}, so the policy does not cover the \
         directory you are now in",
        dir.display()
    ))
}

/// A config path written the way the user would type it from here.
fn display_relative(config: &Path, cwd: &Path) -> String {
    match config.strip_prefix(cwd) {
        Ok(relative) => format!("./{}", relative.display()),
        Err(_) => config.display().to_string(),
    }
}

/// The integration code for `shell`.
///
/// `ask` turns the notice into an offer to enter a confined shell, and `wrap`
/// adds a function per program a user profile claims. Both are opt-in: a shell
/// that interrogates you for moving around, or that quietly shadows commands,
/// is a shell integration people uninstall.
pub fn snippet(shell: Shell, ask: bool, wrap: bool) -> String {
    let mut out = String::new();

    match shell {
        Shell::Fish => {
            if ask {
                out.push_str("set -g __bailey_hook_ask 1\n");
            }
            out.push_str(include_str!("hook/fish.fish"));
            if wrap {
                out.push_str(&fish_wrappers());
            }
        }
        Shell::Bash => {
            if ask {
                out.push_str("__bailey_hook_ask=1\n");
            }
            out.push_str(include_str!("hook/bash.bash"));
            if wrap {
                out.push_str(&bash_wrappers());
            }
        }
    }

    out
}

fn fish_wrappers() -> String {
    let mut out = String::from(
        "\n# Programs your own profiles claim with `applies_to`. `command <name>`\n\
         # still reaches the program itself.\n",
    );
    for name in profiles::claimed_names() {
        out.push_str(&format!(
            "function {name} -d \"bailey: claimed by one of your profiles\"\n    \
             command bailey run {name} $argv\nend\n"
        ));
    }
    out
}

fn bash_wrappers() -> String {
    let mut out = String::from(
        "\n# Programs your own profiles claim with `applies_to`. `command <name>`\n\
         # still reaches the program itself.\n",
    );
    for name in profiles::claimed_names() {
        out.push_str(&format!(
            "{name}() {{ command bailey run {name} \"$@\"; }}\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_snippets_carry_what_the_flags_asked_for() {
        let plain = snippet(Shell::Fish, false, false);
        assert!(plain.contains("__bailey_hook"));
        assert!(
            !plain.contains("__bailey_hook_ask 1"),
            "asking is opt-in: {plain}"
        );

        let asking = snippet(Shell::Fish, true, false);
        assert!(asking.contains("set -g __bailey_hook_ask 1"));

        let bash = snippet(Shell::Bash, true, false);
        assert!(bash.contains("__bailey_hook_ask=1"));
        assert!(bash.contains("PROMPT_COMMAND"));
    }

    #[test]
    fn porcelain_carries_the_state_and_the_message() {
        assert_eq!(Notice::Silent.porcelain(), "");
        assert_eq!(Notice::Ready("hi".into()).porcelain(), "ready\thi");
        assert_eq!(Notice::Info("hi".into()).porcelain(), "info\thi");
    }

    #[test]
    fn a_config_path_is_shown_the_way_it_would_be_typed() {
        assert_eq!(
            display_relative(Path::new("/work/bailey.toml"), Path::new("/work")),
            "./bailey.toml"
        );
        assert_eq!(
            display_relative(Path::new("/other/bailey.toml"), Path::new("/work")),
            "/other/bailey.toml"
        );
    }
}
