//! Lifecycle hooks and their execution.
//!
//! Hooks are user-defined shell commands run at defined points in a sandbox
//! run. A failing `pre-launch` hook aborts the run; `post-exit` and
//! `on-violation` hooks are best-effort and do not abort.

use std::process::Command;

/// Commands run at defined points in a sandbox run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hooks {
    /// Commands run before the target starts. A failure aborts the run.
    pub pre_launch: Vec<String>,
    /// Commands run after the target terminates.
    pub post_exit: Vec<String>,
    /// Commands run when an access is denied or flagged.
    pub on_violation: Vec<String>,
}

/// An error produced while running a hook command.
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    /// The hook command failed to spawn.
    #[error("failed to spawn hook `{command}`: {source}")]
    Spawn {
        /// The command that failed to spawn.
        command: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The hook command ran but exited with a non-zero status.
    #[error("hook `{command}` exited with status {code}")]
    Failed {
        /// The command that failed.
        command: String,
        /// The reported exit code (`-1` if terminated by a signal).
        code: i32,
    },
}

impl Hooks {
    /// Run the `pre-launch` commands in order, aborting on the first failure.
    pub fn run_pre_launch(&self) -> Result<(), HookError> {
        run_all(&self.pre_launch, &[])
    }

    /// Run the `post-exit` commands in order.
    ///
    /// The target's exit code is exposed to each command as the
    /// `BAILEY_EXIT_CODE` environment variable.
    pub fn run_post_exit(&self, exit_code: i32) -> Result<(), HookError> {
        run_all(
            &self.post_exit,
            &[("BAILEY_EXIT_CODE", exit_code.to_string())],
        )
    }

    /// Run the `on-violation` commands in order.
    ///
    /// A description of the violation is exposed to each command as the
    /// `BAILEY_VIOLATION` environment variable.
    pub fn run_on_violation(&self, description: &str) -> Result<(), HookError> {
        run_all(
            &self.on_violation,
            &[("BAILEY_VIOLATION", description.to_string())],
        )
    }
}

fn run_all(commands: &[String], env: &[(&str, String)]) -> Result<(), HookError> {
    for command in commands {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(command);
        for (key, value) in env {
            cmd.env(key, value);
        }
        let status = cmd.status().map_err(|source| HookError::Spawn {
            command: command.clone(),
            source,
        })?;
        if !status.success() {
            return Err(HookError::Failed {
                command: command.clone(),
                code: status.code().unwrap_or(-1),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_launch_aborts_on_failure() {
        let hooks = Hooks {
            pre_launch: vec!["exit 1".into()],
            ..Default::default()
        };
        assert!(matches!(
            hooks.run_pre_launch(),
            Err(HookError::Failed { code: 1, .. })
        ));
    }

    #[test]
    fn pre_launch_succeeds_when_all_pass() {
        let hooks = Hooks {
            pre_launch: vec!["true".into(), "true".into()],
            ..Default::default()
        };
        assert!(hooks.run_pre_launch().is_ok());
    }
}
