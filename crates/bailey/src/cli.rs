//! Command-line interface.
//!
//! Ties config resolution, hook execution, and backend selection together
//! behind the `run`, `audit`, and `show` subcommands.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::backend::{audit::AuditBackend, enforce::EnforceBackend, Backend, Target};
use crate::config::{self, Resolved};

/// Layered sandbox for running untrusted games and binaries.
#[derive(Debug, Parser)]
#[command(name = "bailey", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a target under enforcement.
    Run(RunArgs),
    /// Run a target under audit, recording its access.
    Audit(RunArgs),
    /// Resolve and print the effective policy for a target.
    Show(ShowArgs),
}

#[derive(Debug, clap::Args)]
struct RunArgs {
    /// Explicit config file, taking highest precedence.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// The target executable.
    target: PathBuf,
    /// Arguments passed to the target.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Debug, clap::Args)]
struct ShowArgs {
    /// Explicit config file, taking highest precedence.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// The target executable.
    target: PathBuf,
}

/// Parse arguments and dispatch the selected command.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli.command) {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("bailey: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(command: Command) -> anyhow::Result<i32> {
    match command {
        Command::Run(args) => launch(&EnforceBackend, args),
        Command::Audit(args) => launch(&AuditBackend, args),
        Command::Show(args) => {
            let resolved = config::resolve(&args.target, args.config.as_deref())?;
            print_policy(&resolved);
            Ok(0)
        }
    }
}

fn launch(backend: &dyn Backend, args: RunArgs) -> anyhow::Result<i32> {
    let resolved = config::resolve(&args.target, args.config.as_deref())?;
    let target = Target {
        program: args.target,
        args: args.args,
        cwd: None,
    };

    resolved.hooks.run_pre_launch()?;
    let code = backend.run(&resolved.policy, &target)?;
    if let Err(err) = resolved.hooks.run_post_exit(code) {
        eprintln!("bailey: post-exit hook failed: {err}");
    }
    Ok(code)
}

fn print_policy(resolved: &Resolved) {
    let policy = &resolved.policy;

    println!("filesystem:");
    if policy.filesystem.is_empty() {
        println!("  (none)");
    }
    for rule in &policy.filesystem {
        println!("  {} {}", access_flags(rule.access), rule.path.display());
    }

    println!("network:");
    println!("  egress: {:?}", policy.network.egress);
    println!("  bind_ports: {:?}", policy.network.bind_ports);

    println!("devices:");
    if policy.devices.is_empty() {
        println!("  (none)");
    }
    for rule in &policy.devices {
        println!("  {} {}", access_flags(rule.access), rule.path.display());
    }

    println!("resources: {:?}", policy.resources);
}

fn access_flags(access: crate::policy::Access) -> String {
    use crate::policy::Access;
    let mut flags = String::new();
    flags.push(if access.contains(Access::READ) {
        'r'
    } else {
        '-'
    });
    flags.push(if access.contains(Access::WRITE) {
        'w'
    } else {
        '-'
    });
    flags.push(if access.contains(Access::EXECUTE) {
        'x'
    } else {
        '-'
    });
    flags
}
