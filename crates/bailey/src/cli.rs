//! Command-line interface.
//!
//! Ties config resolution, bundled profiles, hook execution, backend selection,
//! and reconciliation together behind the `run`, `audit`, `show`, and `profile`
//! subcommands.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::backend::{audit::AuditBackend, enforce::EnforceBackend, Backend, Target};
use crate::config::{self, Resolved};
use crate::policy::Access;
use crate::profiles;
use crate::reconcile::{self, Finding, Risk};

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
    /// Run a target under audit, recording its access and reconciling it.
    Audit(RunArgs),
    /// Resolve and print the effective policy for a target.
    Show(ShowArgs),
    /// Inspect bundled profiles.
    Profile(ProfileArgs),
}

#[derive(Debug, clap::Args)]
struct RunArgs {
    /// Explicit config file, taking highest precedence.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Bundled profile to use as the base.
    #[arg(short, long, default_value = profiles::DEFAULT)]
    profile: String,
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
    /// Bundled profile to use as the base.
    #[arg(short, long, default_value = profiles::DEFAULT)]
    profile: String,
    /// The target executable.
    target: PathBuf,
}

#[derive(Debug, clap::Args)]
struct ProfileArgs {
    #[command(subcommand)]
    command: ProfileCommand,
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// List the bundled profiles.
    List,
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
        Command::Run(args) => cmd_run(args),
        Command::Audit(args) => cmd_audit(args),
        Command::Show(args) => cmd_show(args),
        Command::Profile(args) => cmd_profile(args),
    }
}

fn cmd_run(args: RunArgs) -> anyhow::Result<i32> {
    let resolved = resolve(&args.profile, &args.target, args.config.as_deref())?;
    let target = target_from(&args);

    resolved.hooks.run_pre_launch()?;
    let code = EnforceBackend.run(&resolved.policy, &target)?;
    if let Err(err) = resolved.hooks.run_post_exit(code) {
        eprintln!("bailey: post-exit hook failed: {err}");
    }
    Ok(code)
}

fn cmd_audit(args: RunArgs) -> anyhow::Result<i32> {
    let resolved = resolve(&args.profile, &args.target, args.config.as_deref())?;
    let target = target_from(&args);
    let target_dir = target_dir(&args.target);

    resolved.hooks.run_pre_launch()?;
    let (code, trace) = AuditBackend.run_and_record(&resolved.policy, &target)?;
    if let Err(err) = resolved.hooks.run_post_exit(code) {
        eprintln!("bailey: post-exit hook failed: {err}");
    }

    let findings = reconcile::reconcile(&trace, &resolved.policy, &target_dir);
    print_findings(&findings);
    Ok(code)
}

fn cmd_show(args: ShowArgs) -> anyhow::Result<i32> {
    let resolved = resolve(&args.profile, &args.target, args.config.as_deref())?;
    print_sources(&args.profile, &args.target, args.config.as_deref());
    print_policy(&resolved);
    Ok(0)
}

fn cmd_profile(args: ProfileArgs) -> anyhow::Result<i32> {
    match args.command {
        ProfileCommand::List => {
            for profile in profiles::ALL {
                let marker = if profile.name == profiles::DEFAULT {
                    " (default base)"
                } else {
                    ""
                };
                println!("{}{}", profile.name, marker);
                println!("  {}", profile.description);
            }
            Ok(0)
        }
    }
}

fn resolve(profile: &str, target: &Path, explicit: Option<&Path>) -> anyhow::Result<Resolved> {
    let bases = profiles::base_layers(profile).map_err(|err| anyhow::anyhow!(err))?;
    Ok(config::resolve_with_bases(&bases, target, explicit)?)
}

fn target_from(args: &RunArgs) -> Target {
    Target {
        program: args.target.clone(),
        args: args.args.clone(),
        cwd: None,
    }
}

fn target_dir(target: &Path) -> PathBuf {
    std::path::absolute(target)
        .unwrap_or_else(|_| target.to_path_buf())
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn print_sources(profile: &str, target: &Path, explicit: Option<&Path>) {
    println!("profile base: {profile}");
    let sources = config::sources(target, explicit);
    if sources.is_empty() {
        println!("config layers: (none)");
    } else {
        println!("config layers (low to high precedence):");
        for source in sources {
            println!("  {}", source.display());
        }
    }
    println!();
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

fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("audit: no ungranted access observed");
        return;
    }

    let high: Vec<_> = findings.iter().filter(|f| f.risk.is_high()).collect();
    let low: Vec<_> = findings.iter().filter(|f| !f.risk.is_high()).collect();

    println!("audit: {} ungranted access(es) observed", findings.len());
    if !high.is_empty() {
        println!("\nHIGH RISK (review before granting):");
        for finding in high {
            let reason = match &finding.risk {
                Risk::High(reason) => reason.as_str(),
                Risk::Low => "",
            };
            println!(
                "  [{:?}] {} ({reason})",
                finding.kind,
                describe_resource(finding),
            );
        }
    }
    if !low.is_empty() {
        println!("\nroutine (safe to grant):");
        for finding in low {
            println!("  [{:?}] {}", finding.kind, describe_resource(finding));
        }
    }
}

fn describe_resource(finding: &Finding) -> String {
    use crate::event::Resource;
    match &finding.resource {
        Resource::Path(path) => path.display().to_string(),
        Resource::Net { host, port } => match host {
            Some(host) => format!("{host}:{port}"),
            None => format!("port {port}"),
        },
    }
}

fn access_flags(access: Access) -> String {
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
