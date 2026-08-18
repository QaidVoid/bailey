//! Command-line interface.
//!
//! Ties config resolution, bundled profiles, hook execution, backend selection,
//! and reconciliation together behind the `run`, `audit`, `show`, and `profile`
//! subcommands.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::backend::{Backend, Target, audit::AuditBackend, enforce::EnforceBackend};
use crate::config::{self, Resolved};
use crate::event::AccessEvent;
use crate::policy::Access;
use crate::profiles;
use crate::reconcile::{self, Finding, Risk};

/// Layered, deny-by-default sandbox for running untrusted programs on Linux.
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
    Audit(AuditArgs),
    /// Resolve and print the effective policy for a target.
    Show(ShowArgs),
    /// Inspect bundled profiles and generate profiles from audit traces.
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
    /// Reconstruct the target's world with namespaces (defense in depth).
    #[arg(long)]
    isolate: bool,
    /// The target executable, followed by its own arguments.
    #[arg(required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

#[derive(Debug, clap::Args)]
struct AuditArgs {
    /// Explicit config file, taking highest precedence.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Bundled profile to use as the base.
    #[arg(short, long, default_value = profiles::DEFAULT)]
    profile: String,
    /// Write the recorded access trace to this file as JSON.
    #[arg(long)]
    save_trace: Option<PathBuf>,
    /// The target executable, followed by its own arguments.
    #[arg(required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
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
    /// Generate a deny-by-default profile from a saved audit trace.
    Generate(GenerateArgs),
}

#[derive(Debug, clap::Args)]
struct GenerateArgs {
    /// A trace file previously written with `audit --save-trace`.
    #[arg(long)]
    trace: PathBuf,
    /// The target the trace was recorded for, used to resolve the base policy.
    #[arg(long)]
    target: PathBuf,
    /// Explicit config file used when resolving the base policy.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Bundled profile used as the base when resolving.
    #[arg(short, long, default_value = profiles::DEFAULT)]
    profile: String,
    /// Include high-risk access (egress, credentials) in the generated profile.
    #[arg(long)]
    include_high_risk: bool,
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
    let (program, program_args) = split_command(args.command);
    let resolved = resolve(&args.profile, &program, args.config.as_deref())?;
    warn_if_target_denied(&resolved.policy, &program);
    let target = Target {
        program,
        args: program_args,
        cwd: None,
    };

    resolved.hooks.run_pre_launch()?;
    let backend = EnforceBackend {
        isolate: args.isolate,
    };
    let code = backend.run(&resolved.policy, &target)?;
    if let Err(err) = resolved.hooks.run_post_exit(code) {
        eprintln!("bailey: post-exit hook failed: {err}");
    }
    Ok(code)
}

fn cmd_audit(args: AuditArgs) -> anyhow::Result<i32> {
    let (program, program_args) = split_command(args.command);
    let resolved = resolve(&args.profile, &program, args.config.as_deref())?;
    let target_dir = target_dir(&program);
    let target = Target {
        program,
        args: program_args,
        cwd: None,
    };

    resolved.hooks.run_pre_launch()?;
    let (code, trace) = AuditBackend.run_and_record(&resolved.policy, &target)?;
    if let Err(err) = resolved.hooks.run_post_exit(code) {
        eprintln!("bailey: post-exit hook failed: {err}");
    }

    if let Some(path) = &args.save_trace {
        std::fs::write(path, serde_json::to_string_pretty(&trace)?)?;
        eprintln!("bailey: wrote trace to {}", path.display());
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
        ProfileCommand::Generate(args) => cmd_profile_generate(args),
    }
}

fn cmd_profile_generate(args: GenerateArgs) -> anyhow::Result<i32> {
    let text = std::fs::read_to_string(&args.trace)?;
    let trace: Vec<AccessEvent> = serde_json::from_str(&text)?;
    let resolved = resolve(&args.profile, &args.target, args.config.as_deref())?;
    let target_dir = target_dir(&args.target);

    let findings = reconcile::reconcile(&trace, &resolved.policy, &target_dir);
    let excluded = findings
        .iter()
        .filter(|finding| finding.risk.is_high())
        .count();
    let selected: Vec<Finding> = findings
        .into_iter()
        .filter(|finding| args.include_high_risk || !finding.risk.is_high())
        .collect();

    if excluded > 0 && !args.include_high_risk {
        eprintln!(
            "bailey: excluded {excluded} high-risk access(es); pass --include-high-risk to add them"
        );
    }
    print!("{}", reconcile::generate_profile(&selected));
    Ok(0)
}

fn resolve(profile: &str, target: &Path, explicit: Option<&Path>) -> anyhow::Result<Resolved> {
    let implicit = implicit_target_layer(target);
    let mut bases: Vec<(&str, &str)> = vec![("implicit:target", &implicit)];
    bases.extend(profiles::base_layers(profile).map_err(|err| anyhow::anyhow!(err))?);
    Ok(config::resolve_with_bases(&bases, target, explicit)?)
}

/// Split a command line into the target and the arguments passed to it.
///
/// Everything after the target is opaque to bailey, so a target's own flags are
/// never mistaken for bailey's.
fn split_command(mut command: Vec<String>) -> (PathBuf, Vec<String>) {
    let program = PathBuf::from(command.remove(0));
    (program, command)
}

/// The lowest-precedence layer, granting the target executable itself.
///
/// Executing the target is filesystem access like any other, so without this a
/// program outside the system paths cannot start under its own policy. It sits
/// beneath the bundled profile so any user layer can retract it.
fn implicit_target_layer(target: &Path) -> String {
    let program = toml_string(&absolute(target));
    format!("[filesystem]\nread = [{program}]\nexecute = [{program}]\n")
}

/// Render a path as a TOML basic string.
fn toml_string(path: &Path) -> String {
    let escaped = path
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Warn when the resolved policy denies the target itself, which would
/// otherwise surface only as an opaque permission error at exec time.
fn warn_if_target_denied(policy: &crate::policy::Policy, target: &Path) {
    let program = absolute(target);
    if policy.denied.iter().any(|path| program.starts_with(path)) {
        eprintln!(
            "bailey: warning: the policy denies the target `{}`; it will not start",
            program.display()
        );
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
            println!("  {} ({})", source.path.display(), source.origin.label());
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

    if !policy.denied.is_empty() {
        let nested: Vec<_> = policy.nested_denials().collect();
        println!("denied:");
        for path in &policy.denied {
            let note = if nested.contains(&path) {
                "  (nested under a grant: needs --isolate)"
            } else {
                ""
            };
            println!("  --- {}{note}", path.display());
        }
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
            println!("  [{:?}] {} ({reason})", finding.kind, describe(finding));
        }
    }
    if !low.is_empty() {
        println!("\nroutine (safe to grant):");
        for finding in low {
            println!("  [{:?}] {}", finding.kind, describe(finding));
        }
    }
}

fn describe(finding: &Finding) -> String {
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
