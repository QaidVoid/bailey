//! Command-line interface.
//!
//! Ties config resolution, bundled profiles, hook execution, backend selection,
//! and reconciliation together behind the `run`, `audit`, `show`, `profile`,
//! and `trust` subcommands.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::backend::probe;
use crate::backend::world::{self, World};
use crate::backend::{
    Backend, Target, audit::AuditBackend, enforce::EnforceBackend, enforce::Summary, isolation,
    network,
};
use crate::config::{self, Resolved};
use crate::event::Trace;
use crate::hook::{self, Shell};
use crate::policy::Access;
use crate::profiles;
use crate::reconcile::{self, Finding, Risk};
use crate::trust;

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
    /// Run a shell confined to this directory, covering everything it starts.
    Shell(ShellArgs),
    /// Run a target under audit, recording its access and reconciling it.
    Audit(AuditArgs),
    /// Resolve and print the effective policy for a target.
    Show(ShowArgs),
    /// Inspect bundled profiles and generate profiles from audit traces.
    Profile(ProfileArgs),
    /// Accept a discovered config file, or list what has been accepted.
    Trust(TrustArgs),
    /// Withdraw a config file's acceptance.
    Untrust {
        /// The config file to stop applying.
        path: PathBuf,
    },
    /// Emit shell integration, so a directory's policy announces itself.
    Hook(HookArgs),
    /// Report what this host can enforce, and what each gap costs.
    Doctor,
    /// Emit a shell completion script, generated from these commands.
    Completions {
        /// The shell to generate for.
        shell: clap_complete::Shell,
    },
    /// Emit a man page, generated from these commands.
    Man,
}

#[derive(Debug, clap::Args)]
struct RunArgs {
    /// Explicit config file, taking highest precedence.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Profile to use as the base. Defaults to a profile that claims this
    /// target, or to the untrusted floor.
    #[arg(short, long)]
    profile: Option<String>,
    /// Explicitly ask for namespace isolation. It is the default; the flag is
    /// accepted so existing invocations keep working.
    #[arg(long, conflicts_with = "no_isolate")]
    isolate: bool,
    /// Run without namespace isolation, leaving only Landlock and seccomp.
    ///
    /// Several things stop being enforceable: a nested `deny`, a `read_only`
    /// island, the private `/tmp`, and the private home at the real home's path.
    #[arg(long)]
    no_isolate: bool,
    /// Do not print what the run enforced.
    #[arg(long, conflicts_with = "json")]
    quiet: bool,
    /// Print what the run enforced as JSON.
    #[arg(long)]
    json: bool,
    /// The target executable, followed by its own arguments.
    #[arg(required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

#[derive(Debug, clap::Args)]
struct ShellArgs {
    /// Explicit config file, taking highest precedence.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Profile to use as the base. Defaults to a profile that claims the shell,
    /// or to the untrusted floor.
    #[arg(short, long)]
    profile: Option<String>,
    /// The shell to run. Defaults to `$SHELL`, then `/bin/sh`.
    #[arg(long)]
    shell: Option<String>,
    /// Run without namespace isolation, leaving only Landlock and seccomp.
    #[arg(long)]
    no_isolate: bool,
}

#[derive(Debug, clap::Args)]
struct AuditArgs {
    /// Explicit config file, taking highest precedence.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Profile to use as the base. Defaults to a profile that claims this
    /// target, or to the untrusted floor.
    #[arg(short, long)]
    profile: Option<String>,
    /// Write the recorded access trace to this file as JSON.
    #[arg(long)]
    save_trace: Option<PathBuf>,
    /// Namespace isolation, which audit cannot use yet and rejects.
    #[arg(long)]
    isolate: bool,
    /// Run the target with no confinement at all. It will have your full
    /// authority for the duration of the audit.
    #[arg(long)]
    unconfined: bool,
    /// The target executable, followed by its own arguments.
    #[arg(required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

#[derive(Debug, clap::Args)]
struct ShowArgs {
    /// Explicit config file, taking highest precedence.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Profile to use as the base. Defaults to a profile that claims this
    /// target, or to the untrusted floor.
    #[arg(short, long)]
    profile: Option<String>,
    /// The target executable, by path or by name on `PATH`.
    target: String,
}

#[derive(Debug, clap::Args)]
struct TrustArgs {
    /// The config file to accept, recording it as it currently reads.
    #[arg(required_unless_present = "list")]
    path: Option<PathBuf>,
    /// List accepted config files and whether each still applies.
    #[arg(long, conflicts_with = "path")]
    list: bool,
}

#[derive(Debug, clap::Args)]
struct HookArgs {
    #[command(subcommand)]
    command: HookCommand,
}

#[derive(Debug, Subcommand)]
enum HookCommand {
    /// Emit integration for fish: `bailey hook fish | source`.
    Fish(HookOptions),
    /// Emit integration for bash: `eval "$(bailey hook bash)"`.
    Bash(HookOptions),
    /// Print what the hook should say about the current directory.
    Status {
        /// Print a state and the message, tab separated, for the snippets.
        #[arg(long)]
        porcelain: bool,
    },
    /// List the programs `--wrap` defines functions for.
    ListWrapped,
}

#[derive(Debug, clap::Args)]
struct HookOptions {
    /// Offer to enter a confined shell rather than only mentioning one.
    ///
    /// Never offers to trust a config: accepting one stays a deliberate act,
    /// away from whatever you were in the middle of.
    #[arg(long)]
    ask: bool,
    /// Define a function for each program your own profiles claim, so running
    /// it by name runs it under bailey.
    #[arg(long)]
    wrap: bool,
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
    /// Print a bundled profile, so it can be copied and edited.
    Show { name: String },
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
    /// Profile used as the base when resolving. Defaults as `run` does.
    #[arg(short, long)]
    profile: Option<String>,
    /// Include high-risk access (egress, credentials) in the generated profile.
    #[arg(long)]
    include_high_risk: bool,
    /// Generate from a trace that is known to be missing events.
    #[arg(long)]
    accept_truncated: bool,
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
        Command::Shell(args) => cmd_shell(args),
        Command::Audit(args) => cmd_audit(args),
        Command::Show(args) => cmd_show(args),
        Command::Profile(args) => cmd_profile(args),
        Command::Trust(args) => cmd_trust(args),
        Command::Untrust { path } => cmd_untrust(&path),
        Command::Hook(args) => cmd_hook(args),
        Command::Doctor => cmd_doctor(),
        Command::Completions { shell } => {
            // Generated rather than maintained, so it cannot drift from the
            // commands that actually exist.
            let mut command = <Cli as clap::CommandFactory>::command();
            clap_complete::generate(shell, &mut command, "bailey", &mut std::io::stdout());
            Ok(0)
        }
        Command::Man => {
            let command = <Cli as clap::CommandFactory>::command();
            clap_mangen::Man::new(command).render(&mut std::io::stdout())?;
            Ok(0)
        }
    }
}

/// Report each mechanism bailey relies on, and what its absence means for a run.
///
/// Presence alone is not useful: "Landlock: yes" does not say whether network
/// policy will be enforced, which needs ABI 4. The consequence is the part a
/// user can act on.
/// Emit shell integration, or answer the question it asks.
fn cmd_hook(args: HookArgs) -> anyhow::Result<i32> {
    match args.command {
        HookCommand::Fish(options) => {
            print!("{}", hook::snippet(Shell::Fish, options.ask, options.wrap));
        }
        HookCommand::Bash(options) => {
            print!("{}", hook::snippet(Shell::Bash, options.ask, options.wrap));
        }
        HookCommand::Status { porcelain } => {
            let notice = hook::notice();
            if porcelain {
                let line = notice.porcelain();
                if !line.is_empty() {
                    println!("{line}");
                }
            } else if let Some(message) = notice.message() {
                println!("{message}");
            }
        }
        HookCommand::ListWrapped => {
            let names = profiles::claimed_names();
            if names.is_empty() {
                println!("no programs are claimed by your profiles; add `applies_to` to one");
            }
            for name in names {
                println!("{name}");
            }
        }
    }
    Ok(0)
}

fn cmd_doctor() -> anyhow::Result<i32> {
    let caps = probe::probe(true);
    let mut degraded = false;

    println!("kernel:");
    match caps.landlock_abi {
        Some(abi) => {
            println!("  landlock: ABI {abi}");
            if !caps.landlock_network() {
                degraded = true;
                println!("    network policy is NOT enforced (needs ABI 4, Linux 6.7)");
            }
            if !caps.landlock_scope() {
                degraded = true;
                println!(
                    "    abstract sockets and signals are NOT scoped (needs ABI 6, Linux 6.12)"
                );
            }
        }
        None => {
            degraded = true;
            println!("  landlock: unavailable");
            println!("    filesystem and network policy will NOT be enforced");
        }
    }

    println!("  user namespaces: {}", yes_no(caps.unprivileged_userns));
    if !caps.unprivileged_userns {
        degraded = true;
        println!("    `--isolate` will fall back to Landlock and seccomp");
        println!("    denied egress will cover TCP only, not UDP or DNS");
        println!("    a nested `deny` cannot be enforced");
    }

    println!("  cgroup delegation: {}", yes_no(caps.cgroup_delegated));
    if !caps.cgroup_delegated {
        degraded = true;
        println!("    resource limits will be skipped");
        println!("    a run needs a cgroup it may create children in, with the memory, pids");
        println!("    and cpu controllers delegated; set BAILEY_CGROUP_ROOT to name one");
    }

    println!("audit:");
    println!("  kernel BTF: {}", yes_no(caps.btf));
    match &caps.helper {
        probe::HelperStatus::Ready(path) => {
            println!("  helper: ready ({})", path.display());
        }
        probe::HelperStatus::NotPermitted(path) => {
            degraded = true;
            println!("  helper: found but cannot load ({})", path.display());
            println!(
                "    grant it capabilities: setcap cap_bpf,cap_perfmon+ep {}",
                path.display()
            );
        }
        probe::HelperStatus::Missing => {
            degraded = true;
            println!("  helper: not found");
            println!("    `bailey audit` will not run; build it with -p bailey-bpf-helper");
        }
    }

    if !degraded {
        println!("\nEverything bailey uses is available on this host.");
    }
    Ok(0)
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn cmd_run(args: RunArgs) -> anyhow::Result<i32> {
    let (program, program_args) = split_command(args.command)?;
    let profile = select_profile(args.profile.as_deref(), &program)?;
    let resolved = resolve(&profile, &program, args.config.as_deref())?;
    report_untrusted(&program, args.config.as_deref());
    warn_if_target_denied(&resolved.policy, &program);
    let target = Target {
        program,
        args: program_args,
        cwd: None,
    };

    resolved.hooks.run_pre_launch()?;
    let backend = EnforceBackend {
        // Isolation is the default: without it a nested `deny`, a `read_only`
        // island and the private `/tmp` all silently stop being enforceable.
        isolate: !args.no_isolate,
        stop_before_exec: false,
        summary: if args.json {
            Summary::Json
        } else if args.quiet {
            Summary::Quiet
        } else {
            Summary::Text
        },
        always_cgroup: false,
        implicit_write: Vec::new(),
    };
    let code = backend.run(&resolved.policy, &target)?;
    if let Err(err) = resolved.hooks.run_post_exit(code) {
        eprintln!("bailey: post-exit hook failed: {err}");
    }
    Ok(code)
}

/// Run a shell under the policy for the directory it was launched from.
///
/// A Landlock ruleset survives `fork` and `exec` and cannot be relaxed by the
/// process it restricts, and the namespaces are inherited the same way, so
/// everything started from the shell is confined by the same policy. That is the
/// difference between a policy that applies to the commands someone remembered
/// to prefix and one that applies to a directory.
fn cmd_shell(args: ShellArgs) -> anyhow::Result<i32> {
    let shell = resolve_shell(args.shell.as_deref())?;
    let dir = std::env::current_dir()?;

    let profile = select_profile(args.profile.as_deref(), &shell)?;
    let mut resolved = resolve_for_shell(&profile, &shell, &dir, args.config.as_deref())?;
    report_untrusted(&shell, args.config.as_deref());
    report_nesting();
    warn_if_home_granted(&dir);

    // Named here rather than derived from the shell, which is called `bash` in
    // every project and would give them all one home to share.
    if resolved.policy.home.is_none() {
        resolved.policy.home = Some(world::directory_home(&dir));
    }
    // `BAILEY_SANDBOX` comes with any confined run. This names the directory the
    // policy was resolved for, which is the part a prompt wants to show, and it
    // is a marker rather than a modified prompt because every shell spells its
    // own and the prompt belongs to the user.
    resolved
        .policy
        .env
        .set
        .insert("BAILEY_SANDBOX_DIR".into(), dir.display().to_string());

    let target = Target {
        program: shell,
        args: Vec::new(),
        cwd: None,
    };

    resolved.hooks.run_pre_launch()?;
    let backend = EnforceBackend {
        isolate: !args.no_isolate,
        stop_before_exec: false,
        // Before the shell takes the terminal, rather than as the user leaves.
        summary: Summary::Established,
        always_cgroup: false,
        // The launch directory is granted for writing on the user's behalf, so
        // a narrower grant their config makes beneath it is kept narrow.
        implicit_write: vec![dir.clone()],
    };
    let code = backend.run(&resolved.policy, &target)?;
    if let Err(err) = resolved.hooks.run_post_exit(code) {
        eprintln!("bailey: post-exit hook failed: {err}");
    }
    Ok(code)
}

/// The shell to confine: the one the user asked for, the one they chose for
/// themselves, or the one that exists everywhere.
fn resolve_shell(requested: Option<&str>) -> anyhow::Result<PathBuf> {
    if let Some(name) = requested {
        return resolve_target(name);
    }
    match std::env::var("SHELL") {
        Ok(shell) if !shell.is_empty() => resolve_target(&shell),
        _ => resolve_target("/bin/sh"),
    }
}

/// Resolve the policy for a confined shell.
///
/// Two implicit layers sit beneath the profile: the shell itself, without which
/// nothing can start, and the directory the shell was launched from, without
/// which the shell cannot read the thing it was opened to work on. Both are at
/// the bottom of the stack, so any profile or config layer can retract them.
fn resolve_for_shell(
    profile: &str,
    shell: &Path,
    dir: &Path,
    explicit: Option<&Path>,
) -> anyhow::Result<Resolved> {
    let implicit_shell = implicit_target_layer(shell);
    let implicit_dir = implicit_dir_layer(dir);
    let layers = profiles::base_layers(profile).map_err(|err| anyhow::anyhow!(err))?;
    let mut bases: Vec<(&str, &str)> = vec![
        ("implicit:shell", implicit_shell.as_str()),
        ("implicit:cwd", implicit_dir.as_str()),
    ];
    bases.extend(
        layers
            .iter()
            .map(|layer| (layer.label.as_str(), layer.toml.as_str())),
    );
    Ok(config::resolve_with_bases(&bases, shell, explicit)?)
}

/// The layer granting the directory the shell was launched from.
fn implicit_dir_layer(dir: &Path) -> String {
    let dir = toml_string(dir);
    format!("[filesystem]\nread = [{dir}]\nwrite = [{dir}]\nexecute = [{dir}]\n")
}

/// Report that the implicit grant covers the whole home directory.
///
/// Inherent to granting "wherever I am": launched from the home, it grants the
/// home. Refusing would mean overruling a directory the user chose, so this
/// says what happened and leaves the choice alone.
fn warn_if_home_granted(dir: &Path) {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    if Path::new(&home).starts_with(dir) {
        eprintln!(
            "bailey: warning: this shell was launched from `{}`, so the implicit \
             grant covers your whole home directory. Launch it from the directory \
             you meant to confine it to, or retract the grant in config.",
            dir.display()
        );
    }
}

/// Report a shell started inside a shell.
fn report_nesting() {
    let Some(outer) = std::env::var_os("BAILEY_SANDBOX_DIR") else {
        return;
    };
    eprintln!(
        "bailey: note: already inside a sandbox for `{}`. Its policy still \
         applies and this one can only narrow it further; the isolation layer \
         cannot be entered a second time.",
        Path::new(&outer).display()
    );
}

fn cmd_audit(args: AuditArgs) -> anyhow::Result<i32> {
    let (program, program_args) = split_command(args.command)?;
    let profile = select_profile(args.profile.as_deref(), &program)?;
    let resolved = resolve(&profile, &program, args.config.as_deref())?;
    report_untrusted(&program, args.config.as_deref());
    let target_dir = target_dir(&program);
    let target = Target {
        program,
        args: program_args,
        cwd: None,
    };

    resolved.hooks.run_pre_launch()?;
    if args.isolate {
        anyhow::bail!(
            "`audit` cannot use namespace isolation yet: the recorder needs the \
             target stopped at exec, and that stop is not inherited across the \
             fork that puts it in a PID namespace. Audit without `--isolate`, or \
             enforce with `bailey run`."
        );
    }
    let backend = AuditBackend {
        unconfined: args.unconfined,
        // Not defaulted on, unlike `run`: see the check above.
        isolate: false,
    };
    let (code, trace) = backend.run_and_record(&resolved.policy, &target)?;
    if let Err(err) = resolved.hooks.run_post_exit(code) {
        eprintln!("bailey: post-exit hook failed: {err}");
    }

    if trace.is_truncated() {
        eprintln!(
            "bailey: warning: {} access(es) could not be recorded; this trace is incomplete",
            trace.dropped
        );
    }

    if let Some(path) = &args.save_trace {
        std::fs::write(path, serde_json::to_string_pretty(&trace)?)?;
        eprintln!("bailey: wrote trace to {}", path.display());
        // Carrying this run's flags across matters more than it looks: generating
        // against a different policy reconciles the same trace against different
        // grants, and reports a wildly different set of findings without saying
        // that is what happened.
        let mut flags = String::new();
        if let Some(config) = &args.config {
            flags.push_str(&format!(" -c {}", config.display()));
        }
        if let Some(profile) = &args.profile {
            flags.push_str(&format!(" -p {profile}"));
        }
        eprintln!("bailey: turn it into a policy with the same policy this run used:");
        eprintln!(
            "bailey:   bailey profile generate{flags} --trace {} --target {}",
            path.display(),
            target.program.display()
        );
    }

    let effective = policy_with_own_storage(&resolved.policy, &target.program);
    let findings = reconcile::reconcile(&trace.events, &effective, &target_dir);
    print_findings(&findings, code);
    Ok(code)
}

fn cmd_show(args: ShowArgs) -> anyhow::Result<i32> {
    let target = resolve_target(&args.target)?;
    let profile = select_profile(args.profile.as_deref(), &target)?;
    let resolved = resolve(&profile, &target, args.config.as_deref())?;
    print_sources(&profile, &target, args.config.as_deref());
    print_policy(&resolved, &target);
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
            let yours = profiles::user_profiles();
            if !yours.is_empty() {
                println!("\nyours:");
                for (name, path) in yours {
                    println!("{name}");
                    println!("  {}", path.display());
                }
            }
            Ok(0)
        }
        ProfileCommand::Show { name } => {
            let source = profiles::source(&name).map_err(|err| anyhow::anyhow!(err))?;
            print!("{}", source.toml());
            Ok(0)
        }
        ProfileCommand::Generate(args) => cmd_profile_generate(args),
    }
}

/// Accept a config file, so that discovery may apply it.
///
/// Acceptance is a command rather than a prompt during a run. A question asked
/// while someone is trying to get on with something else is answered
/// reflexively, and a run has to work where nobody is present to answer at all.
fn cmd_trust(args: TrustArgs) -> anyhow::Result<i32> {
    let mut store = trust::Store::load();

    if args.list {
        let entries = store.listing();
        if entries.is_empty() {
            println!("no config files have been trusted");
            return Ok(0);
        }
        for (path, rejected) in entries {
            match rejected {
                None => println!("  {:<10} {}", "ok", path.display()),
                Some(reason) => println!("  {:<10} {}", reason.word(), path.display()),
            }
        }
        return Ok(0);
    }

    let path = args
        .path
        .expect("clap requires a path unless --list is given");
    // `record` refuses when the store is unreachable, which is what keeps a
    // trust command run from inside a sandbox from looking like it worked.
    let recorded = store.record(&path).map_err(|err| anyhow::anyhow!(err))?;
    store.save().map_err(|err| anyhow::anyhow!(err))?;
    println!("trusted {}", recorded.display());
    Ok(0)
}

fn cmd_untrust(path: &Path) -> anyhow::Result<i32> {
    let mut store = trust::Store::load();
    let path = absolute(path);
    if !store.forget(&path) {
        anyhow::bail!("`{}` was not trusted", path.display());
    }
    store.save().map_err(|err| anyhow::anyhow!(err))?;
    println!("no longer trusting {}", path.display());
    Ok(0)
}

/// Report every discovered config that was found but did not apply.
///
/// A run proceeds with the narrower policy rather than failing, so this report
/// is the only thing that connects "the program cannot read its own directory"
/// to the file that would have granted it.
fn report_untrusted(target: &Path, explicit: Option<&Path>) {
    for source in config::sources(target, explicit) {
        let Some(rejected) = &source.rejected else {
            continue;
        };
        eprintln!(
            "bailey: not applying `{}`: {}",
            source.path.display(),
            rejected.reason()
        );
        if let Some(remedy) = rejected.remedy(&source.path) {
            eprintln!("bailey:   {remedy}");
        }
    }
}

/// The policy as it stood at run time, including what the sandbox provides on
/// its own.
///
/// The private home is created and granted by the backend rather than written in
/// anyone's config, so a plain reconciliation reports a program reading its own
/// settings as ungranted access outside its directory. Every audited program
/// does that, and a high-risk list full of a program's own storage is one nobody
/// reads.
fn policy_with_own_storage(policy: &crate::policy::Policy, target: &Path) -> crate::policy::Policy {
    let mut effective = policy.clone();
    // Audit does not isolate, so the home the target used is the host one.
    let world = World::derive(target, policy, false);
    if let Some(home) = world.home_host {
        effective.filesystem.push(crate::policy::FsRule {
            path: home,
            access: Access::READ | Access::WRITE,
        });
    }
    effective
}

fn cmd_profile_generate(args: GenerateArgs) -> anyhow::Result<i32> {
    let text = std::fs::read_to_string(&args.trace)?;
    let trace: Trace = serde_json::from_str(&text).map_err(|err| {
        anyhow::anyhow!(
            "`{}` is not a trace this build understands ({err});              record a new one with `bailey audit --save-trace`",
            args.trace.display()
        )
    })?;
    trace.check_version().map_err(|err| anyhow::anyhow!(err))?;

    if trace.is_truncated() && !args.accept_truncated {
        anyhow::bail!(
            "this trace is missing {} access(es), so a profile generated from it \
             would grant less than the target needs; pass --accept-truncated to \
             proceed anyway",
            trace.dropped
        );
    }

    let profile = select_profile(args.profile.as_deref(), &args.target)?;
    let resolved = resolve(&profile, &args.target, args.config.as_deref())?;
    let target_dir = target_dir(&args.target);

    let effective = policy_with_own_storage(&resolved.policy, &args.target);
    let findings = reconcile::reconcile(&trace.events, &effective, &target_dir);

    // Counted apart from the high-risk ones. A finding whose path could not be
    // resolved is dropped whatever the flags say, so folding it into the
    // high-risk count would report a number that disagrees with the list
    // `bailey audit` printed, and would offer a flag that does not bring it
    // back.
    let unresolved = findings.iter().filter(|finding| finding.unresolved).count();
    let excluded = findings
        .iter()
        .filter(|finding| !finding.unresolved && finding.risk.is_high())
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
    if unresolved > 0 {
        eprintln!(
            "bailey: skipped {unresolved} access(es) whose path could not be resolved, so the \
             profile does not grant them. They are relative paths, which the recorder cannot \
             place after the fact; audit the target by its absolute path to resolve them."
        );
    }
    if trace.is_truncated() {
        println!(
            "# Generated from an incomplete trace: {} access(es) were not recorded.",
            trace.dropped
        );
    }
    // What this grants is the difference between the trace and the policy it was
    // reconciled against, so on its own it is not a policy that runs anything.
    if args.config.is_some() || args.profile.is_some() {
        let base = match (&args.config, &args.profile) {
            (Some(config), _) => format!("-c {}", config.display()),
            (_, Some(profile)) => format!("-p {profile}"),
            _ => unreachable!("one of the two is set"),
        };
        println!("# Grants what `{base}` did not. Use it alongside that, not instead of it.");
    }
    if !resolved.policy.env.set.is_empty() {
        println!(
            "# The environment is not generated: `[env]` settings such as PATH are not \
             accesses, so nothing in a trace can imply them. Carry them over yourself."
        );
    }
    print!("{}", reconcile::generate_profile(&selected));
    Ok(0)
}

/// Decide which profile a run uses.
///
/// An explicit `--profile` wins. Otherwise a user profile that claims this
/// target is used, and the choice is reported, since a policy that was selected
/// for you should not be invisible.
fn select_profile(requested: Option<&str>, target: &Path) -> anyhow::Result<String> {
    if let Some(name) = requested {
        return Ok(name.to_owned());
    }
    match profiles::for_target(target).map_err(|err| anyhow::anyhow!(err))? {
        Some(name) => {
            eprintln!("bailey: using profile `{name}`, which claims this target");
            Ok(name)
        }
        None => Ok(profiles::DEFAULT.to_owned()),
    }
}

fn resolve(profile: &str, target: &Path, explicit: Option<&Path>) -> anyhow::Result<Resolved> {
    let implicit = implicit_target_layer(target);
    let layers = profiles::base_layers(profile).map_err(|err| anyhow::anyhow!(err))?;
    let mut bases: Vec<(&str, &str)> = vec![("implicit:target", implicit.as_str())];
    bases.extend(
        layers
            .iter()
            .map(|layer| (layer.label.as_str(), layer.toml.as_str())),
    );
    Ok(config::resolve_with_bases(&bases, target, explicit)?)
}

/// Split a command line into the target and the arguments passed to it.
///
/// Everything after the target is opaque to bailey, so a target's own flags are
/// never mistaken for bailey's.
fn split_command(mut command: Vec<String>) -> anyhow::Result<(PathBuf, Vec<String>)> {
    let program = resolve_target(&command.remove(0))?;
    Ok((program, command))
}

/// Find the program a name refers to.
///
/// A name with no separator is looked up on `PATH`, the way a shell would, so
/// `bailey run curl` means what it appears to. A name that resolves to nothing
/// is an error: silently building a policy for a file that does not exist tells
/// the user about a sandbox they are not going to get.
fn resolve_target(name: &str) -> anyhow::Result<PathBuf> {
    if name.contains('/') {
        let path = PathBuf::from(name);
        if !path.is_file() {
            anyhow::bail!("`{name}` does not exist");
        }
        return Ok(path);
    }

    let paths = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&paths)
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
        .ok_or_else(|| anyhow::anyhow!("`{name}` was not found on PATH"))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
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
        println!();
        return;
    }

    println!("config layers (low to high precedence):");
    for source in &sources {
        match &source.rejected {
            None => println!("  {} ({})", source.path.display(), source.origin.label()),
            Some(rejected) => println!(
                "  {} ({}) [not applied: {}]",
                source.path.display(),
                source.origin.label(),
                rejected.reason()
            ),
        }
    }

    // The policy below is the one that will apply, so the layers missing from
    // it have to be visible here or the gap looks like a bug in the resolver.
    let remedies: Vec<String> = sources
        .iter()
        .filter_map(|source| {
            source
                .rejected
                .as_ref()
                .and_then(|rejected| rejected.remedy(&source.path))
        })
        .collect();
    if !remedies.is_empty() {
        println!("\nto apply what was skipped:");
        for remedy in remedies {
            println!("  {remedy}");
        }
    }
    println!();
}

fn print_policy(resolved: &Resolved, target: &Path) {
    let policy = &resolved.policy;

    println!("filesystem:");
    if policy.filesystem.is_empty() {
        println!("  (none)");
    }
    for rule in &policy.filesystem {
        println!("  {} {}", access_flags(rule.access), rule.path.display());
    }

    if !policy.read_only.is_empty() {
        let nested: Vec<_> = policy.nested_read_only().collect();
        println!("read-only:");
        for path in &policy.read_only {
            let note = if nested.contains(&path) {
                "  (inside a writable grant: needs isolation)"
            } else {
                ""
            };
            println!("  r-- {}{note}", path.display());
        }
    }

    if !policy.denied.is_empty() {
        let nested: Vec<_> = policy.nested_denials().collect();
        println!("denied:");
        for path in &policy.denied {
            let note = if nested.contains(&path) {
                "  (nested under a grant: needs isolation)"
            } else {
                ""
            };
            println!("  --- {}{note}", path.display());
        }
    }

    println!("network:");
    println!("  egress: {:?}", policy.network.egress);
    println!("  bind_ports: {:?}", policy.network.bind_ports);
    let mode = network::select(policy, isolation::available());
    println!("  mode: {}", mode.describe());

    println!("devices:");
    if policy.devices.is_empty() {
        println!("  (none)");
    }
    for rule in &policy.devices {
        println!("  {} {}", access_flags(rule.access), rule.path.display());
    }

    println!("resources: {:?}", policy.resources);

    let world = World::derive(target, policy, false);
    println!("home: {}", world.home_inside.display());
    if world.home_host.is_some() {
        println!("  (private; the real home is not granted)");
    }

    println!("environment:");
    for (name, value) in world::environment(policy, &world, mode) {
        let origin = if policy.env.set.contains_key(&name) {
            "set"
        } else if policy.env.passes(&name) {
            "passed"
        } else {
            "base"
        };
        println!("  {name}={value}  ({origin})");
    }
}

/// Report what the run touched that the policy does not grant.
///
/// The exit status is part of the report. A trace is only evidence about the
/// work the target actually did, so "nothing ungranted" from a run that failed
/// says nothing about whether the policy is sufficient: the target may have
/// stopped long before reaching what it needs.
fn print_findings(findings: &[Finding], exit_code: i32) {
    if findings.is_empty() {
        println!("{}", nothing_observed(exit_code));
        return;
    }
    if exit_code != 0 {
        println!(
            "audit: the target exited {exit_code}, so this trace may stop short of what \
             it needs"
        );
        if let Some(hint) = command_not_found_hint(exit_code) {
            println!("{hint}");
        }
    }

    let unresolved: Vec<_> = findings.iter().filter(|f| f.unresolved).collect();
    let high: Vec<_> = findings
        .iter()
        .filter(|f| !f.unresolved && f.risk.is_high())
        .collect();
    let low: Vec<_> = findings
        .iter()
        .filter(|f| !f.unresolved && !f.risk.is_high())
        .collect();

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
    if !unresolved.is_empty() {
        println!("\nunresolved (relative paths whose directory could not be read):");
        for finding in unresolved {
            println!("  [{:?}] {}", finding.kind, describe(finding));
        }
    }
}

/// What to say when a trace holds nothing the policy does not already grant.
///
/// From a run that worked, that is the answer everyone wants. From one that
/// failed it is close to meaningless, and reads like a clean bill of health,
/// which is the worst way for this to be wrong.
fn nothing_observed(exit_code: i32) -> String {
    if exit_code == 0 {
        return "audit: no ungranted access observed".into();
    }
    let mut message = format!(
        "audit: no ungranted access observed, but the target exited {exit_code}, so this \
         trace is of a run that did not do its work. Nothing here says the policy is \
         sufficient."
    );
    if let Some(hint) = command_not_found_hint(exit_code) {
        message.push('\n');
        message.push_str(&hint);
    }
    message
}

/// Explain the status a shell returns for a program it could not find.
///
/// The way to get it here is an interpreter: a `#!/usr/bin/env foo` script whose
/// `foo` lives under the home, which the built `PATH` does not name. Nothing is
/// recorded for it either, because a program that never looks somewhere never
/// opens anything there, and the trace can only hold what was opened.
fn command_not_found_hint(exit_code: i32) -> Option<String> {
    (exit_code == 127).then(|| {
        format!(
            "audit: 127 is what a shell returns for a program it could not find, and \
             nothing is recorded for a path that was never looked at. The sandbox PATH \
             is `{}`, so an interpreter installed under your home is not on it. Grant \
             its directory and pass PATH through, or name it by absolute path.",
            world::SANDBOX_PATH
        )
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_trace_from_a_failed_run_is_not_a_clean_bill_of_health() {
        let worked = nothing_observed(0);
        assert_eq!(worked, "audit: no ungranted access observed");

        let failed = nothing_observed(1);
        assert!(failed.contains("did not do its work"), "{failed}");
        assert!(
            !failed.contains("127 is what a shell returns"),
            "the interpreter hint belongs to 127 alone: {failed}"
        );

        // The case that prompted this: a `#!/usr/bin/env node` script whose node
        // is installed under the home, so nothing is ever opened to record.
        let missing = nothing_observed(127);
        assert!(missing.contains("did not do its work"), "{missing}");
        assert!(missing.contains(world::SANDBOX_PATH), "{missing}");
    }
}
