//! Command-line interface.
//!
//! Ties config resolution, bundled profiles, hook execution, backend selection,
//! and reconciliation together behind the `run`, `audit`, `show`, `profile`,
//! and `trust` subcommands.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::backend::probe;
use crate::backend::world::{self, World};
use crate::backend::{
    Backend, Target, audit::AuditBackend, enforce::EnforceBackend, enforce::Summary, forward,
    isolation, network,
};
use crate::config::{self, Resolved};
use crate::event::Trace;
use crate::hook::{self, Shell};
use crate::hooks::{self, Hooks};
use crate::policy::{Access, Egress, Policy, PortForward};
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

/// One-off grants given on the command line.
///
/// They form the highest-precedence layer, above `--config`, and need no
/// config file and no trust step: the caller typed them, which is the same
/// standing an explicit config has. Paths resolve the way config paths do,
/// with one difference: relative paths resolve against the working directory,
/// because `--allow-write .` means "from where I am", not "from where the
/// target lives".
#[derive(Debug, Default, clap::Args)]
pub struct QuickGrants {
    /// Grant read access to a path.
    #[arg(long, value_name = "PATH")]
    pub allow_read: Vec<String>,
    /// Grant write access to a path.
    #[arg(long, value_name = "PATH")]
    pub allow_write: Vec<String>,
    /// Grant execute access to a path.
    #[arg(long, value_name = "PATH")]
    pub allow_exec: Vec<String>,
    /// Keep a path read-only inside an allowed writable parent. Needs
    /// isolation to hold.
    #[arg(long, value_name = "PATH")]
    pub read_only: Vec<String>,
    /// Deny a path outright, retracting any grant a config made. Needs
    /// isolation to hold.
    #[arg(long, value_name = "PATH")]
    pub deny: Vec<String>,
    /// Allow outbound TCP to this port, on any host. Enforcement matches the
    /// port only; a config layer's egress choice is replaced.
    #[arg(long, value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
    pub allow_net: Vec<u16>,
}

impl QuickGrants {
    /// Whether any grant was asked for.
    pub fn is_empty(&self) -> bool {
        self.allow_read.is_empty()
            && self.allow_write.is_empty()
            && self.allow_exec.is_empty()
            && self.read_only.is_empty()
            && self.deny.is_empty()
            && self.allow_net.is_empty()
    }

    /// The layer these flags describe, as TOML, or `None` when no flag was
    /// given.
    pub fn layer(&self) -> anyhow::Result<Option<String>> {
        if self.is_empty() {
            return Ok(None);
        }
        let resolve_all = |paths: &[String]| -> anyhow::Result<Vec<PathBuf>> {
            paths
                .iter()
                .map(|raw| {
                    config::expand_flag_path(raw)
                        .map_err(|err| anyhow::anyhow!("--allow path: {err}"))
                })
                .collect()
        };
        let read = resolve_all(&self.allow_read)?;
        let write = resolve_all(&self.allow_write)?;
        let execute = resolve_all(&self.allow_exec)?;
        let read_only = resolve_all(&self.read_only)?;
        let deny = resolve_all(&self.deny)?;

        let mut granted = std::collections::BTreeSet::new();
        for path in read.iter().chain(&write).chain(&execute) {
            granted.insert(path.clone());
        }
        for path in &deny {
            if granted.contains(path) {
                anyhow::bail!(
                    "`{}` is both granted and denied on the command line",
                    path.display()
                );
            }
        }

        let list = |paths: &[PathBuf]| -> String {
            paths
                .iter()
                .map(|path| crate::strings::quoted(&path.to_string_lossy()))
                .collect::<Vec<_>>()
                .join(", ")
        };

        let mut out = String::new();
        let mut fs_keys = Vec::new();
        if !read.is_empty() {
            fs_keys.push(format!("read = [{}]", list(&read)));
        }
        if !write.is_empty() {
            fs_keys.push(format!("write = [{}]", list(&write)));
        }
        if !execute.is_empty() {
            fs_keys.push(format!("execute = [{}]", list(&execute)));
        }
        if !read_only.is_empty() {
            fs_keys.push(format!("read_only = [{}]", list(&read_only)));
        }
        if !deny.is_empty() {
            fs_keys.push(format!("deny = [{}]", list(&deny)));
        }
        if !fs_keys.is_empty() {
            out.push_str("[filesystem]\n");
            for key in &fs_keys {
                out.push_str(key);
                out.push('\n');
            }
        }
        if !self.allow_net.is_empty() {
            let rules = self
                .allow_net
                .iter()
                .map(|port| format!("{{ host = \"*\", port = {port} }}"))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("[network]\negress_allow = [{rules}]\n"));
        }
        Ok(Some(out))
    }
}

#[derive(Debug, clap::Args)]
struct RunArgs {
    /// Explicit config file, taking highest precedence.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// One-off grants, taking precedence over every config file.
    #[command(flatten)]
    quick_grants: QuickGrants,
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
    #[command(flatten)]
    network: NetworkArgs,
    /// The target executable, followed by its own arguments.
    #[arg(required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

#[derive(Debug, Default, clap::Args)]
struct NetworkArgs {
    /// Route egress through a private network namespace, so the session sees a
    /// synthetic address and MAC rather than the host's. Needs pasta and user
    /// namespaces; where either is missing the run is refused rather than
    /// silently staying on the host's network.
    #[arg(long, conflicts_with = "no_proxy_net")]
    proxy_net: bool,
    /// Never use a private network namespace, even where one was available.
    #[arg(long)]
    no_proxy_net: bool,
    /// Force all egress through a broker reachable only at ADDR:PORT.
    ///
    /// Implies `--proxy-net`. The private namespace is given ADDR as the host's
    /// loopback stand-in, and a netfilter rule drops every outbound connection
    /// except one to ADDR:PORT, so the session reaches the broker and nothing
    /// else. If the rule cannot be applied the run refuses rather than fall
    /// back to open egress. Needs pasta, user namespaces and `nft`; where one
    /// is missing the run is refused.
    #[arg(long, value_name = "ADDR:PORT", conflicts_with = "no_proxy_net")]
    egress_proxy: Option<String>,
    /// Publish this sandbox TCP port on host loopback, so a service bound
    /// inside the sandbox is reachable at `127.0.0.1:<PORT>` on the host.
    /// Repeatable. Needs the private namespace, which automatic mode provides
    /// where the host can, and namespace isolation.
    #[arg(long = "publish-port", value_name = "PORT")]
    publish_port: Vec<u16>,
}

#[derive(Debug, clap::Args)]
struct ShellArgs {
    /// Explicit config file, taking highest precedence.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// One-off grants, taking precedence over every config file.
    #[command(flatten)]
    quick_grants: QuickGrants,
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
    #[command(flatten)]
    network: NetworkArgs,
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
    /// One-off grants, taking precedence over every config file.
    #[command(flatten)]
    quick_grants: QuickGrants,
    /// Profile to use as the base. Defaults to a profile that claims this
    /// target, or to the untrusted floor.
    #[arg(short, long)]
    profile: Option<String>,
    /// The network flags, so the decision shown is the one a run with the same
    /// invocation would make.
    #[command(flatten)]
    network: NetworkArgs,
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
    // The same fact the run summary carries: which layer refuses a namespace
    // a target tries to create. The kernel limit rides on the user namespace
    // a run builds, so a host without one leaves only the filter.
    if caps.unprivileged_userns {
        println!("  nested namespaces: refused (kernel limit, seccomp)");
    } else {
        println!("  nested namespaces: refused (seccomp only)");
        println!(
            "    runs carry no user namespace to hold the kernel limit, so the \
             filter alone refuses namespace creation"
        );
    }

    // The same decision a run makes from these facts, stated before anything
    // runs: automatic mode does one thing on this host and refuses another,
    // and a policy that names its mode outright is refused where the host
    // cannot honour it.
    let pasta = resolve_helper("pasta").is_ok();
    let nft = resolve_helper("nft").is_ok();
    if pasta && caps.unprivileged_userns {
        println!("  private network: available");
        println!("    runs that allow egress use the private network namespace by default");
        if !nft {
            degraded = true;
            println!("    a broker cannot be confined, because its lockdown rule needs nft");
        }
    } else {
        degraded = true;
        let missing = if caps.unprivileged_userns {
            "pasta, which is not in a trusted location"
        } else {
            "unprivileged user namespaces, which are unavailable"
        };
        println!("  private network: unavailable ({missing})");
        println!("    runs that allow egress share the host's network namespace");
        println!(
            "    policies with forwards, published ports, a broker, or private \
             mode are refused"
        );
    }

    let delegated = &caps.cgroup_delegated;
    let missing: Vec<&str> = ["memory", "pids", "cpu"]
        .into_iter()
        .filter(|controller| !delegated.contains(controller))
        .collect();
    if delegated.is_empty() {
        println!("  cgroup delegation: no");
        degraded = true;
        println!("    resource limits will be skipped");
        println!("    a run needs a cgroup it may create children in, with the memory, pids");
        println!("    and cpu controllers delegated; set BAILEY_CGROUP_ROOT to name one");
    } else if missing.is_empty() {
        println!("  cgroup delegation: {}", delegated.join(", "));
    } else {
        degraded = true;
        println!(
            "  cgroup delegation: {} ({} not delegated)",
            delegated.join(", "),
            missing.join(", ")
        );
        println!("    limits using {} will be skipped", missing.join(", "));
    }

    println!("audit:");
    println!("  kernel BTF: {}", yes_no(caps.btf));
    if !caps.btf {
        degraded = true;
        println!("    `bailey audit` needs it to load the eBPF programs");
    }
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

/// The private address a proxied session is given, in place of the host's.
///
/// Every proxied run has a network namespace to itself, so the same address in
/// each collides with nothing: a concurrent run is a separate namespace, not a
/// second interface on one.
const PROXY_ADDRESS_V4: &str = "10.0.2.15";
/// The private IPv6 address a proxied session is given, a ULA that routes
/// nowhere on its own; pasta translates it to the host's real source address.
const PROXY_ADDRESS_V6: &str = "fd00::2";

/// Reads an `ADDR:PORT` egress-proxy value into an IPv4 address and a port.
pub(crate) fn parse_egress_proxy(value: &str) -> anyhow::Result<(std::net::Ipv4Addr, u16)> {
    let (addr, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("--egress-proxy must be ADDR:PORT, got {value:?}"))?;
    let addr = addr
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| anyhow::anyhow!("--egress-proxy address is not IPv4: {addr:?}"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("--egress-proxy port is not a port: {port:?}"))?;
    // A Landlock rule on port 0 reads as any port, so a broker named that way
    // would widen egress rather than bound it.
    if port == 0 {
        anyhow::bail!("--egress-proxy port 0 is not a port a broker listens on");
    }
    Ok((addr, port))
}

/// Permit a local endpoint's TCP port after netfilter bounds its destination.
fn permit_egress_port(policy: &mut crate::policy::Policy, port: u16) {
    use crate::policy::{Egress, EgressRule};
    let rule = EgressRule {
        host: "*".to_string(),
        port: Some(port),
    };
    match &mut policy.network.egress {
        Egress::Allow(rules) => rules.push(rule),
        // Deny would not have reached a proxied run; all-ports needs nothing.
        Egress::DenyAll => policy.network.egress = Egress::Allow(vec![rule]),
        Egress::AllowAll => {}
    }
}

/// Lock this run's own namespace to the broker, refusing setup on nft failure.
fn lock_egress_to_broker(addr: std::net::Ipv4Addr, port: u16) -> anyhow::Result<()> {
    // A dedicated table, so it is this rule that is added and removed and never
    // another's. IPv6 has no accept rule, so the inet chain drops it entirely.
    //
    // Loopback is dropped, not accepted. pasta forwards the namespace's own
    // 127.0.0.0/8 to the HOST's loopback, so an `oif lo accept` would let a
    // session reach a host service on an allowed port. There is no loopback
    // that stays inside the namespace to protect, so dropping it costs nothing
    // and closes host-loopback reach.
    let ruleset = format!(
        "table inet bailey_egress {{\n\
         \tchain output {{\n\
         \t\ttype filter hook output priority 0; policy drop;\n\
         \t\tip daddr 127.0.0.0/8 drop\n\
         \t\tip6 daddr ::1 drop\n\
         \t\tip daddr {addr} tcp dport {port} accept\n\
         \t\tct state established,related accept\n\
         \t}}\n\
         }}\n"
    );

    run_nft(&ruleset).map_err(|err| {
        anyhow::anyhow!("the egress lockdown could not be installed, so the run is refused: {err}")
    })
}

/// Restrict the namespace's loopback traffic to what keeps the boundary.
///
/// The blanket drops are gone: with bailey's pasta arguments and `--no-map-gw`,
/// namespace loopback never reaches the host, so a drop there only broke the
/// servers a target talks to over its own loopback. What stays is the
/// anti-widening half: a forwarded port must not become a new remote egress
/// allowance, and a publication must not expose anything but its own endpoint.
fn proxy_loopback_ruleset(forwards: &[PortForward], publishes: &[u16], egress: &Egress) -> String {
    let mut ruleset = String::from(
        "table inet bailey_loopback {\n\
         \tchain output {\n\
         \t\ttype filter hook output priority 0; policy accept;\n",
    );
    if !forwards.is_empty() || !publishes.is_empty() {
        ruleset.push_str("\t\tct state established accept\n");
    }
    for port in publishes {
        // pasta's namespace-side socket dials the published loopback port.
        ruleset.push_str(&format!("\t\tip daddr 127.0.0.1 tcp dport {port} accept\n"));
    }
    for forward in forwards {
        ruleset.push_str(&format!(
            "\t\tip daddr 127.0.0.1 tcp dport {} accept\n",
            forward.port
        ));
        // pasta answers a forwarded port on the whole loopback range and on
        // ::1, so the forward is held to the one address its contract names:
        // the namespace may dial it at 127.0.0.1 and nowhere else.
        ruleset.push_str(&format!(
            "\t\tip daddr 127.0.0.0/8 tcp dport {} drop\n",
            forward.port
        ));
        ruleset.push_str(&format!(
            "\t\tip6 daddr ::1 tcp dport {} drop\n",
            forward.port
        ));
    }
    for forward in forwards {
        let already_allowed = match egress {
            Egress::AllowAll => true,
            Egress::DenyAll => false,
            Egress::Allow(rules) => rules
                .iter()
                .any(|rule| rule.port == Some(0) || rule.port == Some(forward.port)),
        };
        if already_allowed {
            // pasta's listener must not also expose the host service through
            // the namespace's non-loopback addresses.
            ruleset.push_str(&format!(
                "\t\tip daddr {PROXY_ADDRESS_V4} tcp dport {} drop\n\
                 \t\tip6 daddr {PROXY_ADDRESS_V6} tcp dport {} drop\n",
                forward.port, forward.port
            ));
        } else {
            // Landlock permits connects by port, not address. Its added local
            // port must not become a new remote egress allowance.
            ruleset.push_str(&format!("\t\ttcp dport {} drop\n", forward.port));
        }
    }
    ruleset.push_str("\t}\n}\n");
    ruleset
}

/// Apply the network flags to the resolved policy as its highest layer.
///
/// `--proxy-net` requests the private namespace, `--no-proxy-net` the host's,
/// and `--egress-proxy` names a broker, which selects the private namespace
/// with it. `--publish-port` ports join the policy's own publications, so the
/// policy a `show` reports is the one this invocation resolves. Whatever a
/// config layer set, a flag passed to this run replaces or extends it, and
/// the source names the flag so the summary says what chose the mode.
fn apply_network_flags(policy: &mut Policy, args: &NetworkArgs) -> anyhow::Result<()> {
    for port in &args.publish_port {
        if !policy.network.publish_ports.contains(port) {
            policy.network.publish_ports.push(*port);
        }
    }
    if args.no_proxy_net {
        policy.network.mode = crate::policy::NetworkMode::Host;
        policy.network.mode_source = "flag --no-proxy-net".to_owned();
    } else if args.proxy_net {
        policy.network.mode = crate::policy::NetworkMode::Private;
        policy.network.mode_source = "flag --proxy-net".to_owned();
    }
    if let Some(proxy) = &args.egress_proxy {
        let (addr, port) = parse_egress_proxy(proxy)?;
        // The broker needs the private namespace, so naming one selects the
        // mode as well: it outranks a configured host mode the same way
        // --proxy-net does, while a contradiction written entirely in config
        // stays refused.
        policy.network.mode = crate::policy::NetworkMode::Private;
        policy.network.mode_source = "flag --egress-proxy".to_owned();
        policy.network.broker = Some((addr, port));
        policy.network.broker_source = Some("flag --egress-proxy".to_owned());
    }
    Ok(())
}

/// Reject resolved network settings that contradict each other.
///
/// The check runs after the flags are mapped on, so a flag can rescue a
/// contradiction a config layer wrote: `mode = "host"` beside a forward is
/// refused, but `--proxy-net` beside the same forward raises the mode above
/// the refusal. Every refusal names the layer or flag that set each side.
fn check_network_contradictions(
    policy: &Policy,
    forwards: &[PortForward],
    publishes: &[u16],
) -> anyhow::Result<()> {
    if policy.network.mode == crate::policy::NetworkMode::Host {
        let source = &policy.network.mode_source;
        if let Some((addr, port)) = policy.network.broker {
            anyhow::bail!(
                "host mode ({source}) cannot hold the broker at {addr}:{port} \
                 ({}), which needs a private namespace",
                policy.network.broker_source.as_deref().unwrap_or("unknown")
            );
        }
        if !publishes.is_empty() {
            anyhow::bail!(
                "host mode ({source}) cannot publish ports, which need a \
                 network namespace of the run's own"
            );
        }
        // Denied-egress forwards are carried by the backend in the namespace
        // the policy builds anyway, so they need nothing host mode gives up.
        // Only forwards under allowed egress need the private namespace.
        if !forwards.is_empty() && !matches!(policy.network.egress, Egress::DenyAll) {
            anyhow::bail!(
                "host mode ({source}) cannot forward ports under allowed \
                 egress, which needs a private namespace"
            );
        }
    }
    if let Some(source) = &policy.network.broker_source {
        if !forwards.is_empty() {
            anyhow::bail!(
                "the broker set by {source} must remain the only egress, so \
                 the policy's forwards cannot be carried"
            );
        }
        if !publishes.is_empty() {
            anyhow::bail!(
                "the broker set by {source} leaves no route for the host to \
                 reach a published port, so the publications cannot be carried"
            );
        }
    }
    Ok(())
}

/// The user namespace limit the proxy namespace holds, decided from the
/// layout table in the change design.
///
/// With the isolation layer running, the run's own namespace nests inside the
/// proxy namespace and spends its single slot. With the target running in the
/// proxy namespace directly, nothing may be created beneath it at all.
fn proxy_guard_limit(no_isolate: bool) -> u32 {
    if no_isolate { 0 } else { 1 }
}

/// Select forwards carried by pasta rather than the denied-egress backend.
///
/// A forward under a denied egress is the backend's to carry, in the empty
/// namespace the policy builds anyway, so the list is kept whole for the
/// decision to see: a nested run refuses it there, where the namespace it
/// needs cannot be made.
fn collect_forwards(policy: &Policy, no_isolate: bool) -> anyhow::Result<Vec<PortForward>> {
    if policy.forwards.is_empty() {
        return Ok(Vec::new());
    }
    if !matches!(policy.network.egress, Egress::DenyAll) && no_isolate {
        anyhow::bail!("port forwards need namespace isolation; remove --no-isolate");
    }
    forward::validate(&policy.forwards, &policy.network.bind_ports).map_err(anyhow::Error::msg)
}

/// Merge the sandbox ports to publish on host loopback, from the flag and the
/// policy.
fn collect_publish_ports(
    policy: &Policy,
    args: &NetworkArgs,
    no_isolate: bool,
) -> anyhow::Result<Vec<u16>> {
    let mut publishes: Vec<u16> = Vec::new();
    for port in args
        .publish_port
        .iter()
        .chain(policy.network.publish_ports.iter())
    {
        if *port == 0 {
            anyhow::bail!("a published port must be a real port, not 0");
        }
        if !publishes.contains(port) {
            publishes.push(*port);
        }
    }
    if publishes.is_empty() {
        return Ok(publishes);
    }
    if matches!(policy.network.egress, Egress::DenyAll) {
        anyhow::bail!(
            "published ports need allowed egress; a denied network keeps the \
             sandbox unreachable"
        );
    }
    if no_isolate {
        anyhow::bail!("published ports need namespace isolation; remove --no-isolate");
    }
    for forward in &policy.forwards {
        if publishes.contains(&forward.port) {
            anyhow::bail!(
                "port {} is both forwarded and published; one sandbox port \
                 cannot be an inbound forward and a published listener",
                forward.port
            );
        }
        if publishes.contains(&forward.host_port) {
            anyhow::bail!(
                "published port {} is the host side of a forward; the \
                 publication listener would take the port the forward needs",
                forward.host_port
            );
        }
    }
    Ok(publishes)
}

/// What the host can provide for a network decision.
fn host_network_caps() -> network::HostCapabilities {
    network::HostCapabilities {
        user_namespaces: isolation::available(),
        pasta: resolve_helper("pasta").is_ok(),
        nft: resolve_helper("nft").is_ok(),
    }
}

/// The decision a run would make for `policy` with these forwards and
/// publications, whatever network this process starts in.
fn network_decision(
    policy: &Policy,
    forwards: &[PortForward],
    publishes: &[u16],
) -> anyhow::Result<network::NetworkDecision> {
    // Inside a sandbox the host cannot provide anything: the outer filter
    // refuses every namespace this run could try to build, and the decision
    // must say what that costs rather than probe for it.
    let nested = world::inside_sandbox();
    let caps = if nested {
        network::HostCapabilities {
            user_namespaces: false,
            pasta: false,
            nft: false,
        }
    } else {
        host_network_caps()
    };
    network::decide(policy, &caps, nested, forwards, publishes)
}

/// Feeds a ruleset to `nft -f -`, returning an error with nft's own message.
fn run_nft(ruleset: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let nft = resolve_helper("nft")?;
    let mut child = std::process::Command::new(&nft)
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|err| anyhow::anyhow!("nft could not run: {err}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("could not write the ruleset to nft"))?
        .write_all(ruleset.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!("nft: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

/// Re-run the target inside a pasta-provided network namespace when the
/// decision calls for one.
///
/// Returns `Wrapped::Parent` with the child's exit code when the parent should
/// stop there, `Wrapped::Creator` once this process sits in the new namespace.
/// The decision above this call refused the run where a prerequisite was
/// missing, so a missing helper or user namespace cannot downgrade to the
/// host's network here.
///
/// The inner run keeps every layer of confinement; pasta only supplies the
/// interface it runs behind, a private address and a synthetic MAC in place of
/// the host's. Egress is still gated by the policy's ports, since Landlock
/// applies inside the namespace as it does outside.
/// Which side of the private namespace this process ended up on.
enum Wrapped {
    /// The parent: the run happened in the child, and this is its status.
    Parent(i32),
    /// The child: this process created the network namespace, so it is the one
    /// that may install a rule in it.
    Creator,
    /// No private namespace was made, so this process is where it started.
    Unwrapped,
}

/// What pasta is asked for: a private network for egress, and nothing else.
///
/// Only named TCP forwards reach the host. Every other forwarding direction
/// explicitly uses `none`: pasta's `auto` defaults would otherwise expose
/// listeners and inventory host services in the namespace's `/proc/net` tables.
///
/// `egress_addr` is the broker's namespace-visible address, when there is one.
/// The host's loopback is mapped to it so a connection there reaches the
/// broker; the plain `--proxy-net` path maps no host at all.
///
/// IPv6 only where the host has it: handing the namespace a v6 route the host
/// cannot follow would leave a program stalling on v6 before it fell back.
fn pasta_arguments(
    egress_addr: Option<&str>,
    host_has_ipv6: bool,
    forwards: &[PortForward],
    publishes: &[u16],
) -> Vec<String> {
    let mut pasta_args: Vec<String> = ["--config-net", "--quiet", "--no-map-gw"]
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect();
    for forwarding in ["-t", "-u", "-T", "-U"] {
        if forwarding == "-T" && !forwards.is_empty() {
            for forward in forwards {
                pasta_args.push(forwarding.to_owned());
                pasta_args.push(format!("{}:{}", forward.port, forward.host_port));
            }
        } else if forwarding == "-t" && !publishes.is_empty() {
            for port in publishes {
                // The host listener is loopback only: a published development
                // service must not become reachable from the local network.
                pasta_args.push(forwarding.to_owned());
                pasta_args.push(format!("127.0.0.1/{port}"));
            }
        } else {
            pasta_args.push(forwarding.to_owned());
            pasta_args.push("none".to_owned());
        }
    }
    if !publishes.is_empty() {
        // Deliver the connection to a service bound on the sandbox loopback,
        // not only to one bound on every interface.
        pasta_args.push("--host-lo-to-ns-lo".to_owned());
    }
    if let Some(addr) = egress_addr {
        pasta_args.push("--map-host-loopback".to_owned());
        pasta_args.push(addr.to_owned());
    }
    pasta_args.push("-a".to_owned());
    pasta_args.push(PROXY_ADDRESS_V4.to_owned());
    if host_has_ipv6 {
        pasta_args.push("-a".to_owned());
        pasta_args.push(PROXY_ADDRESS_V6.to_owned());
    } else {
        pasta_args.push("-4".to_owned());
    }
    pasta_args
}

fn wrap_in_private_namespace(
    broker: Option<(std::net::Ipv4Addr, u16)>,
    forwards: &[PortForward],
    publishes: &[u16],
    announce: bool,
    guard_limit: u32,
) -> anyhow::Result<Wrapped> {
    // The decision above this call refused the run when a prerequisite was
    // missing, so the lookups here cannot fail honestly. Resolving again in
    // an error would be a race with the decision, not a second opinion.
    let pasta = resolve_helper("pasta")?;

    if announce {
        eprintln!(
            "bailey: egress runs through a private namespace; the host address \
             and MAC are not exposed"
        );
    }

    // Private addresses, so the host's own are not copied in. Its global IPv6
    // encodes the interface MAC, so a private one is given in its place rather
    // than the host's; `--no-map-gw` keeps the host's gateway address out too.
    //
    // IPv6 only where the host has it: handing the namespace a v6 route the host
    // cannot follow would leave a program stalling on v6 before it fell back.
    let egress_addr = broker.map(|(addr, _)| addr.to_string());
    let pasta_args = pasta_arguments(egress_addr.as_deref(), host_has_ipv6(), forwards, publishes);
    // The namespace is made here rather than by pasta, and pasta is pointed at
    // it. Whoever installs the lockdown rule has to know which namespace it
    // lands in, and that cannot be established by looking: every reference a
    // caller could hand over is one a caller could choose. Creating it settles
    // the question, so the child below installs the rule and nothing has to be
    // asserted. See issue #24.
    let ready = Relay::new()?;
    let release = Relay::new()?;

    // Safety: the child runs after `fork` in a process that is single threaded
    // at this point, so the heap and every lock it inherits are consistent and
    // it may go on running ordinary code rather than only what is
    // async-signal-safe.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error().into()),
        0 => {
            let ready = ready.into_writer();
            let release = release.into_reader();
            // A user and network namespace of this process's own, mapped to
            // root inside so that `nft` keeps its capabilities across the exec
            // that installs the rule. The namespace is also the run's guard,
            // so the limit says whether the isolation layer may nest the run's
            // own namespace inside it.
            if let Err(error) = network::enter_proxy_namespace(guard_limit) {
                eprintln!("bailey: could not create the private namespace: {error}");
                std::process::exit(1);
            }
            if ready.send().is_err() {
                std::process::exit(1);
            }
            drop(ready);
            // A closed pipe means the parent gave up, which is the failure
            // case: the namespace has no networking and no rule, so the run
            // must not continue into it.
            if release.wait().is_err() {
                eprintln!("bailey: the private namespace was never configured; the run is refused");
                std::process::exit(1);
            }
            Ok(Wrapped::Creator)
        }
        child => {
            let ready = ready.into_reader();
            let release = release.into_writer();
            if ready.wait().is_err() {
                reap(child);
                anyhow::bail!("the private namespace could not be created; the run is refused");
            }
            let status = std::process::Command::new(&pasta)
                .args(&pasta_args)
                .arg(child.to_string())
                .status();
            let configured = matches!(&status, Ok(status) if status.success());
            if !configured {
                // Dropping the release end tells the child to stop, so it never
                // runs with a namespace pasta did not finish configuring.
                drop(release);
                reap(child);
                match status {
                    Ok(status) => anyhow::bail!(
                        "pasta could not configure the private namespace (exit {}); \
                         the run is refused",
                        status.code().unwrap_or(-1)
                    ),
                    Err(error) => anyhow::bail!(
                        "pasta could not be run to configure the private namespace: {error}"
                    ),
                }
            }
            release.send()?;
            drop(release);
            Ok(Wrapped::Parent(reap(child)))
        }
    }
}

/// One direction of a parent-and-child handshake over a pipe.
///
/// Both ends are held until the fork, then each side keeps the one it uses. A
/// read that ends without a byte means the other side died, which every caller
/// here treats as a refusal rather than as permission to carry on.
struct Relay {
    read: OwnedFd,
    write: OwnedFd,
}

struct Reader(OwnedFd);
struct Writer(OwnedFd);

impl Relay {
    fn new() -> io::Result<Self> {
        let mut fds = [0 as libc::c_int; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            read: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            write: unsafe { OwnedFd::from_raw_fd(fds[1]) },
        })
    }

    fn into_reader(self) -> Reader {
        Reader(self.read)
    }

    fn into_writer(self) -> Writer {
        Writer(self.write)
    }
}

impl Reader {
    fn wait(&self) -> io::Result<()> {
        let mut byte = [0u8; 1];
        let read = unsafe { libc::read(self.0.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
        if read == 1 {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
    }
}

impl Writer {
    fn send(&self) -> io::Result<()> {
        let byte = [1u8; 1];
        let written = unsafe { libc::write(self.0.as_raw_fd(), byte.as_ptr().cast(), 1) };
        if written == 1 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Wait for the child and report the status a shell would.
fn reap(child: libc::pid_t) -> i32 {
    let mut status = 0;
    if unsafe { libc::waitpid(child, &mut status, 0) } < 0 {
        return 1;
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

/// Whether the host holds a routable IPv6 address of its own.
///
/// Read rather than assumed, because a namespace given a v6 route the host
/// cannot follow makes a program try v6 and wait for it to fail. A global-scope
/// address on something other than loopback is the signal that v6 goes
/// anywhere at all.
fn host_has_ipv6() -> bool {
    match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(contents) => ipv6_global_present(&contents),
        // Reading nothing is as good a reason as any to stay on IPv4.
        Err(_) => false,
    }
}

/// Whether `/proc/net/if_inet6` names a global-scope address off the loopback.
///
/// Each line is an address, an interface index, a prefix length, a scope, a set
/// of flags, and a device name. Scope `00` is global; loopback and link-local
/// carry their own and reach nowhere off the host.
fn ipv6_global_present(if_inet6: &str) -> bool {
    if_inet6.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let scope = fields.nth(3);
        let device = fields.nth(1);
        scope == Some("00") && device != Some("lo")
    })
}

/// Refuse to confine anything while running as root.
///
/// The user namespace maps the caller to itself, so as uid 0 the target is uid
/// 0 on the host: its files are root-owned and ordinary permissions stop being
/// a barrier, leaving Landlock as the only one. The model this is built on is
/// an unprivileged caller, and a root run quietly produces something else.
fn refuse_root() -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    // Being uid 0 is not the same as being real root. Inside a user namespace
    // the caller is often mapped to 0 while owning nothing on the host: pasta
    // does exactly that for the inner run. What matters is who 0 stands for
    // and how far the mapping reaches, which the kernel's map says. Nothing
    // from the environment is consulted, because a caller can set any of it:
    // a guard that trusts its own marker has a door built in.
    let map = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
    let Some((host_uid, range)) = host_uid_of_root(&map) else {
        anyhow::bail!(
            "bailey confines an unprivileged process, but /proc/self/uid_map \
             cannot be read to tell real root from a mapped one; the run is \
             refused"
        );
    };
    // 0 mapped to 0 across the whole uid range happens in exactly one way: a
    // namespace the host's root seeded, the initial one directly or a nested
    // one granted the full range. A nested 0 that maps less is someone else's
    // mapped root, and the namespace that produced it was subject to this
    // guard when it ran unconfined.
    if host_uid == 0 && range == u32::MAX {
        anyhow::bail!(
            "bailey confines an unprivileged process and is running as real root; \
             a target would be root on the host too. Run it as the user it is for"
        );
    }
    Ok(())
}

/// Who uid 0 stands for outside this user namespace, read from a `uid_map`.
///
/// A line is `<inside> <outside> <count>`. The entry whose range covers 0
/// answers with the outside uid and the width of the mapped range; `None`
/// when nothing covers 0.
fn host_uid_of_root(map: &str) -> Option<(u32, u32)> {
    for line in map.lines() {
        let mut parts = line.split_whitespace();
        let inside: u32 = parts.next()?.parse().ok()?;
        let outside: u32 = parts.next()?.parse().ok()?;
        let count: u32 = parts.next()?.parse().ok()?;
        if inside == 0 && count >= 1 {
            return Some((outside, count));
        }
    }
    None
}

/// Establish shared network confinement before hooks or target execution.
///
/// Flags are mapped onto the resolved policy as its highest layer, the
/// contradictions are refused, and one decision covers the wrap, the lockdown,
/// and what the backend reports. Returns what the caller should do, whether
/// the caller now runs beneath the guard user namespace of a private namespace
/// this process created, and the decision for the backend to report.
fn prepare_network(
    policy: &mut Policy,
    args: &NetworkArgs,
    no_isolate: bool,
    announce: bool,
) -> anyhow::Result<(Wrapped, bool, Option<network::NetworkDecision>)> {
    apply_network_flags(policy, args)?;
    // --no-isolate promises a run of Landlock and seccomp alone, so automatic
    // mode does not hand back a namespace with it. A policy or flag that asks
    // for the private network outright is still honoured: the request is the
    // user's, the fallback is ours.
    if no_isolate && policy.network.mode == crate::policy::NetworkMode::Auto {
        policy.network.mode = crate::policy::NetworkMode::Host;
        policy.network.mode_source = "flag --no-isolate".to_owned();
    }
    // Validate publications first: a run that asks for both should be told
    // about the publication it got wrong, not about a forward it configured
    // correctly.
    let publishes = collect_publish_ports(policy, args, no_isolate)?;
    let forwards = collect_forwards(policy, no_isolate)?;
    check_network_contradictions(policy, &forwards, &publishes)?;
    let decision = network_decision(policy, &forwards, &publishes)?;

    // The proxy namespace doubles as the run's guard user namespace. With the
    // isolation layer nesting the run's own namespace inside it, one slot
    // stays free for that. With the target running in the proxy namespace
    // directly, none is left at all.
    let guard_limit = proxy_guard_limit(no_isolate);
    let made_the_namespace = match decision.mode {
        network::NetworkMode::Private | network::NetworkMode::Brokered => {
            match wrap_in_private_namespace(
                policy.network.broker,
                &forwards,
                &publishes,
                announce,
                guard_limit,
            )? {
                Wrapped::Parent(code) => {
                    return Ok((Wrapped::Parent(code), false, Some(decision)));
                }
                Wrapped::Creator => true,
                Wrapped::Unwrapped => false,
            }
        }
        network::NetworkMode::Isolated | network::NetworkMode::LandlockOnly => false,
    };

    // Inside the namespace now, whether by the wrap above or a re-exec into it.
    // The lockdown goes on before the target is confined and run, so there is
    // no window in which the target has both a network and no egress rule.
    if let Some((addr, port)) = policy.network.broker {
        // Only the process that created the namespace installs a rule in it.
        // This is not a check on something a caller said; it is which branch of
        // the fork above this process took, and a caller cannot choose that.
        if !made_the_namespace {
            anyhow::bail!(
                "--egress-proxy installs its firewall rule in a network namespace of \
                 this run's own, and none was created; the run is refused"
            );
        }
        lock_egress_to_broker(addr, port)?;
        // Landlock gates egress by port, and the broker does not listen on the
        // policy's ports. The netfilter rule already holds egress to the broker
        // address, so permitting its port here widens nothing a session can
        // reach; it only stops Landlock from refusing the one allowed hop.
        permit_egress_port(policy, port);
    } else if made_the_namespace {
        let ruleset = proxy_loopback_ruleset(&forwards, &publishes, &policy.network.egress);
        if let Err(err) = run_nft(&ruleset) {
            if !forwards.is_empty() || !publishes.is_empty() {
                anyhow::bail!(
                    "the forwarding firewall could not be installed, so the run is refused: {err}"
                );
            }
            eprintln!("bailey: warning: host loopback stays reachable: {err}");
        }
        for forward in &forwards {
            permit_egress_port(policy, forward.port);
            if announce {
                eprintln!(
                    "bailey: forward 127.0.0.1:{} to host port {} through pasta",
                    forward.port, forward.host_port
                );
            }
        }
        for port in &publishes {
            if announce {
                eprintln!(
                    "bailey: publish host 127.0.0.1:{port} to sandbox port {port} through pasta"
                );
            }
        }
        if !forwards.is_empty() {
            policy.forwards.clear();
        }
        if !publishes.is_empty() {
            // Publishing implies the sandbox may bind the port. An empty bind
            // list means binds are unrestricted already, so only a list that
            // already restricts them needs the published port added.
            if !policy.network.bind_ports.is_empty() {
                for port in &publishes {
                    if !policy.network.bind_ports.contains(port) {
                        policy.network.bind_ports.push(*port);
                    }
                }
            }
            policy.network.publish_ports.clear();
        }
    }

    Ok((
        if made_the_namespace {
            Wrapped::Creator
        } else {
            Wrapped::Unwrapped
        },
        made_the_namespace,
        Some(decision),
    ))
}

fn cmd_run(args: RunArgs) -> anyhow::Result<i32> {
    refuse_root()?;
    let (program, program_args) = split_command(args.command.clone())?;
    let profile = select_profile(args.profile.as_deref(), &program)?;
    let mut resolved = resolve(
        &profile,
        &program,
        args.config.as_deref(),
        &args.quick_grants,
    )?;
    report_untrusted(&program, args.config.as_deref());
    warn_if_target_denied(&resolved.policy, &program);

    let (wrapped, guard_in_place, decision) = prepare_network(
        &mut resolved.policy,
        &args.network,
        args.no_isolate,
        !args.quiet && !args.json,
    )?;
    if let Wrapped::Parent(code) = wrapped {
        return Ok(code);
    }

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
        network: decision,
        guard_in_place,
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
    refuse_root()?;
    let shell = resolve_shell(args.shell.as_deref())?;
    let dir = std::env::current_dir()?;

    let profile = select_profile(args.profile.as_deref(), &shell)?;
    let mut resolved = resolve_for_shell(
        &profile,
        &shell,
        &dir,
        args.config.as_deref(),
        &args.quick_grants,
    )?;
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

    let (wrapped, guard_in_place, decision) =
        prepare_network(&mut resolved.policy, &args.network, args.no_isolate, true)?;
    if let Wrapped::Parent(code) = wrapped {
        return Ok(code);
    }

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
        network: decision,
        guard_in_place,
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
    grants: &QuickGrants,
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
    let overrides = override_layers(grants)?;
    let override_refs: Vec<(&str, &str)> = overrides
        .iter()
        .map(|(label, text)| (*label, text.as_str()))
        .collect();
    Ok(config::resolve_with_bases(
        &bases,
        shell,
        explicit,
        &override_refs,
    )?)
}

/// The command-line grants as `(label, toml)` pairs, empty when none were
/// given.
fn override_layers(grants: &QuickGrants) -> anyhow::Result<Vec<(&'static str, String)>> {
    match grants.layer()? {
        Some(text) => Ok(vec![("command-line grants", text)]),
        None => Ok(Vec::new()),
    }
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
    refuse_root()?;
    let (program, program_args) = split_command(args.command)?;
    let profile = select_profile(args.profile.as_deref(), &program)?;
    let resolved = resolve(
        &profile,
        &program,
        args.config.as_deref(),
        &QuickGrants::default(),
    )?;
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
    // Audit runs in the host namespace by design, so a policy whose mode asks
    // for more than Landlock's TCP rules reports the gap rather than quietly
    // skipping it. The findings stay about what was recorded.
    if !args.unconfined {
        if let Some((addr, port)) = resolved.policy.network.broker {
            eprintln!(
                "bailey: note: audit runs in the host namespace, so the broker \
                 at {addr}:{port} ({}) is not applied; the trace records what \
                 Landlock's TCP rules allow alone",
                resolved
                    .policy
                    .network
                    .broker_source
                    .as_deref()
                    .unwrap_or("unknown")
            );
        } else if resolved.policy.network.mode == crate::policy::NetworkMode::Private {
            eprintln!(
                "bailey: note: audit runs in the host namespace, so the private \
                 network set by {} is not applied; the trace records what \
                 Landlock's TCP rules allow alone",
                resolved.policy.network.mode_source
            );
        }
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
    let mut resolved = resolve(
        &profile,
        &target,
        args.config.as_deref(),
        &args.quick_grants,
    )?;
    apply_network_flags(&mut resolved.policy, &args.network)?;
    print_sources(&profile, &target, args.config.as_deref());
    print_policy(&resolved, &target, &args.network);
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
/// Print the commands a config would run outside the sandbox, if it has any.
fn report_hooks(out: &mut impl io::Write, path: &Path) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(raw) = toml::from_str::<toml::Value>(&text) else {
        return;
    };
    let Some(hooks) = raw.get("hooks").and_then(|hooks| hooks.as_table()) else {
        return;
    };
    let mut named = Vec::new();
    for when in hooks::HOOK_KEYS {
        match hooks.get(when) {
            Some(toml::Value::String(one)) => named.push((when, one.clone())),
            Some(toml::Value::Array(many)) => {
                for entry in many {
                    if let Some(one) = entry.as_str() {
                        named.push((when, one.to_string()));
                    }
                }
            }
            _ => {}
        }
    }
    if named.is_empty() {
        return;
    }
    writeln!(
        out,
        "this config runs commands outside the sandbox, as you:"
    )
    .expect("writing the hook report");
    for (when, command) in named {
        writeln!(out, "  {when}: {command}").expect("writing the hook report");
    }
}

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
    // A config is not only a policy: its hooks are commands that run as the
    // caller, unconfined, before the sandbox exists. Trusting the file is
    // trusting those too, so they are named rather than left to be discovered.
    report_hooks(&mut io::stdout(), &path);
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
/// The private home and the terminal are provided by the backend rather than
/// written in anyone's config, so a plain reconciliation reports a program
/// reading its own settings, or writing to its own terminal, as ungranted
/// access. Every audited program does that, and a findings list full of what the
/// sandbox itself handed over is one nobody reads. The terminal matters twice
/// over: a generated profile would name this session's pty, which is a different
/// number tomorrow.
fn policy_with_own_storage(policy: &crate::policy::Policy, target: &Path) -> crate::policy::Policy {
    let mut effective = policy.clone();
    // Audit does not isolate, so the home the target used is the host one.
    let world = World::derive(target, policy, false);
    for path in world.home_host.into_iter().chain(world.terminal) {
        effective.filesystem.push(crate::policy::FsRule {
            path,
            access: Access::READ | Access::WRITE,
            at: None,
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
    let resolved = resolve(
        &profile,
        &args.target,
        args.config.as_deref(),
        &QuickGrants::default(),
    )?;
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

fn resolve(
    profile: &str,
    target: &Path,
    explicit: Option<&Path>,
    grants: &QuickGrants,
) -> anyhow::Result<Resolved> {
    let implicit = implicit_target_layer(target);
    let layers = profiles::base_layers(profile).map_err(|err| anyhow::anyhow!(err))?;
    let mut bases: Vec<(&str, &str)> = vec![("implicit:target", implicit.as_str())];
    bases.extend(
        layers
            .iter()
            .map(|layer| (layer.label.as_str(), layer.toml.as_str())),
    );
    let overrides = override_layers(grants)?;
    let override_refs: Vec<(&str, &str)> = overrides
        .iter()
        .map(|(label, text)| (*label, text.as_str()))
        .collect();
    Ok(config::resolve_with_bases(
        &bases,
        target,
        explicit,
        &override_refs,
    )?)
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
/// The id an unmapped owner reads as inside a user namespace.
/// Directories a helper bailey runs itself may come from.
///
/// Fixed rather than taken from `PATH`: these programs run outside the sandbox
/// with the caller's authority, so a writable directory on the caller's `PATH`
/// would be host code execution on the next proxied run.
const HELPER_DIRS: [&str; 6] = [
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/usr/local/sbin",
    "/usr/local/bin",
];

/// The directories [`resolve_helper`] searches, honouring an override.
///
/// `BAILEY_HELPER_DIRS` names whole directories, colon-separated, in place of
/// the fixed ones. It exists so the answers a run gives can be checked
/// without the helpers themselves: pointing it at an empty directory makes
/// every lookup fail, which is what a host without pasta or `nft` answers.
/// The trust test still applies to whatever is found, so the override can
/// only make bailey refuse more, never run something its own directories
/// would not.
fn helper_dirs() -> Vec<std::borrow::Cow<'static, str>> {
    match std::env::var_os("BAILEY_HELPER_DIRS") {
        Some(value) => std::env::split_paths(&value)
            .map(|dir| std::borrow::Cow::Owned(dir.to_string_lossy().into_owned()))
            .collect(),
        None => HELPER_DIRS.iter().map(|dir| (*dir).into()).collect(),
    }
}

/// Find a helper program in a trusted location, refusing one anyone else can
/// write.
///
/// A file held to [`crate::backend::probe::runnable_as_caller`] is one only
/// the system or the caller could have put there. Anything else is refused by
/// name rather than run.
pub fn resolve_helper(name: &str) -> anyhow::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let mut rejected = Vec::new();
    for dir in helper_dirs() {
        let candidate = Path::new(dir.as_ref()).join(name);
        let Ok(meta) = std::fs::metadata(&candidate) else {
            continue;
        };
        if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
            continue;
        }
        if crate::backend::probe::runnable_as_caller(&meta) {
            return Ok(candidate);
        }
        rejected.push(candidate.display().to_string());
    }
    if rejected.is_empty() {
        anyhow::bail!("`{name}` was not found in a trusted location");
    }
    anyhow::bail!(
        "`{name}` was found at {} but is writable by someone other than its owner; refusing to run it",
        rejected.join(", ")
    )
}

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
    crate::strings::quoted(&path.to_string_lossy())
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

/// The directory the target actually lives in.
///
/// Resolved rather than taken as written: a program on `PATH` is often a symlink
/// into a store elsewhere, and the directory beside the link holds none of its
/// code. Reconciliation calls everything outside this directory unexpected, so
/// getting it wrong marks a program's own files as foreign access.
fn target_dir(target: &Path) -> PathBuf {
    std::fs::canonicalize(target)
        .or_else(|_| std::path::absolute(target))
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

/// Print the hooks a policy will run outside the sandbox.
///
/// A hook runs as the caller, unconfined, before any layer of the sandbox is
/// built, so it is the one part of a policy that acts on the host rather than
/// inside the run. Nothing is printed for a policy that runs none, so a config
/// without hooks keeps the report it had.
fn print_hooks(out: &mut impl io::Write, hooks: &Hooks) {
    let [pre_launch_key, post_exit_key] = hooks::HOOK_KEYS;
    if hooks.pre_launch.is_empty() && hooks.post_exit.is_empty() {
        return;
    }
    writeln!(out, "hooks:").expect("writing the policy report");
    for command in &hooks.pre_launch {
        writeln!(out, "  {pre_launch_key}: {command}").expect("writing the policy report");
    }
    for command in &hooks.post_exit {
        writeln!(out, "  {post_exit_key}: {command}").expect("writing the policy report");
    }
}

/// Print the resolved policy for `target`.
///
/// The body is in [`print_policy_to`] so a test can drive the real report into a
/// buffer. A test that printed only the hooks section would stay green when the
/// section's call site here was deleted, which is the wiring this guards.
fn print_policy(resolved: &Resolved, target: &Path, network: &NetworkArgs) {
    print_policy_to(&mut io::stdout(), resolved, target, network);
}

/// The decision a run would make for the policy as this invocation resolves
/// it, including the flags it was passed.
fn network_decision_for_show(
    policy: &Policy,
    args: &NetworkArgs,
) -> anyhow::Result<network::NetworkDecision> {
    let forwards = collect_forwards(policy, false)?;
    let publishes = collect_publish_ports(policy, args, false)?;
    check_network_contradictions(policy, &forwards, &publishes)?;
    network_decision(policy, &forwards, &publishes)
}

/// The report [`print_policy`] prints, written to `out`.
fn print_policy_to(
    out: &mut impl io::Write,
    resolved: &Resolved,
    target: &Path,
    network: &NetworkArgs,
) {
    let policy = &resolved.policy;

    writeln!(out, "filesystem:").expect("writing the policy report");
    if policy.filesystem.is_empty() {
        writeln!(out, "  (none)").expect("writing the policy report");
    }
    for rule in &policy.filesystem {
        writeln!(
            out,
            "  {} {}",
            access_flags(rule.access),
            rule.path.display()
        )
        .expect("writing the policy report");
    }

    if !policy.read_only.is_empty() {
        let nested: Vec<_> = policy.nested_read_only().collect();
        writeln!(out, "read-only:").expect("writing the policy report");
        for path in &policy.read_only {
            let note = if nested.contains(&path) {
                "  (inside a writable grant: needs isolation)"
            } else {
                ""
            };
            writeln!(out, "  r-- {}{note}", path.display()).expect("writing the policy report");
        }
    }

    if !policy.denied.is_empty() {
        let nested: Vec<_> = policy.nested_denials().collect();
        writeln!(out, "denied:").expect("writing the policy report");
        for path in &policy.denied {
            let note = if nested.contains(&path) {
                "  (nested under a grant: needs isolation)"
            } else {
                ""
            };
            writeln!(out, "  --- {}{note}", path.display()).expect("writing the policy report");
        }
    }

    writeln!(out, "network:").expect("writing the policy report");
    writeln!(out, "  egress: {:?}", policy.network.egress).expect("writing the policy report");
    writeln!(out, "  bind_ports: {:?}", policy.network.bind_ports)
        .expect("writing the policy report");
    writeln!(out, "  publish_ports: {:?}", policy.network.publish_ports)
        .expect("writing the policy report");
    if let Some((addr, port)) = policy.network.broker {
        writeln!(
            out,
            "  broker: {addr}:{port} (set by {})",
            policy.network.broker_source.as_deref().unwrap_or("unknown")
        )
        .expect("writing the policy report");
    }
    // The same decision a run with this invocation would make, refusal
    // included: a policy the host cannot honour shows as refused here rather
    // than as a mode that would never come into force.
    let decision = network_decision_for_show(policy, network);
    match &decision {
        Ok(decision) => writeln!(
            out,
            "  mode: {} ({}: {})",
            decision.mode.name(),
            decision.source,
            decision.reason
        )
        .expect("writing the policy report"),
        Err(err) => writeln!(out, "  mode: refused ({err})").expect("writing the policy report"),
    }
    let mode = decision
        .map(|decision| decision.mode)
        .unwrap_or(network::NetworkMode::LandlockOnly);

    writeln!(out, "devices:").expect("writing the policy report");
    if policy.devices.is_empty() {
        writeln!(out, "  (none)").expect("writing the policy report");
    }
    for rule in &policy.devices {
        writeln!(
            out,
            "  {} {}",
            access_flags(rule.access),
            rule.path.display()
        )
        .expect("writing the policy report");
    }

    writeln!(out, "resources: {:?}", policy.resources).expect("writing the policy report");

    print_hooks(out, &resolved.hooks);

    let world = World::derive(target, policy, false);
    writeln!(out, "home: {}", world.home_inside.display()).expect("writing the policy report");
    if world.home_host.is_some() {
        writeln!(out, "  (private; the real home is not granted)")
            .expect("writing the policy report");
    }

    writeln!(out, "environment:").expect("writing the policy report");
    for (name, value) in world::environment(policy, &world, Some(network::Inherited::publish(mode)))
    {
        let origin = if policy.env.set.contains_key(&name) {
            "set"
        } else if policy.env.passes(&name) {
            "passed"
        } else {
            "base"
        };
        writeln!(out, "  {name}={value}  ({origin})").expect("writing the policy report");
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

    /// pasta forwards every bound port in both directions unless told not to,
    /// and a forwarded host port shows up in the namespace's own `/proc/net`
    /// tables. A confined program reading those gets a list of what this host
    /// runs and where, loopback-only services included, without ever opening a
    /// connection for the netfilter rule to refuse.
    #[test]
    fn a_private_network_forwards_no_port_in_either_direction() {
        let args = pasta_arguments(Some("169.254.169.1"), true, &[], &[]);

        for forwarding in ["-t", "-u", "-T", "-U"] {
            let at = args
                .iter()
                .position(|arg| arg == forwarding)
                .unwrap_or_else(|| panic!("{forwarding} must be named, or it defaults to auto"));
            assert_eq!(args[at + 1], "none", "{forwarding} must forward nothing");
        }

        // The broker is still reachable: that is the one thing the namespace
        // is allowed to talk to, and it is a mapping rather than a forward.
        let at = args
            .iter()
            .position(|arg| arg == "--map-host-loopback")
            .expect("the broker's address is mapped");
        assert_eq!(args[at + 1], "169.254.169.1");
    }

    /// Without an egress proxy no host address is mapped at all, and a host
    /// with no IPv6 gets none rather than a route it cannot follow.
    #[test]
    fn a_plain_private_network_maps_no_host_and_no_absent_route() {
        let args = pasta_arguments(None, false, &[], &[]);

        assert!(!args.iter().any(|arg| arg == "--map-host-loopback"));
        assert!(args.iter().any(|arg| arg == "-4"));
        assert!(!args.iter().any(|arg| arg == PROXY_ADDRESS_V6));
    }

    fn proxy_args(options: &[&str]) -> RunArgs {
        let cli = Cli::try_parse_from(
            ["bailey", "run"]
                .into_iter()
                .chain(options.iter().copied())
                .chain(["/bin/true"]),
        )
        .unwrap();
        match cli.command {
            Command::Run(args) => args,
            _ => unreachable!(),
        }
    }

    fn parsed_proxy_forwards(
        policy: &Policy,
        options: &[&str],
    ) -> anyhow::Result<Vec<PortForward>> {
        let args = proxy_args(options);
        collect_forwards(policy, args.no_isolate)
    }

    #[test]
    fn online_forwards_collect_without_a_flag() {
        let mut policy = Policy::default();
        policy.forwards.push(PortForward {
            port: 8081,
            host_port: 8080,
        });
        // A denied egress keeps the forwards for the backend, which carries
        // them in the namespace the policy builds anyway.
        assert_eq!(
            parsed_proxy_forwards(&policy, &[]).unwrap(),
            policy.forwards
        );
        assert_eq!(
            parsed_proxy_forwards(&policy, &["--proxy-net"]).unwrap(),
            policy.forwards
        );
        assert_eq!(
            parsed_proxy_forwards(&policy, &["--no-proxy-net"]).unwrap(),
            policy.forwards
        );
        assert_eq!(
            parsed_proxy_forwards(&policy, &["--egress-proxy", "169.254.169.1:8443"]).unwrap(),
            policy.forwards
        );
        policy.network.egress = Egress::AllowAll;
        // Allowed egress hands the forwards to pasta, which needs isolation.
        assert!(parsed_proxy_forwards(&policy, &["--proxy-net", "--no-isolate"]).is_err());
        assert_eq!(
            parsed_proxy_forwards(&policy, &["--proxy-net"]).unwrap(),
            policy.forwards
        );
    }

    #[test]
    fn run_and_shell_accept_the_same_network_flags_and_conflicts() {
        for command in ["run", "shell"] {
            let parse = |options: &[&str]| {
                Cli::try_parse_from(
                    ["bailey", command]
                        .into_iter()
                        .chain(options.iter().copied())
                        .chain((command == "run").then_some("/bin/true")),
                )
            };
            for (options, proxy, disabled, broker) in [
                (vec!["--proxy-net"], true, false, None),
                (vec!["--no-proxy-net"], false, true, None),
                (
                    vec!["--egress-proxy", "169.254.169.1:8443"],
                    false,
                    false,
                    Some("169.254.169.1:8443"),
                ),
            ] {
                let network = match parse(&options).unwrap().command {
                    Command::Run(args) => args.network,
                    Command::Shell(args) => args.network,
                    _ => unreachable!(),
                };
                assert_eq!(network.proxy_net, proxy);
                assert_eq!(network.no_proxy_net, disabled);
                assert_eq!(network.egress_proxy.as_deref(), broker);
            }
            assert!(parse(&["--proxy-net", "--no-proxy-net"]).is_err());
            assert!(parse(&["--egress-proxy", "169.254.169.1:8443", "--no-proxy-net"]).is_err());
        }
    }

    #[test]
    fn proxy_network_maps_only_explicit_tcp_forwards() {
        let forwards = [
            PortForward {
                port: 8081,
                host_port: 8080,
            },
            PortForward {
                port: 5433,
                host_port: 5432,
            },
        ];
        let args = pasta_arguments(None, false, &forwards, &[]);
        let mappings: Vec<_> = args
            .windows(2)
            .filter(|pair| pair[0] == "-T")
            .map(|pair| pair[1].as_str())
            .collect();
        assert_eq!(mappings, ["8081:8080", "5433:5432"]);
        for direction in ["-t", "-u", "-U"] {
            let at = args.iter().position(|arg| arg == direction).unwrap();
            assert_eq!(args[at + 1], "none");
        }
        assert!(args.iter().any(|arg| arg == "--no-map-gw"));
        assert!(
            !args
                .iter()
                .any(|arg| arg == "auto" || arg == "--map-host-loopback")
        );
    }

    #[test]
    fn proxy_loopback_default_admits_the_sandbox_loopback() {
        let rules = proxy_loopback_ruleset(&[], &[], &Egress::AllowAll);
        assert!(rules.contains("policy accept;"));
        // The blanket drops are gone: namespace loopback never reaches the
        // host under bailey's pasta arguments, so a drop there would only
        // break the servers the target talks to over its own loopback.
        assert!(!rules.contains("ip daddr 127.0.0.0/8 drop"));
        assert!(!rules.contains("ip6 daddr ::1 drop"));
        assert!(!rules.contains("dport"));
        assert!(!rules.contains("ct state"));
    }

    #[test]
    fn proxy_loopback_accepts_only_exact_forwarded_tcp_endpoints() {
        let forwards = [PortForward {
            port: 8081,
            host_port: 8080,
        }];
        let rules = proxy_loopback_ruleset(&forwards, &[], &Egress::AllowAll);
        let permit = rules
            .find("ip daddr 127.0.0.1 tcp dport 8081 accept")
            .unwrap();
        let deny_loopback = rules
            .find("ip daddr 127.0.0.0/8 tcp dport 8081 drop")
            .unwrap();
        assert!(permit < deny_loopback);
        assert!(rules.find("ct state established accept").unwrap() < permit);
        assert!(rules.contains("policy accept;"));
        assert!(rules.contains("ip daddr 10.0.2.15 tcp dport 8081 drop"));
        assert!(rules.contains("ip6 daddr fd00::2 tcp dport 8081 drop"));
        assert!(rules.contains("ip6 daddr ::1 tcp dport 8081 drop"));
        assert!(!rules.contains("udp"));
        assert!(!rules.contains("dport 8080"));
        assert!(!rules.contains("oif lo accept"));
        // No blanket drop may come back: the sandbox's own servers on other
        // loopback addresses and ports stay reachable.
        assert!(!rules.contains("127.0.0.0/8 drop\n"));
        assert!(!rules.contains("\t\tip6 daddr ::1 drop\n"));
    }

    #[test]
    fn proxy_forward_connect_ports_do_not_widen_partial_remote_egress() {
        use crate::policy::EgressRule;
        let mut policy = Policy::default();
        policy.network.egress = Egress::Allow(vec![EgressRule {
            host: "*".into(),
            port: Some(443),
        }]);
        let forwards = [PortForward {
            port: 8081,
            host_port: 8080,
        }];
        let rules = proxy_loopback_ruleset(&forwards, &[], &policy.network.egress);
        let permit = rules
            .find("ip daddr 127.0.0.1 tcp dport 8081 accept")
            .unwrap();
        let deny_remote = rules.find("\t\ttcp dport 8081 drop").unwrap();
        assert!(permit < deny_remote);
        assert!(!rules.contains("tcp dport 443 drop"));
        permit_egress_port(&mut policy, 8081);
        assert!(
            matches!(policy.network.egress, Egress::Allow(ref ports) if ports.iter().any(|rule| rule.port == Some(8081)))
        );
    }

    #[test]
    fn proxy_forwards_preserve_existing_remote_port_allowances() {
        use crate::policy::EgressRule;
        let forwards = [PortForward {
            port: 8081,
            host_port: 8080,
        }];
        for port in [0, 8081] {
            let egress = Egress::Allow(vec![EgressRule {
                host: "*".into(),
                port: Some(port),
            }]);
            let rules = proxy_loopback_ruleset(&forwards, &[], &egress);
            assert!(!rules.contains("\t\ttcp dport 8081 drop"));
        }
    }

    fn publish_args(options: &[&str]) -> NetworkArgs {
        proxy_args(options).network
    }

    #[test]
    fn published_ports_collect_from_the_flag_and_the_policy() {
        let args = publish_args(&["--publish-port", "3800"]);
        let policy = |egress: Egress, publish: &[u16]| {
            let mut policy = Policy::default();
            policy.network.egress = egress;
            policy.network.publish_ports = publish.to_vec();
            policy
        };
        assert_eq!(
            collect_publish_ports(&policy(Egress::AllowAll, &[]), &args, false).unwrap(),
            vec![3800]
        );
        // The policy's own publications merge with the flag's, without
        // repeating one.
        assert_eq!(
            collect_publish_ports(
                &policy(Egress::AllowAll, &[3800, 4000]),
                &publish_args(&["--publish-port", "3800"]),
                false
            )
            .unwrap(),
            vec![3800, 4000]
        );
        assert!(collect_publish_ports(&policy(Egress::DenyAll, &[]), &args, false).is_err());
        assert!(collect_publish_ports(&policy(Egress::AllowAll, &[]), &args, true).is_err());
        assert!(
            collect_publish_ports(
                &policy(Egress::AllowAll, &[]),
                &publish_args(&["--publish-port", "0"]),
                false
            )
            .is_err()
        );
    }

    #[test]
    fn published_ports_do_not_collide_with_forwards() {
        let mut policy = Policy::default();
        policy.network.egress = Egress::AllowAll;
        policy.forwards.push(PortForward {
            port: 8081,
            host_port: 8080,
        });
        let publish = |port: &str| {
            let args = publish_args(&["--publish-port", port]);
            collect_publish_ports(&policy, &args, false)
        };
        assert!(publish("8081").is_err(), "the forward's sandbox port");
        assert!(publish("8080").is_err(), "the forward's host port");
        assert_eq!(publish("3800").unwrap(), vec![3800]);
    }

    /// The publication flag lands in the policy itself, so `show` reports the
    /// publications this invocation resolves.
    #[test]
    fn a_publish_port_flag_joins_the_policy() {
        let mut policy = Policy::default();
        policy.network.publish_ports = vec![4000];
        apply_network_flags(
            &mut policy,
            &publish_args(&["--publish-port", "3800", "--publish-port", "4000"]),
        )
        .unwrap();
        assert_eq!(policy.network.publish_ports, vec![4000, 3800]);
    }

    /// Each contradictory combination the policy-config delta names, refused
    /// with both sides named.
    #[test]
    fn contradictory_network_settings_are_refused_naming_the_layers() {
        let forward = PortForward {
            port: 8081,
            host_port: 8080,
        };
        let forwards = [forward];
        let host_mode = |broker: bool, broker_source: &str| {
            let mut policy = Policy::default();
            policy.network.egress = Egress::AllowAll;
            policy.network.mode = crate::policy::NetworkMode::Host;
            policy.network.mode_source = "/global/bailey.toml".to_owned();
            if broker {
                policy.network.broker = Some(("169.254.169.1".parse().unwrap(), 8443));
                policy.network.broker_source = Some(broker_source.to_owned());
            }
            policy
        };

        // Host mode with a broker.
        let err = check_network_contradictions(&host_mode(true, "/global/bailey.toml"), &[], &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("host mode"), "{err}");
        assert!(err.contains("/global/bailey.toml"), "{err}");
        assert!(err.contains("169.254.169.1:8443"), "{err}");

        // Host mode with published ports.
        let err = check_network_contradictions(&host_mode(false, ""), &[], &[3800])
            .unwrap_err()
            .to_string();
        assert!(err.contains("host mode"), "{err}");
        assert!(err.contains("/global/bailey.toml"), "{err}");

        // Host mode with forwards under allowed egress.
        let err = check_network_contradictions(&host_mode(false, ""), &forwards, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("host mode"), "{err}");
        assert!(err.contains("forward"), "{err}");

        // A broker with forwards, and a broker with published ports.
        let mut brokered = Policy::default();
        brokered.network.egress = Egress::AllowAll;
        brokered.network.broker = Some(("169.254.169.1".parse().unwrap(), 8443));
        brokered.network.broker_source = Some("/project/bailey.toml".to_owned());
        let err = check_network_contradictions(&brokered, &forwards, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("broker"), "{err}");
        assert!(err.contains("/project/bailey.toml"), "{err}");
        let err = check_network_contradictions(&brokered, &[], &[3800])
            .unwrap_err()
            .to_string();
        assert!(err.contains("broker"), "{err}");
        assert!(err.contains("/project/bailey.toml"), "{err}");

        // A mode the flags raised above the refusal is no contradiction: this
        // is how --proxy-net rescues a config layer that asked for host mode
        // beside a forward.
        let mut rescued = host_mode(false, "");
        rescued.network.mode = crate::policy::NetworkMode::Private;
        rescued.network.mode_source = "flag --proxy-net".to_owned();
        check_network_contradictions(&rescued, &forwards, &[]).unwrap();

        // A denied-egress forward needs no private namespace, so host mode
        // beside one is no contradiction: the backend carries it in the
        // namespace the policy builds anyway.
        let mut denied = host_mode(false, "");
        denied.network.egress = Egress::DenyAll;
        check_network_contradictions(&denied, &forwards, &[]).unwrap();
    }

    /// Each flag overrides each config value, as the highest layer.
    #[test]
    fn network_flags_override_every_config_value() {
        let config_layer = |mode: &str, broker: bool| {
            let mut policy = Policy::default();
            policy.network.egress = Egress::AllowAll;
            policy.network.mode = crate::policy::NetworkMode::parse(mode).unwrap();
            policy.network.mode_source = "/project/bailey.toml".to_owned();
            if broker {
                policy.network.broker = Some(("169.254.169.9".parse().unwrap(), 9000));
                policy.network.broker_source = Some("/project/bailey.toml".to_owned());
            }
            policy
        };

        // --proxy-net over a config's host mode.
        let mut policy = config_layer("host", false);
        apply_network_flags(&mut policy, &publish_args(&["--proxy-net"])).unwrap();
        assert_eq!(policy.network.mode, crate::policy::NetworkMode::Private);
        assert_eq!(policy.network.mode_source, "flag --proxy-net");

        // --no-proxy-net over a config's private mode.
        let mut policy = config_layer("private", false);
        apply_network_flags(&mut policy, &publish_args(&["--no-proxy-net"])).unwrap();
        assert_eq!(policy.network.mode, crate::policy::NetworkMode::Host);
        assert_eq!(policy.network.mode_source, "flag --no-proxy-net");

        // --egress-proxy over a config's broker.
        let mut policy = config_layer("auto", true);
        apply_network_flags(
            &mut policy,
            &publish_args(&["--egress-proxy", "169.254.169.1:8443"]),
        )
        .unwrap();
        assert_eq!(
            policy.network.broker,
            Some(("169.254.169.1".parse().unwrap(), 8443))
        );
        assert_eq!(
            policy.network.broker_source.as_deref(),
            Some("flag --egress-proxy")
        );

        // --egress-proxy over a config's host mode selects the mode as well:
        // the broker needs the private namespace, so naming one implies
        // --proxy-net.
        let mut policy = config_layer("host", false);
        apply_network_flags(
            &mut policy,
            &publish_args(&["--egress-proxy", "169.254.169.1:8443"]),
        )
        .unwrap();
        assert_eq!(policy.network.mode, crate::policy::NetworkMode::Private);
        assert_eq!(policy.network.mode_source, "flag --egress-proxy");
    }

    #[test]
    fn publication_maps_only_loopback_and_keeps_other_directions_off() {
        let args = pasta_arguments(None, false, &[], &[3800, 4000]);
        let mappings: Vec<_> = args
            .windows(2)
            .filter(|pair| pair[0] == "-t")
            .map(|pair| pair[1].as_str())
            .collect();
        assert_eq!(mappings, ["127.0.0.1/3800", "127.0.0.1/4000"]);
        assert!(args.iter().any(|arg| arg == "--host-lo-to-ns-lo"));
        for direction in ["-u", "-T", "-U"] {
            let at = args.iter().position(|arg| arg == direction).unwrap();
            assert_eq!(args[at + 1], "none");
        }
        assert!(!args.iter().any(|arg| arg == "auto"));
    }

    #[test]
    fn publication_rules_admit_the_local_connection() {
        let rules = proxy_loopback_ruleset(&[], &[3800], &Egress::AllowAll);
        let established = rules.find("ct state established accept").unwrap();
        let accept = rules
            .find("ip daddr 127.0.0.1 tcp dport 3800 accept")
            .unwrap();
        assert!(established < accept);
        assert!(!rules.contains("127.0.0.0/8 drop"));
        // A publication is not an egress allowance, so it gets no remote drop.
        assert!(!rules.contains("\t\ttcp dport 3800 drop"));
        assert!(!rules.contains("udp"));
        assert!(!rules.contains("oif lo accept"));
    }

    #[test]
    fn publication_only_rules_keep_established_replies() {
        let rules = proxy_loopback_ruleset(&[], &[3800], &Egress::AllowAll);
        assert!(rules.contains("ct state established accept"));
    }

    #[test]
    fn the_proxy_holds_one_slot_for_the_isolation_layer() {
        assert_eq!(proxy_guard_limit(false), 1);
        assert_eq!(proxy_guard_limit(true), 0);
    }

    #[test]
    fn an_egress_proxy_value_parses_into_an_address_and_port() {
        assert_eq!(
            parse_egress_proxy("169.254.169.1:8443").unwrap(),
            ("169.254.169.1".parse().unwrap(), 8443),
        );
        assert!(parse_egress_proxy("169.254.169.1").is_err()); // no port
        assert!(parse_egress_proxy("not-an-addr:443").is_err()); // not IPv4
        // A Landlock rule on port 0 reads as any port, so a broker named that
        // way would widen egress instead of bounding it.
        assert!(parse_egress_proxy("169.254.169.1:0").is_err());
        assert!(parse_egress_proxy("169.254.169.1:70000").is_err()); // out of range
    }

    #[test]
    fn permitting_the_broker_port_widens_only_that_port() {
        use crate::policy::{Egress, EgressRule, Policy};

        // An Allow policy gains the broker port alongside what it had.
        let mut policy = Policy::default();
        policy.network.egress = Egress::Allow(vec![EgressRule {
            host: "*".into(),
            port: Some(443),
        }]);
        permit_egress_port(&mut policy, 8443);
        match &policy.network.egress {
            Egress::Allow(rules) => {
                assert!(rules.iter().any(|r| r.port == Some(443)));
                assert!(rules.iter().any(|r| r.port == Some(8443)));
            }
            _ => panic!("expected Allow"),
        }

        // AllowAll already permits every port, so it is left alone.
        let mut open = Policy::default();
        open.network.egress = Egress::AllowAll;
        permit_egress_port(&mut open, 8443);
        assert_eq!(open.network.egress, Egress::AllowAll);
    }
    /// A hook runs as the caller, unconfined, before the sandbox exists, so
    /// trusting a config is trusting whoever can write it to run programs as
    /// you. The warning is the whole value of the trust command, and it looked
    /// for keys the schema never reads.
    #[test]
    fn trust_reports_the_hooks_a_config_runs() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("bailey.toml");
        std::fs::write(
            &config,
            "[hooks]\npre_launch = [\"echo INSTALLING DEPENDENCIES\"]\npost_exit = [\"echo CLEANING UP\"]",
        )
        .unwrap();

        let mut out = Vec::new();
        report_hooks(&mut out, &config);
        let report = String::from_utf8(out).unwrap();

        assert!(
            report.contains("pre_launch: echo INSTALLING DEPENDENCIES"),
            "{report}"
        );
        assert!(report.contains("post_exit: echo CLEANING UP"), "{report}");
    }

    /// `on_violation` is accepted for backwards compatibility and can never
    /// run, so naming it would warn about a command that does nothing.
    #[test]
    fn trust_names_no_hook_that_can_never_run() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("bailey.toml");
        std::fs::write(&config, "[hooks]\non_violation = [\"echo TOO LATE\"]").unwrap();

        let mut out = Vec::new();
        report_hooks(&mut out, &config);

        assert!(
            out.is_empty(),
            "on_violation cannot run: {:?}",
            String::from_utf8_lossy(&out)
        );
    }

    /// `show` resolves and prints the effective policy, and the hooks are part
    /// of what a policy does, so they belong in the report beside the rest.
    ///
    /// The report is driven through `print_policy`, not through `print_hooks`
    /// directly, because the wiring is what this is guarding: a test that calls
    /// `print_hooks` itself stays green when the call inside `print_policy` is
    /// deleted, which is the failure the section exists to prevent.
    #[test]
    fn show_lists_the_hooks_a_config_runs() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("prog");
        let resolved = Resolved {
            hooks: Hooks {
                pre_launch: vec!["echo INSTALLING DEPENDENCIES".into()],
                post_exit: vec!["echo CLEANING UP".into()],
            },
            ..Default::default()
        };

        let mut out = Vec::new();
        print_policy_to(&mut out, &resolved, &target, &NetworkArgs::default());
        let report = String::from_utf8(out).unwrap();

        assert!(report.contains("hooks:"), "{report}");
        assert!(
            report.contains("pre_launch: echo INSTALLING DEPENDENCIES"),
            "{report}"
        );
        assert!(report.contains("post_exit: echo CLEANING UP"), "{report}");
    }

    /// A policy that runs no hooks prints no section, so the report of a config
    /// without any is the one it always was. Driven through the same path, so
    /// the pair fails if either half of the wiring goes.
    #[test]
    fn no_hooks_prints_no_hooks_section() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("prog");
        let config = dir.path().join("bailey.toml");
        std::fs::write(&config, "[filesystem]\nread = [\"/granted\"]").unwrap();

        let mut trusted = Vec::new();
        report_hooks(&mut trusted, &config);

        let mut shown = Vec::new();
        print_policy_to(
            &mut shown,
            &Resolved::default(),
            &target,
            &NetworkArgs::default(),
        );
        let report = String::from_utf8(shown).unwrap();

        assert!(
            trusted.is_empty(),
            "no hooks to name: {:?}",
            String::from_utf8_lossy(&trusted)
        );
        assert!(
            !report.contains("hooks:"),
            "a policy with no hooks prints no hooks section: {report}"
        );
    }

    #[test]
    fn a_global_v6_address_is_what_marks_the_host_as_reachable() {
        // A global-scope address on wlan0 (scope 00), alongside loopback and a
        // link-local that reach nowhere off the host.
        let with_global = "\
fe80000000000000869e56fffe032b71 04 40 20 80    wlan0
00000000000000000000000000000001 01 80 10 80       lo
24001a005b2bdc94869e56fffe032b71 04 80 00 00    wlan0
";
        assert!(ipv6_global_present(with_global));

        // Loopback and link-local only: no route off the host, so v4 alone.
        let no_global = "\
fe80000000000000869e56fffe032b71 04 40 20 80    wlan0
00000000000000000000000000000001 01 80 10 80       lo
";
        assert!(!ipv6_global_present(no_global));
        assert!(!ipv6_global_present(""));
    }

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

#[cfg(test)]
mod root_guard_tests {
    use super::host_uid_of_root;

    #[test]
    fn a_mapped_root_is_not_real_root() {
        // 0 mapped to 0 across the whole range: the initial namespace, or a
        // nested one the host's root seeded. Both are the caller the guard
        // refuses.
        assert_eq!(
            host_uid_of_root("         0          0 4294967295\n"),
            Some((0, u32::MAX))
        );
        // What pasta gives the inner run: 0 stands for the caller.
        assert_eq!(
            host_uid_of_root("         0       1000          1\n"),
            Some((1000, 1))
        );
        // A map that does not cover 0 at all.
        assert_eq!(host_uid_of_root("      1000       1000          1\n"), None);
        assert_eq!(host_uid_of_root(""), None);
    }
}

#[cfg(test)]
mod helper_resolution_tests {
    use super::{HELPER_DIRS, resolve_helper};

    #[test]
    fn a_helper_is_never_taken_from_path() {
        // Whatever PATH says, only the fixed directories are searched, so a
        // writable entry on it cannot supply a program bailey runs itself.
        assert!(!HELPER_DIRS.iter().any(|dir| dir.starts_with("/tmp")));
        let missing = resolve_helper("bailey-no-such-helper-xyz");
        assert!(missing.is_err());
    }

    #[test]
    fn a_real_system_helper_still_resolves() {
        // `sh` is in a system directory on any host this runs on.
        let found = resolve_helper("sh").expect("sh should resolve");
        assert!(HELPER_DIRS.iter().any(|dir| found.starts_with(dir)));
    }
}
