# bailey

An ergonomic, layered sandbox for running untrusted games and binaries on Linux.

Bailey confines a program to a deny-by-default policy using Landlock for
filesystem and network access, seccomp to trim the syscall surface, and cgroups
for resource limits. It reads a cascading, mise-style config (global, then
per-directory, then per-game), ships safe bundled profiles, and has a
first-class audit mode that records what a program actually touches so you can
tighten a profile from evidence instead of guesswork.

## Why

Running an unknown Steam title, an itch.io download, or a mod gives that code the
full authority of your user account. Bailey puts a cheap, unprivileged wall
around it and gives you the tools to see and shrink what it can reach.

## Status

Implemented and verified: the policy model, cascading config, the enforcement
backend (Landlock filesystem and network, seccomp, cgroups), reconciliation, the
CLI, and bundled profiles. The eBPF audit backend is implemented and
compile-verified; running it needs a privileged environment (see below).

Deferred: namespace and mount-view hardening (defense in depth on top of
Landlock), and the exec (`bprm`) audit tracepoint.

## Build

Default build (enforcement, config, profiles, reconciliation). No special
toolchain required:

```
cargo build --release
```

The eBPF audit backend is behind the `ebpf` feature and needs a nightly
toolchain and `bpf-linker` at build time:

```
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
cargo build --release --features ebpf
```

## Quick start

```
# Run a binary under the default deny-by-default profile.
bailey run ./game

# See the effective policy for a target, with the config layers that shaped it.
bailey show ./game

# List the bundled profiles.
bailey profile list

# Use the native-game profile as the base (adds GPU, audio, display, fonts).
bailey run --profile native-game ./game
```

The enforcement backend is unprivileged. If a program will not start, its policy
is missing something it needs (often a system path); widen the profile or add a
per-game config.

## Configuration

Config is TOML, merged from three layers of increasing precedence:

1. Global: `$XDG_CONFIG_HOME/bailey/config.toml` (or `~/.config/bailey/config.toml`).
2. Per-directory: `bailey.toml` files discovered by walking up from the target,
   outermost first.
3. Explicit: a file passed with `--config`.

A bundled profile (`--profile`, default `untrusted`) is applied beneath all of
these as the safe floor. Filesystem and device grants accumulate across layers;
scalar settings from a later layer override earlier ones.

```toml
[filesystem]
# reset = true clears filesystem grants accumulated by lower-precedence layers.
read = ["~/.config/mygame", "./assets"]
write = ["./saves"]
execute = ["./game"]
# deny removes a path granted by a lower layer.
deny = ["~/.config/mygame/secrets"]

[network]
egress = "deny"          # "deny" (default) or "allow"
# Or allow specific TCP ports (host is advisory; Landlock enforces the port):
egress_allow = [{ host = "*", port = 443 }]
bind_ports = [27015]

[[device]]
path = "/dev/dri"
access = "rw"            # any of r, w, x

[resources]
memory = "2GiB"          # bytes, or a suffix: KiB/MiB/GiB or KB/MB/GB
pids_max = 512
cpu_percent = 150        # percent of one core (100 = one full core)

[hooks]
pre_launch = ["./setup.sh"]     # a failure here aborts the run
post_exit = ["./cleanup.sh"]    # gets BAILEY_EXIT_CODE
on_violation = ["./log.sh"]     # gets BAILEY_VIOLATION
```

Relative paths resolve against the config file's directory. A `~` prefix expands
to your home directory.

## Audit workflow

Audit mode runs the target permissively while recording the filesystem and
network access of its process tree, then compares that trace to the current
policy and flags anything ungranted, calling out high-risk access (network
egress, credential reads, access outside the target directory).

```
# Record a session and review it. Requires privilege (see below).
sudo bailey audit --save-trace trace.json ./game

# Turn the reviewed trace into a deny-by-default profile.
# High-risk access is excluded unless you pass --include-high-risk.
bailey profile generate --trace trace.json --target ./game > bailey.toml
```

Audit-generated profiles are for tightening software you already trust. Auditing
genuinely untrusted code and blindly accepting the result would grant whatever
that code did, including a credential read or a call home. That is why high-risk
access is flagged and never included without an explicit opt-in.

## Kernel and privilege requirements

- Enforcement needs Landlock (Linux 5.13+; network rules need 6.7+). It is
  unprivileged and requires no setuid binary or daemon. Bailey negotiates the
  Landlock ABI best-effort and reports restrictions the kernel cannot enforce.
- Cgroup limits are best-effort. Without a writable delegated cgroup they are
  skipped with a warning rather than failing the run.
- The audit backend loads eBPF programs and requires `CAP_BPF` and
  `CAP_PERFMON`. Run it under `sudo`, or grant the binary the capabilities:

  ```
  sudo setcap cap_bpf,cap_perfmon+ep ./target/release/bailey
  ```

## Security notes and limits

- Landlock denies access to ungranted paths but does not hide them: a path still
  exists, opening it just fails. Enforcement is by denial, not by concealment.
  Namespace-based world reconstruction is a planned defense-in-depth layer.
- Landlock network rules are TCP-port based. Host or CIDR restrictions in
  `egress_allow` are advisory: bailey enforces the port and warns that the host
  is not enforced.
- The seccomp filter denies a set of dangerous syscalls (module loading,
  `ptrace`, `bpf`, namespace and mount operations, and similar). It is a
  hardening layer, not a complete allowlist.
- X11 is not sandboxable at the display-protocol level; prefer Wayland.

## License

MIT OR Apache-2.0.
