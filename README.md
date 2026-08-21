# bailey

A layered, deny-by-default sandbox for running untrusted programs on Linux.

Bailey puts a wall around a program and gives you the tools to see and shrink
what it can reach. It confines with Landlock, seccomp, cgroups, and namespaces,
reads a cascading config that layers global defaults under per-directory and
per-program rules, and can record what a program actually touches so you can
tighten its policy from evidence instead of guesswork.

Everything except the audit recorder is unprivileged. No setuid binary, no
daemon, no container runtime. A confined run costs about 2.6 ms to establish,
and around 12% on a workload that is nothing but opening files; the numbers and
the script that produced them are in the documentation.

## Why

Most code you run was written by someone you have never met. A game from a store
page, a release binary from a repository you skimmed, a build script from a
dependency, a coding agent with shell access. All of it runs with the full
authority of your user account: your SSH keys, your browser profile, your
documents, your network.

The usual answers are awkward. A VM is heavy. A container is built for shipping
services, not for running a desktop program. `firejail` and `bubblejail` carry
flat, hand-maintained profiles with no way to observe what a program actually
needs. `landrun` is a thin one-shot Landlock wrapper with no config model.

Bailey is the middle path: a launcher with a real policy model, layered kernel
enforcement underneath it, and an audit mode that turns "I have no idea what this
needs" into a profile you can read.

## How it works

| Layer | Mechanism | What it does |
| --- | --- | --- |
| Filesystem | Landlock | Deny-by-default rules on path hierarchies |
| Network | Network namespace, Landlock | Denied egress means no route at all; a partial allowance is enforced by TCP port |
| Syscalls | seccomp | Removes syscalls a normal program never needs |
| Resources | cgroup v2 | Caps memory, process count, and CPU |
| World | user, mount, PID namespaces | Rebuilds the root from the policy, so ungranted paths are absent rather than merely denied, and host processes are invisible |
| Reachability | Landlock scoping | Host abstract UNIX sockets and processes outside the sandbox are out of reach |
| Observation | eBPF, via a privileged helper | Records what the program opens and connects to, without blocking it |
| Coverage | Inheritance | `bailey shell` confines a shell, and a Landlock ruleset cannot be dropped, so everything started from it is confined too |

One policy drives all of it. Config resolves into a single mechanism-independent
`Policy` that both the enforcement backend and the audit backend consume, so a
profile built by watching a program is directly usable for confining it.

## Install

A release carries a statically linked binary for x86_64 and aarch64, with shell
completions and a man page. Unpack it and put `bailey` on your `PATH`.

From source, enforcement, config, profiles, and reconciliation build with a
stable toolchain and no system dependencies:

```sh
cargo build --release
```

The audit recorder is a separate, minimal binary that loads the eBPF programs.
Building it needs nightly and `bpf-linker`:

```sh
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
cargo build --release -p bailey-bpf-helper
```

It is the only component that needs privilege. Grant it capabilities once:

```sh
sudo setcap cap_bpf,cap_perfmon+ep ./target/release/bailey-bpf-helper
```

The main tool finds the helper through `BAILEY_BPF_HELPER`, then next to its own
executable, then on `PATH`.

## Quick start

```sh
# Run a program under the deny-by-default floor, with namespace isolation:
# ungranted paths are absent and host processes are invisible.
bailey run ./program

# Confine a whole session instead. Everything started from this shell is
# covered by the directory's policy, prefix or no prefix.
bailey shell

# Have a directory's policy announce itself when you enter it.
bailey hook fish | source     # or: eval "$(bailey hook bash)"

# Start from a profile shaped for native Linux games.
bailey run --profile native-game ./game

# See the effective policy and the config layers that produced it.
bailey show ./program

# List the bundled profiles.
bailey profile list
```

If a program will not start, its policy is missing something it needs, usually a
system path or a device. Widen the profile, add a `bailey.toml` next to the
program, or record a session with `bailey audit` and let the trace tell you.

## Configuration

Config is TOML, merged from layers of increasing precedence:

1. A bundled profile (`--profile`, default `untrusted`), the safe floor.
2. Global config: `$XDG_CONFIG_HOME/bailey/config.toml`.
3. Per-directory `bailey.toml` files, discovered by walking up from the target,
   outermost first, and applied only once you have trusted them.
4. An explicit file passed with `--config`.

Filesystem and device grants accumulate across layers. Scalar settings from a
later layer replace earlier ones. Relative paths resolve against the config
file's own directory, and `~` expands to your home.

```toml
[filesystem]
read = ["~/.config/myapp", "./assets"]
write = ["./saves"]
execute = ["./program"]
deny = ["~/.config/myapp/secrets"]  # removes a grant from a lower layer
# reset = true                      # clears everything lower layers granted

[network]
egress = "deny"                     # "deny" (default) or "allow"
egress_allow = [{ host = "*", port = 443 }]
bind_ports = [27015]

[[device]]
path = "/dev/dri"
access = "rw"                       # any of r, w, x

[resources]
memory = "2GiB"                     # bytes, or KiB/MiB/GiB, or KB/MB/GB
pids_max = 512
cpu_percent = 150                   # percent of one core

[hooks]
pre_launch = ["./setup.sh"]         # a non-zero exit aborts the run
post_exit = ["./cleanup.sh"]        # receives BAILEY_EXIT_CODE
```

`bailey show <target>` prints the merged result and every file that contributed
to it. When something is unexpectedly denied, start there.

A `bailey.toml` found by walking a directory can have arrived with the code you
are confining, so it contributes nothing until you accept it once:

```sh
bailey trust ./bailey.toml     # accept it as it currently reads
bailey trust --list            # what has been accepted, and whether it still applies
bailey untrust ./bailey.toml   # withdraw
```

Acceptance is recorded against the file's contents, so an edit revokes it. A run
that meets an untrusted file proceeds with the narrower policy and reports the
file rather than prompting. Your global config, your own profiles, and a file you
pass with `--config` need no record.

## Audit workflow

Audit mode runs a program while recording the filesystem and network access of
its process tree, then compares that trace against the current policy and flags
everything ungranted, calling out high-risk access separately: network egress,
credential and dotfile reads, and anything outside the program's own directory.

```sh
# Record a session and review what it touched.
bailey audit --save-trace trace.json ./program

# Turn the reviewed trace into a deny-by-default profile.
# High-risk access is excluded unless you pass --include-high-risk.
bailey profile generate --trace trace.json --target ./program > bailey.toml
```

Audit is for tightening software you have some reason to trust. Auditing
genuinely hostile code and accepting the result would grant exactly what that
code did, including its call home and its look through your keys. That is why
high-risk findings are separated and never included without an explicit opt-in.

## Requirements

- Linux 5.13 or newer for Landlock. Network rules need 6.7, and scoping needs
  6.12. Bailey negotiates the ABI best-effort and reports what the kernel cannot
  enforce.
- Unprivileged user namespaces for the isolation layer and the network
  namespace.
  Without them, enforcement falls back to Landlock and seccomp with a warning,
  and egress is restricted by TCP port only.
- Cgroup v2 with a writable delegated cgroup for resource limits. Without one,
  limits are skipped with a warning rather than failing the run.
- Kernel BTF and the privileged helper for `bailey audit`.

## What bailey does not do yet

Being clear about the edges matters more than sounding complete.

- **A partial egress allowance restricts TCP only.** Allowing any egress, or
  binding a port, keeps the target in the host's network namespace where only
  Landlock's TCP port rules apply. The run warns that UDP, QUIC, and DNS are not
  restricted. A full `egress = "deny"`, the default, has no such gap.
- **Taking access away needs the isolation layer**, which is on by default. A
  nested `deny` is enforced by covering the path, and a `read_only` island by a
  read-only mount, because Landlock rules add rights and never subtract them.
  Under `--no-isolate` both are reported as unenforced rather than silently
  ignored.
- **Audit falls back to process-tree scoping without a cgroup.** Where a run can
  be given a cgroup, scoping is exact; otherwise a very short-lived child can be
  missed, and the run says so.
- **A denied access is not reported.** Landlock denies silently, and seeing a
  denial needs the kernel's audit subsystem enabled at boot plus permission to
  read its records. Use `bailey audit` to find out what a program wanted.
- **The seccomp filter is a denylist,** covering module loading, `ptrace`, `bpf`,
  namespace and mount operations, and similar. It is a hardening layer, not a
  complete allowlist.
- **Host and CIDR egress rules are advisory.** Landlock matches on TCP port; the
  host field is not enforced and bailey warns when you use it.
- **X11 is not sandboxable at the protocol level.** Prefer Wayland.

## Status

Everything described above is implemented and exercised by the test suite,
including the audit backend: its eBPF programs are loaded and attached for real
in tests, on a host where the helper has its capabilities. Tests that need
something the host cannot provide, a delegated cgroup or the audit helper, skip
rather than pretend.

What bailey does not do is listed above and in the documentation, with the reason
in each case.

## Documentation

Full documentation lives in `docs/`, built with VitePress:

```sh
cd docs
bun install
bun run dev
```

## License

MIT OR Apache-2.0.
