# Roadmap

Planned work, grouped by what it fixes. Every gap listed here is verified against
the current implementation and described in [known
limitations](/security/limitations).

## Policy fidelity

Making the policy mean what it says. Most of this has shipped:

- **Unenforceable rules fail loudly.** ✅ An `egress_allow` entry without a port
  is an error at resolution time rather than a silent conversion to deny-all.
- **The target executable is granted implicitly.** ✅ `bailey run ./program` works
  with no config instead of failing with `Permission denied`.
- **Cgroup membership before exec.** ✅ The target joins its cgroup from the
  pre-exec child, so limits cover every descendant and work under `--isolate`.
- **Config discovery covers the working directory.** ✅ A project's `bailey.toml`
  applies when the target is an interpreter under a system path.
- **Target arguments pass through.** ✅ Bailey stops parsing its own flags at the
  target.
- **Denials are carried, enforced, and reported.** ✅ A denial survives
  resolution and is enforced under `--isolate` by covering the path with an empty
  read-only filesystem. Without isolation there is no mechanism for it, so the run
  reports the denial as unenforced instead of failing quietly.

## The world the target sees

Shipped:

- **Environment policy.** ✅ Deny-by-default environment with a reconstructed base,
  plus `pass`, `set`, and `deny` directives. Display and audio variables follow
  their grants. Your credentials no longer cross by default.
- **Private `/tmp` and `/dev/shm`.** ✅ tmpfs per run under `--isolate`, invisible
  to the host and to other sandboxes, discarded at exit.
- **A private home per target.** ✅ Persistent, and mounted at the real home's path
  under isolation, so programs that insist on writing to `$HOME` work without
  reaching yours.
- **Working directory preserved.** ✅ Kept outside isolation, and bound and entered
  under it.
- **Isolation root hygiene.** ✅ A per-run staging directory, removed by the parent
  after the run.

## Network confinement

Shipped, except the user-mode stack:

- **Real egress denial.** ✅ When the policy denies egress, the target runs in a
  network namespace with only loopback, so UDP, QUIC, DNS, and everything else
  fail, not just TCP. This applies to a plain `bailey run`.
- **Landlock scoping.** ✅ Abstract UNIX sockets outside the sandbox are
  unreachable and processes outside it cannot be signalled, on Linux 6.12 and
  later.
- **Honest reporting.** ✅ `bailey show` prints the mode in force, and a run warns
  when the policy is enforced more narrowly than it reads.
- **Optional user-mode networking.** Still open. For a policy that allows some
  egress, attaching a stack such as `pasta` would isolate the namespace while
  keeping connectivity. It would not filter UDP by port, which those stacks do not
  do, so the gain is isolation rather than filtering.

## Audit fidelity

Shipped:

- **Audit runs confined.** ✅ The resolved policy applies during an audit, widened
  only by read on the target's own directory, with `--unconfined` as an explicit
  opt-out.
- **Nothing missed at startup.** ✅ The target is stopped at `exec` until the
  recorder confirms it is watching, so the dynamic linker's search appears in the
  trace.
- **Full path coverage and resolved paths.** ✅ One hook below the syscalls covers
  every way of opening a path; relative paths are resolved and marked, and
  unresolved ones are never turned into grants.
- **Executions, IPv6, and timestamps** ✅ in the record.
- **Truncation reported** ✅, and a truncated trace cannot silently become a
  profile.
- **Architecture independence.** ✅ BTF-driven `fentry` attachment instead of
  hard-coded x86_64 offsets, which also removed the tracefs dependency and the
  extra capability it would have cost the privileged helper.
- **Exact scoping.** ✅ Observation is scoped to the run's cgroup, whose
  membership the kernel inherits at fork, so a short-lived child cannot be
  missed. Where no cgroup is available it falls back to following the process
  tree and says so.

## Operator experience

Shipped:

- **`bailey doctor`.** ✅ Reports which layers this host can enforce and what each
  missing feature costs, including whether the audit helper can really load.
- **A post-run summary.** ✅ What was enforced, and what the host took away, with
  `--quiet` and `--json`.
- **Better profiles.** ✅ `native-game` gains the NVIDIA nodes, `/dev/input`, and a
  runtime directory scoped to your own uid; `desktop-app`, `ai-agent`, and
  `network-client` are new, and `profile show` prints any of them for editing.
- **Generated shell completions and a man page.** ✅
- **The violation hook is gone.** ✅ Investigation showed no denial signal is
  reachable on a normal host: it needs the kernel's audit subsystem enabled at
  boot as well as permission to read its records. Rather than carry a config key
  that silently does nothing, the hook was removed; a config that still sets it is
  accepted with an explanation, and `bailey audit` answers the same question.

## Not planned

- **Transparent interception**, so that every program launched by a store client
  is automatically sandboxed. Explicit launcher only.
- **BPF-LSM enforcement.** It would raise the privilege floor for every run and
  depend on a kernel config the user cannot change without a reboot.
- **X11 nesting.** Wayland first.
- **Non-Linux platforms.**
