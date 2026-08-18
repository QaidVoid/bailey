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

- **Audit runs confined.** The resolved policy, widened to a permissive envelope,
  applies during an audit run, with an explicit opt-out for trusted software.
- **Nothing missed at startup.** The target is held before exec until observation
  is confirmed, so the dynamic linker's search appears in the trace.
- **Cgroup scoping.** Replaces PID-tree tracking, which cannot be raceless.
- **Resolved absolute paths**, covering every path-opening syscall rather than
  `openat` alone, plus `execve` for child launches.
- **IPv6, timestamps, and access modes** in the record.
- **Truncation reported**, and a truncated trace cannot silently become a profile.
- **Architecture independence.** BTF-driven argument access instead of hard-coded
  x86_64 offsets.

## Operator experience

- **`bailey doctor`.** Reports which layers this host can enforce and what each
  missing feature costs, before you run anything.
- **Denial reporting.** Surface Landlock denials where the kernel provides them,
  and drive `on_violation` hooks from that signal. Where it is unavailable, say so
  instead of accepting config that never runs.
- **A post-run summary.** What was enforced, what was skipped and why, what was
  denied.
- **Better profiles.** Fix `native-game` (NVIDIA nodes, `/dev/input`, `/dev/shm`,
  a runtime directory scoped to your own uid), and add `desktop-app`, `ai-agent`,
  and `network-client`.
- **Generated shell completions and a man page.**

## Not planned

- **Transparent interception**, so that every program launched by a store client
  is automatically sandboxed. Explicit launcher only.
- **BPF-LSM enforcement.** It would raise the privilege floor for every run and
  depend on a kernel config the user cannot change without a reboot.
- **X11 nesting.** Wayland first.
- **Non-Linux platforms.**
