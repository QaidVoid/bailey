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
- **Denials are carried and reported.** ✅ A denial survives resolution, appears
  in `bailey show`, and produces a warning when it cannot be enforced.
- **Denials become enforced.** Still open. Landlock cannot subtract rights from a
  granted parent, so this needs either mount-based concealment under isolation or
  splitting the parent grant. See [known limitations](/security/limitations).

## The world the target sees

- **Environment policy.** Deny-by-default environment with a reconstructed safe
  base, plus explicit `pass` and `set` directives. Display and audio variables
  follow their grants. Ends the wholesale inheritance of your credentials.
- **Private `/tmp` and `/dev/shm`.** tmpfs per run, invisible to the host and to
  other sandboxes, discarded at exit.
- **A private home per target.** Persistent, mounted at the real home's path under
  isolation, so programs that insist on writing to `$HOME` work without reaching
  yours.
- **Working directory preserved.** Bound into the reconstructed root and chdir'd
  back into, so relative paths resolve under `--isolate`.
- **Isolation root hygiene.** A unique staging directory, removed after the pivot,
  so concurrent isolated runs do not collide.

## Network confinement

- **Real egress denial.** When the policy denies egress, run in a network
  namespace with only loopback, so UDP, QUIC, DNS, and everything else fail, not
  just TCP.
- **Landlock scoping.** Raise the target ABI so abstract UNIX sockets outside the
  sandbox are unreachable and host processes cannot be signalled, on kernels that
  support it.
- **Optional user-mode networking.** For the partial case, attach a user-mode
  stack such as `pasta` so allowed egress can be filtered beyond TCP.
- **Honest reporting.** The run states which network mode is in force and what it
  does not cover.

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
