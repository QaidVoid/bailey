# What is bailey

Bailey is a command-line sandbox for Linux. You point it at a program, it builds
a confined world from a policy, and it runs the program in there.

```sh
bailey run ./program
```

That is the whole interface. What makes it worth using is the policy model
underneath and the audit mode beside it.

## The problem

Most code on a desktop machine runs with the full authority of the user who
started it. A program you downloaded this morning can read your SSH keys, your
browser profile, your password manager's database, and your documents, and it can
send all of that anywhere, and nothing on a stock system will stop it or even
mention it.

That is a strange arrangement, and it gets stranger as the amount of code you run
without reading grows: game store downloads, release binaries, build scripts that
run as part of a dependency install, coding agents with shell access.

The mechanisms to fix this have been in the Linux kernel for years. What has been
missing is a tool that makes them ergonomic enough to use for ordinary programs.

## What bailey does

**Confines.** A resolved policy says which paths, ports, and devices a program may
reach. Everything else is denied. Enforcement is layered: Landlock for path and
port rules, seccomp to remove syscalls a normal program never needs, cgroups for
resource caps, and namespaces to rebuild the filesystem and process view so
ungranted paths are absent rather than merely refused.

**Cascades.** Config is layered the way tools like `mise` and `direnv` layer
theirs: a global default, per-directory `bailey.toml` files discovered by walking
up from the target, then an explicit per-run file. Grants accumulate, scalars are
overridden by the nearest layer, and `bailey show` prints the result along with
every file that contributed to it. As in those tools, a discovered file applies
only once you have accepted it, because the file that decides how far to open a
sandbox should not arrive with the thing being sandboxed.

**Observes.** Audit mode runs a program while recording what it opens and connects
to, using eBPF loaded by a small privileged helper. The trace is diffed against
your current policy, and the difference is what you were missing. High-risk
findings, such as network egress and credential reads, are separated from routine
ones so that "generate a profile from this trace" cannot quietly bless a program's
call home.

## What bailey is not

- **Not a container runtime.** There is no image, no layer store, no registry.
  Bailey runs the binary that is already on your disk.
- **Not a VM.** The program runs on your kernel, at native speed. The trade-off is
  that the kernel's sandboxing primitives are the ceiling on what can be enforced.
- **Not malware analysis.** Audit mode tells you what a program did during one
  run. A program that behaves while it thinks it is being watched will show you a
  clean trace.
- **Not a substitute for not running the thing.** A sandbox reduces what a
  compromise costs. It does not make hostile code safe.

## How it compares

| | bailey | bubblewrap | firejail | landrun |
| --- | --- | --- | --- | --- |
| Unprivileged | yes | yes | setuid by default | yes |
| Policy model | cascading config | command-line flags | flat profiles | command-line flags |
| Landlock | yes | no | partial | yes |
| Namespaces | yes | yes | yes | no |
| seccomp | yes | caller-supplied | yes | no |
| Resource limits | yes | no | yes | no |
| Observation mode | yes | no | no | no |

Bubblewrap is a building block, and an excellent one; it expects something else to
decide policy. Firejail has the largest profile collection and a long history,
and it is a setuid binary with a correspondingly large attack surface. Landrun is
a focused Landlock wrapper. Bailey's bet is that the policy model and the ability
to observe are what makes a sandbox get used.

## Next

- [Installation](/guide/installation)
- [Quick start](/guide/quick-start)
- [The policy model](/guide/policy-model)
