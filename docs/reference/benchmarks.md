# What it costs

Every number here comes from `scripts/overhead.py` in the repository. Run it
yourself; the interesting question is what it says on *your* kernel.

```sh
cargo build --release -p bailey
scripts/overhead.py --runs 300
```

The tables below were measured on an AMD Ryzen 7 7700, Linux 7.2, Landlock ABI
10, with user namespaces available. 300 runs per case after 20 warmup runs,
medians reported. The egress section at the end is the exception and says so:
it needs a real download, and its numbers come from an earlier host.

::: tip The cases are interleaved, not run one after another
Timing each case to completion in turn makes the later ones look faster, because
the page cache is warmer by the time they run. Measured that way, the isolated
case came out faster than the one with *less* confinement, which is not a thing
that can be true. The harness runs one of each per round and rotates which goes
first.
:::

## Starting a program

`/bin/true`, which does nothing, so this is the fixed cost of putting a sandbox
around something.

| Case | Median | vs bare |
| --- | --- | --- |
| `/bin/true`, no bailey | 0.4 ms | |
| `bailey --version` | 0.8 ms | +0.4 ms |
| Landlock + seccomp | 2.6 ms | +2.2 ms |
| + network namespace | 3.1 ms | +2.7 ms |
| + namespace isolation | 6.6 ms | +6.2 ms |

**A confined run costs about 6 ms to establish on this host.** `bailey
--version` is there to separate the two halves of that: 0.4 ms is bailey's own
process starting, roughly 2.7 ms is Landlock, seccomp and the network
namespace, and the rest, about 3.5 ms, is namespace isolation: rebuilding the
root out of bind mounts. That last number varies more between hosts and
filesystems than any other in this table.

That is once per run, not once per operation. For a game, an editor, a shell, or
anything else you start and then use, it is not a cost you can perceive. For a
program invoked in a loop, a wrapped compiler called once per source file, it is
6 ms every time and it adds up.

## How much the policy grants

| Profile | Grants | Median |
| --- | --- | --- |
| `untrusted` floor | 8 paths, 6 devices | 6.1 ms |
| `desktop-app` | ~20 | 6.5 ms |
| `native-game` | ~30 | 6.7 ms |

**Grant count barely matters.** Nearly four times the paths costs 0.6 ms. Each
grant is a path opened as a file descriptor before the ruleset is applied, and
that is cheap.

This is worth stating because the opposite is a natural assumption. "Grant fewer
paths so it starts faster" is not a reason to write a narrower policy. Write a
narrower policy because it is narrower.

## Running a program that opens a lot of files

Reading the 2,243 header files under `/usr/include`, which is close to the worst
case for this kind of sandbox: almost every syscall is an `open`, and `open` is
exactly where Landlock does its work.

| Case | Median | vs bare |
| --- | --- | --- |
| No bailey | 24.1 ms | |
| `--no-isolate` | 28.7 ms | +4.5 ms (+19%) |
| Isolated | 34.6 ms | +10.5 ms (+44%) |

**Roughly 4.7 µs per file opened, all in.** The isolation layer adds a little
more than Landlock on this host: rebuilding the world is a startup cost, not a
running one, but every open is resolved against the reconstructed root.

A workload that is nothing but path resolution is the ceiling, not the average.
A program that opens some files and then computes, or waits, or draws, pays
proportionally less, because the fraction of its time spent in `open` is what is
being taxed.

## Observing that workload

An audit records instead of confining, with one of two observers, chosen with
`--observer`. This host has the unprivileged seccomp fallback available and no
capable helper, so the script measures the fallback and skips eBPF, saying so.
The audited policy granted `/usr/include` read, so the workload itself ran
exactly as in the table above.

| Case | Median | vs bare |
| --- | --- | --- |
| No observer | 23.8 ms | |
| seccomp fallback observer | 69.7 ms | +45.9 ms |

**About 20 µs per observed file, all in.** Each observed open stops the target
while bailey reads what it needs from the target's memory and continues it; the
wait itself measured about 7.5 µs, and resolving the path behind it brings the
per-event cost to the number above. It is paid per observed open, exec and
connect, so a program that opens tens of thousands of files pays it on every
one.

Audit is not a mode you run things in normally. The fallback is what lets an
audit happen at all on a host without the helper, and its cost is the reason
the eBPF observer exists.

## Egress through the private network namespace

A policy that allows egress is placed in a private network namespace by default
(`mode = "auto"`), which starts pasta before the target. Measured with an
egress-allowing policy, the host namespace against the private namespace,
300 interleaved rounds for startup and three interleaved rounds for a 100 MB
HTTPS download:

| Case | Median |
| --- | --- |
| Startup, host namespace | 7.4 ms |
| Startup, private namespace | 17.9 ms |
| 100 MB download, host namespace | 15.69 MB/s |
| 100 MB download, private namespace | 15.86 MB/s |

**The private namespace costs about 10.5 ms of startup**, which is pasta and
the namespace setup, and no measurable throughput on a link-bound download:
the bottleneck is the connection itself, and pasta adds nothing on it.
Automatic mode pays this only for policies that allow egress; a denied egress
keeps the namespace bailey builds anyway. `mode = "host"` restores the host's
namespace for users who prefer the startup time.

## What this means

- **Interactive programs, games, shells, editors, agents.** The cost is not
  observable. Use the sandbox.
- **Build systems and anything that opens files in bulk.** Expect low double
  digit percent on the file-heavy phases. Worth measuring on your own workload
  before deciding it is fine.
- **Something invoked thousands of times in a loop.** The ~6 ms setup dominates.
  Confine the thing that runs the loop rather than each iteration of it, which is
  what [a confined shell](/guide/shell) is for: the policy is established once
  and inherited by everything the loop starts.

## What is not measured here

- One machine, one kernel, warm page cache. Landlock's cost depends on the depth
  of the paths being resolved and on your filesystem.
- Memory. The reconstructed root is tmpfs mounts and bind mounts; it holds no
  copies of anything.
- The eBPF audit observer, which needs a helper with capabilities this host does
  not grant. The script skips the case and says so; the fallback section above
  is the number that was measurable.
- Anything under load. Every number here was taken on an idle machine.
