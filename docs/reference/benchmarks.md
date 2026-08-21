# What it costs

Every number here comes from `scripts/overhead.py` in the repository. Run it
yourself; the interesting question is what it says on *your* kernel.

```sh
cargo build --release -p bailey
scripts/overhead.py --runs 300
```

Measured on an AMD Ryzen 7 7700, Linux 6.18, Landlock ABI 7, with user
namespaces available. 300 runs per case after 20 warmup runs, medians reported.

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
| `/bin/true`, no bailey | 0.5 ms | |
| `bailey --version` | 0.8 ms | +0.3 ms |
| Landlock + seccomp | 2.0 ms | +1.5 ms |
| + network namespace | 2.4 ms | +1.9 ms |
| + namespace isolation | 3.1 ms | +2.6 ms |

**A confined run costs about 2.6 ms to establish.** `bailey --version` is there
to separate the two halves of that: 0.3 ms is bailey's own process starting, and
the rest is the sandbox. Resolving config, checking the trust store, probing the
host for user namespaces, building the Landlock ruleset, entering the namespaces,
and rebuilding the root come to roughly 2.3 ms between them.

That is once per run, not once per operation. For a game, an editor, a shell, or
anything else you start and then use, it is not a cost you can perceive. For a
program invoked in a loop, a wrapped compiler called once per source file, it is
2.6 ms every time and it adds up.

## How much the policy grants

| Profile | Grants | Median |
| --- | --- | --- |
| `untrusted` floor | 8 paths, 6 devices | 3.2 ms |
| `desktop-app` | ~20 | 3.3 ms |
| `native-game` | ~30 | 3.4 ms |

**Grant count barely matters.** Roughly four times the paths costs 0.2 ms. Each
grant is a path opened as a file descriptor before the ruleset is applied, and
that is cheap.

This is worth stating because the opposite is a natural assumption. "Grant fewer
paths so it starts faster" is not a reason to write a narrower policy. Write a
narrower policy because it is narrower.

## Running a program that opens a lot of files

Reading 10,227 header files under `/usr/include`, which is close to the worst
case for this kind of sandbox: almost every syscall is an `open`, and `open` is
exactly where Landlock does its work.

| Case | Median | vs bare |
| --- | --- | --- |
| No bailey | 108.2 ms | |
| `--no-isolate` | 121.1 ms | +13.0 ms (+12%) |
| Isolated | 122.0 ms | +13.8 ms (+13%) |

**About 12%, or roughly 1.3 µs per file opened.** The isolation layer adds
almost nothing on top of Landlock: rebuilding the world is a startup cost, not a
running one.

Twelve percent on a workload that is nothing but path resolution is the ceiling,
not the average. A program that opens some files and then computes, or waits, or
draws, pays proportionally less, because the fraction of its time spent in `open`
is what is being taxed.

## What this means

- **Interactive programs, games, shells, editors, agents.** The cost is not
  observable. Use the sandbox.
- **Build systems and anything that opens files in bulk.** Expect low double
  digit percent on the file-heavy phases. Worth measuring on your own workload
  before deciding it is fine.
- **Something invoked thousands of times in a loop.** The 2.6 ms setup dominates.
  Confine the thing that runs the loop rather than each iteration of it, which is
  what [a confined shell](/guide/shell) is for: the policy is established once
  and inherited by everything the loop starts.

## What is not measured here

- One machine, one kernel, warm page cache. Landlock's cost depends on the depth
  of the paths being resolved and on your filesystem.
- Memory. The reconstructed root is tmpfs mounts and bind mounts; it holds no
  copies of anything.
- `bailey audit`, which is a different order of magnitude and not a mode you run
  things in normally: eBPF programs record every access and stream it to a
  helper.
- Anything under load. Every number here was taken on an idle machine.
