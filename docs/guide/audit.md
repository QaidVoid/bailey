# Auditing a program

Writing a policy by guessing what a program needs is miserable and produces
policies that are too wide. Audit mode replaces the guessing with a recording.

```sh
bailey audit --save-trace trace.json ./program
```

## What it does

The program runs while bailey records the filesystem and network access of its
process tree, and reports everything the resolved policy does not already
grant. Two observers can do the recording, chosen with `--observer`:

- **eBPF** (the default when available): the privileged helper loads programs
  that hook the kernel below the syscalls and stream events out.
- **seccomp** (the fallback): a seccomp notification listener answers the
  target's opens, execs and connects one by one, with no helper and no
  privilege.

By default bailey starts the eBPF helper and falls back to seccomp when the
helper cannot run, saying so. See [Without the helper](#without-the-helper).

When the program exits, the trace is diffed against your current resolved
policy, and everything the policy does not already grant is reported:

```
audit: 34 ungranted access(es) observed

HIGH RISK (review before granting):
  [Connect] 93.184.216.34:443 (network egress)
  [Read] /home/you/.ssh/id_ed25519 (credential or secret path)

routine (safe to grant):
  [Read] /usr/share/mygame/assets.pak
  [Write] /home/you/.local/share/mygame/save.dat
```

The split is the point. Routine access is a list of grants to add. High-risk
access is a decision, and it is deliberately not presented as a routine addition.

## Risk classification

An ungranted access is high risk when it is:

- **Network egress.** Every outbound destination, always.
- **A credential path.** Anything containing `.ssh`, `.gnupg`, `.aws`,
  `.config/gcloud`, `.password-store`, or `.mozilla`, and files named `.netrc`,
  `.git-credentials`, `id_rsa`, or `id_ed25519`.
- **Outside the target's own directory**, unless it is a system path such as
  `/usr`, `/etc`, `/lib`, or `/dev`.

Everything else is routine.

## Audit by absolute path

```sh
bailey audit --save-trace trace.json /home/you/app/program     # not ./program
```

A path the program opens relatively is recorded as the kernel saw it, and
resolving one needs the accessing process's working directory, which is gone by
the time the recorder looks. Such findings are reported separately:

```
unresolved (relative paths whose directory could not be read):
  [Read] ./data/settings.conf
```

**A profile generated from them grants nothing**, because a path that names
nothing in particular cannot be granted. The same program audited by its
absolute path resolves the same reads and generates the grant. Launching it as
`./program` is what makes the difference, not anything about the program.

## Generating a profile

**Give it the same `-c` and `-p` the audit used.** A trace is only meaningful
against a policy: generating against a different one reconciles the same events
against different grants and reports a completely different set of findings. One
real trace gave 11 findings against the policy it was recorded under, and 1736
against the bare floor. The audit prints the matching command after writing a
trace, so copying that line is the safe move.

```sh
bailey profile generate -c ./audit.toml --trace trace.json --target ./program > bailey.toml
```

What comes out grants the difference between the trace and that policy, so it is
a supplement rather than a replacement; the header comment in the generated file
says so. `[env]` settings are never generated, because an environment variable is
not an access and nothing in a trace can imply one. If your policy sets `PATH`,
carry it across yourself.

The generated profile is deny-by-default and grants exactly the routine findings.
High-risk findings are excluded, and the count of what was excluded is reported:

```
bailey: excluded 2 high-risk access(es); pass --include-high-risk to add them
```

Anything unresolved is reported on its own line, since no flag brings it back:

```
bailey: skipped 2 access(es) whose path could not be resolved, so the profile
does not grant them.
```

Above every flag sits a never tier. `/`, your home directory and its ancestors,
and credential paths (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/gcloud` and
friends) are never written into a generated profile, whatever their risk and
whatever flags are passed. A direct finding of one is left out, and so is a
directory that coalescing would otherwise arrive at by merging its children:

```
bailey: never generated 3 access(es): /, /home/you, /home/you/.ssh/id_ed25519. \
Write any grant you still want by hand; no flag changes this.
```

Read the excluded list before reaching for `--include-high-risk`. A game that
connects to a content server and a game that connects to a stranger's server look
identical in a trace.

## What audit is for

**Tightening software you have some reason to trust.** You installed it, you
believe it is what it claims to be, and you want it to stop having access to your
home directory.

**Not vetting unknown code.** Two reasons. First, a trace shows one run: code that
only misbehaves on a certain date, or that detects it is being observed, shows you
a clean trace. Second, generating a profile from a hostile program's trace grants
exactly what that program did, including its exfiltration. That is why high-risk
findings are separated and never included silently.

::: tip Audit runs confined
The resolved policy applies during an audit, widened only by read access to the
target's own directory. A program audited under the default policy still cannot
reach your home directory or the network; the attempts are recorded instead.
`--unconfined` lifts that, and says so when it does. It needs the eBPF
observer, because the fallback observes through the very filter that
`--unconfined` would lift.
:::

## Requirements and privilege

Audit has two observers, and they need different things.

The eBPF observer needs the `bailey-bpf-helper` binary with `CAP_BPF` and
`CAP_PERFMON`, and a kernel with BTF. The seccomp observer needs only Linux
5.5 or newer, and no privilege at all. Either one is enough to audit. See
[installation](/guide/installation).

Neither observer runs the program. The unprivileged main tool spawns or
notifies, and the program never runs with elevated privilege. The helper loads
a fixed set of eBPF programs and copies bytes; that is its entire job.

## Without the helper

`--observer` selects who records:

- `auto` (the default) starts the helper; when it cannot run, records with the
  fallback and says so.
- `ebpf` uses the helper only. Without it, the audit fails.
- `seccomp` uses the fallback only, which needs Linux 5.5+ and no privilege.

Auto-falling back is loud, twice. When the helper is not found, the run prints
the reason and the cost before the target starts:

```
bailey: warning: required kernel feature unavailable: no `bailey-bpf-helper`
found. Looked at $BAILEY_BPF_HELPER, beside this executable, and on PATH.
Build it with `cargo build --release -p bailey-bpf-helper`, then grant it
capabilities with `setcap cap_bpf,cap_perfmon+ep`.; recording with the seccomp
fallback observer instead. It is less complete than eBPF, and each observed
open, exec and connect waits for bailey.
```

and after the findings, what the fallback does not see:

```
bailey: note: recorded with the seccomp fallback observer, which is less
complete than eBPF: it does not see the opens the kernel makes on the target's
behalf (the ELF and script interpreters), a racing writer can skew what was
recorded, and every observed open, exec and connect waits for bailey
```

A profile generated from such a trace carries the same note as a header
comment.

The cost is real but bounded: each observed syscall stops the target until
bailey has read what it needs out of the target's memory and continued it,
which measured about 7.5 microseconds per open, exec and connect. A workload
that opens tens of thousands of files pays it on every one; see
[benchmarks](/reference/benchmarks). `bailey doctor` reports whether the
fallback is available on this host, under `audit:`.

### What each observer sees

| | eBPF | seccomp fallback |
| --- | --- | --- |
| Opens by the target, however named | Every one, seen at `do_filp_open` | `open`, `openat`, `openat2` |
| Opens the kernel makes on the target's behalf (ELF and script interpreters) | Seen | Not seen |
| Executions | Every one, seen at `do_open_execat` | `execve` |
| Outbound connects | IPv4 and IPv6 | IPv4 and IPv6 (`AF_INET`, `AF_INET6`) |
| Relative paths | Resolved against the accessing process's working directory | Same |
| Delivery | Streamed from the kernel, off the target's critical path | Each observed syscall waits for bailey |
| Privilege | Helper with `CAP_BPF`, `CAP_PERFMON`, kernel BTF | None; Linux 5.5+ |

The fallback's own filter is what makes it work, so it cannot audit an
unconfined run: `--unconfined` needs the eBPF observer.

### Descendants left behind

A fallback audit observes while the audited target lives. If the target exits
and leaves a descendant running (a backgrounded job, a daemon it forked), that
descendant keeps the filter but has no listener behind it anymore: its next
open, exec or connect fails with `ENOSYS` ("Function not implemented"). The
run itself ends when the target exits, and does not wait for the descendant.
Record what you meant to record before backgrounding work, or leave the
background work to a supervisor that outlives the audit.

## What the trace covers

Both observers record the same event shapes. The eBPF observer sees every way
of opening a path, because its programs attach below the syscalls at
`do_filp_open` rather than to `openat` alone. The fallback sees the syscalls
its filter notifies it about. Program executions. Outbound connections, IPv4
and IPv6. Each event carries a timestamp and the path as the kernel resolved
it; a relative path is resolved against the accessing process's working
directory and marked as such, and one that could not be resolved is listed
separately rather than compared against your policy as though it were
absolute. See [What each observer sees](#what-each-observer-sees) for the
difference in coverage.

The trace records what it lost. If the kernel could not deliver an event, the
event cap was reached, or the fallback gave up on a memory read, the count and
the reason reach the trace and `profile generate` refuses to turn it into a
profile without `--accept-truncated`.

### Resource peaks

Where the run's cgroup carries the accounting, the trace also records what the
run reached: its highest memory use (`memory.peak`) and its highest task count
(`pids.peak`). `memory.peak` needs Linux 5.19 or newer, `pids.peak` needs 6.1 or
newer, and both need the run's cgroup to have the memory and pids controllers,
which is what an audit asks for where the host delegates them. A peak that is
missing from the trace is named in it, with the reason: no cgroup for the run at
all, a delegation without the controller (`the run's cgroup has no memory
controller`), or a kernel too old to keep the high-water mark (`this kernel does
not report pids.peak (needs Linux 6.1)`). An unconfined run has no cgroup of its
own and says so.

`profile generate` reads the peaks and suggests a commented-out resource block:
twice each measured peak, floored at 64 MiB of memory and 32 tasks. The block
applies nothing as written; uncommenting it is a choice you make after reading
it. Why twice, and why a floor at all:

- One run is one sample. A larger input routinely needs more than the run you
  happened to audit, and a limit set from one lucky run breaks the next one.
- `memory.peak` includes page cache, so it already leans high for a program
  that reads a lot. Doubling it errs further toward a limit that does not kill
  the program, which is the safe direction for a number you did not measure
  twice.
- The floors cover a short run whose peak says almost nothing: a shell, an
  interpreter starting, a pipeline of a few processes. `pids.peak` counts
  threads, and so does `pids_max`, so the two numbers compare directly.

A limit the policy you audited against already sets is not suggested: doubling
a limit the run already pushed against would quietly widen it. Nothing is
suggested for a trace recorded before peaks were measured; the generated file
says that instead of inventing numbers.

## How observation is scoped

Where a cgroup can be created for the run, observation is scoped to it. Cgroup
membership is inherited at fork by the kernel, so every process the target
creates is in scope from its first instruction, and nothing outside the run is
recorded.

Where no cgroup is available, the recorder follows the process tree instead,
refreshing it from `/proc`, and the run says so:

```
bailey: warning: no cgroup for this run, so observation follows the process
tree; a process that is born and reaped between passes can be missed.
```

That fallback is a race: a child that lives a couple of milliseconds usually has
its file reads recorded and its `exec` missed. `bailey doctor` reports whether
this host can give a run a cgroup.
