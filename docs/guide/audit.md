# Auditing a program

Writing a policy by guessing what a program needs is miserable and produces
policies that are too wide. Audit mode replaces the guessing with a recording.

```sh
bailey audit --save-trace trace.json ./program
```

## What it does

The program runs while eBPF programs record the filesystem and network access of
its process tree. When it exits, the trace is diffed against your current resolved
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
`--unconfined` lifts that, and says so when it does.
:::

## Requirements and privilege

Audit needs the `bailey-bpf-helper` binary with `CAP_BPF` and `CAP_PERFMON`, and a
kernel with BTF. See [installation](/guide/installation).

The helper does not run the program. The unprivileged main tool spawns it and tells
the helper which PID to observe, so the program never runs with elevated
privilege. The helper loads a fixed set of eBPF programs and copies bytes; that is
its entire job.

## What the trace covers

Every way of opening a path, because the recorder attaches below the syscalls at
`do_filp_open` rather than to `openat` alone. Program executions. Outbound
connections, IPv4 and IPv6. Each event carries a timestamp and the path as the
kernel resolved it; a relative path is resolved against the accessing process's
working directory and marked as such, and one that could not be resolved is
listed separately rather than compared against your policy as though it were
absolute.

The trace records what it lost. If the kernel could not deliver an event, or the
event cap was reached, the count reaches the trace and `profile generate` refuses
to turn it into a profile without `--accept-truncated`.

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
