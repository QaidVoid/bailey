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

## Generating a profile

```sh
bailey profile generate --trace trace.json --target ./program > bailey.toml
```

The generated profile is deny-by-default and grants exactly the routine findings.
High-risk findings are excluded, and the count of what was excluded is reported:

```
bailey: excluded 2 high-risk access(es); pass --include-high-risk to add them
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

::: danger Audit currently runs the target unconfined
The resolved policy is not applied during an audit run. The program has your full
user authority while it is being recorded. Do not audit something you would not be
willing to run normally. Confining audit runs is
[proposed](/roadmap).
:::

## Requirements and privilege

Audit needs the `bailey-bpf-helper` binary with `CAP_BPF` and `CAP_PERFMON`, and a
kernel with BTF. See [installation](/guide/installation).

The helper does not run the program. The unprivileged main tool spawns it and tells
the helper which PID to observe, so the program never runs with elevated
privilege. The helper loads a fixed set of eBPF programs and copies bytes; that is
its entire job.

## What the trace covers

Today: file opens via `openat`, outbound IPv4 TCP connections, and fork
propagation so children of the target are included.

Not yet: `execve`, IPv6 destinations, other path-opening syscalls, and absolute
path resolution for relative opens. Timestamps are recorded as zero. The event
count is capped and truncation is not reported. All of that is on the
[roadmap](/roadmap); until then, read a trace as a strong hint rather than a
complete record.
