# Knowing what was enforced

Every layer bailey uses can be absent or partial on a given host, and each one
degrades quietly so that a program still runs. That is the right default and it
has an obvious failure mode: a run that enforces nothing looks exactly like a run
that enforces everything. Two commands close that gap.

## Before you run anything

```sh
bailey doctor
```

```
kernel:
  landlock: ABI 7
  user namespaces: yes
  cgroup delegation: no
    resource limits will be skipped
audit:
  kernel BTF: yes
  helper: ready (/usr/local/bin/bailey-bpf-helper)
reporting:
  violation hooks: no
    the kernel records denials but bailey cannot read them
    `on_violation` hooks will not fire
```

Each answer is followed by what it costs. "Landlock: yes" would not tell you
whether network policy is enforced, which needs ABI 4; the indented lines are the
part you can act on.

`doctor` starts the audit helper to find out whether it can really load its
programs, rather than guessing from the file being present.

## After a run

```sh
bailey run ./program
```

```
bailey: enforced: landlock, seccomp, network namespace
```

The summary lists the layers that applied, and any the host took away:

```
bailey: not enforced, resource limits: Permission denied (os error 13)
```

A layer you simply did not ask for is not listed. `--isolate` being off is a
choice, not a gap, and restating your command line would bury the things that
are.

For scripts:

```sh
bailey run --quiet ./program     # no summary
bailey run --json ./program      # one line of JSON on stdout
```

```json
{"applied":["landlock","seccomp","network namespace"],"skipped":[],"exit_code":0}
```

## Violation hooks

`hooks.on_violation` is meant to run when an access is denied. Landlock denies
silently, and while the kernel records denials from ABI 7 (Linux 6.15) onwards,
reading that record needs access most systems do not give an ordinary user:
`kernel.dmesg_restrict` is commonly `1`, and the audit subsystem needs
`CAP_AUDIT_READ`.

Where bailey cannot read those records, a configured hook is reported rather than
accepted in silence:

```
bailey: warning: an `on_violation` hook is configured but cannot fire on this
host; bailey cannot read the kernel's record of denied access.
```

The hook still does not fire. Reporting it is not a fix, but it is the difference
between config that visibly does nothing and config you believe is protecting
you. See [known limitations](/security/limitations).

## Shell completions and a man page

Both are generated from the command definitions, so they cannot drift from the
commands that exist:

```sh
bailey completions fish > ~/.config/fish/completions/bailey.fish
bailey completions bash > /usr/share/bash-completion/completions/bailey
bailey man > /usr/share/man/man1/bailey.1
```
