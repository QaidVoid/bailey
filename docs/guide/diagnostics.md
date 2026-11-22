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
    systemd is not init; there is no user manager to ask
audit:
  fallback observer: available
  kernel BTF: yes
  helper: ready (/usr/local/bin/bailey-bpf-helper)
```

Each answer is followed by what it costs. "Landlock: yes" would not tell you
whether network policy is enforced, which needs ABI 4; the indented lines are the
part you can act on.

Where limits would otherwise be skipped, `doctor` asks the systemd user manager
for a delegated scope the same way a run would, and says where the delegation
came from:

```
  cgroup delegation: memory, pids, cpu (systemd user scope)
```

or the one reason a scope could not be had: no systemd, a process outside the
user manager's tree (an SSH or TTY login, or a system service), a user manager
that does not linger (`loginctl enable-linger` to opt in), a private socket
that is missing or not served by your uid, or the manager's own refusal.

`doctor` starts the audit helper to find out whether it can really load its
programs, rather than guessing from the file being present. The fallback
observer is probed the same way: the real seccomp mechanism runs in a
throwaway child, so the answer is what the kernel would do, not what a feature
column says. With the helper missing but the fallback available, the cost is
named rather than counted as a failure:

```
  helper: not found
    audit will use the fallback observer; recording is less complete than eBPF
```

and with neither observer available, audit is the one thing that refuses
instead of degrading:

```
  helper: not found
    `bailey audit` will not run: neither observer is available (...);
    build the helper with -p bailey-bpf-helper
```

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

A layer you turned off is not listed. `--no-isolate` is a choice, not a gap, and
restating your command line would bury the things that are.

A run whose cgroup came from the systemd user manager names it in the same list:

```
bailey: enforced: landlock, resource limits, systemd user scope
```

and a scope request that reached the manager and was refused adds the refusal to
the limits' reason, so a run is never quieter about why it degraded than before:

```
bailey: not enforced, resource limits: no cgroup this user may create runs in; ...; systemd user scope: the manager's answer
```

For scripts:

```sh
bailey run --quiet ./program     # no summary
bailey run --json ./program      # one line of JSON on stdout
```

```json
{"applied":["landlock","seccomp","network namespace"],"skipped":[],"exit_code":0}
```

## Shell completions and a man page

Both are generated from the command definitions, so they cannot drift from the
commands that exist:

```sh
bailey completions fish > ~/.config/fish/completions/bailey.fish
bailey completions bash > /usr/share/bash-completion/completions/bailey
bailey man > /usr/share/man/man1/bailey.1
```
