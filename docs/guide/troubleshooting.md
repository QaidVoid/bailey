# Troubleshooting

Almost every problem is the same problem: the policy is missing something. These
are the shapes it takes.

## The program does not start at all

```
bailey: io error: Permission denied (os error 13)
```

Bailey could not exec the target. The policy does not grant execute on the binary.
Add it:

```toml
[filesystem]
read = ["."]
execute = ["./program"]
```

The `untrusted` floor grants the system paths, so a binary under `/usr/bin` runs
without this. Anything in your home directory does not.

## The program starts and immediately fails

Usually a missing library, config file, or device. Confirm what the policy actually
is:

```sh
bailey show ./program
```

Check that the layer you expected is listed. The most common surprise is that the
per-directory walk starts at the **target's** directory, not your shell's, so a
`bailey.toml` in your project is not picked up when the target is an interpreter
under `/usr/bin`. Pass it explicitly with `--config`.

Then find out what it wanted:

```sh
bailey audit --save-trace trace.json ./program
```

Without the audit helper installed, `strace -f -e trace=file ./program` outside the
sandbox gives you a rougher version of the same answer.

## Landlock is not enforcing

```
bailey: warning: Landlock is not enforced by this kernel
```

The kernel has no Landlock support, or it is not enabled. Check:

```sh
grep landlock /sys/kernel/security/lsm
```

If it is absent, Landlock needs to be in the kernel's `lsm=` list. Bailey still
applies seccomp and cgroups, but the filesystem and network policy is not being
enforced.

## Isolation is skipped

```
bailey: warning: unprivileged user namespaces unavailable; running without namespace isolation
```

Unprivileged user namespaces are disabled or blocked by a security policy such as
AppArmor. The run continues with Landlock and seccomp. To check:

```sh
cat /proc/sys/user/max_user_namespaces
sysctl kernel.unprivileged_userns_clone 2>/dev/null
```

## Resource limits are skipped

```
bailey: warning: resource limits not applied: ...
```

There is no writable delegated cgroup v2 for your session. On a systemd system,
running inside a user session usually provides one; running from a bare TTY or an
unusual init may not.

## Relative paths break under `--isolate`

```
cat: ./file.txt: No such file or directory
```

The working directory is not carried into the reconstructed root, so the program
starts at `/`. Use absolute paths, or drop `--isolate`, until this is fixed. See
the [roadmap](/roadmap).

## The audit helper will not start

```
bailey: audit helper did not start; it needs CAP_BPF and CAP_PERFMON
```

Either the helper was not built, it is not where bailey looks for it, or it does
not have its capabilities. Check each:

```sh
ls -l target/release/bailey-bpf-helper
getcap target/release/bailey-bpf-helper
BAILEY_BPF_HELPER=$PWD/target/release/bailey-bpf-helper bailey audit ./program
```

## A network rule seems to do nothing

Two known causes:

- The rule has no `port`. Portless `egress_allow` entries are dropped, which turns
  the policy into a full deny. Always give a port.
- The traffic is not TCP. Only TCP connect and bind are restricted; UDP, QUIC, and
  DNS are not. See [known limitations](/security/limitations).

## A `deny` seems to do nothing

`deny` retracts a grant of exactly the same path. It does not restrict a path
nested inside a granted directory. Instead of granting a parent and denying a
child, grant the specific children you want:

```toml
[filesystem]
# Does not protect ~/.ssh:
# read = ["~"]
# deny = ["~/.ssh"]

# Does:
read = ["~/Documents", "~/Downloads"]
```
