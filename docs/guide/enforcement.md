# Enforcement layers

Enforcement is four mechanisms stacked, each covering something the others
cannot. All of them are unprivileged on a modern kernel, and all of them are
cheap enough for a game.

## Landlock

Landlock is the kernel's unprivileged access-control LSM. Bailey uses it for two
things:

**Filesystem rules.** Each grant becomes a rule on a path hierarchy with a set of
access rights. Landlock is additive and deny-by-default: a program restricted by a
ruleset can reach exactly the hierarchies the ruleset names, with exactly the
rights it names.

**Network rules.** TCP connect and bind, matched by port. Available from Landlock
ABI 4 (Linux 6.7).

Rules are opened as file descriptors before the ruleset is applied, and Landlock
governs inodes rather than path strings, so enforcement survives later mount
changes such as the bind mounts that isolation performs.

### ABI negotiation

Landlock's capabilities grew across kernel versions, and a ruleset that asks for a
right the running kernel does not know about is an error. Bailey requests its
target ABI in best-effort mode, so on an older kernel it applies the strongest
subset available and reports what it could not enforce rather than failing.

A grant naming a path that does not exist is skipped rather than aborting the run.

### What Landlock does not do

It restricts access; it does not hide it. A denied path still exists, and the
program can tell it exists. If you want absence, add
[isolation](/guide/isolation).

## seccomp

A seccomp filter is installed before the program execs, denying a fixed set of
syscalls with `EPERM`:

`ptrace`, `add_key`, `request_key`, `keyctl`, `kexec_load`, `kexec_file_load`,
`init_module`, `finit_module`, `delete_module`, `bpf`, `perf_event_open`,
`userfaultfd`, `swapon`, `swapoff`, `reboot`, `mount`, `umount2`, `pivot_root`,
`setns`, `unshare`, `process_vm_readv`, `process_vm_writev`,
`open_by_handle_at`, `acct`.

These are not needed by normal applications and are common building blocks for
sandbox escape, privilege escalation, and tampering with other processes.

::: warning A denylist, not an allowlist
This is a hardening layer. A complete allowlist would be stronger, and it is also
the kind of thing that breaks a program six months later when a libc update starts
using a new syscall. Bailey chose the layer that fails open over the layer that
fails mysteriously; the access control that matters is Landlock's.
:::

`PR_SET_NO_NEW_PRIVS` is set before both seccomp and Landlock, which is what
allows an unprivileged process to restrict itself.

## cgroups

Resource limits are applied through cgroup v2. Bailey creates a child cgroup under
its own, writes the limits, and places the target in it:

| Config | cgroup file |
| --- | --- |
| `memory` | `memory.max` |
| `pids_max` | `pids.max` |
| `cpu_percent` | `cpu.max`, as a quota against a 100 ms period |

This is best-effort. On a system without a writable delegated cgroup, limits are
skipped with a warning rather than failing the run. The cgroup is removed when the
run ends.

::: warning
The target is placed in the cgroup after it is spawned, so processes it creates
before that point are not moved into it, and under `--isolate` the limits do not
reach the target at all. See [known limitations](/security/limitations).
:::

## Order of application

Inside the forked child, before exec:

1. `PR_SET_NO_NEW_PRIVS`.
2. Namespaces and the reconstructed root, if `--isolate` is on.
3. Landlock ruleset, applied against the world the program will see.
4. seccomp filter, last, so it does not block the setup it would otherwise
   prevent.

Then exec. Every layer is in place before the program's first instruction.
