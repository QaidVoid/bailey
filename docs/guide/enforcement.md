# Enforcement layers

Enforcement is four mechanisms stacked, each covering something the others
cannot. All of them are unprivileged on a modern kernel, and together they cost
about 2.6 ms to establish and around 12% on a workload that does nothing but
open files. See [what it costs](/reference/benchmarks).

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
syscalls with `EPERM`. Everything it refuses is below, grouped by the reason
the refusal exists. The lists between the markers are held equal to the
filter's own named tables by a unit test, so the page cannot drift from the
code without a failing test in the same commit.

<!-- seccomp-denied:start -->

**Kernel and module control.** Loading code into the kernel, instrumenting it,
or flipping host-wide state the sandbox has no share of: modules, kernel
images, tracing and profiling, kernel keyrings, swap devices, process
accounting, reboot.

`bpf`, `perf_event_open`, `init_module`, `finit_module`, `delete_module`,
`kexec_load`, `kexec_file_load`, `add_key`, `request_key`, `keyctl`, `reboot`,
`acct`, `swapon`, `swapoff`

**Cross-process reach.** The run shares a uid with the caller, so the namespace
layer cannot separate the two. These calls read, write, or steer another
process's memory and internals, which is escape or tampering given any name of
a process outside the sandbox.

`ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`, `process_madvise`,
`process_mrelease`

**Namespace and mount control.** A new namespace or a moved mount root redraws
what the sandbox can see. The clone flags are matched on the first argument of
clone; the mount family is denied unless the policy asks for self_fuse, which
keeps the mount capability for the target's own FUSE filesystem. The others
stay denied even then.

`unshare`, `setns`, `pivot_root`, `chroot`, `CLONE_NEWNS`, `CLONE_NEWCGROUP`,
`CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWUSER`, `CLONE_NEWPID`,
`CLONE_NEWNET`, `mount`, `umount2`, `fsopen`, `fsconfig`, `fsmount`,
`move_mount`, `open_tree`, `fspick`, `mount_setattr`

**Filesystem paths Landlock cannot see.** Landlock judges a file when a path
opens. These reach the filesystem without opening a path Landlock saw: an
anonymous inode with no path at all, an open by inode handle, quota control on
a mounted filesystem, and the subvolume ioctls of the two filesystems bailey
knows, named after the filesystem rather than the request.

`memfd_create`, `open_by_handle_at`, `quotactl`, `btrfs`, `bcachefs`

**Descriptor and ring bypasses.** Landlock checks a descriptor when it is
opened, not when it is duplicated, and a ring issues ioctls without ever
passing the ioctl rules below.

`pidfd_getfd`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`

**Terminal injection.** The terminal is shared with the caller's shell, and
these two requests put bytes into its input queue as though the user had typed
them.

`TIOCSTI`, `TIOCLINUX`

**Memory pinning.** Pinning every page or building fault handlers shapes
memory in ways the kernel bounds only by host-wide limits, and both are
standard building blocks of kernel exploits.

`userfaultfd`, `mlockall`

<!-- seccomp-denied:end -->

Ordinary applications need none of these, and each group above is what a
sandbox escape or an attack on the caller is built from.

The ioctl syscall is not denied whole, since ordinary programs use it
constantly. Only the two subvolume families are refused, matched on the
request's type byte. Landlock mediates the path operations that create a file,
but not the ioctls with which btrfs or bcachefs creates a subvolume or
snapshot, so on such a filesystem those would otherwise plant a directory of
files in any host directory the target may read. FICLONE shares the btrfs type
byte, so a reflink copy is refused with it and falls back to a full copy.

A syscall number only means something for the architecture it was made on, and
the filter is written for the native one. A denied syscall reached through a
foreign ABI arrives as a different number and would match no rule, so the
filter first checks the architecture and refuses anything that is not native.
On x86_64 that means the i386 `int 0x80` entry and the x32 ABI are both
refused, since either would otherwise carry a denied syscall past the rules
under a number they never named. A 32-bit program that relies on those entry
points does not run here.

Two socket kinds are refused in the same prologue, because Landlock's TCP port
rules do not reach them. Landlock's network hooks act only on sockets the
kernel classifies as TCP, and an `IPPROTO_MPTCP` socket is not one of those
although it falls back to plain TCP on the wire, and an `AF_SMC` socket falls
back through a socket the kernel opens without the caller's Landlock domain.
Either one would connect or bind any port a TCP socket was refused for. The
filter refuses them at `socket()`, on every address family, with the errno a
kernel without the feature returns: `ENOPROTOOPT` for MPTCP, which is what
`net.mptcp.enabled = 0` gives, and `EAFNOSUPPORT` for SMC. MPTCP-aware clients
read that as a kernel without MPTCP and fall back to plain TCP, where the
Landlock rules hold. The refusals apply in every network mode, including
denied egress where the namespace already makes them moot, so the filter has
one shape regardless of policy.

`clone3` is refused in the same prologue, with `ENOSYS` instead of `EPERM`. The
flags that turn a `clone` into a namespace creator sit in a structure the filter
cannot read, so `clone3` is refused whole, and `ENOSYS` is the error that makes
glibc treat it as unimplemented here and retry with `clone`, whose flags the
filter does read. Answering `EPERM` would end the attempt instead of redirecting
it, and a thread pool that gets `EPERM` treats it as fatal. musl never calls
`clone3`, and Go and Rust's standard library use `clone` already, so ordinary
thread and process creation is unaffected everywhere. What the filter cannot
see past, the kernel does: every run that builds a user namespace creates a
guard namespace first, whose limit on namespaces created beneath it is spent by
the run's own namespace, leaving none for the program.

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

The cgroup is created before the target is spawned, and the target joins it
itself just before exec, so membership is inherited by every process it goes on
to create, with and without `--isolate`. The cgroup is removed when the run ends.

### It needs a delegated cgroup

The run's cgroup is created as a *sibling* of bailey's own, not a child of it.
The kernel refuses to enable a controller on a cgroup that contains processes,
and bailey's own cgroup always contains bailey, so a child of it could never
receive `memory.max` to write.

Bailey therefore walks up from its own cgroup to the nearest ancestor that it may
create directories in and whose children receive the controller files. That is
the shape a session manager produces when it delegates a subtree: a directory you
own, with the controllers enabled, and your processes in a leaf of it.

```
/sys/fs/cgroup/bailey/          # yours, controllers delegated, no processes
    shell/                      # your shell, and bailey
    bailey.12345/               # the run's limits
```

Where the search picks the wrong one, name it explicitly:

```sh
export BAILEY_CGROUP_ROOT=/sys/fs/cgroup/bailey
```

Where the search finds nothing at all, and no override names one, a run with
limits asks the systemd user manager for a transient scope with `Delegate=yes`
and moves bailey into a leaf of it, so the same walk then finds the scope. The
request goes over the manager's private socket, and bailey is identified to the
manager by the connection's peer credentials, never by a process id: a pid is
only meaningful in a PID namespace, so nothing else can be moved in bailey's
place.

The request is only made where a scope can be had and trusted to last:

- systemd must be init. Other inits, elogind included, are not asked, and
  `BAILEY_CGROUP_ROOT` remains the way to name a cgroup on them.
- Your user must linger (`loginctl enable-linger`). A manager that does not
  linger stops at your last logout, and a scope it granted would take a
  detached run (`tmux`, `nohup`) down with it that survives logout today.
- The private socket must be owned by your uid and served by your uid, which
  the kernel confirms before anything is sent.

A run that gets a scope leaves the logind session: `loginctl` and polkit no
longer see bailey or the target as part of it. Inside an outer bailey sandbox,
or with `BAILEY_CGROUP_ROOT` set, no request is made at all. Anything that goes
wrong leaves the run as it was before, with the manager's reason, if one was
received, appended to the summary.

This is best-effort throughout. Without such a cgroup, limits are skipped and the
run's summary says so rather than failing the run. `bailey doctor` answers the
same question before you start.

Two of them hold without any cgroup, because they are rlimits. `file_max` is
`RLIMIT_FSIZE`: one file's size, on every host, with or without a cgroup.
`open_files` is `RLIMIT_NOFILE`: the largest descriptor number a process may
newly open. It is inherited by every process the target starts, a target that
cannot live within it fails with `EMFILE` at whatever it was doing, and where
the policy asks for more than the caller already has, the caller's lower limits
stand, because an unprivileged run cannot grant what the caller did not have.

One of them has a fallback. Where no cgroup was delegated, `pids_max` is applied
as `RLIMIT_NPROC` instead, and the summary reports a `process limit`. The count
behind that rlimit is kept per user within a user namespace, so it only means the
policy's number on a run that makes one of its own, which is every run under
`--isolate` and every run whose policy denies egress. A run that stays in the
caller's namespace would be counting the caller's own processes, so the fallback
is not applied there and the limit is reported skipped as before.

`memory` has a narrower one, offered for the same reason and named for exactly
what it is. A policy may set `address_space`, which is applied as `RLIMIT_AS`
only where `memory` is set and no cgroup could carry it, and reported as
`per-process address space` while the memory limit is still reported as skipped.
`RLIMIT_AS` bounds address space rather than resident memory: it counts
reservations, misses tmpfs pages once unmapped, and never sees page cache or
kernel memory, and it bounds one process rather than the run. That is why it is
opt-in with its own number and never derived from `memory`: runtimes reserve
address ranges far beyond what they touch, so the same number for both would
make every JVM fail where `memory = "4GiB"` meant to allow a 4 GiB heap. Set it
well above the target's largest reservation, and treat it as the better-than-
nothing bound for the runaway case, not as the memory limit it is not.
`cpu_percent` has no equivalent: `RLIMIT_CPU` bounds total CPU seconds rather
than a share.

## Order of application

Inside the forked child, before exec:

1. `PR_SET_NO_NEW_PRIVS`.
2. Joining the run's cgroup, while the host's cgroup filesystem is still
   reachable.
3. Namespaces and the reconstructed root, if `--isolate` is on.
4. Landlock ruleset, applied against the world the program will see.
5. The target's own rlimits, `open_files` and the address-space fallback where
   it applies, after the setup steps that open descriptors and map memory.
6. seccomp filter, last, so it does not block the setup it would otherwise
   prevent.

Then exec. Every layer is in place before the program's first instruction.
