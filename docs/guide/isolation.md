# Namespace isolation

```sh
bailey run --isolate ./program
```

Landlock denies access to ungranted paths. Isolation goes further: it rebuilds the
world so those paths are not there.

## What changes

**Filesystem.** The program gets a fresh root, built on tmpfs, containing only the
paths the policy grants plus the essential system paths. Everything else is absent
from its mount table. `ls /home` does not return a permission error; it returns
nothing, because `/home` does not exist in that world.

**Processes.** A new PID namespace, with a fresh `/proc`. The program is PID 1 in
its own namespace and cannot see or signal anything outside its own tree.

**Privilege.** All of it happens inside a user namespace, so none of it needs
root. The invoking user is mapped to uid 0 inside the namespace, which is what
makes the mount operations permitted; that root is meaningless outside the
namespace.

## How it is built

Inside the pre-exec child:

1. `unshare(CLONE_NEWUSER)`, then write `uid_map` and `gid_map` with `setgroups`
   denied.
2. `unshare(CLONE_NEWNS | CLONE_NEWPID)`.
3. Fork. A PID namespace only takes effect for a child of the process that
   unshared it, so the target becomes PID 1 in the new namespace. The intermediate
   process waits for it and exits with its status.
4. Make the mount tree private, mount a tmpfs as the new root, and bind-mount each
   granted path into it.
5. Mount a fresh `/proc`.
6. `pivot_root` into the new root and detach the old one.

Landlock is applied after this, against the reconstructed root. Because Landlock
governs inodes and the granted directories are bind mounts of the same inodes,
enforcement holds on both sides of the pivot.

## The bind set

The paths bound into the new root come from the policy: every filesystem grant and
every device grant. Nested paths under an already-bound directory are skipped,
since they arrive with the parent. `/proc` is excluded, because a fresh one is
mounted inside the new PID namespace.

A grant naming a path that does not exist on the host is skipped.

## Graceful degradation

Isolation needs unprivileged user namespaces, which some distributions and
security policies disable. Bailey probes for real rather than trusting a sysctl:
it forks a throwaway child that attempts the actual setup, including the uid map
and a tmpfs mount, since a host can report user namespaces as permitted while a
policy such as AppArmor still blocks the unshare.

If the probe fails, the run continues with Landlock and seccomp only, and says so:

```
bailey: warning: unprivileged user namespaces unavailable; running without namespace isolation
```

## Current limitations

Isolation is the newest layer and the roughest.

- **The working directory is not carried in.** The program starts at `/` in the
  new root, so relative paths do not resolve. Use absolute paths under
  `--isolate`.
- **There is no `/tmp` or `/dev/shm`** unless the policy grants them. Many
  programs require both.
- **`HOME` still names the host's home directory**, which is not mounted, so
  programs that write to their home directory fail confusingly.
- **The staging directory leaks.** The new root is built at a fixed path under the
  host's `/tmp` and is not removed afterwards, so concurrent isolated runs collide.
- **The network namespace is not used**, so isolation does not currently affect
  network reachability.

All of these are on the [roadmap](/roadmap).
