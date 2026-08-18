# Kernel requirements

Bailey adapts to what the running kernel offers. Nothing here is a hard
requirement for the tool to run; each missing feature removes a layer, and bailey
reports what it could not enforce.

## Summary

| Feature | Needed for | Since | Without it |
| --- | --- | --- | --- |
| Landlock | Filesystem policy | 5.13 | No filesystem or network enforcement, warned |
| Landlock ABI 4 | Network rules | 6.7 | Network policy not enforced |
| Landlock ABI 5 | Device ioctl restrictions | 6.10 | That subset is skipped |
| Unprivileged user namespaces | `--isolate` | long-standing, often disabled | Falls back to Landlock and seccomp, warned |
| cgroup v2 with delegation | Resource limits | long-standing | Limits skipped, warned |
| seccomp filters | Syscall denylist | long-standing | Run fails to establish |
| BTF (`/sys/kernel/btf/vmlinux`) | Audit backend | 5.x with `CONFIG_DEBUG_INFO_BTF` | Audit unavailable |

## Checking

```sh
# Landlock active?
grep landlock /sys/kernel/security/lsm

# Unprivileged user namespaces?
cat /proc/sys/user/max_user_namespaces
sysctl kernel.unprivileged_userns_clone 2>/dev/null

# cgroup v2?
stat -fc %T /sys/fs/cgroup

# BTF?
test -e /sys/kernel/btf/vmlinux && echo yes
```

## Landlock ABI negotiation

Landlock's access rights grew across versions, and asking for a right the kernel
does not know is an error rather than a no-op. Bailey requests its target ABI in
best-effort mode: the kernel applies the rights it knows and the rest are dropped,
and bailey reports what was not enforced.

The practical consequence is that on a kernel older than 6.7 your network policy
is not applied even though the config is valid. `bailey show` prints the policy as
written; it does not tell you what the kernel will do with it.

## Distribution notes

**Unprivileged user namespaces** are the most commonly disabled feature. Debian
and Ubuntu have shipped restrictions at various points, and AppArmor profiles can
block the `unshare` even when the sysctl permits it. Bailey probes by attempting
the real setup in a throwaway child rather than reading the sysctl, so its
report reflects what will actually happen.

**BTF** requires `CONFIG_DEBUG_INFO_BTF=y`. Most mainstream distribution kernels
enable it; minimal or custom kernels often do not.

**Landlock** must be in the kernel's `lsm=` boot parameter list. Most
distributions include it by default on kernels that support it.

## Architecture

x86_64 and aarch64 are supported for the seccomp filter. Other architectures fail
to build the filter and therefore fail to establish a sandbox.

The eBPF audit programs currently use x86_64 tracepoint field offsets, so audit
results on aarch64 are not trustworthy. Making argument access architecture
independent is on the [roadmap](/roadmap).
