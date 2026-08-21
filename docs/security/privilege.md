# Privilege model

Bailey's design rule: the sandbox must not require more privilege than the thing
it is confining.

## Enforcement is unprivileged

Running a program under enforcement needs no root, no setuid binary, and no
daemon. Every mechanism it uses is available to an ordinary user on a modern
kernel:

- **Landlock** is designed for unprivileged use. A process may always restrict
  itself further.
- **seccomp** filters can be installed by an unprivileged process once
  `PR_SET_NO_NEW_PRIVS` is set, which bailey does first.
- **Namespaces** are entered inside a user namespace, which unprivileged users can
  create. The mount and `pivot_root` operations that follow are permitted because
  the process is root *inside* that namespace, which confers nothing outside it.
- **cgroups** are written under the session's own delegated cgroup, if there is
  one. Where there is not, limits are skipped rather than escalating.

This matters beyond convenience. A setuid sandbox, which is how firejail works by
default, is a privileged binary that untrusted input flows into: a bug in it is a
local root exploit. Bailey has no such binary in the enforcement path.

## Audit needs capabilities, in a separate binary

Loading eBPF programs requires `CAP_BPF` and `CAP_PERFMON`. Those live on
`bailey-bpf-helper`, a small separate binary whose whole job is to load a fixed
set of programs and copy bytes from a ring buffer to its stdout.

```sh
sudo setcap cap_bpf,cap_perfmon+ep ./target/release/bailey-bpf-helper
```

The design constraints on that binary:

- **The main tool has no eBPF code and no capabilities.** It cannot load programs
  even if compromised.
- **The helper never spawns the target.** The unprivileged main tool runs the
  program and tells the helper which PID to watch, so the audited program never
  inherits elevated privilege.
- **The helper's interface is two pipes.** A greeting with a protocol version
  out, the PID and cgroup id to observe in, an acknowledgement and then framed
  records out, EOF to stop. There is no path by which the target influences what
  the helper loads.
- **The privilege is per-run.** The helper starts with the audit, exits with it,
  and holds nothing between runs. There is no daemon with standing privilege.

If you would rather not use file capabilities at all, run the audit under `sudo`.
The trade-off is that the whole audit invocation is then privileged.

## Why enforcement does not use eBPF

BPF-LSM can enforce, not just observe. Bailey deliberately does not use it for
enforcement:

- It requires `CONFIG_BPF_LSM=y` and `bpf` in the boot `lsm=` list, which a user
  cannot change without a reboot and some distributions omit.
- It requires the capabilities above for every run, not just for audit.

Keeping enforcement on Landlock keeps the common path unprivileged and portable,
and confines the privilege requirement and the kernel-config dependency to the
audit path, which is optional.

## What runs with your authority

Some things deliberately do not run in the sandbox:

- **Hook commands** (`pre_launch`, `post_exit`) run as you, outside the sandbox.
  They are your code.
- **Bailey itself** before it forks. It reads your config, resolves the policy, and
  sets up the sandbox with your authority, then drops into the confined world
  before exec.

## Trust boundaries

| Component | Privilege | Trusted with |
| --- | --- | --- |
| `bailey` | Yours | Reading config, building the sandbox, spawning the target |
| `bailey-bpf-helper` | `CAP_BPF`, `CAP_PERFMON` | Loading a fixed program set, streaming records |
| The target | Yours, minus the policy | Nothing |
| Hook commands | Yours | Whatever you wrote them to do |
