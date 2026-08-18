# Known limitations

Every item here has been verified against the current implementation. A sandbox
that overstates itself is worse than one that does not exist, because you make
different decisions.

## Network

### `egress = "deny"` blocks TCP only

Landlock's network rules cover TCP connect and bind. UDP, QUIC, DNS, ICMP, and
raw sockets are unaffected.

```sh
# Under the default deny-all-egress policy:
# TCP connect to 1.1.1.1:443 -> blocked
# UDP datagram to 8.8.8.8:53 -> delivered
```

A program that wants to send data off the machine can. Planned fix: run the target
in a network namespace with no route when the policy denies egress.

### Host and CIDR rules are advisory

`egress_allow = [{ host = "example.com", port = 443 }]` enforces the port and
ignores the host. Bailey warns when you set a host other than `*`.

## Filesystem

### A nested `deny` is not enforced

`deny` retracts a grant of the same path, and records a denial. Enforcement does
not yet honor a denial that sits inside a directory another layer granted.

```toml
[filesystem]
read = ["."]
deny = ["./secret"]
```

Under this policy, `./secret/key` is still readable. Verified.

The cause is structural rather than an oversight. Landlock resolves access by
walking up from the accessed file, and any ancestor rule that grants the access
allows it, so a narrower rule on a subpath cannot take rights away. A rule with
no access rights at all is rejected by the kernel. Subtraction is only possible
by stacking a second ruleset, or by not granting the parent in the first place.

Bailey warns on every run where a nested denial applies, and marks it
`NOT ENFORCED` in `bailey show`, so the policy is never quietly weaker than it
reads. Until enforcement lands, grant the specific subdirectories you want
instead of granting the parent and carving out exceptions.

## Environment

### The whole environment is inherited

Every variable in your shell reaches the target, including `SSH_AUTH_SOCK`,
`GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, and `HOME`. Verified. Until an
environment policy lands, clear it yourself:

```sh
env -i HOME="$HOME" PATH=/usr/bin:/bin TERM="$TERM" bailey run ./program
```

## Isolation

### The working directory is not carried in

Under `--isolate` the target starts at `/` in the reconstructed root, so relative
paths do not resolve. Verified. Use absolute paths.

### No `/tmp` or `/dev/shm`

Neither is mounted in the reconstructed root unless the policy grants them. Many
programs require both.

### `HOME` points at an unmounted path

`HOME` still names the host's home directory, which is not in the new root, so
programs that write to their home directory fail in confusing ways.

### The staging directory leaks and collides

The new root is built at a fixed path under the host's `/tmp`, named by the PID
inside the new namespace, which is always 1. It is not removed after the run.
Concurrent isolated runs collide.

### No network namespace

Isolation does not currently affect network reachability, including access to
host abstract UNIX sockets such as X11 and D-Bus.

## Resource limits

### Skipped without a delegated cgroup

Limits need a writable cgroup v2 for your session. Where there is none they are
skipped with a warning rather than failing the run, so a policy that sets a
memory cap may not be applying one. The warning is the only signal.

## Audit

### The target runs unconfined

The resolved policy is not applied during an audit run. Do not audit code you
would not be willing to run normally.

### Observation starts late

The target is spawned first and the observation scope is seeded afterwards, so
early access is missed, including the dynamic linker's library search.

### Coverage gaps

Only `openat` is observed for filesystem access, so other path-opening syscalls
and `execve` do not appear. Only IPv4 destinations are recorded. Paths are
recorded as passed rather than resolved, so relative opens do not match absolute
policy grants. Timestamps are always zero.

### Silent truncation

The trace is capped at 200,000 events. Beyond that, events are dropped with no
marker, so a generated profile can be incomplete without saying so.

### x86_64 only

The eBPF programs use hard-coded x86_64 tracepoint field offsets, so audit results
on other architectures are wrong rather than unavailable.

## Other

### `on_violation` hooks never fire

Landlock denies silently and bailey has no denial signal, so the hook has no
trigger. The config key is accepted anyway.

### The seccomp filter is a denylist

It removes a fixed set of dangerous syscalls rather than allowing a known-good
set. It is a hardening layer, not the access control.

---

Fixes for all of the above are on the [roadmap](/roadmap).
