# Known limitations

Every item here has been verified against the current implementation. A sandbox
that overstates itself is worse than one that does not exist, because you make
different decisions.

## Network

### A partial egress allowance restricts TCP only

When the policy allows any egress, or binds a port, the target stays in the
host's network namespace and only Landlock's TCP port rules apply. UDP, QUIC,
DNS, and ICMP are unrestricted in that mode, and the run says so:

```
bailey: warning: outbound access is restricted by TCP port only;
UDP, QUIC, and DNS are not restricted
```

A full `egress = "deny"`, which is the default, does not have this problem: the
target gets its own network namespace with no route off the host, so every
protocol fails.

### Host and CIDR rules are advisory

`egress_allow = [{ host = "example.com", port = 443 }]` enforces the port and
ignores the host. Bailey warns when you set a host other than `*`.

## Filesystem

### A nested `deny` needs `--isolate`

```toml
[filesystem]
read = ["."]
deny = ["./secret"]
```

Under `--isolate` this is enforced: `./secret` becomes an empty read-only
filesystem, so there is nothing to read and nothing can be written. Without
`--isolate`, `./secret/key` is still readable, and the run says so:

```
bailey: warning: `/work/secret` is denied but nested under a granted path,
and is not enforced without `--isolate`.
```

The reason is structural. Landlock resolves access by walking up from the
accessed file, and any ancestor rule that grants the access allows it, so a
narrower rule on a subpath cannot take rights away; a rule with no access rights
at all is rejected by the kernel. Taking access away from a granted hierarchy is
only possible by covering the path over, which is what the mount namespace does.

For runs without isolation, grant the specific subdirectories you want instead of
granting the parent and carving out exceptions.

## Environment

### A passed variable is passed in full

The environment is deny-by-default, but `pass` forwards a variable verbatim. If
you pass a variable that holds a credential, that credential is in the sandbox.
Bailey does not inspect values.

## Isolation

### A private /tmp is skipped when the policy grants anything under /tmp

Using the private `/tmp` means granting it read-write, and Landlock rights only
add, so that grant would widen a narrower grant on a path that happens to live
under `/tmp`. Bailey leaves `/tmp` alone in that case rather than silently
widening access.

### Isolation depends on user namespaces

Both the reconstructed root and the network namespace need unprivileged user
namespaces. Where a host disables them, the run falls back to Landlock and
seccomp and reports the downgrade, which for the network means TCP-only
restriction.

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
