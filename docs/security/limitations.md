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

### A short-lived child can be missed

Observation is scoped to the target's process tree, and membership is refreshed
by reading `/proc` every 200 microseconds. A process that is born and reaped
inside that window is never added, so its access does not appear. In practice a
child's file reads are captured and its `exec` often is not.

Exact scoping needs either a delegated cgroup, whose membership children inherit,
or a PID namespace. Neither is wired up yet.

### A trace shows one run

A program that behaves while it thinks it is being watched, or that only
misbehaves on a certain date, produces a clean trace. Audit tightens software you
have some reason to trust; it does not vet unknown code.

## Other

### `on_violation` hooks do not fire on most hosts

Landlock denies silently. The kernel records denials from ABI 7 (Linux 6.15), but
reading them needs a readable kernel log or `CAP_AUDIT_READ`, which most systems
do not give an ordinary user. Bailey now reports a configured hook that cannot
fire, and `bailey doctor` says whether this host can produce the signal, but the
hook still does not run where the record is unreadable.

### The seccomp filter is a denylist

It removes a fixed set of dangerous syscalls rather than allowing a known-good
set. It is a hardening layer, not the access control.

---

Fixes for all of the above are on the [roadmap](/roadmap).
