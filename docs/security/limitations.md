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

The same mode leaves the host's loopback reachable, since the target shares your
network namespace.

A full `egress = "deny"`, which is the default, has neither problem: the target
gets its own network namespace with no route off the host and no access to your
loopback, so every protocol fails.

### UNIX sockets are not part of the egress policy

The ruleset is written against Landlock ABI 6. A right the ruleset does not
handle is not restricted at all, so the rights added after that ABI are invisible
to a run however new the kernel is. The one that matters here is the check on
connecting to a pathname UNIX socket, which arrived in ABI 9.

So "egress denied" is about TCP. A socket in a directory the policy grants for
writing can still be connected to, and the profiles that need a session bus
grant the whole of `${XDG_RUNTIME_DIR}`, which is where the session bus,
`ssh-agent`, `gpg-agent` and PipeWire all keep theirs. Raising the ABI alone
would start refusing those connects and break the profiles that rely on them:
what the grant is really saying is "let this program create its own socket
here", and separating that from "let it connect to every socket already here"
needs a policy of its own rather than a wider right.

Where that matters, grant a narrower directory than the whole runtime directory.

### Binding a port costs the network namespace

The isolated network namespace is chosen only for a policy that denies egress
and binds nothing. A policy that denies egress but binds a port keeps the host's
network namespace, because a port bound inside a private one would not be
reachable from the host, which is the point of binding it. Landlock then gates
TCP ports and nothing else, so UDP, QUIC, DNS and ICMP are unrestricted for that
run. The summary says `landlock only (TCP ports; other protocols unrestricted)`;
what it does not say is that a `bind_ports` entry is what asked for it.

### Host and CIDR rules are advisory

`egress_allow = [{ host = "example.com", port = 443 }]` enforces the port and
ignores the host. Bailey warns when you set a host other than `*`.

## Filesystem

### Taking access away needs the isolation layer

```toml
[filesystem]
read = ["."]
deny = ["./secret"]
read_only = ["./versions"]
```

With isolation, which is the default, both are enforced: `./secret` becomes an
empty read-only filesystem, and `./versions` is remounted read-only. Under
`--no-isolate` neither is, and the run says so before it starts:

```
bailey: warning: `/work/secret` is denied but nested under a granted path, and
is not enforced without namespace isolation. Drop `--no-isolate`, or grant the
specific subdirectories you need instead of granting the parent.
```

The reason is structural. Landlock resolves access by walking up from the
accessed file, and any ancestor rule that grants the access allows it, so a
narrower rule on a subpath cannot take rights away; a rule with no access rights
at all is rejected by the kernel. Taking access away from a granted hierarchy is
only possible by covering the path over or remounting it, which is what the mount
namespace does.

For runs without isolation, grant the specific subdirectories you want instead of
granting the parent and carving out exceptions.

### A read grant still allows metadata to be changed without isolation

Landlock governs the content of a file and the shape of a directory. It does not
govern a file's mode, its owner, its timestamps, or its extended attributes, so
`chmod`, `chown`, `utimensat` and `setxattr` are not rights it can withhold.
Measured with Landlock alone on a read-granted path: creating, writing,
deleting, linking and binding are all refused, and those four return `OK`.

The isolation layer closes this. A path the policy grants read and nothing else,
with no writable grant overlapping it in either direction, is remounted
read-only, and the kernel then refuses the metadata change before it looks at
ownership, so `CAP_FOWNER` inside the user namespace does not help. A path the
policy makes writable keeps the metadata rights that come with writing, which is
what the policy asked for.

Under `--no-isolate` the gap is open again, and the run says namespace isolation
is not enforced. seccomp cannot close it: it matches syscall numbers and
register values, not resolved paths, so it cannot tell `chmod` on a granted path
from `chmod` on a path outside one, and a target that may not `chmod` inside its
own workspace is not a working sandbox. The boundary belongs in Landlock, which
does not yet express it.

Grant read where a target genuinely needs to read. A path granted for the sake
of one file inside it exposes the metadata of everything else in it.

## Environment

### A deny does not cover another name for the same file

`deny` takes a path out of the granted set and, where the denied path sits under
a granted one, covers it in the mount namespace. Both work on paths, while the
mechanisms underneath do not: Landlock rules apply to inodes reached by walking
from a granted directory, and a mount covers one location rather than an inode.

So a hard link to a denied file, made anywhere under a granted directory before
the run, is still readable, and so is a bind mount of a denied directory placed
under a granted path. Neither needs the target to do anything; the aliases exist
already. A target cannot create such a link to a file it could not already read,
so this limits what `deny` means rather than opening a way in.

Where a file must be withheld and may have other names, do not grant the
directory that holds them.

### Watches follow whatever is visible

`inotify_add_watch` is not an access Landlock understands, and the filter does
not deny it. Anything the target can reach by path can be watched: under
isolation that is what the policy put in the reconstructed root, and without it
every path the user can traverse. A watch reports names, sizes and timing rather
than contents, and is an aid to winning a race. `fanotify` needs a capability in
the initial namespace and is out of reach.

### Hooks run before the sandbox, as the caller

`pre-launch` and `post-exit` hooks run with `sh -c` in the bailey process,
before any layer of confinement is built, with the caller's environment. A
trusted config is therefore more than a policy: it is also the commands it
names, run unconfined as the user. Trusting a config that sets hooks is
trusting whoever can write it to run programs as you.

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

Limits need a cgroup you may create children in, with the controllers delegated
to it. A session manager that does not hand your user such a subtree leaves
limits unenforceable: they are skipped and the run's summary says so, rather than
failing the run. `bailey doctor` reports it, and `BAILEY_CGROUP_ROOT` names one
explicitly. See [enforcement layers](/guide/enforcement).

## Audit

### A short-lived child can be missed without a cgroup

Where the run gets a cgroup, scoping is exact: membership is inherited at fork,
so nothing can be missed. Where no cgroup can be created, observation falls back
to following the process tree through `/proc`, and a process born and reaped
between two passes is never added. In practice such a child's file reads are
captured and its `exec` is not.

The run warns when it is on the fallback, and `bailey doctor` reports whether
this host can provide a cgroup.

### A trace shows one run

A program that behaves while it thinks it is being watched, or that only
misbehaves on a certain date, produces a clean trace. Audit tightens software you
have some reason to trust; it does not vet unknown code.

## Other

### A denied access is not reported

Landlock denies silently, and bailey has no way to see a denial: it needs the
kernel's audit subsystem enabled at boot (`audit=1`) plus permission to read its
records, and a normal desktop provides neither. A program that fails under
enforcement gives you its own error and nothing more.

`bailey audit` is the answer to "what was it trying to reach", and it records
every access rather than only the denied ones.

### The seccomp filter is a denylist

It removes a fixed set of dangerous syscalls rather than allowing a known-good
set. It is a hardening layer, not the access control.

---

None of these are pending work with a fix on the way. Each is either a property
of the mechanisms bailey builds on, or a decision recorded in
[project status](/roadmap).
