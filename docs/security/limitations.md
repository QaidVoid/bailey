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

### A bound port is reachable only from inside the sandbox

A policy that denies egress keeps its own network namespace even when it binds a
port. Loopback is up in there, so the service can be reached by anything else in
the same sandbox, and the ports the policy binds are also the ports it may
connect to, since a port bound and then not connectable is a port bound for
nothing.

Nothing outside can reach it. Publishing the port would mean using the host's
network namespace, and that hands the run UDP, QUIC, DNS and ICMP as well, none
of which Landlock gates: the port would be served at the cost of everything else
being unrestricted. A policy that needs the port reachable from outside should
allow egress, which keeps the host's namespace and says so in the run summary.

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

## Desktop relays and mounts

### A relayed Wayland socket is your compositor

The `[[socket]]` relay keeps the rest of the runtime directory out of reach,
ssh-agent included, but a client that reaches the compositor through the relay
can screenshot and inject input unless the compositor itself restricts it. That
is a property of the Wayland protocol, not of the relay. Relay Wayland to
programs you would let use your desktop; prefer the `url-open` broker when the
only thing a program needs from your desktop is a browser.

### A FUSE mount command runs before the sandbox, as the caller

A `[[fuse]]` entry runs its command with `sh -c` in the bailey process, before
any confinement exists, exactly where a `pre_launch` hook runs. Trusting a
config with a `[[fuse]]` entry is trusting whoever can write it to run programs
as you. The target never holds the mount syscalls: the seccomp filter denies
them and the capability drop leaves nothing to mount with.

### A hard-hung mount can hold the run at startup

A mount whose server has gone away answers reads with an error once the
connection is torn down, and hangs before that. Bailey refuses a run whose
granted path cannot be read, naming the path and the error, but it cannot
answer for the kernel before the kernel does: a mount that hangs `stat` hangs
the run the same way it would hang any program touching it.

### The URL broker opens only http and https

The `url-open` relay validates the scheme, refuses anything else, and hands the
URL to `xdg-open` as a single argument, never through a shell. What it grants
is the browser's dispatcher, not the browser: a page can still be anything the
web can be, and `xdg-open` is looked up in a trusted location and refused if
someone other than its owner can write it.

### A forwarded port is a door with one number on it

The `[[forward]]` entry carries one host TCP port onto the sandbox's loopback.
What dials it reaches the host service with the host service's own powers, so
forward a service whose powers you would give the target directly. The forward
is loopback IPv4 only, needs the network namespace that isolation provides, and
carries no egress with it: everything else in the namespace stays refused. Each
forwarded port serves its connections one at a time, so a many-client port
queues rather than multiplexes.

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

### `self_fuse` trades Landlock for mount power

`self_fuse = true` keeps the mount syscalls and `CAP_SYS_ADMIN` inside the
run's user namespace so the target can mount its own FUSE filesystems. This
kernel will not let both stand: a process under a Landlock domain is refused
every mount of a new filesystem, and a FUSE mount is a new filesystem. Binding
and remounting what is already there stays allowed, but `mount("tmpfs")` and
`mount("fuse")` return `EPERM` the moment a ruleset is applied, whichever
rights the ruleset handles, and the kernel offers no right that opts back in.

A `self_fuse` run therefore carries no Landlock ruleset. What still confines
it is the shape of the root: only granted subtrees are bound in, a `deny` no
grant reaches is simply not there, and the user namespace maps only the
target's own uid, so DAC still stops it reading files its user could not read
anyway. What weakens is everything that depended on a mount staying put:

- A `read_only` island is a read-only bind the target can remount writable,
  which would let it write a path the policy only let it read. The config
  refuses `read_only` alongside `self_fuse` rather than enforce it loosely.
- A `deny` beneath a grant is an empty mount the target could remove, so the
  config refuses that combination too. A `deny` no grant reaches costs
  nothing and stays.
- The read-only remounts bailey adds on its own, such as the metadata
  protection on read-granted paths, stay in place but are advisory: the
  target has the power to lift them, and only the target's own good behavior
  says it will not.

The pid namespace, the network namespace, the seccomp filter (which still
denies `pivot_root`, `setns`, and `unshare`), and the capability drop of
everything but `CAP_SYS_ADMIN` all hold in a `self_fuse` run. It is a real
confinement, measured by what the root contains rather than by what the
kernel promises to refuse.

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
