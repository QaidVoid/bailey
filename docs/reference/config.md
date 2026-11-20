# Configuration reference

TOML. Unknown keys are rejected, so a typo is an error rather than a silently
ignored rule.

## Discovery order

Lowest precedence first:

1. The implicit grant of the target executable, read and execute.
2. Profile: the `untrusted` floor, plus the profile named by `--profile`, or one
   that claims this target with `applies_to`. A profile is either bundled or a
   file in `$XDG_CONFIG_HOME/bailey/profiles/`.
3. `$XDG_CONFIG_HOME/bailey/config.toml`, or `~/.config/bailey/config.toml`.
4. Every `bailey.toml` found walking up from the target's directory and from the
   working directory, ordered by path depth, shallowest first. A file found by
   both walks contributes once; at equal depth the working directory wins. Each
   applies only once trusted with `bailey trust <file>`; see
   [trusting a config](/guide/trusting-a-config).
5. The file given to `--config`.

Layers 1 to 3 and layer 5 need no trust record: each is a file you wrote or a
path you typed. Only the discovered files in layer 4 are gated.

## `[filesystem]`

| Key | Type | Description |
| --- | --- | --- |
| `read` | list of paths | Grant read on each path hierarchy |
| `write` | list of paths | Grant write on each path hierarchy |
| `execute` | list of paths | Grant execute on each path hierarchy |
| `connect` | list of paths | Permit connecting to a pathname UNIX socket at each path |
| `deny` | list of paths | Retract a grant of the same path and record the path as denied |
| `read_only` | list of paths | Make a path read-only inside a writable grant. Needs the isolation layer |
| `reset` | bool | Clear all filesystem grants from lower layers before applying this one |

Rights for the same path combine across layers. A grant on a directory covers
everything beneath it.

```toml
[filesystem]
read = ["~/.config/app", "./assets"]
write = ["./saves"]
execute = ["./program"]
deny = ["~/.config/app/token"]
```

Granting and denying the same path within one layer is an error.

### Connecting to a UNIX socket

`connect` names pathname UNIX sockets the target may talk to. It is its own
grant: read or write on a directory never carries the right to connect to the
sockets in it, because a pathname socket is a door into another program, and
reaching a directory is not the same as being allowed to knock on every door in
it.

```toml
[filesystem]
connect = [
    "${XDG_RUNTIME_DIR}/${WAYLAND_DISPLAY}",
    "${XDG_RUNTIME_DIR}/pulse/native",
]
```

A plain path names one socket. A literal directory names every socket beneath
it, whatever this run and future runs add there, so prefer naming sockets one
by one. `at` is not available for a connect entry: a socket is reached where
the host keeps it.

The entries expand the way other paths do, with stricter rules, because a
widened result here is a door into another program:

- A variable that is unset, or set to the empty string, drops the entry with a
  warning rather than granting nothing. A profile that needs the display only
  when there is a display keeps working under ssh or on a TTY login.
- A variable whose value is absolute replaces everything to its left. Wayland
  defines an absolute `WAYLAND_DISPLAY`, so the template above is correct for
  a compositor that sets one.
- An entry that used a variable and resolves to an existing directory is
  dropped with a warning: the variable was meant to name a socket.
- An entry that resolves to the session runtime directory, to an ancestor of
  it, or to `/` is dropped whether or not it used a variable. Those are the
  directories whose sockets the connect list exists to separate.

A path that does not exist yet is kept, and skipped at enforcement like any
other missing grant.

Connecting is enforced by Landlock on kernels with ABI 9 (Linux 7.1) and later.
On older kernels the run summary says so, and any socket the target can reach
by path can be connected to. Under `--no-isolate` the same control holds; the
connect list does not need the isolation layer.

### Placing a grant somewhere else

An entry may be a table naming where the path should appear to the target:

```toml
[filesystem]
read = [{ path = "/home/you/projects/thing", at = "/workspace" }]
write = [{ path = "/home/you/projects/thing", at = "/workspace" }]
```

The target sees `/workspace`, and the host path does not exist for it at all.
This needs the isolation layer, since without a reconstructed root there is
nowhere else for a path to be.

Paths are otherwise preserved exactly, and that is worth keeping: a program that
resolves anything relative to its own location breaks when moved, which is why a
granted symlink is recreated rather than bound through. Reach for `at` when the
name of a path is itself the thing to withhold. A directory named after the
person running the sandbox tells a target who they are and how the host is laid
out, and no amount of access control takes that back once the target has read
it.

A `deny` beneath a relocated grant is applied at the new location, and two
different paths may not be placed at the same location.

### A read-only island

`read_only` is how you keep part of a writable hierarchy from being written:

```toml
[filesystem]
write = ["~/.local/share/thing"]
read_only = ["~/.local/share/thing/versions"]
```

Unlike `deny`, the contents stay readable; only writes are refused. It is
enforced by mounting the path over itself read-only, which the VFS honours
whatever Landlock says, so it needs the isolation layer. That is the default;
under `--no-isolate` the run warns and the path stays writable.

::: warning A nested `deny` needs the isolation layer
A denial of a path inside a granted directory is enforced by covering the path
with an empty read-only filesystem, which only the isolation layer can do. That
layer is on by default; under `--no-isolate` the denial is reported as unenforced
before the run starts.
:::

## `[network]`

| Key | Type | Description |
| --- | --- | --- |
| `egress` | `"deny"` or `"allow"` | Outbound policy. Default `"deny"` |
| `egress_allow` | list of tables | Permitted destinations, `{ host, port }` |
| `mode` | `"auto"`, `"private"` or `"host"` | How the network is placed. Default `"auto"` |
| `broker` | `"ADDR:PORT"` | Hold the run to one egress route, through a broker at that address |
| `bind_ports` | list of integers | TCP ports the target may bind |
| `publish_ports` | list of integers | Sandbox TCP ports published on the host at `127.0.0.1:PORT`; needs the private namespace and allowed egress |

```toml
[network]
egress_allow = [{ host = "*", port = 443 }]
bind_ports = [27015]
```

`egress_allow` takes precedence over `egress` when both are present. `bind_ports`
and `publish_ports` accumulate across layers; `egress`, `mode` and `broker` are
replaced by the nearest layer that sets them, and `filesystem.reset = true`
clears an inherited broker.

`mode` picks how the network is placed. `auto`, the default, uses the private
namespace wherever the host provides it, falls back to the host's namespace
when nothing in the policy needs the private one, and refuses a policy that
needs it where the host cannot provide it, naming pasta or the user namespaces
as the missing prerequisite. `private` asks for the private namespace outright
and refuses the run where pasta or working unprivileged user namespaces are
missing, rather than silently staying on the host's network. `host` shares the
host's namespace, where Landlock's TCP port rules are the only restriction.
A policy that denies egress keeps its own loopback-only namespace in every
mode, because the namespace is the only way to deny every protocol at once.

`broker` is a boundary the policy itself names: every outbound connection
except one to `ADDR:PORT` is dropped, so the session reaches the broker and
nothing else. It needs the private namespace and `nft`, and refuses the run
where either is missing.

Resolved settings that contradict each other are refused at resolution,
naming the layers that set them: host mode with forwards, published ports, or
a broker under allowed egress, or a broker beside forwards or published ports.

`publish_ports = [3800]` makes a TCP service bound inside the sandbox on
`127.0.0.1:3800` or `0.0.0.0:3800` reachable from the host at
`127.0.0.1:3800`, not at the host's LAN addresses. Entries accumulate across
layers and are cleared alongside forwards by `[filesystem] reset = true`.
Port 0 is a config error. A publication matching either a forward's sandbox
port or its host port is refused.

Publication needs the private namespace and namespace isolation, which
automatic mode provides where the host can. It is refused with
`mode = "host"`, a broker, `--no-proxy-net`, `--no-isolate`, `egress = "deny"`,
or audit. Missing pasta, working unprivileged user namespaces, or `nft`, or
failure to install the firewall, refuses the run rather than degrading it.
Each publication is reported before the target starts. Publication grants no
outbound egress and leaves unrelated host loopback services blocked. Only TCP
over IPv4 is published, never UDP or IPv6. See
[publishing a sandbox service](/guide/network#publishing-a-sandbox-service).

- `host` is advisory. Landlock matches on TCP port only, and bailey warns when
  `host` is anything other than `*`.
- An entry without a `port` is a resolution error, because the resulting policy
  would mean the opposite of what it says.
- Only TCP is restricted. See [known limitations](/security/limitations).

## `[[device]]`

An array of tables, one per device.

| Key | Type | Description |
| --- | --- | --- |
| `path` | path | Device node or directory |
| `access` | string | Any combination of `r`, `w`, `x` |

```toml
[[device]]
path = "/dev/dri"
access = "rw"
```

Device grants use filesystem semantics and accumulate across layers like
filesystem grants.

## `[[fuse]]`

An array of tables, one per FUSE filesystem bailey mounts itself. Bailey runs
the mount command as the caller before the target starts, with
`BAILEY_MOUNTPOINT` naming the host directory to mount onto, and unmounts when
the run ends. The target sees the filesystem at `at` and never holds the mount
syscalls. See [desktop services and mounts](/guide/desktop).

| Key | Type | Description |
| --- | --- | --- |
| `mount` | string | Shell command that performs the mount |
| `at` | path | Where the mount appears to the target |

```toml
[[fuse]]
mount = "rclone mount secret:project"
at = "/mnt/project"
```

Entries accumulate across layers and are cleared by `filesystem.reset = true`.
A failing mount command refuses the run. Isolation is required; `--no-isolate`
with a `[[fuse]]` entry in the policy is an error.

## `self_fuse`

A top-level boolean that lets the target mount its own filesystems. It keeps
the mount syscalls, holds `CAP_SYS_ADMIN` inside the run's user namespace, and
gets `/dev/fuse` without a `[[device]]` entry:

```toml
self_fuse = true
```

Like `egress`, the nearest layer that sets it decides. Isolation is required;
`self_fuse` without `--isolate` is refused at startup.

The cost is structural, and bailey refuses combinations that would promise
more than it can deliver:

- Recent kernels refuse a new filesystem to any process under a Landlock
  domain, and a FUSE mount is a new filesystem. A `self_fuse` run therefore
  has no Landlock ruleset; confinement rests on the reconstructed root alone.
  See [known limitations](/security/limitations).
- A `read_only` path is a read-only bind the target could remount writable,
  so any `read_only` entry alongside `self_fuse` is a resolution error.
- A `deny` beneath a grant is an empty mount the target could remove, so that
  combination is a resolution error too. A `deny` no grant reaches is absent
  from the root outright and stays enforced.
- An egress allowance is a Landlock port restriction, and it is enforced by the
  same ruleset the switch gives up, so that combination is a resolution error
  too. Allow-everything and deny-everything are both unaffected: the first
  promises no restriction, and the second is held by the run's own network
  namespace rather than by Landlock.

## `[[socket]]`

An array of tables, one per desktop service socket relayed into the sandbox.
Bailey listens on a socket of its own and carries connections to the real one,
so a single service is reachable while the directory holding it, and every
other socket in it, stays ungranted.

Either name a `service`, or name both ends yourself, never both:

| Key | Type | Description |
| --- | --- | --- |
| `service` | string | One of `wayland`, `x11`, `pulse`, `dbus`, `url-open` |
| `host` | path | The host socket to relay, when naming a custom one |
| `at` | path | Where the target sees it; defaults to `host` |

```toml
[[socket]]
service = "wayland"

[[socket]]
service = "url-open"

[[socket]]
host = "${XDG_RUNTIME_DIR}/pipewire-0"
at = "${XDG_RUNTIME_DIR}/pipewire-0"
```

Named services take their paths from the session the run is launched from, so
`XDG_RUNTIME_DIR` must be set for them. The environment follows the relay: the
target's `XDG_RUNTIME_DIR` is a per-run directory, and each service sets the
variables that point a program at it. Entries accumulate across layers and are
cleared by `filesystem.reset = true`. A relay overlapping a grant is a
resolution error, because the relay exists to keep the directory ungranted.

## `[[forward]]`

An array of tables, one per host TCP port carried onto the sandbox's own
loopback. The target dials `127.0.0.1:port` the way it would dial a local
daemon, and bailey carries the connection to `127.0.0.1:host_port` on the host.
Other host loopback services remain blocked in the private network namespace.

| Key | Type | Description |
| --- | --- | --- |
| `port` | integer | The port inside the sandbox; required, not 0 |
| `host_port` | integer | The host port it lands on; defaults to `port` |

```toml
[[forward]]
port = 9876

[[forward]]
port = 5432
host_port = 15432
```

Entries accumulate across layers and are cleared by `filesystem.reset = true`.
Two different host ports for one sandbox port is refused, as is a forward
sharing a port the policy already binds. Isolation is required. With denied
egress, only the forwarded services are reachable.

With `egress = "allow"` or `egress_allow`, forwards are carried by pasta in the
private namespace, which automatic mode provides where the host can; a config
or `--proxy-net` that names `private` outright makes the request explicit.
Pasta and working unprivileged user namespaces are needed there, and a run
whose policy needs the private namespace where the host cannot provide it is
refused, naming pasta and the forward, rather than dropping the protection.
Host mode, `--no-proxy-net`, or `--no-isolate` alongside allowed egress is
refused, as is a forward beside a broker or `--egress-proxy`. The existing
internet allowance is preserved, not widened to include forward-only TCP
ports on remote hosts.

Only explicit TCP forwards are enabled, with no automatic, inbound, or UDP
forwarding. They are private to the sandbox. Denied-egress forwards serve
connections sequentially per port; online forwards use pasta and support
concurrent connections. See [desktop services and mounts](/guide/desktop).

## `[resources]`

| Key | Type | Description |
| --- | --- | --- |
| `memory` | string | Maximum memory. Bytes, or a suffix |
| `address_space` | string | Per-process address space, the fallback for `memory` where no cgroup carries it |
| `pids_max` | integer | Maximum processes and threads |
| `open_files` | integer | Largest descriptor number a process may newly open |
| `cpu_percent` | integer | CPU quota as a percentage of one core |
| `file_max` | string | Largest single file the target may create |
| `tmp_size` | string | Size of the private `/tmp`. Default 64MiB |
| `shm_size` | string | Size of the private `/dev/shm`. Default 256MiB |

Accepted size suffixes, case-insensitive: `b`, `k`/`kb` (1000), `kib` (1024),
`m`/`mb`, `mib`, `g`/`gb`, `gib`, `t`/`tb`, `tib`.

```toml
[resources]
memory = "2GiB"
pids_max = 512
cpu_percent = 150
open_files = 512
file_max = "1GiB"
```

Each key is replaced by the nearest layer that sets it. `memory`, `pids_max` and
`cpu_percent` are applied through cgroup v2, best-effort: without a writable
delegated cgroup they are skipped, and the run reports that.

`file_max` is different. It is an `RLIMIT_FSIZE`, so it holds on any host,
cgroups or not, and it is inherited by every process the target starts. A write
past it raises `SIGXFSZ`, and fails with `EFBIG` for a target that handles the
signal.

It bounds one file rather than total usage. Linux has no rootless way to cap
what a process tree writes in aggregate, because cgroups have no disk controller
and a sized filesystem needs a mount. What this stops is the runaway log or dump
that fills a disk, not a target that writes many small files.

`open_files` is an `RLIMIT_NOFILE`, so like `file_max` it holds on any host and
is inherited by every process the target starts. It bounds the descriptor
numbers a process may newly open: once the numbers below it are spent, further
opens fail with `EMFILE`, visibly, at whatever the target was doing. Zero is
refused at resolution, since it would refuse the target's first open. Two
properties of the kernel limit are worth knowing. Descriptors the process
inherited above the number stay open; the limit binds new opens, not old ones,
and bailey's own descriptors are close-on-exec. And the limit is lower-only:
where the policy's number is above the caller's own, the caller's limit stands,
because an unprivileged run cannot grant what the caller did not have. A value
too small for the target's own startup fails that startup visibly with
`EMFILE`; measured from the bottom, an isolated `/bin/true` survives 4 and dies
at 3, where the dynamic loader can no longer open `libc.so.6`, and
`python3 -c 0` starts under a limit of 8. There is no enforced floor beyond
zero.

`address_space` is an `RLIMIT_AS`, and it is not a memory limit. It bounds the
address ranges one process may map, which counts reservations rather than
resident pages: memory in tmpfs leaves the count once unmapped, and page cache
and kernel memory never enter it. It is the opt-in fallback for `memory` on the
hosts where `memory` cannot be enforced, the ones with no writable delegated
cgroup: bailey applies it only on a run where `memory` is set and no cgroup
could carry it, and where a cgroup carries `memory` the fallback is not applied
at all, because the cgroup's `memory.max` is the sound bound and stacking an
address-space cap on top would only add breakage. Resolution refuses
`address_space` without `memory`, since it would never act. Set it by name,
never derived from `memory`: the right address-space number for a program is
not its resident-memory number, because runtimes reserve address ranges far
beyond what they touch. Measured on one 30 GiB host: `python3 -c 0` and
`go version` start under 1 GiB, and `node -e 0` dies with SIGTRAP at 1 GiB and
starts under 4 GiB, both through bailey. The JVM's default heap reservation is
a fraction of physical RAM, so the number it needs grows with the machine:
measured with `prlimit`, `java -version` fails at 4 GiB and starts at 16 GiB
on this host. Set it well above the largest reservation the target's runtime
makes.

## `[env]`

| Key | Type | Description |
| --- | --- | --- |
| `pass` | list of names | Forward these caller variables. A trailing `*` matches by prefix |
| `set` | table | Define variables outright. `${VAR}` and a leading `~` expand, as they do in paths |
| `deny` | list of names | Remove these from the final environment, including the base set |
| `reset` | bool | Discard everything lower layers passed or set |

```toml
[env]
pass = ["MANGOHUD*"]
set = { RUST_LOG = "debug" }
deny = ["TERM"]
```

The target's environment is built, not inherited: it starts empty, gets a base
set of `PATH`, `HOME`, `TMPDIR`, `TERM`, `LANG`, `LC_*`, `USER`, `LOGNAME`,
`SHELL`, `TZ`, `BAILEY_SANDBOX`, and `BAILEY_SANDBOX_NET`, and takes nothing else
from the caller unless named here. See
[environment and storage](/guide/environment).

## `applies_to`

A top-level key, meaningful only in a profile under
`$XDG_CONFIG_HOME/bailey/profiles/`. It lists the programs the profile is for, so
that bailey selects it without `--profile`.

```toml
applies_to = ["claude", "/opt/thing/bin/thing"]
```

An entry with no `/` matches the target's file name; one with a `/` must match
the resolved path. An explicit `--profile` overrides it, and two profiles
claiming one target is an error.

## `home`

A top-level key giving the host directory to use as the target's private home,
overriding the derived `$XDG_DATA_HOME/bailey/<target>/home`.

```toml
home = "~/games/thegame/home"
```

Granting your real home in `[filesystem]` turns the private home off entirely.

## `[hooks]`

| Key | Type | When |
| --- | --- | --- |
| `pre_launch` | list of commands | Before the target starts. Non-zero exit aborts the run |
| `post_exit` | list of commands | After the target terminates. Gets `BAILEY_EXIT_CODE` |

`on_violation` was removed: nothing could trigger it. A config that still sets it
is accepted with a warning rather than rejected. See
[lifecycle hooks](/guide/hooks).

Commands run through `sh -c` and accumulate across layers, running in layer order.

## Path handling

- Relative paths resolve against the directory of the config file containing them.
- `~` and `~/...` expand using `$HOME`.
- `${VAR}` expands from the environment, which is how a shared profile can name
  something like `${XDG_RUNTIME_DIR}`. It expands in `env.set` values too, since
  most of what goes there is a path. An unset variable expands to nothing,
  leaving a path that matches nothing rather than one that matches something
  unintended.
- `${PWD}` is the directory the run was launched from, asked of the kernel when
  the shell has not exported it. A profile uses it to grant "wherever I am",
  which is what lets a per-program policy work without a config file in every
  project. Launch from a directory you actually want granted: from your home, it
  grants your home.
- `.` and `..` are collapsed lexically, so different spellings of one path merge
  into a single grant.

## Errors

| Error | Cause |
| --- | --- |
| `failed to parse config` | Not valid TOML, or an unknown key |
| `invalid config` | A bad value, such as an unknown access character or size suffix |
| `conflicting directives` | One layer both granted and denied the same path |
| `failed to read config` | The file named by `--config` does not exist or is unreadable |
