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
| `bind_ports` | list of integers | TCP ports the target may bind |

```toml
[network]
egress_allow = [{ host = "*", port = 443 }]
bind_ports = [27015]
```

`egress_allow` takes precedence over `egress` when both are present. `bind_ports`
accumulate across layers; `egress` is replaced by the nearest layer that sets it.

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

## `[resources]`

| Key | Type | Description |
| --- | --- | --- |
| `memory` | string | Maximum memory. Bytes, or a suffix |
| `pids_max` | integer | Maximum processes and threads |
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
