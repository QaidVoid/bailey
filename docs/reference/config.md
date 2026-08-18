# Configuration reference

TOML. Unknown keys are rejected, so a typo is an error rather than a silently
ignored rule.

## Discovery order

Lowest precedence first:

1. The implicit grant of the target executable, read and execute.
2. Bundled profile: the `untrusted` floor, plus the profile named by `--profile`.
3. `$XDG_CONFIG_HOME/bailey/config.toml`, or `~/.config/bailey/config.toml`.
4. Every `bailey.toml` found walking up from the target's directory and from the
   working directory, ordered by path depth, shallowest first. A file found by
   both walks contributes once; at equal depth the working directory wins.
5. The file given to `--config`.

## `[filesystem]`

| Key | Type | Description |
| --- | --- | --- |
| `read` | list of paths | Grant read on each path hierarchy |
| `write` | list of paths | Grant write on each path hierarchy |
| `execute` | list of paths | Grant execute on each path hierarchy |
| `deny` | list of paths | Retract a grant of the same path and record the path as denied |
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

::: warning A nested `deny` needs `--isolate`
A denial of a path inside a granted directory is enforced by covering the path
with an empty read-only filesystem, which only the isolation layer can do.
Without `--isolate` the denial is reported as unenforced before the run starts.
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
| `tmp_size` | string | Size of the private `/tmp`. Default 64MiB |
| `shm_size` | string | Size of the private `/dev/shm`. Default 256MiB |

Accepted size suffixes, case-insensitive: `b`, `k`/`kb` (1000), `kib` (1024),
`m`/`mb`, `mib`, `g`/`gb`, `gib`, `t`/`tb`, `tib`.

```toml
[resources]
memory = "2GiB"
pids_max = 512
cpu_percent = 150
```

Each key is replaced by the nearest layer that sets it. Applied through cgroup v2,
best-effort.

## `[env]`

| Key | Type | Description |
| --- | --- | --- |
| `pass` | list of names | Forward these caller variables. A trailing `*` matches by prefix |
| `set` | table | Define variables outright |
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
`SHELL`, and `TZ`, and takes nothing else from the caller unless named here. See
[environment and storage](/guide/environment).

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
  something like `${XDG_RUNTIME_DIR}`. An unset variable expands to nothing,
  leaving a path that matches nothing rather than one that matches something
  unintended.
- `.` and `..` are collapsed lexically, so different spellings of one path merge
  into a single grant.

## Errors

| Error | Cause |
| --- | --- |
| `failed to parse config` | Not valid TOML, or an unknown key |
| `invalid config` | A bad value, such as an unknown access character or size suffix |
| `conflicting directives` | One layer both granted and denied the same path |
| `failed to read config` | The file named by `--config` does not exist or is unreadable |
