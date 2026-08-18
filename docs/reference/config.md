# Configuration reference

TOML. Unknown keys are rejected, so a typo is an error rather than a silently
ignored rule.

## Discovery order

Lowest precedence first:

1. Bundled profile: the `untrusted` floor, plus the profile named by `--profile`.
2. `$XDG_CONFIG_HOME/bailey/config.toml`, or `~/.config/bailey/config.toml`.
3. Every `bailey.toml` found walking up from the target's directory, outermost
   first.
4. The file given to `--config`.

## `[filesystem]`

| Key | Type | Description |
| --- | --- | --- |
| `read` | list of paths | Grant read on each path hierarchy |
| `write` | list of paths | Grant write on each path hierarchy |
| `execute` | list of paths | Grant execute on each path hierarchy |
| `deny` | list of paths | Remove a grant of exactly this path from lower layers |
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

::: danger `deny` is a retraction, not a rule
It removes a grant of the same path. It does not restrict a path nested inside a
directory another layer granted.
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
- An entry without a `port` is dropped, which turns the rule into a full deny.
  Always give a port.
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

## `[hooks]`

| Key | Type | When |
| --- | --- | --- |
| `pre_launch` | list of commands | Before the target starts. Non-zero exit aborts the run |
| `post_exit` | list of commands | After the target terminates. Gets `BAILEY_EXIT_CODE` |
| `on_violation` | list of commands | On a denied or flagged access. Gets `BAILEY_VIOLATION`. Does not currently fire |

Commands run through `sh -c` and accumulate across layers, running in layer order.

## Path handling

- Relative paths resolve against the directory of the config file containing them.
- `~` and `~/...` expand using `$HOME`.
- `.` and `..` are collapsed lexically, so different spellings of one path merge
  into a single grant.

## Errors

| Error | Cause |
| --- | --- |
| `failed to parse config` | Not valid TOML, or an unknown key |
| `invalid config` | A bad value, such as an unknown access character or size suffix |
| `conflicting directives` | One layer both granted and denied the same path |
| `failed to read config` | The file named by `--config` does not exist or is unreadable |
