# Configuration

Config is TOML. It cascades, so shared rules live high up and specific rules live
next to the thing they apply to.

## Layers

From lowest precedence to highest:

1. **The bundled profile.** `--profile <name>`, default `untrusted`. The
   `untrusted` floor is always applied; a named profile layers over it.
2. **Global config.** `$XDG_CONFIG_HOME/bailey/config.toml`, falling back to
   `~/.config/bailey/config.toml`.
3. **Per-directory config.** Every `bailey.toml` found by walking up from the
   target's directory *and* from your working directory, ordered by path depth so
   a closer file wins.
4. **Explicit config.** A file passed with `--config`.

Missing files are skipped. `bailey show <target>` lists the ones that were
actually found, in order, and says which walk found each.

::: tip Both walks matter
The target walk covers a program that lives with its config. The working
directory walk covers the interpreter case: for `bailey run /usr/bin/python3
app.py` the target walk starts at `/usr/bin` and finds nothing, while the working
directory walk finds your project's `bailey.toml`. A file found by both
contributes once. At equal depth, the working directory wins.
:::

## Merge rules

- **Filesystem and device grants accumulate.** Rights for the same path combine,
  so a layer granting read and a layer granting write produce read-write.
- **`filesystem.reset = true`** clears everything lower layers granted, letting a
  layer start from nothing.
- **`filesystem.deny`** removes a grant of the same path from a lower layer and
  records the path as denied. A later layer that grants the path again overrides
  the denial.
- **Scalars are replaced** by the nearest layer that sets them: `network.egress`,
  each key under `[resources]`.
- **`network.bind_ports` accumulate.**
- **Hooks accumulate** and run in layer order.
- **Granting and denying the same path within one layer is an error**, naming the
  file and the path.

::: warning A nested `deny` needs `--isolate`
Denying a path inside a directory another layer granted is enforced by covering
that path with an empty read-only filesystem, which only the isolation layer can
do. `bailey run --isolate` enforces it; a plain `bailey run` reports it as
unenforced and the path stays readable.

Landlock rules cannot express this: access resolution walks up from the file, so
an ancestor grant satisfies it and no narrower rule can subtract. See
[known limitations](/security/limitations).
:::

## Paths

- Relative paths resolve against the directory of the config file that contains
  them, not against your shell's working directory.
- `~` and `~/...` expand to `$HOME`.
- `.` and `..` are collapsed lexically before merging, so different spellings of
  the same path merge into one grant.

## A complete example

```toml
[filesystem]
# reset = true
read = ["~/.config/mygame", "./assets"]
write = ["./saves"]
execute = ["./game"]
deny = ["~/.config/mygame/telemetry"]

[network]
egress = "deny"                            # "deny" (default) or "allow"
egress_allow = [{ host = "*", port = 443 }]
bind_ports = [27015]

[[device]]
path = "/dev/dri"
access = "rw"

[[device]]
path = "/dev/snd"
access = "rw"

[resources]
memory = "4GiB"
pids_max = 512
cpu_percent = 300

[hooks]
pre_launch = ["./mount-assets.sh"]
post_exit = ["./sync-saves.sh"]
on_violation = ["notify-send 'bailey' \"$BAILEY_VIOLATION\""]
```

Every key is documented in the [configuration reference](/reference/config).

## Network rules

`egress = "deny"` is the default. `egress_allow` lists permitted destinations:

```toml
[network]
egress_allow = [{ host = "*", port = 443 }]
```

Landlock matches on TCP port, so the `host` field is advisory. Bailey warns when
you set a host other than `*`, because the rule will not restrict by host. An
entry with no `port` is a resolution error naming the layer, rather than a rule
that silently becomes a full deny.

::: danger Only TCP is restricted
Landlock's network rules cover TCP connect and bind. UDP, QUIC, DNS, and ICMP are
not restricted by `egress = "deny"` today. See
[known limitations](/security/limitations).
:::

## Resource limits

```toml
[resources]
memory = "2GiB"     # bytes, or a KiB/MiB/GiB or KB/MB/GB suffix
pids_max = 512      # processes and threads
cpu_percent = 150   # percent of one core; 100 is one full core
```

Applied through cgroup v2, best-effort. Without a writable delegated cgroup they
are skipped with a warning.
