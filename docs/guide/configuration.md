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
   target's directory, applied outermost first, so a closer file wins.
4. **Explicit config.** A file passed with `--config`.

Missing files are skipped. `bailey show <target>` lists the ones that were
actually found, in order.

::: tip Discovery starts at the target
The upward walk starts from the directory holding the target executable, not from
your shell's working directory. For `bailey run /usr/bin/python3 app.py` the walk
starts at `/usr/bin`, so a `bailey.toml` in your project is not discovered. Pass
it with `--config` until [this is fixed](/roadmap).
:::

## Merge rules

- **Filesystem and device grants accumulate.** Rights for the same path combine,
  so a layer granting read and a layer granting write produce read-write.
- **`filesystem.reset = true`** clears everything lower layers granted, letting a
  layer start from nothing.
- **`filesystem.deny`** removes a path that a lower layer granted.
- **Scalars are replaced** by the nearest layer that sets them: `network.egress`,
  each key under `[resources]`.
- **`network.bind_ports` accumulate.**
- **Hooks accumulate** and run in layer order.
- **Granting and denying the same path within one layer is an error**, naming the
  file and the path.

::: danger `deny` is not a deny rule
`deny` removes a grant of exactly that path. It does not restrict a path nested
inside a directory a layer granted. Granting `~` and denying `~/.ssh` leaves
`~/.ssh` readable. See [known limitations](/security/limitations).
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
you set a host other than `*`, because the rule will not restrict by host. An entry
with no `port` is currently dropped, which turns the rule into a full deny; always
give a port.

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
