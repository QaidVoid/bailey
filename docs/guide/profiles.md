# Profiles

A profile is a named config fragment shipped with bailey. It is the starting
point, applied beneath your own config so you can extend it rather than write a
policy from nothing.

```sh
bailey profile list
bailey run --profile native-game ./game
```

## `untrusted`

The deny-by-default floor. It is applied to **every** run, including runs that
select another profile, and it grants only what a dynamically linked binary needs
to start:

```toml
[filesystem]
read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/sys"]
execute = ["/usr", "/lib", "/lib64", "/bin", "/sbin"]
```

Plus the device nodes nearly every program opens: `/dev/null`, `/dev/zero`,
`/dev/full`, `/dev/urandom`, `/dev/random`, `/dev/tty`.

No home directory. No network. No GPU, audio, or input. If a program needs any of
that, it has to be granted.

## `native-game`

Additive over the floor, for a native Linux game:

```toml
[filesystem]
read = [
    "/usr/share/fonts", "~/.fonts", "~/.local/share/fonts",
    "~/.config/fontconfig", "~/.icons", "/usr/share/icons",
]
write = ["/run/user"]

[[device]]
path = "/dev/dri"
access = "rw"

[[device]]
path = "/dev/snd"
access = "rw"
```

It deliberately does not grant the game's own directory or its save location: those
are per-game decisions that belong in a `bailey.toml` next to the game.

::: warning Gaps in this profile
It grants `/dev/dri`, which covers Mesa drivers but not the proprietary NVIDIA
driver, which needs its own `/dev/nvidia*` nodes. It grants write on all of
`/run/user` rather than just your own runtime directory. It grants no `/dev/input`,
so controllers will not work, and no `/dev/shm`. Fixes are proposed in the
[roadmap](/roadmap); until then, add what you need in your own config.
:::

## Writing your own

There is no user-profile directory yet. Reuse in the meantime comes from the
cascade: put shared rules in a `bailey.toml` high in a directory tree, or in your
global config, and let everything below inherit them.

```
~/games/
  bailey.toml        # GPU, audio, fonts: applies to everything below
  factory-game/
    bailey.toml      # this game's directory and saves
    game
```

## Choosing a base

| Situation | Start with |
| --- | --- |
| A binary you downloaded and want to poke at | `untrusted` |
| A native Linux game | `native-game` plus a per-game config |
| A CLI tool that should only touch one project | `untrusted` plus a grant on that directory |
| Something that needs the network | `untrusted` plus `egress_allow` with a port |

Then run [`bailey audit`](/guide/audit) to find what is missing rather than
guessing.
