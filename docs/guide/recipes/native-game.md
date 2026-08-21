# Recipe: a native game

A game needs more than a CLI tool: a GPU, audio, a display, fonts, and a place to
write saves. It also has the most to gain from confinement, because a game is a
large binary from a stranger that you run for hours.

## Start from the profile

```sh
bailey run --profile native-game ~/games/thegame/thegame
```

The profile grants fonts, icons, `/dev/dri`, and `/dev/snd` over the `untrusted`
floor. It does not grant the game's own directory, because that is per-game.

## Add the per-game config

```toml
# ~/games/thegame/bailey.toml
[filesystem]
read = ["."]
write = ["./saves", "~/.local/share/thegame"]
execute = ["./thegame"]

[resources]
memory = "8GiB"
pids_max = 1024
```

Then accept it once and run:

```sh
bailey trust ~/games/thegame/bailey.toml
bailey run --profile native-game ~/games/thegame/thegame
```

## Share the desktop rules across games

Put the parts that apply to every game one directory up, and let the cascade do
the rest:

```
~/games/
  bailey.toml          # GPU, audio, display socket, fonts
  thegame/
    bailey.toml        # this game's own directory and saves
    thegame
```

```toml
# ~/games/bailey.toml
[filesystem]
read = ["/usr/share/vulkan", "/usr/share/glvnd", "~/.cache/mesa_shader_cache"]
write = ["/run/user/1000"]           # your own runtime dir: Wayland, PipeWire
```

Replace `1000` with your uid. Each file in the cascade is accepted separately, so
the shared one needs `bailey trust ~/games/bailey.toml` of its own.

## NVIDIA

The bundled profile grants `/dev/dri`, which is what Mesa uses. The proprietary
NVIDIA driver needs its own nodes:

```toml
[[device]]
path = "/dev/nvidiactl"
access = "rw"

[[device]]
path = "/dev/nvidia0"
access = "rw"

[[device]]
path = "/dev/nvidia-uvm"
access = "rw"
```

## Controllers

```toml
[[device]]
path = "/dev/input"
access = "r"
```

This grants read on all input devices, including your keyboard, which is a
keylogging surface. Grant the specific `event*` node for your controller if you
can identify it.

## Networking

Most single-player games do not need the network. Leave `egress = "deny"`, which
is the default.

For a game that does, allow the port and nothing else:

```toml
[network]
egress_allow = [{ host = "*", port = 443 }]
bind_ports = [27015]
```

Remember that only TCP is restricted today. A game using UDP for multiplayer
traffic is not restricted by this at all, in either direction.

## Wayland and X11

Prefer Wayland. A Wayland client is confined to its own surfaces by the protocol.
X11 has no such boundary: every client can read every other client's input and
window contents, so an X11 game is unsandboxable at the display layer no matter
what the filesystem policy says.

## Audit it once

Games touch a lot. Record a session, then read the output rather than piping it
straight into a profile:

```sh
bailey audit --save-trace game.json ~/games/thegame/thegame
```

Anti-cheat systems, telemetry, and launcher integrations all show up here, and
they are exactly the accesses worth deciding about deliberately.
