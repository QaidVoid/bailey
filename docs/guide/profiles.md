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

Additive over the floor, for a native Linux game. Fonts, icons, and the Vulkan
and GLVND data; write access to your own session runtime directory, which is
where the compositor and audio sockets live; the render nodes under `/dev/dri`
and the NVIDIA device nodes for the proprietary driver; `/dev/snd`; and
`/dev/input` for controllers.

```sh
bailey profile show native-game
```

`${XDG_RUNTIME_DIR}` expands to your own runtime directory, so the grant covers
your session rather than `/run/user`, which would cover every logged-in account.
A device node that does not exist is skipped, so the NVIDIA entries cost nothing
on a Mesa system.

It deliberately does not grant the game's own directory or its save location: those
are per-game decisions that belong in a `bailey.toml` next to the game.

::: tip Device grants are the expensive ones
`/dev/input` covers every input device, including your keyboard, which is a
keylogging surface. Grant the specific `event*` node for your controller where
you can identify it.
:::

## `desktop-app`

Display, audio, fonts, icons, and your session's runtime directory, with no
controllers and no direct GPU nodes beyond rendering. The right base for an
ordinary graphical application.

## `ai-agent`

For a coding agent: one project, and the API it talks to. Outbound HTTPS, no home
directory, no devices.

Allowing egress at all gives up the network namespace, so the agent shares your
network namespace where UDP, DNS and your host's loopback are reachable and only
TCP ports are enforced. That is the price of a program that must call an API. For
an agent that must *not* reach the network, use `untrusted`, which denies it
outright.

It cannot know where your project is, so grant that yourself:

```toml
# ~/projects/thing/bailey.toml
[filesystem]
read = ["."]
write = ["."]
deny = ["./secrets"]
```

```sh
bailey run --isolate --profile ai-agent agent-cli
```

Use `--isolate`: it is what makes the `deny` enforceable and what puts the agent
in a world where your other projects do not exist.

Remember that nothing intercepts your shell. Running `agent-cli` on its own runs
it unsandboxed; the policy applies only when you launch it through bailey. The
`bailey: enforced:` line after a run is the confirmation.

## `network-client`

The floor plus outbound TCP on 443 and the certificates to verify it. Remember
that allowing egress at all gives up the network namespace, so UDP is
unrestricted in this mode; see [network confinement](/guide/network).

## Copying a profile

```sh
bailey profile show native-game > bailey.toml
```

Profiles are ordinary config, so this is a starting point you can edit rather
than a black box.

## Writing your own

A profile is just a TOML fragment, so you can add your own in
`$XDG_CONFIG_HOME/bailey/profiles/<name>.toml`, and select it by name:

```toml
# ~/.config/bailey/profiles/claude.toml
[filesystem]
read = ["~/.local/share/claude"]

[network]
egress_allow = [{ host = "*", port = 443 }]
```

```sh
bailey run --isolate --profile claude claude
```

`bailey profile list` shows yours under the bundled ones, and
`bailey profile show <name>` prints either. The bundled names are reserved: a
file called `untrusted.toml` is ignored with a warning rather than quietly
replacing the safe floor.

## Letting a profile claim a program

Naming the profile on every run gets old. A profile can say which programs it is
for, and bailey will pick it up automatically:

```toml
# ~/.config/bailey/profiles/claude.toml
applies_to = ["claude"]
```

```sh
bailey run --isolate claude          # uses the claude profile, wherever you are
```

```
bailey: using profile `claude`, which claims this target
```

An entry with no `/` matches the program's file name, so it works wherever the
binary is installed. An entry with a `/` must match the resolved path exactly.

A profile that fails to parse is reported and ignored, rather than quietly
ceasing to apply.

## Granting the directory you are in

A profile cannot name your project, but it can name *wherever you launched from*:

```toml
# ~/.config/bailey/profiles/agent.toml
applies_to = ["my-agent"]

[filesystem]
read = ["${PWD}"]
write = ["${PWD}"]
```

That is the answer to "must I write a `bailey.toml` in every project": no, if the
rule belongs to the program rather than to the place. Put it in the profile and
launch the program from the directory you want it to have.

Keep in mind what it means literally. Launch from your home directory and you
have granted your home; the sandbox will not save you from a `cd` you did not
think about.

Two rules keep this from becoming surprising: an explicit `--profile` always
wins, and a run says which profile was chosen for it. If two profiles claim the
same program, the run stops and names both rather than picking one.

## Sharing rules by location instead

Where the rules belong to a place rather than a program, the cascade already
covers it: put them in a `bailey.toml` high in a directory tree and everything
below inherits them.

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
| A graphical application | `desktop-app` |
| A coding agent | `ai-agent` plus a grant on the project directory |
| Something that only fetches over HTTPS | `network-client` |

Then run [`bailey audit`](/guide/audit) to find what is missing rather than
guessing.
