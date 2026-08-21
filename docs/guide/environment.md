# Environment and private storage

Access control decides what a program may reach. This page is about what it is
handed before it starts, which is a separate question with the same stakes: an
inherited `SSH_AUTH_SOCK` is a live credential that no filesystem rule can take
back.

## The environment is built, not inherited

A target starts with an empty environment. Bailey then adds a small base set, and
nothing else crosses from your shell unless you name it.

```sh
AWS_SECRET_ACCESS_KEY=hunter2 bailey run /usr/bin/env
```

```
HOME=/home/you/.local/share/bailey/env/home
LANG=C.UTF-8
LOGNAME=you
PATH=/usr/local/bin:/usr/bin:/bin
SHELL=/bin/bash
TERM=xterm-256color
USER=you
```

The base set is `PATH` (a sandbox-appropriate one, not yours), `HOME`, `TMPDIR`
where a private `/tmp` applies, and the locale and terminal variables `TERM`,
`LANG`, `LC_*`, `USER`, `LOGNAME`, `SHELL`, and `TZ`.

`bailey show <target>` prints the exact environment a target will receive, and
where each variable came from.

## Passing variables through

```toml
[env]
pass = ["STEAM_COMPAT_DATA_PATH", "MANGOHUD*"]
set = { RUST_LOG = "debug" }
deny = ["TERM"]
# reset = true    # discard everything lower layers passed or set
```

- **`pass`** forwards a variable from the caller. A trailing `*` matches by
  prefix.
- **`set`** defines a variable outright, whatever the caller has.
- **`deny`** removes a variable from the final environment, including one from
  the base set or from a lower layer.

An allowlist is the only model where adding a new secret to your shell profile
does not silently widen every sandbox you already configured.

## Display and audio variables follow their grants

`WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR`, `PULSE_SERVER`, and `XDG_SESSION_TYPE` are
passed only when the policy grants your session's runtime directory. `DISPLAY`
and `XAUTHORITY` are passed only when `/tmp/.X11-unix` is granted.

The variable without the socket is useless, and the socket without the variable
is a program that cannot find its display, so bailey derives one from the other.

## The private home

Each target gets its own home directory at
`$XDG_DATA_HOME/bailey/<target>/home`, created on first use, and `HOME` names it.
Programs write their settings and save data there; your real home stays
unreachable.

```sh
bailey run ./program        # writes land in the private home
```

It persists between runs, so settings and saves survive. Under isolation, which
is the default, it is mounted at the path your real home would have, so a program
that hard-codes `/home/you/.config/...` still writes inside the sandbox. Under
`--no-isolate` it stays at its own path, and only `HOME` points at it.

Two targets with the same file name share a private home. Override the location
per target:

```toml
home = "~/games/thegame/home"
```

To opt out entirely and give a program your real home, grant the home itself:

```toml
[filesystem]
read = ["~"]
```

Only a grant on the home directory itself, or on an ancestor of it, does that. A
grant on something *inside* your home, such as a project directory, leaves the
private home in place, and under isolation that granted path appears within it.
Most programs live under your home, and the target is granted implicitly, so the
narrower rule is what keeps the private home from switching itself off.

## Private temporary storage

Under isolation, `/tmp` and `/dev/shm` are fresh tmpfs mounts private to the run.
The host's `/tmp` is not visible, nothing written there reaches the host or
another sandbox, and everything is discarded when the run ends. Under
`--no-isolate` the host's `/tmp` is what the program gets.

```toml
[resources]
tmp_size = "256MiB"     # default 64MiB
shm_size = "512MiB"     # default 256MiB
```

The shared `/tmp` is a world-writable channel between every program on your
machine, which is where cross-application snooping and symlink games live, so a
sandbox that shares it has left a side door open.

::: warning A grant under /tmp turns it off
If the policy grants any path under `/tmp`, bailey does not provide a private
`/tmp`. Making the private one usable means granting it read-write, and Landlock
rights only add, so that grant would silently widen a narrower grant on a path
that happens to live under `/tmp`.
:::

## The working directory

A target starts in the directory you invoked it from, so relative paths behave as
they do outside the sandbox. Under isolation that directory only exists inside
the sandbox if the policy grants it; where it does not, the target starts in its
private home and the run says so:

```
bailey: warning: the working directory is not granted, so it is absent under
isolation; starting in /home/you instead
```
