# Desktop services and mounts

An agent or a desktop program usually needs less than "the runtime directory"
and more than nothing: one Wayland socket, one bus, one browser. The blunt tool
is a grant of `${XDG_RUNTIME_DIR}`, which drags in every socket that lives
there, ssh-agent and gpg-agent among them. Bailey offers a narrower road for
each of these: it carries the one socket in itself and leaves the directory
behind.

## Relaying a service socket

```toml
[[socket]]
service = "wayland"
```

The `service` names one of `wayland`, `x11`, `pulse`, `dbus`, or `url-open`.
Bailey listens on a socket of its own, presents it to the target at the
service's usual path, and carries every connection to the real one. The target
sees a working compositor, bus, or sound server; the rest of the runtime
directory stays absent, because it was never granted.

Sockets that must never cross, ssh-agent above all, are safe by position: they
are files in a directory the policy does not grant, and the relay is a single
socket rather than a directory.

A custom socket is relayed the same way, naming both ends:

```toml
[[socket]]
host = "${XDG_RUNTIME_DIR}/pipewire-0"
at = "${XDG_RUNTIME_DIR}/pipewire-0"
```

The environment follows the relay, so a program finds what it looks for:
`XDG_RUNTIME_DIR` points at a per-run directory the target owns, and each named
service sets the variables that point a program at it, `WAYLAND_DISPLAY` for
Wayland, `DISPLAY` for X11, `DBUS_SESSION_BUS_ADDRESS` for the bus.

::: warning A relayed Wayland socket is your compositor
The relay keeps the rest of the runtime directory out of reach, but a Wayland
client that reaches the compositor can screenshot and inject input unless the
compositor itself restricts it. That is a property of the protocol, and no
filesystem policy changes it. Relay Wayland to programs you would let use your
desktop; use the URL broker below when the only thing an agent needs from your
desktop is a browser.
:::

## Opening a URL in the host browser

```toml
[[socket]]
service = "url-open"
```

The target gets a socket that speaks one line: a URL in, `OK` or `ERR` out,
then the connection closes. Bailey validates the scheme, accepts only `http`
and `https`, and hands the URL to `xdg-open` on the host as a single argument.
The target never sees the browser, its profile, its cookies, or any other page
it did not ask to open.

Any language speaks it. In a shell:

```sh
printf 'https://example.com\n' | socat - UNIX-CONNECT:"$XDG_RUNTIME_DIR/url-open"
```

`xdg-open` is taken from a trusted location and refused if someone other than
its owner can write it, the standard every helper bailey runs holds to.

## Mounting a FUSE filesystem

```toml
[[fuse]]
mount = "rclone mount secret:project"
at = "/mnt/project"
```

Bailey runs the mount command as you, before the target starts, with
`BAILEY_MOUNTPOINT` naming the host directory to mount onto, and it unmounts
when the run ends. The target sees the filesystem at `at` and can read and
write it; the seccomp filter still denies the mount syscalls and the capability
drop still leaves nothing to mount with, so the target can use a FUSE
filesystem without ever holding the power to create one.

A mount command runs exactly where a `pre_launch` hook runs: as you, before any
confinement exists. A config carrying one is trusted the way a config carrying
hooks is, and for the same reason.

Existing FUSE mounts need none of this: a grant of the mountpoint binds it in
like any other directory. What bailey adds for them is refusal instead of
silence. A stale or dead mount answers reads with an error rather than a
missing file, and a run whose grant cannot be read stops with that error named
instead of starting without the grant.

::: warning A hung mount can still hang the run
A mount whose server has gone away answers errors once the connection is torn
down, and hangs before that. A hard-hung mount can hold the run at startup the
same way it would hold any program that touches it; bailey refuses loudly as
soon as the kernel answers, and cannot answer for the kernel before that.
:::

## Where relays and mounts end

- Both need namespace isolation, which is the default. `--no-isolate` with
  either in the policy refuses the run rather than dropping the feature.
- A relay and a grant of the same hierarchy are refused together: the relay
  exists to keep a directory ungranted, and both at once is a contradiction.
- A FUSE entry and `--no-isolate` are refused the same way, because a mount
  placed for the target needs a root to place it in.
- On a machine without working relays or mounts, the refusal names what was
  missing. Nothing is silently dropped from a policy.
