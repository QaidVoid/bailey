# Desktop services and mounts

An agent or a desktop program usually needs less than "the runtime directory"
and more than nothing: one Wayland socket, one bus, one browser. The blunt tool
is a grant of `${XDG_RUNTIME_DIR}`, which drags in every socket that lives
there, ssh-agent and gpg-agent among them. Bailey offers a narrower road for
each of these: it carries the one socket in itself and leaves the directory
behind.

## Migrating from a directory grant

Connecting to a pathname UNIX socket is its own grant on a modern kernel: a
`connect` entry naming the socket. A read or write grant on a directory no
longer carries it, so a config that reached the compositor or the bus through a
grant of `${XDG_RUNTIME_DIR}` stops connecting on kernels with Landlock ABI 9
(Linux 7.1) and later. A run that sees this shape prints one note saying so.

The fix is one line per socket the program really talks to:

```toml
[filesystem]
connect = [
    "${XDG_RUNTIME_DIR}/${WAYLAND_DISPLAY}",
    "${XDG_RUNTIME_DIR}/bus",
]
```

`bailey show` lists what resolved, with the connect bit shown as `c`. An entry
for a variable that is unset, or that lands on the runtime directory itself, is
dropped with a warning rather than widened.

For a program whose only need is one service, a `[[socket]]` relay stays the
tighter choice: it carries the connection itself and leaves even the listed
socket out of the target's view.

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

## Forwarding a local TCP port

Some tools dial a TCP port on localhost the way a desktop service dials its
socket: an MCP server that drives Blender listens on `127.0.0.1:9876`, a
database insists on `127.0.0.1:5432`. A port forward carries one such port
onto the sandbox's own loopback:

```toml
[[forward]]
port = 9876
```

The target dials `127.0.0.1:9876` and reaches the host service. The port it
dials and the port that answers need not match:

```toml
[[forward]]
port = 5432
host_port = 15432
```

With denied egress, the forward is the only way out of the private network
namespace. It carries only TCP connections the target initiates to the named
port, not inbound connections from outside the sandbox.

### Keeping internet access alongside a forward

To reach a host service such as zai-proxy on `127.0.0.1:8080` while retaining
internet access, use the same forward syntax with an egress allowance:

```toml
[network]
egress = "allow"

[[forward]]
port = 8080
```

Launch with no flag: automatic mode provides the private namespace the forward
is carried by wherever the host can.

```sh
bailey shell
```

Inside the sandbox, `127.0.0.1:8080` reaches zai-proxy on the host. General
internet egress remains allowed, but unrelated host loopback services stay
blocked. With `egress_allow` instead, internet access remains limited to its
permitted TCP ports. A forward does not add its port to the internet allowance.

Online forwards need isolation, pasta, and working unprivileged user
namespaces, which automatic mode arranges where the host can. The run is
refused if a prerequisite is missing, or if a broker is set, since the broker
remains the sole egress path in brokered runs. The same options apply to
`bailey run` and `bailey shell`.

Only the configured TCP ports are forwarded. No automatic, inbound, or UDP
forwarding is enabled, and the forwards remain private to the sandbox.

::: warning Denied-egress forwards carry one connection at a time
With denied egress, each forwarded port serves its connections sequentially.
A local daemon that holds one connection per client is the shape this backend
is built for; concurrent clients queue instead. Online forwards use pasta and
support concurrent connections. Prefer the service's own socket relay
(`[[socket]]`) when one exists.
:::

## Where relays, mounts, and forwards end

- All three need namespace isolation, which is the default. `--no-isolate`
  with any of them in the policy refuses the run rather than dropping the
  feature.
- A relay and a grant of the same hierarchy are refused together: the relay
  exists to keep a directory ungranted, and both at once is a contradiction.
- A FUSE entry and `--no-isolate` are refused the same way, because a mount
  placed for the target needs a root to place it in.
- A forward needs a private network namespace, which automatic mode provides
  where the host can and which the run is refused without when a policy needs
  it. Neither exposes a listener to outside clients.
- On a machine without working relays, mounts, or forwards, the refusal names
  what was missing. Nothing is silently dropped from a policy.
