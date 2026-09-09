# Network confinement

There are two modes, chosen from the policy and from what the host can do.
`bailey show <target>` prints which one applies.

| Policy | Mode | What is enforced |
| --- | --- | --- |
| `egress = "deny"`, no bound ports | **isolated** | Own network namespace, loopback only. Nothing reaches off the host, at any protocol |
| Any egress allowed, or a bound port | **landlock only** | Landlock rules over TCP ports. Other protocols are unrestricted |

The default policy denies egress, so the default mode is isolated.

## Isolated mode

The target runs in its own network namespace containing a loopback interface and
nothing else. A namespace with no route has nowhere to send anything, so TCP,
UDP, QUIC, DNS, ICMP, and raw sockets all fail at the socket layer rather than at
a rule.

```sh
bailey run /usr/bin/python3 -c "
import socket
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'x', ('8.8.8.8', 53))"
# OSError: Network is unreachable
```

The namespace is created through a user namespace, so it needs no privilege, and
it applies to every `bailey run`, including one with `--no-isolate`: a denied
egress is enforced this way regardless of the filesystem isolation.

Two things come along with the namespace:

- **Loopback still works inside the sandbox.** A program that binds a local port
  for its own IPC keeps working. That loopback reaches nothing but the sandbox;
  the host's loopback services are in a different namespace.
- **Host abstract UNIX sockets are unreachable.** The abstract socket namespace
  is tied to the network namespace, so X11, D-Bus, and PipeWire sockets addressed
  by abstract name cannot be reached.

## Landlock-only mode

Allowing any egress means the sandbox needs real connectivity, which a namespace
with no route cannot provide, so the target stays in the host's network namespace
and Landlock enforces the policy's TCP ports.

That is a genuinely weaker position, and the run says so:

```
bailey: warning: outbound access is restricted by TCP port only;
UDP, QUIC, and DNS are not restricted
```

Two things are worth knowing about this mode, because both are permanent rather
than pending:

- **UDP, QUIC, DNS, and ICMP are unrestricted.** Landlock has no rule for them.
- **The host's loopback is reachable.** The target shares your network namespace,
  so a service on `127.0.0.1` is subject only to the TCP port rules, and any UDP
  port on loopback is reachable outright.

If you need a program to reach one TCP port and nothing else, this mode does
that. If you need more than that, deny egress entirely and give the program its
data another way, or put it behind a proxy that can filter.

Because the target shares the host's network namespace, it also sees the host's
interfaces: the IP address, the MAC, the ARP neighbours, and the routes are all
readable, whether through `ip`, `/proc/net`, or `/sys/class/net`. Blocking one
of those does not help, since the same facts are reachable through the others,
and the host's global IPv6 address encodes the interface MAC on its own.

### Hiding the host's address with `--proxy-net`

`bailey run --proxy-net` gives the target its own network namespace after all,
with connectivity supplied by [pasta](https://passt.top). The target sees a
private address and a synthetic MAC in place of the host's; egress still leaves
over the host's connection, and the policy's TCP ports are still enforced by
Landlock inside the namespace exactly as they are without it.

```sh
bailey run --proxy-net /usr/bin/ip -o addr show scope global
# a private address such as 10.0.2.15, never the host's
```

It needs pasta on `PATH` and unprivileged user namespaces. Without either, the
run continues and says the host address stays visible rather than failing. Egress
is IPv4 only, so the host's global IPv6, and the MAC embedded in it, are never
formed. This addresses the host-identity exposure above; it does not tighten the
egress surface, which the policy's ports already govern.

## Scoping

Independently of the mode, on Linux 6.12 and later bailey asks Landlock to scope
the target away from two things that no path rule can cover:

- **Abstract UNIX sockets** created outside the sandbox.
- **Signals** to processes outside the sandbox.

```sh
bailey run /usr/bin/python3 -c "import os; os.kill($$, 0)"
# PermissionError
```

This is what protects a target in landlock-only mode, where there is no network
namespace to isolate the abstract socket namespace. On older kernels the request
is dropped, along with the protection.

## What is not covered

- **Host and CIDR rules in `egress_allow` are advisory.** Landlock matches on TCP
  port; the host field is not enforced, and bailey warns when you set one.
- **UDP filtering.** There is no mode that allows some UDP and denies the rest.
- **Ingress.** A sandbox in isolated mode has no address, so there is nothing to
  reach it on. In landlock-only mode, `bind_ports` governs what it may listen on.

See [known limitations](/security/limitations) for the full list.
