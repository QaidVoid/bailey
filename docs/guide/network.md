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
it applies to a plain `bailey run`. `--isolate` is not required for it.

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

If you need a program to reach one TCP port and nothing else, this mode does
that. If you need UDP filtering, bailey cannot give it to you today; deny egress
entirely, or put the program behind something that can.

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
