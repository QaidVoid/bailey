# Network confinement

The base network mode follows the policy. `bailey show <target>` prints it;
`bailey run --proxy-net` or `bailey shell --proxy-net` can add a private
namespace with connectivity for allowed egress.

| Policy | Mode | What is enforced |
| --- | --- | --- |
| `egress = "deny"` | **isolated** | Own network namespace, loopback only. Only explicit forwards reach host services |
| Any egress allowed, without `--proxy-net` | **landlock only** | Landlock rules over TCP ports. Other protocols are unrestricted |
| Any egress allowed, with `--proxy-net` | **proxy network** | Private namespace with pasta connectivity. Explicit forwards and publications require fail-closed setup |

The default policy denies egress, so the default mode is isolated. Explicit
`[[forward]]` entries can carry selected host TCP services into a private
namespace without exposing other host loopback services. With allowed egress,
these entries require explicit `--proxy-net` on `bailey run` or `bailey shell`.

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
non-TCP protocols such as UDP, QUIC, SCTP, and DNS are not restricted
```

Two things are worth knowing about this mode, because both are permanent rather
than pending:

- **UDP, QUIC, DNS, ICMP, and stream protocols such as SCTP are unrestricted.**
  Landlock has no rule for them. MPTCP and SMC are refused outright instead,
  since they would carry TCP traffic past the port rules.
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

It needs pasta in a trusted system location and unprivileged user namespaces.
Without either, the run continues and says the host address stays visible rather
than failing, unless forwards, publications, or `--egress-proxy` require fail-closed isolation.
The namespace is given a private IPv6 address as well, where the host has one to
reach, so the host's global IPv6 and the MAC embedded in it are never formed; on
a host with no IPv6, the namespace gets none rather than a route it cannot
follow. This addresses the host-identity exposure above; it does not tighten the
egress surface, which the policy's ports already govern. With denied egress,
`--proxy-net` does not add connectivity.

pasta can forward namespace loopback to the host's loopback. Under
`--proxy-net`, bailey blocks that access with a netfilter rule. Without
forwards or publications, this protection is best-effort and needs `nft`; the run reports if
the rule cannot be installed. The default landlock-only mode shares the host
network namespace, so there is no separate loopback to protect there.

### Reaching selected host services while online

Use `[[forward]]` with `--proxy-net` to expose selected host TCP services while
keeping the policy's internet access:

```toml
[network]
egress = "allow"

[[forward]]
port = 8080
```

```sh
bailey shell --proxy-net
```

The sandbox's `127.0.0.1:8080` now reaches a host service such as zai-proxy on
`127.0.0.1:8080`. Set `host_port` to use a different host port. General internet
egress stays available, while unrelated host loopback services remain blocked.
With `egress_allow`, the existing TCP port allowance is retained instead.
Forward-only ports do not become new internet permissions.

Online forwards require explicit `--proxy-net`, isolation, pasta, working
unprivileged user namespaces, and `nft`. Missing prerequisites or failure to
install the firewall refuse the run. The firewall permits the selected TCP
loopback connections and established replies, then blocks other host loopback
access. Only explicit TCP forwards are enabled, with no automatic, inbound, or
UDP forwarding. The forwards stay private to the sandbox.

Forwards without `--proxy-net` are supported only with denied egress. Combining
forwards with `--egress-proxy` is refused so the broker remains the sole egress
path. Both `bailey run` and `bailey shell` support these options. See
[desktop services and mounts](/guide/desktop) for remapping and concurrency.

### Publishing a sandbox service

Publication is the reverse of a forward: it makes a TCP service inside the
sandbox reachable from the host, only at `127.0.0.1:PORT`. For a dev server on
3800, use a policy with allowed egress and permission to bind that port:

```toml
[network]
egress_allow = [{ host = "*", port = 443 }]
bind_ports = [3800]
```

```sh
bailey shell --proxy-net --publish-port 3800
# Inside the confined shell:
python3 -m http.server 3800 --bind 127.0.0.1
```

From a separate host terminal, open `http://127.0.0.1:3800`. A server bound to
sandbox `0.0.0.0:3800` works too. The host's LAN addresses do not expose it.
Instead of the repeatable `--publish-port` flag, add `publish_ports = [3800]`
to `[network]`. Entries accumulate across layers and are cleared alongside
forwards by `[filesystem] reset = true`.

Publication does not grant outbound egress or unblock unrelated host loopback
services. It publishes IPv4 TCP only, never UDP or IPv6. Port 0 is a config
error, and a published port matching either a forward's sandbox port or its
host port is refused. Each publication is reported before the target starts.

Publishing requires explicit `--proxy-net`, namespace isolation, and allowed
egress. It is unavailable in audit or without the proxy network setup, and is
refused with `--no-proxy-net`, `--no-isolate`, `--egress-proxy`, or
`egress = "deny"`. Missing pasta, working unprivileged user namespaces, or
`nft`, or failure to install the firewall, refuses the run rather than
degrading it.

### Forcing egress through a broker with `--egress-proxy`

Port rules cannot tell one host on 443 from another, so a session may reach any
host there, and a userspace VPN turns that reach into a two-way channel.
`--egress-proxy ADDR:PORT` closes that. It implies `--proxy-net`, maps the
host's loopback into the namespace at ADDR so a broker listening on the host is
reachable, and installs a netfilter rule that drops every outbound connection
except one to ADDR:PORT.

```sh
bailey run --egress-proxy 169.254.169.1:8443 -- curl https://example.com
# reaches the broker at 169.254.169.1:8443 and nothing else; 1.1.1.1:443 is dropped
```

`bailey shell --egress-proxy 169.254.169.1:8443` applies the same lockdown
to an interactive shell. Broker mode cannot be combined with publications or `--no-isolate`.

The broker is whatever the caller runs there: it admits an allowlist of hosts
and refuses the rest, so a session reaches the endpoints it needs and no relay
it does not. The lockdown is the enforcement, and it is fail-closed: if the
netfilter rule cannot be installed, or pasta or user namespaces are missing,
the run is refused rather than left with open egress. `nft` must be present.

Inside the session, TCP to ADDR:PORT is the only way out. UDP, ICMP, and all of
IPv6 are dropped, so there is no DNS and no path MTU discovery. A client names
its destination to the broker, and the broker resolves and dials it from the
host. When a client reaches the broker but times out waiting for its reply,
the delay lies in the broker's lookup or dial, and the broker's own log is
where that shows. The session also cannot list the rule,
because `nft` inside it has no permission to read the table.

A brokered run publishes `BAILEY_SANDBOX_NET=broker`, so a program or a nested
run can tell it is in one. The run summary reports the lockdown as `egress
broker` rather than warning that UDP is unrestricted.

bailey creates the network namespace itself and then has pasta configure it,
rather than the other way round. The rule is installed by the process that made
the namespace, which is the only way to know which namespace it lands in: a
process that has to be told cannot check the answer, because whatever it is told
the caller chose. There is no flag that says "this run is already inside a
namespace", and a caller cannot ask for the rule to be installed anywhere.

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
- **Ingress.** A sandbox in isolated mode has no address, so nothing outside can
  reach it; a port it binds is reachable from inside the sandbox and nowhere
  else. In landlock-only mode without `--proxy-net`, `bind_ports` governs what
  it may listen on and the port is reachable as usual. Online forwards under
  `--proxy-net` do not enable inbound access. Explicit `publish_ports` entries
  or `--publish-port` flags expose only the selected IPv4 TCP ports on the
  host loopback.

See [known limitations](/security/limitations) for the full list.
