# Network confinement

The policy's `mode` key picks how the network is placed. `bailey show <target>`
prints the decision a run would make, naming the layer or flag that chose it.

| Policy | Mode | What is enforced |
| --- | --- | --- |
| `egress = "deny"` | **isolated** | Own network namespace, loopback only, in every mode. Only explicit forwards reach host services |
| `broker = "ADDR:PORT"` | **brokered** | Private namespace held to one egress route, in every mode. Destination rules are superseded by the broker and the summary says so |
| Egress allowed, `mode = "private"` | **private** | Private namespace with pasta connectivity; destination rules and DNS enforced by nftables; refused where the host cannot provide it |
| Egress allowed, `mode = "host"` | **host** | The host's namespace, with Landlock rules over TCP ports. Other protocols are unrestricted, and destination rules are refused |
| Egress allowed, `mode = "auto"` (default) | **private or host** | The private namespace where the host provides it, otherwise the host's namespace, unless the policy needs the private one and the host cannot provide it |

The default policy denies egress, so the default mode is isolated. `bailey
doctor` states whether the private network is available on your host and what
automatic mode will do as a result.

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

A policy that denies egress keeps this namespace whatever `mode` says, because
the namespace is the only way to deny every protocol at once, and no mode
setting asks to give that up. The namespace is created through a user namespace,
so it needs no privilege, and it applies to every `bailey run`, including one
with `--no-isolate`: a denied egress is enforced this way regardless of the
filesystem isolation.

Two things come along with the namespace:

- **Loopback still works inside the sandbox.** A program that binds a local port
  for its own IPC keeps working. That loopback reaches nothing but the sandbox;
  the host's loopback services are in a different namespace.
- **Host abstract UNIX sockets are unreachable.** The abstract socket namespace
  is tied to the network namespace, so X11, D-Bus, and PipeWire sockets addressed
  by abstract name cannot be reached.

## Host mode

`mode = "host"` shares the host's network namespace, and Landlock enforces the
policy's TCP ports. Automatic mode falls back to it where the host cannot
provide the private namespace and nothing in the policy needs the private one.

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
data another way, or put it behind a broker that can filter.

Because the target shares the host's network namespace, it also sees the host's
interfaces: the IP address, the MAC, the ARP neighbours, and the routes are all
readable, whether through `ip`, `/proc/net`, or `/sys/class/net`. Blocking one
of those does not help, since the same facts are reachable through the others,
and the host's global IPv6 address encodes the interface MAC on its own.

Resolution rejects policy elements that need a private namespace alongside host
mode: a broker, published ports, or forwards under allowed egress are all
refused, naming the layers that set them.

## Private mode

`mode = "private"` gives the target its own network namespace after all, with
connectivity supplied by [pasta](https://passt.top). The target sees a private
address and a synthetic MAC in place of the host's; egress still leaves over the
host's connection, and the policy's TCP ports are enforced by Landlock inside
the namespace exactly as they are without it.

```sh
bailey run /usr/bin/ip -o addr show scope global
# a private address such as 10.0.2.15, never the host's
```

It needs pasta in a trusted system location and unprivileged user namespaces.
Where either is missing, an explicit `private` mode refuses the run rather than
silently staying on the host's network: the request is the policy's, and a
downgrade would lie about where the session's traffic leaves from. The namespace
is given a private IPv6 address as well, where the host has one to reach, so the
host's global IPv6 and the MAC embedded in it are never formed; on a host with
no IPv6, the namespace gets none rather than a route it cannot follow. This
addresses the host-identity exposure above; it does not tighten the egress
surface, which the policy's ports already govern. With denied egress, private
mode changes nothing that is enforced, since the isolated namespace is already
the strictest placement.

### Naming destinations

Port rules cannot tell one host on 443 from another: with a plain port
allowance, a session may reach any host there. In the private namespace the
policy's rules are enforced by nftables instead, per destination, so the host
part of a rule is the enforcement and not a wish:

```toml
[network]
egress_allow = [{ host = "api.example.com", port = 443 }]
```

```sh
bailey run -- curl https://api.example.com/v1/models
# reaches api.example.com on 443; every other destination is dropped
```

Bailey resolves each hostname once, on the host, before the target starts. The
addresses it resolved to are what the firewall admits, and the same names
resolve to those addresses inside the sandbox, so the destinations the rules
enforce and the ones a client dials are the same addresses. A name that does
not resolve refuses the run: a rule naming it could otherwise only ever be a
silent no-op.

A block covers a range, and `protocol = "udp"` covers a datagram port:

```toml
[network]
egress_allow = [
  { host = "10.0.0.0/8", port = 443 },
  { host = "game.example.net", port = 7777, protocol = "udp" },
]
```

`egress_deny` drops traffic ahead of every allowance, which is how a cloud
metadata service is kept out of an otherwise allowed range:

```toml
[network]
egress_allow = [{ host = "10.0.0.0/8", port = 443 }]
egress_deny = [{ host = "169.254.169.254", port = 80 }]
```

Rules accumulate across config layers, entries for port 53 are refused (DNS is
the `dns` setting's decision, not a rule's), and a deny naming loopback is
refused, since the sandbox's own loopback is how its services talk to each
other. The run summary lists each rule in force, the addresses each hostname
resolved to, and the DNS state.

Destination rules need the private namespace, and they need `nft` in a trusted
location to install the firewall. Under host mode a policy that names
destinations is refused, naming the layer that set it; under automatic mode the
private namespace becomes required, and the run is refused where the host
cannot provide it.

### DNS inside the sandbox

The `dns` setting decides who answers the target's questions:

- `dns = "allow"` permits DNS, delivered to the namespace's forwarder and no
  one else. The forwarder answers UDP and TCP, so a truncated or large answer
  that drives the resolver to TCP is answered too.
- `dns = "deny"` drops DNS questions whatever the allow rules say.
- `dns = "auto"`, the default, allows DNS exactly when a rule names any
  address (`host = "*"`): a rule that reaches every address is useless without
  resolution, and one that names its destinations is safer without it, since
  the pinned names resolve from the generated `/etc/hosts` alone.

When a hostname rule is pinned, its name resolves inside the sandbox without
sending any query. A query to a public resolver such as `8.8.8.8` is dropped in
every case: the forwarder is the only DNS path there is.

### Automatic mode

`mode = "auto"`, the default, prefers the private namespace wherever the host
provides it: a policy that allows egress runs there with no flag. Where the host
cannot, what happens depends on what the policy needs:

- **Nothing needs the private namespace** (no forwards, published ports, or
  broker): the run continues in the host's namespace and warns that the host's
  address and loopback are visible and only TCP ports are restricted.
- **The policy needs the private namespace**: the run is refused, naming pasta
  or the user namespaces as the missing prerequisite, and what needed it.

`bailey show <target>` prints the same decision a run would make, refusal
included, before anything starts.

### The flags as overrides

The flags map onto the mode as the highest layer, above every config file:

| Flag | Mode it asks for |
| --- | --- |
| `--proxy-net` | `private` |
| `--no-proxy-net` | `host` |
| `--egress-proxy ADDR:PORT` | A broker at that address |
| `--no-isolate` | `host` for automatic mode, where nothing else asks |

A flag rescues a contradiction a config layer wrote: `mode = "host"` beside a
forward is refused, but `--proxy-net` beside the same forward raises the mode
above the refusal. `--no-isolate` promises a run of Landlock and seccomp alone,
so automatic mode does not hand back a namespace with it; a policy or flag that
asks for the private network outright is still honoured, since the request is
the user's and the fallback is bailey's.

### Reaching selected host services while online

Use `[[forward]]` to expose selected host TCP services while keeping the
policy's internet access:

```toml
[network]
egress = "allow"

[[forward]]
port = 8080
```

```sh
bailey shell
```

No flag is needed: automatic mode provides the private namespace the forwards
are carried by, wherever the host can. The sandbox's `127.0.0.1:8080` now
reaches a host service such as zai-proxy on `127.0.0.1:8080`. Set `host_port`
to use a different host port. General internet egress stays available, while
unrelated host loopback services remain blocked. With `egress_allow`, the
existing TCP port allowance is retained instead. Forward-only ports do not
become new internet permissions.

Online forwards need the private namespace, namespace isolation, pasta, and
working unprivileged user namespaces, which automatic mode arranges where the
host can; a run that needs them where the host cannot provide them is refused,
naming pasta and the forward. The firewall permits the selected TCP loopback
connections and established replies, then blocks other host loopback access.
Only explicit TCP forwards are enabled, with no automatic, inbound, or UDP
forwarding. The forwards stay private to the sandbox.

Forwards without the private namespace are supported only with denied egress,
where the backend carries them in the namespace the policy builds anyway.
Combining forwards with a broker is refused so the broker remains the sole
egress path. Both `bailey run` and `bailey shell` support these options. See
[desktop services and mounts](/guide/desktop) for remapping and concurrency.

### Publishing a sandbox service

Publication is the reverse of a forward: it makes a TCP service inside the
sandbox reachable from the host, only at `127.0.0.1:PORT`. For a dev server on
3800, use a policy with allowed egress and permission to bind that port:

```toml
[network]
egress_allow = [{ host = "*", port = 443 }]
bind_ports = [3800]
publish_ports = [3800]
```

```sh
bailey shell
# Inside the confined shell:
python3 -m http.server 3800 --bind 127.0.0.1
```

From a separate host terminal, open `http://127.0.0.1:3800`. A server bound to
sandbox `0.0.0.0:3800` works too. The host's LAN addresses do not expose it.
Instead of the `publish_ports` key, pass the repeatable `--publish-port` flag.
Entries accumulate across layers and are cleared alongside forwards by
`[filesystem] reset = true`.

Publication does not grant outbound egress or unblock unrelated host loopback
services. It publishes IPv4 TCP only, never UDP or IPv6. Port 0 is a config
error, and a published port matching either a forward's sandbox port or its
host port is refused. Each publication is reported before the target starts.

Publishing needs the private namespace and namespace isolation, which
automatic mode provides where the host can. It is unavailable in audit, and is
refused with `mode = "host"`, a broker, `--no-proxy-net`, `--no-isolate`, or
`egress = "deny"`. Missing pasta, working unprivileged user namespaces, or
`nft`, or failure to install the firewall, refuses the run rather than
degrading it.

### Holding egress to a broker

Port rules cannot tell one host on 443 from another, so a session may reach any
host there, and a userspace VPN turns that reach into a two-way channel. A
broker closes that: every outbound connection except one to the broker is
dropped, so the session reaches the broker and nothing else.

```sh
bailey run --egress-proxy 169.254.169.1:8443 -- curl https://example.com
# reaches the broker at 169.254.169.1:8443 and nothing else; 1.1.1.1:443 is dropped
```

A policy can name the broker instead of a flag:

```toml
[network]
broker = "169.254.169.1:8443"
```

```sh
bailey run -- curl https://example.com
# the same confinement, chosen by the config layer
```

The broker implies the private namespace, and maps the host's loopback into it
at ADDR so a broker listening on the host is reachable. `bailey shell
--egress-proxy 169.254.169.1:8443` applies the same lockdown to an interactive
shell. A broker cannot be combined with publications, host mode, or
`--no-isolate`; those combinations are refused, naming the layers involved.

Destination rules beside a broker start the run rather than refusing it: the
broker's namespace is built for the broker alone, so the rules have nothing to
attach to, and the summary says they are superseded. Read that line as what it
is: the broker is the egress policy in force, and the config's rules are not.

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

## Nested runs

A run started inside another bailey sandbox cannot create a network namespace
or install netfilter rules of its own, so it inherits the outer run's network
and enforces only what it can apply itself, which is Landlock's TCP port rules.
A nested policy that needs more is refused: forwards, published ports, a
broker, and explicit private mode all refuse a nested run, whatever network the
outer run provides, because the outer run's rules are its own policy, not the
inner one's. The nested run's report says the network is inherited and names
only the restrictions it applied itself.

## Migration

Three behaviours changed, all in the same direction: what used to be a flag
requirement is now a policy decision, and what used to degrade silently now
refuses.

- **Forwards and publications no longer need `--proxy-net`.** With allowed
  egress, automatic mode provides the private namespace they are carried by
  wherever the host can. Configs that spelled the flag out can drop it.
- **`--proxy-net` and `mode = "private"` refuse where the host cannot provide
  the private namespace**, instead of continuing with a warning. A run that
  must not touch the host's network says so rather than downgrading. Automatic
  mode still continues where nothing needs the private namespace.
- **A broker can be named in config** with `broker = "ADDR:PORT"`, and is
  confined exactly as `--egress-proxy` confines a run.
- **Host and CIDR rules in `egress_allow` are enforced now.** They used to be
  advisory, enforced by port alone; they now need the private namespace, where
  the host part is enforced by nftables, and a policy that names destinations
  refuses where the private namespace cannot be provided.

## Scoping

Independently of the mode, on Linux 6.12 and later bailey asks Landlock to scope
the target away from two things that no path rule can cover:

- **Abstract UNIX sockets** created outside the sandbox.
- **Signals** to processes outside the sandbox.

```sh
bailey run /usr/bin/python3 -c "import os; os.kill($$, 0)"
# PermissionError
```

This is what protects a target in host mode, where there is no network
namespace to isolate the abstract socket namespace. On older kernels the request
is dropped, along with the protection.

## What is not covered

- **The sandbox's own loopback.** Inside the private namespace, loopback is how
  the target's services talk to each other, and the firewall admits it whole. A
  port the target binds is reachable from everywhere in the sandbox.
- **What shares an admitted address.** A rule admits an address, and whatever
  else answers on that address is admitted with it: a hosting neighbour, a
  round-robin name that rotates mid-run, a pinned name whose DNS record changed
  after the run started. See [known limitations](/security/limitations).
- **Ingress.** A sandbox in isolated mode has no address, so nothing outside can
  reach it; a port it binds is reachable from inside the sandbox and nowhere
  else. In host mode, `bind_ports` governs what it may listen on and the port
  is reachable as usual. Online forwards do not enable inbound access. Explicit
  `publish_ports` entries or `--publish-port` flags expose only the selected
  IPv4 TCP ports on the host loopback.

See [known limitations](/security/limitations) for the full list.
