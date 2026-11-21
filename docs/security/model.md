# Threat model

What bailey is trying to stop, what it assumes, and where its guarantees end.

## The threat

Code you run without having read it, executing with your full user authority. It
does not have to be malicious to be a problem; it has to be wrong, or compromised
upstream, or doing something reasonable that you would not have agreed to.

The specific outcomes worth preventing:

- **Reading things it has no business reading.** SSH keys, cloud credentials,
  browser profiles, password manager databases, documents, other projects' source.
- **Writing things it has no business writing.** Shell profiles, autostart
  entries, systemd user units, other programs' config: all of the ways a program
  turns one execution into persistence.
- **Sending what it read somewhere.** Exfiltration, telemetry you did not agree
  to, a command-and-control channel.
- **Interfering with other processes.** Reading another process's memory, tracing
  it, signalling it.
- **Consuming the machine.** Fork bombs, memory exhaustion.

## The attacker

An unprivileged program on your machine, running as you, which may be actively
hostile and which knows it might be sandboxed. It cannot already be root, and it
does not have a kernel exploit. If either of those is false, no unprivileged
sandbox helps.

## Assumptions

- **The kernel is sound.** Every guarantee here is the kernel's. A Landlock, user
  namespace, or seccomp bug undoes it.
- **The host is not already compromised.** Bailey confines what it starts. It does
  not clean up what was there before.
- **The policy is what the user meant.** A policy granting the home directory
  confines nothing interesting. A config found in a directory is not part of the
  policy until the user accepts it, so a repository cannot ship the policy that
  is meant to contain it.
- **The user reads the audit output.** Generating a profile from a hostile
  program's trace and accepting it grants exactly what the hostile program did.

## What is enforced

| Property | Mechanism | Status |
| --- | --- | --- |
| Cannot read or write ungranted paths | Landlock | Enforced |
| Cannot see ungranted paths | Mount namespace, `pivot_root` | Enforced unless `--no-isolate` |
| Cannot see or signal host processes | PID namespace | Enforced unless `--no-isolate` |
| Cannot open ungranted TCP connections | Landlock network rules, plus the seccomp refusal of MPTCP and SMC sockets | Enforced on Linux 6.7+; the seccomp part needs seccomp filters |
| Cannot reach a destination the policy does not name, TCP or UDP | nftables in the private network namespace, from addresses resolved before the target starts | Enforced where the private namespace runs; needs `nft` in a trusted location. Under a broker the broker is the boundary instead |
| Cannot reach host abstract UNIX sockets | Landlock scoping, network namespace | Enforced on Linux 6.12+ |
| Cannot connect to a pathname UNIX socket the policy does not list | Landlock socket connect right, `connect` entries | Enforced on Linux 7.1+; on older kernels a read grant on the socket's directory is enough, and under `--no-isolate` no grant is needed |
| Cannot signal processes outside the sandbox | Landlock scoping, PID namespace | Enforced on Linux 6.12+ |
| Cannot send UDP, QUIC, or DNS to destinations the policy does not name | nftables in the private network namespace | Enforced where the private namespace runs; in the host's namespace, non-TCP traffic is unrestricted |
| Cannot send UDP, QUIC, or DNS anywhere | Network namespace | Enforced when egress is denied, and when the `dns` setting drops DNS |
| Cannot load kernel modules, trace processes, or create namespaces | seccomp, capability drop, kernel limit | Enforced: `unshare`, `setns`, and `clone` with a `CLONE_NEW*` flag are refused, `clone3` is refused with the error libcs fall back from, and on any run that builds a user namespace a kernel limit leaves nothing beneath it for the target |
| Cannot exceed memory, process, or CPU limits | cgroup v2 | Best-effort, and see the caveat below. Without a cgroup, `open_files` and `file_max` still hold as rlimits, and `address_space` bounds each process where `memory` cannot be carried |
| Cannot read your environment variables | Built environment | Enforced; only named variables cross |
| Cannot supply its own policy | Trust store | Enforced; a discovered config applies only once accepted |

## Where the guarantees end

**Non-TCP traffic in the host's namespace.** Allowing egress prefers the
private namespace, where UDP is governed per destination like TCP. Where the
host cannot provide it, the run falls back to the host's namespace and only
Landlock's TCP port rules apply: UDP, SCTP and the rest are unrestricted there,
and the run says so.

**Variables you pass.** `pass` forwards a variable verbatim, so passing one that
holds a credential puts that credential in the sandbox.

**Nested denials without isolation.** Denying a path inside a granted directory,
or marking one read-only, is enforced only by the isolation layer, where the path
can be covered over or remounted. `--no-isolate` gives that up.

**Side channels.** Bailey does not attempt to prevent timing attacks, resource
observation, or anything else in that family.

**The display server.** X11 gives every client access to every other client's
input and window contents. No filesystem policy fixes that; use Wayland.

**Anything granted.** A program granted `/dev/dri` can talk to the GPU, and GPU
drivers are a large kernel attack surface. Every grant is a decision, and the
device grants are the expensive ones.

**A partial egress allowance.** A partial allowance reaches the internet. What
it reaches is limited in the private namespace by the named destinations and
the addresses they resolved to, but whatever shares an admitted address is
admitted with it, and a hostname's addresses are whatever resolution returned
when the run started.

The full list with details is in [known limitations](/security/limitations).

## Defence in depth

The layers overlap deliberately. Landlock is the access control; seccomp removes
syscalls that would be useful for escaping it; namespaces remove the paths and
processes from view entirely; cgroups bound the damage of the crudest attacks. A
weakness in any one of them does not immediately hand over the machine.

That is why isolation is the default rather than an option, even though Landlock
alone already denies: absence is a stronger property than refusal, and it is
enforced by a different mechanism.
