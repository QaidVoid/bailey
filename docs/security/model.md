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
| Cannot see ungranted paths | Mount namespace, `pivot_root` | Enforced under `--isolate` |
| Cannot see or signal host processes | PID namespace | Enforced under `--isolate` |
| Cannot open ungranted TCP connections | Landlock network rules | Enforced on Linux 6.7+ |
| Cannot reach host abstract UNIX sockets | Landlock scoping, network namespace | Enforced on Linux 6.12+ |
| Cannot signal processes outside the sandbox | Landlock scoping, PID namespace | Enforced on Linux 6.12+ |
| Cannot send UDP, QUIC, or DNS | Network namespace | Enforced when egress is denied |
| Cannot load kernel modules, trace processes, or manipulate namespaces | seccomp | Enforced |
| Cannot exceed memory, process, or CPU limits | cgroup v2 | Best-effort, and see the caveat below |
| Cannot read your environment variables | Built environment | Enforced; only named variables cross |
| Cannot supply its own policy | Trust store | Enforced; a discovered config applies only once accepted |

## Where the guarantees end

**Non-TCP traffic under a partial allowance.** Allowing any egress drops the
network namespace, leaving only TCP port rules. There is no mode that allows some
UDP and denies the rest.

**Variables you pass.** `pass` forwards a variable verbatim, so passing one that
holds a credential puts that credential in the sandbox.

**Nested denials without isolation.** Denying a path inside a granted directory
is enforced only under `--isolate`, where the path can be covered over.

**Side channels.** Bailey does not attempt to prevent timing attacks, resource
observation, or anything else in that family.

**The display server.** X11 gives every client access to every other client's
input and window contents. No filesystem policy fixes that; use Wayland.

**Anything granted.** A program granted `/dev/dri` can talk to the GPU, and GPU
drivers are a large kernel attack surface. Every grant is a decision, and the
device grants are the expensive ones.

**A partial egress allowance.** Allowing any egress drops the network namespace,
so non-TCP traffic and the host's loopback are both reachable.

The full list with details is in [known limitations](/security/limitations).

## Defence in depth

The layers overlap deliberately. Landlock is the access control; seccomp removes
syscalls that would be useful for escaping it; namespaces remove the paths and
processes from view entirely; cgroups bound the damage of the crudest attacks. A
weakness in any one of them does not immediately hand over the machine.

That is a reason to use `--isolate` even though Landlock alone already denies:
absence is a stronger property than refusal, and it is enforced by a different
mechanism.
