# The policy model

Everything in bailey routes through one value: a resolved `Policy`. Config
produces it, backends consume it, and nothing else crosses between them.

```
profile ──┐
global ───┤
bailey.toml (walked up) ──┼──▶ resolve ──▶ Policy ──┬──▶ enforce backend
--config ─┘                                         └──▶ audit backend
```

## What a policy contains

A policy is declarative intent, independent of any kernel mechanism:

- **Filesystem grants**: a path hierarchy and the rights on it, read, write, or
  execute. A grant on a directory covers everything beneath it.
- **Network policy**: egress denied, allowed, or allowed to a list of
  destinations, plus the TCP ports the program may bind.
- **Device grants**: paths under `/dev` with their rights. Device grants share
  filesystem semantics; they are separate in config because they are a different
  decision.
- **Resource limits**: memory, process count, and CPU quota.

It carries no notion of Landlock rules, seccomp filters, mount points, or cgroup
files. That separation is what lets the same value drive both backends.

## Why two backends

Landlock has no permissive mode. It denies, silently, by construction. There is no
flag that makes it log what it would have denied, and kernel audit logging only
records denials under a ruleset that is already strict, so it cannot tell you what
a program *wants*.

So observing and enforcing are mechanically different things:

- The **enforcement backend** builds a deny-by-default world with Landlock,
  seccomp, cgroups, and optionally namespaces.
- The **audit backend** runs the program permissively while eBPF programs record
  what it touches.

They share the policy type, which is what makes the workflow work: a profile you
built by watching a program is directly usable for confining it.

## Deny by default

Anything the policy does not grant is denied. This has a consequence people meet
immediately: a dynamically linked program needs read and execute on the dynamic
linker and the shared libraries it loads, and those are filesystem access like any
other. The `untrusted` floor profile exists to supply that baseline, and it is
applied beneath every run.

## Resolution is deterministic

Given the same config files and the same target, resolution produces the same
policy, independent of environment ordering. Where two layers say things that
cannot both be true within one layer, such as granting and denying the same path,
resolution fails with an error naming the file and the path rather than silently
dropping a rule.

See [configuration](/guide/configuration) for the layer order and merge rules.

## Inspecting a resolved policy

```sh
bailey show ./program
```

This prints the profile base, every config file that contributed in precedence
order, and the merged policy. When something is unexpectedly denied, this is where
to start: a rule you thought applied is usually in a layer that was never
discovered.
