# Quick start

This walks through confining a program you do not trust, from nothing to a
working policy.

## 1. Look before you run

Every run resolves a policy first. Ask what it will be:

```sh
bailey show ./program
```

```
profile base: untrusted
config layers: (none)

filesystem:
  r-x /bin
  r-- /etc
  r-x /lib
  r-x /lib64
  r-- /proc
  r-x /sbin
  r-- /sys
  r-x /usr
network:
  egress: DenyAll
  bind_ports: []
devices:
  rw- /dev/full
  rw- /dev/null
  r-- /dev/random
  rw- /dev/tty
  r-- /dev/urandom
  rw- /dev/zero
resources: ResourceLimits { memory_bytes: None, pids_max: None, cpu_percent: None }
```

That is the `untrusted` floor profile: enough for a dynamically linked binary to
start, and nothing else. No home directory, no network, no GPU.

## 2. Run it

```sh
bailey run ./program
```

The program itself is granted implicitly, as the lowest layer, so a binary
outside the system paths starts without any config. Everything else it wants is
denied, which is usually the next thing you find out.

## 3. Add what it actually needs

Put a `bailey.toml` next to the program and add grants one at a time:

```toml
[filesystem]
read = ["."]
write = ["./data"]
```

Paths are relative to the config file's own directory, so `.` here means the
directory the program lives in.

When you cannot guess, stop guessing and record a session:

```sh
bailey audit --save-trace trace.json ./program
```

The output lists every access the current policy does not grant, with the
high-risk ones separated out. Turn the reviewed trace into a profile:

```sh
bailey profile generate --trace trace.json --target ./program > bailey.toml
```

See [auditing a program](/guide/audit) for the whole loop.

## 4. Turn on isolation

By default, ungranted paths are denied but still visible: the program can see that
`/home/you/.ssh` exists, it just cannot open it. Isolation rebuilds the world so
those paths are not there at all, and host processes are invisible:

```sh
bailey run --isolate ./program
```

This needs unprivileged user namespaces. Where they are unavailable, bailey warns
and falls back to Landlock and seccomp.

::: warning
Under `--isolate` today, the working directory is not carried into the new root,
so relative paths do not resolve. Use absolute paths, or run without `--isolate`,
until [this is fixed](/roadmap).
:::

## 5. Start from a profile

Rather than building a policy from nothing, start from one shaped for your case:

```sh
bailey profile list
bailey run --profile native-game ./game
```

Profiles are additive over the `untrusted` floor, and your own config layers on
top of them. See [profiles](/guide/profiles).

## Where to go next

- [Configuration](/guide/configuration) for the full config model.
- [The policy model](/guide/policy-model) for how layers resolve.
- [Known limitations](/security/limitations) for what is not enforced yet. Read
  this one before you rely on the sandbox for anything that matters.
