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
  r-x /home/you/programs/program
  r-x /usr
network:
  egress: DenyAll
  bind_ports: []
  mode: isolated (own namespace, loopback only, no route off the host)
devices:
  rw- /dev/full
  rw- /dev/null
  r-- /dev/random
  rw- /dev/tty
  r-- /dev/urandom
  r-- /dev/zero
resources: ResourceLimits { memory_bytes: None, pids_max: None, cpu_percent: None, tmp_bytes: None, shm_bytes: None }
home: /home/you/.local/share/bailey/program/home
  (private; the real home is not granted)
environment:
  HOME=/home/you/.local/share/bailey/program/home  (base)
  LANG=C.UTF-8  (base)
  ...
```

That is the `untrusted` floor profile, plus the target itself: enough for a
dynamically linked binary to start, and nothing else. No home directory, no
network, no GPU.

The last three sections are worth reading as carefully as the first. `mode` says
how the network policy will actually be enforced, `home` says where the program's
writes will land, and `environment` is the exact set of variables it will be
handed.

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

A config found by walking a directory could have arrived with the program, so it
applies only once you accept it:

```sh
bailey trust ./bailey.toml
```

Do that again whenever you edit the file. Until you do, the run reports the file
it skipped rather than applying it. See
[trusting a config](/guide/trusting-a-config).

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

## 4. Know what isolation is doing

Landlock alone denies ungranted paths but leaves them visible: the program can
see that `/home/you/.ssh` exists, it just cannot open it. Isolation rebuilds the
world so those paths are not there at all, and host processes are invisible.

It is on by default. Turning it off leaves Landlock and seccomp:

```sh
bailey run --no-isolate ./program
```

Four things stop being enforceable without it: a nested `deny`, a `read_only`
island, the private `/tmp`, and the private home at your real home's path. Each
is reported as unenforced rather than silently dropped.

Isolation needs unprivileged user namespaces. Where they are unavailable, bailey
warns and falls back to Landlock and seccomp on its own.

It also gives the program a private `/tmp`, a private home, and the directory you
invoked it from, so relative paths work as they do outside. See
[environment and storage](/guide/environment).

## 5. Start from a profile

Rather than building a policy from nothing, start from one shaped for your case:

```sh
bailey profile list
bailey run --profile native-game ./game
```

Profiles are additive over the `untrusted` floor, and your own config layers on
top of them. See [profiles](/guide/profiles).

## 6. Confine a session instead of a command

Everything above confines one program at a time. When the thing you want to
confine is the work rather than a single binary, start a shell instead:

```sh
cd ~/projects/thing
bailey shell
```

The policy is resolved for that directory and inherited by every process the
shell starts, so it covers the commands you did not think to prefix. See
[a confined shell](/guide/shell).

## Where to go next

- [Configuration](/guide/configuration) for the full config model.
- [The policy model](/guide/policy-model) for how layers resolve.
- [Known limitations](/security/limitations) for what is not enforced yet. Read
  this one before you rely on the sandbox for anything that matters.
