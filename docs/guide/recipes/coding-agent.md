# Recipe: a coding agent

An agent with shell access is a program that runs other programs, chosen at
runtime, based on text it read somewhere. It should see one project directory and
nothing else. This is the case where a sandbox earns its keep, and it is also the
case where bailey's current gaps matter most, so read the caveats at the end.

## The policy

```toml
# ~/projects/thing/bailey.toml
[filesystem]
read = ["."]
write = ["."]
execute = ["/usr/bin/git", "/usr/bin/cargo", "/usr/bin/rustc", "/usr/bin/sh"]

# Enforced by the isolation layer: these become empty and read-only.
deny = ["./.env", "./secrets"]

[network]
# An agent that cannot reach its model is not an agent. This costs the network
# namespace: see /guide/network.
egress_allow = [{ host = "*", port = 443 }]

[resources]
memory = "4GiB"
pids_max = 512
```

The `untrusted` floor already grants read and execute on the system paths, so most
tools work. The point of the explicit `execute` list is not to restrict which
binaries run, since the floor grants `/usr` anyway, but to document what the agent
is expected to reach for.

## Running it

```sh
cd ~/projects/thing
bailey trust ./bailey.toml     # once, and again whenever you edit it
bailey run /usr/bin/agent-cli
```

Under isolation, which is the default, the agent's world is the system paths and
this project. Your other projects, your home directory, and your keys are not
present in its filesystem view.

The trust step matters more here than anywhere else. An agent that can write your
project can write your project's `bailey.toml`, and a policy a program can edit is
not a policy. Editing the file revokes it, so the widened version does not apply
until you have read it.

## What this does not protect against yet

Be honest about the boundary, because an agent is the workload most likely to walk
into all of these.

**A variable you pass is passed in full.** The environment is deny-by-default,
so `SSH_AUTH_SOCK` and `GITHUB_TOKEN` do not reach the agent unless you name
them. If the agent genuinely needs a token, remember that passing it hands it
over.

**`deny` inside a granted directory needs the isolation layer.** The
`deny = ["./secrets"]` above is enforced by covering the path over, which the
mount namespace does. That layer is the default; under `--no-isolate` the denial
is reported as unenforced before the run starts.

**Nothing intercepts your shell.** Running `agent-cli` directly runs it with your
full authority. The policy applies to what you launch through bailey, and the
`bailey: enforced:` line after a run is the confirmation.

See [known limitations](/security/limitations) for the full list, and
[project status](/roadmap) for what was deliberately not built.

## A narrower variation

If the agent only needs to read and edit source, and you run the build yourself,
take away execution of everything except the interpreter it runs on:

```toml
[filesystem]
reset = true
read = ["/usr/lib", "/lib", "/lib64", "/etc/ld.so.cache", "."]
write = ["."]
execute = ["/usr/lib", "/lib", "/lib64", "/usr/bin/python3"]
```

`reset = true` throws away the floor's broad `/usr` grant and starts from an
explicit list. Expect to iterate: run it, watch what fails, add the path, repeat.
