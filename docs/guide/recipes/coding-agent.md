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

# Enforced under --isolate: these become empty and read-only.
deny = ["./.env", "./secrets"]

[network]
egress = "deny"

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
bailey run --isolate /usr/bin/agent-cli
```

Under isolation, the agent's world is the system paths and this project. Your
other projects, your home directory, and your keys are not present in its
filesystem view.

## What this does not protect against yet

Be honest about the boundary, because an agent is the workload most likely to walk
into all of these.

**A variable you pass is passed in full.** The environment is deny-by-default,
so `SSH_AUTH_SOCK` and `GITHUB_TOKEN` do not reach the agent unless you name
them. If the agent genuinely needs a token, remember that passing it hands it
over.

**`deny` inside a granted directory only works under `--isolate`.** The
`deny = ["./secrets"]` above is enforced when you pass `--isolate`, and is
reported as unenforced when you do not. The command below uses it.

See the [roadmap](/roadmap) for the proposals that close each of these, and
[known limitations](/security/limitations) for the full list.

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
