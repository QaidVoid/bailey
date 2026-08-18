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

**Your environment goes through.** Every variable in your shell is passed to the
target, including `SSH_AUTH_SOCK`, `GITHUB_TOKEN`, `AWS_*`, and anything else your
profile exports. An agent that reads its own environment has your credentials. Run
it from a shell that does not have them:

```sh
env -i HOME="$HOME" PATH=/usr/bin:/bin TERM="$TERM" bailey run --isolate /usr/bin/agent-cli
```

**`deny` does not protect files inside a granted directory.** The `deny = ["./.env"]`
above does not work, because `.` is granted. Keep secrets out of the project
directory, or grant subdirectories individually instead of granting `.`.

**`egress = "deny"` blocks TCP only.** An agent can still send UDP and DNS traffic,
which is enough to exfiltrate anything it can read. If that matters, run it with
no network route at all by other means until the network namespace work lands.

**Relative paths break under `--isolate`.** The working directory is not carried
in, so the agent starts at `/`. For now, either pass absolute paths or run without
`--isolate` and accept that ungranted paths are denied but visible.

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
