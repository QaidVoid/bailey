# Recipe: a downloaded binary

You downloaded a release binary. You want to run it without giving it your home
directory.

## Set it up

Put it in its own directory with a config next to it:

```
~/sandbox/thing/
  bailey.toml
  thing
```

```toml
# ~/sandbox/thing/bailey.toml
[filesystem]
read = ["."]
write = ["./out"]
execute = ["./thing"]

[network]
egress = "deny"

[resources]
memory = "1GiB"
pids_max = 128
```

You wrote that file, so accept it once. A `bailey.toml` found by walking a
directory applies only after you have:

```sh
bailey trust ~/sandbox/thing/bailey.toml
```

## Check before you run

```sh
bailey show ~/sandbox/thing/thing
```

Read the filesystem list. Everything on it is something the program can reach. If
your home directory is on that list, stop and find out why. A config layer marked
`not applied` is one you have not trusted yet.

## Run it

```sh
bailey run ~/sandbox/thing/thing
```

Isolation is on by default, so the program's world contains the system paths, its
own directory, and nothing else. Your home directory does not exist in there.

Under `--no-isolate` the same policy is enforced, but the rest of the filesystem
remains visible, just unreadable.

## Find out what it wanted

If it fails, record a session:

```sh
cd ~/sandbox/thing
bailey audit --save-trace trace.json ./thing
```

Read the output. A tool that reads a config file under `/etc` is unremarkable. A
tool that reads `~/.ssh/id_ed25519` and connects to an address you do not
recognise has told you something, and you should not grant it.

## Tighten from the trace

```sh
bailey profile generate --trace trace.json --target ./thing > bailey.toml
bailey trust ./bailey.toml
```

Review the generated file before trusting it, especially anything under your home
directory. Rewriting the config is what the trust step is there to catch: the file
does not apply until you have read this version of it.

::: warning An audit is one run
The policy applies during an audit, so the program is confined while it is being
watched, but a trace only shows what happened this time. For a binary you
genuinely do not trust, run it under enforcement and widen the policy from the
failures rather than granting whatever it reached for.
:::
