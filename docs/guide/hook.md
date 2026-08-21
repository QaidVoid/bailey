# Shell integration

A directory's policy is invisible until you remember it is there. The hook makes
it announce itself.

```fish
# ~/.config/fish/config.fish
bailey hook fish | source
```

```bash
# ~/.bashrc
eval "$(bailey hook bash)"
```

Then entering a directory with a `bailey.toml` says so, once:

```
bailey: this directory has a policy; `bailey shell` works under it
```

## What it cannot do

It cannot confine the shell you are in. Landlock restricts a process for its
lifetime, and by the time a shell can run a hook it already exists with the
authority it was given. Nothing can take that back.

So the hook tells you, and can start something confined for you. If you were
hoping for a policy that applies itself on `cd`, [a confined
shell](/guide/shell) is the closest thing that is real.

## What it says

| State | What you see |
| --- | --- |
| A trusted config | there is a policy here, and `bailey shell` works under it |
| A config you have not accepted | what it is, and the `bailey trust` command that would accept it |
| A config that changed since you accepted it | that it changed, and the command to accept it again |
| No config | nothing at all |

The notice is for a `bailey.toml` in the directory you just entered, not every
one the [cascade](/guide/configuration) would find. A config high in a tree
applies to everything under it, and announcing that on every `cd` within a
project would be noise. `bailey show` still uses the full cascade.

## Being asked instead of told

```fish
bailey hook fish --ask | source
```

Entering a directory with a trusted config now offers:

```
bailey: this directory has a policy; `bailey shell` works under it
bailey: enter a confined shell here? [y/N]
```

Answer `n` and it does not ask again for that directory in that session. Answer
`y` and you get a confined shell; leave it with `exit` and you are back where you
were, unconfined.

::: warning It never offers to trust
The offer is only ever to enter a sandbox, which narrows what your next commands
can do and costs nothing to refuse. Accepting a config is the opposite: it widens
what a program may reach, and it is exactly the decision that should not be made
while you are in the middle of something else. That is why an untrusted config is
reported and never prompted. See [trusting a config](/guide/trusting-a-config).
:::

## Running a claimed program by name

A profile can name the programs it is for:

```toml
# ~/.config/bailey/profiles/agent.toml
applies_to = ["my-agent"]
```

That picks the profile when bailey runs the program. It does not make typing
`my-agent` run it under bailey, because nothing intercepts your shell. With
`--wrap`, the hook defines a function that does:

```fish
bailey hook fish --wrap | source
```

```sh
bailey hook list-wrapped     # exactly which names are shadowed
command my-agent             # the program itself, unconfined
```

This is opt-in because shadowing a command is a surprise, and a surprise in a
shell is a bug report. Only bare names from your own profiles are wrapped; a
claim written as a path names one executable, and a function of that name would
catch every program that happens to share it. Bundled profiles claim nothing.

## Inside a confined shell

The hook goes quiet, with one exception:

```
bailey: this shell is confined to /home/you/projects/thing, so the policy does
not cover the directory you are now in
```

The policy was resolved when the shell started and does not follow a `cd`.
Without that line, moving to another project inside a confined shell produces
permission errors that look like a broken tool rather than a working sandbox.

## zsh

Not yet. The integration would be a few lines like the others, but there is no
zsh on the machine bailey is developed on, and shell code that has never been run
is how shell integrations break. `bailey hook zsh` says so rather than emitting
something untested.
