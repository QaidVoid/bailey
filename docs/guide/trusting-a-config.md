# Trusting a config

A `bailey.toml` found by walking up from the target or from your working
directory is a file that decides how much of the sandbox to open. It can also be
a file that arrived with the code you are trying to confine: cloned with a
repository, unpacked from an archive, written by the program you ran yesterday.

So a discovered config contributes nothing until you have said, once, that you
accept it.

```sh
bailey trust ./bailey.toml
```

## What a run does when it meets one

It runs. The policy is the one that would have applied had the file not existed,
and the file is reported:

```
bailey: not applying `/home/you/src/thing/bailey.toml`: you have not trusted it
bailey:   bailey trust /home/you/src/thing/bailey.toml
```

Nothing waits for an answer, so runs work from scripts, from CI, and from a shell
with nobody watching. Skipping is safe by construction: every layer only adds to
a deny-by-default floor, so dropping one can never grant something.

The cost is that your program fails for want of access rather than for want of
trust. The report is what connects the two, which is why it names the file and
the command rather than only complaining.

::: tip Existing configs
A `bailey.toml` that worked before this behaviour existed stops applying until
you trust it once. Run the program, read the line it prints, accept the file.
:::

## What trust is recorded against

The file's contents, not its path alone. Editing a trusted config revokes it:

```
bailey: not applying `/home/you/src/thing/bailey.toml`: it changed since you trusted it
bailey:   review the change, then run: bailey trust /home/you/src/thing/bailey.toml
```

That covers the case the path alone would miss, where a repository ships a
harmless config, gets accepted, and changes it in the next commit. Restoring the
contents you accepted restores trust with no further action, because the record
is a hash rather than a timestamp.

Editing your own project config therefore asks again. That is the price of the
property, and it is one command.

## Listing and revoking

```sh
bailey trust --list
```

```
  ok         /home/you/src/mine/bailey.toml
  changed    /home/you/src/thing/bailey.toml
  unreadable /home/you/src/deleted/bailey.toml
```

The status is computed against the file as it is now, so the list says what will
happen on the next run rather than what happened when you accepted it.

```sh
bailey untrust ./bailey.toml
```

The store lives at `$XDG_DATA_HOME/bailey/trusted.toml`, or
`~/.local/share/bailey/trusted.toml`.

## Files bailey will not trust

A config that someone else can change is refused, both when you try to trust it
and on every run afterwards:

- **Owned by another user.** The command fails and names the owner.
- **Writable by group or by everyone.** A recorded hash is only a guarantee if
  the file cannot change behind it; otherwise it is a race. `chmod go-w` fixes
  it.

## What needs no trust

| Source | Why |
| --- | --- |
| `$XDG_CONFIG_HOME/bailey/config.toml` | Your own file, in your own directory |
| Profiles under `$XDG_CONFIG_HOME/bailey/profiles/` | The same |
| `--config <file>` | You named it on the command line, for this run |

The last one is a sharp edge worth stating plainly: `bailey run --config
./repo/bailey.toml ./repo/program` applies the repository's file, because you
pointed at it. Every tool treats an explicit argument that way, and unlike
discovery it is visible in the command you typed rather than implied by where
your shell happens to be.

## What this does not do

Bailey can tell you who owns a config and whether it changed since you looked. It
cannot tell you whether what it says is wise. `bailey show <target>` prints the
policy a config resolves to, which is the thing worth reading before accepting
one.
