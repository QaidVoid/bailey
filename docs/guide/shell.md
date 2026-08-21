# A confined shell

`bailey run` confines one program. That leaves a gap that is easy to miss: a
`bailey.toml` in a directory reads like a property of the directory, but it only
ever applied to the commands you remembered to prefix. The `make`, the
`npm install`, the editor, and whatever a build script decided to fetch all ran
with your full authority.

```sh
cd ~/projects/thing
bailey shell
```

Everything you type in that shell is confined by that directory's policy.

## Why it covers everything

Not by watching what you run. A Landlock ruleset is a property of the process:
it survives `fork` and `exec`, and the process it restricts cannot relax it. The
seccomp filter behaves the same way, and the mount and PID namespaces are entered
once and inherited. Confining the shell confines the whole tree of processes that
grows out of it.

That also means there is no way out from inside, including for you. A program
that tries to escape is in the same position as one started with `bailey run`,
and so are you until you exit the shell.

## What it grants

The directory you launched from, read, write, and execute, as the lowest layer:

```
bailey: enforced: landlock, seccomp, network namespace, namespace isolation
```

```
filesystem:
  rwx /home/you/projects/thing      <- implicit
  r-x /usr, /lib, /bin, ...         <- the untrusted floor
network:
  egress: DenyAll
```

The implicit grant sits beneath the profile and every config layer, so any of
them can retract it with `deny` or `reset`. Everything else is the ordinary
cascade: the profile, your global config, the directory's `bailey.toml` once
[trusted](/guide/trusting-a-config), and `--config`.

::: warning Launch it from the directory you mean
The grant is literally "where I am". Run `bailey shell` from your home directory
and you have granted your home. The run says so:

```
bailey: warning: this shell was launched from `/home/you`, so the implicit grant
covers your whole home directory.
```
:::

## Your shell starts without your dotfiles

The shell gets a private home, so `~/.config/fish`, your history, and your
prompt are not there. The shell starts, and it starts plain.

Grant what you want to keep, read-only, in a profile so it applies wherever you
open a shell:

```toml
# ~/.config/bailey/profiles/shell.toml
[filesystem]
read = ["~/.config/fish", "~/.config/starship.toml", "~/.config/nvim"]
```

```sh
bailey shell --profile shell
```

A read grant stays a read grant: the path is remounted read-only inside the
sandbox, so a program in there cannot rewrite your editor config even though it
sits inside a home the shell can otherwise write. The same holds for a read grant
on something inside the launch directory. See
[the policy model](/guide/policy-model#grants-bailey-adds-for-you).

## Being told a directory has a policy

`bailey shell` still has to be typed. [Shell integration](/guide/hook) announces
a directory's policy when you enter it, and can offer to start the shell for you.

## Knowing you are in one

Bailey sets `BAILEY_SANDBOX`, `BAILEY_SANDBOX_NET`, and `BAILEY_SANDBOX_DIR`, and
leaves your prompt alone, since every shell spells its own and the prompt is
yours.

```fish
# fish
function fish_right_prompt
    test -n "$BAILEY_SANDBOX"; and echo -n (set_color yellow)"[sandboxed]"(set_color normal)
end
```

```bash
# bash
[ -n "$BAILEY_SANDBOX" ] && PS1="[sandboxed] $PS1"
```

`BAILEY_SANDBOX_DIR` names the directory the policy was resolved for, which is
worth showing if you move around inside the shell: the policy does not follow
you, it was fixed when the shell started.

## A private home per directory

Each launch directory gets its own home under
`$XDG_DATA_HOME/bailey/shell/<name>-<digest>/home`, so two projects do not share
one. It persists, so shell history and tool state survive between sessions in the
same directory. Under isolation it is mounted where your real home would be, so a
tool that hard-codes `~/.config/...` writes inside the sandbox.

## What it cannot do

**Confine a shell you already have.** The process exists with the authority it
was given, and nothing can take that back. `bailey shell` starts a new one; that
is the whole mechanism.

**Add isolation to a shell inside a shell.** Nesting works and the policies
intersect, so the inner shell is never wider than the outer one. But the seccomp
filter denies `unshare` and `mount`, so the inner run cannot build a second
world. It does not need to: the outer one is inherited and cannot be left.

```
bailey: note: already inside a sandbox for `/home/you/projects/thing`. Its policy
still applies and this one can only narrow it further; the isolation layer cannot
be entered a second time.
bailey: enforced: landlock, seccomp, network namespace (inherited), namespace isolation (inherited)
```

Two things follow from that, and are worth knowing before they confuse you:

- **A nested run cannot see your trust store.** `$HOME` inside the sandbox is the
  private home, so the store is not there and cannot be. Discovered configs
  therefore do not apply inside, and the run says the store is unreachable rather
  than claiming you never trusted the file. `bailey trust` from inside is refused
  for the same reason: the record would go into a home that is discarded.
- **Editing a config from inside changes nothing you can use.** The shell you are
  in resolved its policy when it started. A shell you start after the edit
  intersects with the one you are in, so a config edited to grant *more* grants
  nothing. This is the property that makes the launch directory safe to hand to a
  program: it can rewrite the policy file, and rewriting it cannot help it.

**Stop you from leaving.** Exit the shell and you are back to your ordinary
authority. This is a tool for scoping work, not a jail.

## Options

| Option | Description |
| --- | --- |
| `--shell <PATH>` | The shell to run. Defaults to `$SHELL`, then `/bin/sh` |
| `-c, --config <FILE>` | Explicit config file, highest precedence |
| `-p, --profile <NAME>` | Profile used as the base |
| `--no-isolate` | Landlock and seccomp only, without the rebuilt world |

The shell's exit status is bailey's, so `bailey shell` composes in a script the
way a shell does.
