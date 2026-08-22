# Troubleshooting

Almost every problem is the same problem: the policy is missing something. These
are the shapes it takes.

## The program does not start at all

```
bailey: io error: Permission denied (os error 13)
```

Bailey could not exec the target. The target is granted implicitly, so this means
a config layer retracted that grant. `bailey show <target>` prints the denials;
bailey also warns up front when the policy denies the target itself.

## The program starts and immediately fails

Usually a missing library, config file, or device. Confirm what the policy actually
is:

```sh
bailey show ./program
```

Check that the layer you expected is listed. Each is labelled with the walk that
found it, `target` or `working dir`, which is usually enough to explain a config
that did not apply.

Then find out what it wanted:

```sh
bailey audit --save-trace trace.json ./program
```

Without the audit helper installed, `strace -f -e trace=file ./program` outside the
sandbox gives you a rougher version of the same answer.

## Something that exists says "No such file or directory"

```
/bin/sh: /home/you/.local/share/bun/bin/pi: No such file or directory
```

The path is right there on the host, so this reads as nonsense. It usually means
a **symlink whose target you did not grant**. Modern toolchain installers put a
farm of links on your `PATH` pointing into a store somewhere else:

```sh
readlink -f "$(command -v pi)"
# /home/you/.local/share/bun/install/global/node_modules/.../dist/cli.js
```

Granting the `bin` directory grants the links. Their targets are elsewhere, so
under isolation they are absent, and following one lands on nothing. Grant both:

```toml
[filesystem]
read = ["~/.local/share/bun/bin", "~/.local/share/bun/install/global/node_modules"]
execute = ["~/.local/share/bun/bin", "~/.local/share/bun/install/global/node_modules"]
```

`bun`, `mise`, `npm`, `pnpm`, and `nvm` all have this shape, and a version
manager adds a second hop: `.../node/latest/bin/node` is itself a link to
`.../node/26.7.0/bin/node`.

::: tip A symlinked target is fine
This applies to links a program follows at run time. The target you name on the
command line is bind-mounted, and a bind follows the link, so
`bailey run ~/.local/bin/some-link` works without granting anything extra.
:::

## An interpreter is not found

```
env: 'node': No such file or directory
```

A `#!/usr/bin/env foo` script looks for `foo` on `PATH`, and the sandbox `PATH`
is `/usr/local/bin:/usr/bin:/bin` rather than yours. An interpreter installed
under your home is not on it, so the script never finds it.

```toml
[filesystem]
read = ["~/.local/share/mise/installs/node/26.7.0"]
execute = ["~/.local/share/mise/installs/node/26.7.0"]

[env]
set = { PATH = "${HOME}/.local/share/mise/installs/node/26.7.0/bin:/usr/local/bin:/usr/bin:/bin" }
```

Setting `PATH` outright is usually better than passing yours through, which would
name directories the policy does not grant. Use `${HOME}` rather than `~` in a
value with more than one entry: a leading `~` expands, but only a leading one,
and `PATH` is a list.

Note that `bailey audit` cannot help you find this one: a program that never
looks somewhere opens nothing there, so there is nothing to record. The audit
says so when the target exits 127.

## A `bailey.toml` next to the program is ignored

```
bailey: not applying `/home/you/src/thing/bailey.toml`: you have not trusted it
bailey:   bailey trust /home/you/src/thing/bailey.toml
```

A discovered config applies only once accepted, because a file found by walking a
directory can have arrived with the code being confined. Run the command in the
second line. If it says the file changed instead, it was edited since you
accepted it: read the change and accept it again. See
[trusting a config](/guide/trusting-a-config).

## Landlock is not enforcing

```
bailey: warning: Landlock is not enforced by this kernel
```

The kernel has no Landlock support, or it is not enabled. Check:

```sh
grep landlock /sys/kernel/security/lsm
```

If it is absent, Landlock needs to be in the kernel's `lsm=` list. Bailey still
applies seccomp and cgroups, but the filesystem and network policy is not being
enforced.

## Isolation is skipped

```
bailey: warning: unprivileged user namespaces unavailable; running without namespace isolation
```

Unprivileged user namespaces are disabled or blocked by a security policy such as
AppArmor. The run continues with Landlock and seccomp. To check:

```sh
cat /proc/sys/user/max_user_namespaces
sysctl kernel.unprivileged_userns_clone 2>/dev/null
```

## Resource limits are skipped

```
bailey: warning: resource limits not applied: ...
```

There is no writable delegated cgroup v2 for your session. On a systemd system,
running inside a user session usually provides one; running from a bare TTY or an
unusual init may not.

## Relative paths fail under `--isolate`

```
cat: ./file.txt: No such file or directory
```

The target keeps the directory you invoked it from, but under `--isolate` that
directory only exists inside the sandbox if the policy grants it. Where it does
not, the run says so and starts in the private home instead:

```
bailey: warning: the working directory is not granted, so it is absent under
isolation; starting in /home/you instead
```

Grant the directory, and the relative path resolves.

## The audit helper will not start

```
bailey: audit helper did not start; it needs CAP_BPF and CAP_PERFMON
```

Either the helper was not built, it is not where bailey looks for it, or it does
not have its capabilities. Check each:

```sh
ls -l target/release/bailey-bpf-helper
getcap target/release/bailey-bpf-helper
BAILEY_BPF_HELPER=$PWD/target/release/bailey-bpf-helper bailey audit ./program
```

## A network rule seems to do nothing

The traffic is probably not TCP. Only TCP connect and bind are restricted; UDP,
QUIC, and DNS are not. See [known limitations](/security/limitations).

A rule with no `port` no longer fails quietly: it is a resolution error naming
the layer.

## A `deny` seems to do nothing

Check whether the run had the isolation layer. A denial nested inside a granted
directory is enforced by covering the path over, which needs the mount namespace,
so under `--no-isolate` the run says:

```
bailey: warning: `/home/you/.ssh` is denied but nested under a granted path, and
is not enforced without namespace isolation. Drop `--no-isolate`, or grant the
specific subdirectories you need instead of granting the parent.
```

`bailey show <target>` marks the same paths `(nested under a grant: needs
isolation)`. Isolation is the default, so this is usually a `--no-isolate` you
did not mean to keep.

Where you do need `--no-isolate`, grant the specific children instead of granting
a parent and carving out an exception:

```toml
[filesystem]
# Under --no-isolate, does not protect ~/.ssh:
# read = ["~"]
# deny = ["~/.ssh"]

# Does, everywhere:
read = ["~/Documents", "~/Downloads"]
```

A `read_only` island has the same shape: it is a read-only mount, so it needs the
same layer and warns the same way.
