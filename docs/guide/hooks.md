# Lifecycle hooks

Hooks are shell commands that run at defined points around a run. They are
declared in config and accumulate across layers, running in layer order.

```toml
[hooks]
pre_launch = ["./mount-assets.sh"]
post_exit = ["./sync-saves.sh"]
```

Each command runs through `sh -c`, so shell syntax works.

## `pre_launch`

Runs before the target starts, in order. A non-zero exit **aborts the run**: the
target is never started, and bailey reports which hook failed.

Use it for setup the sandbox cannot do itself: decrypting a data directory,
mounting something, checking that a dependency is present.

## `post_exit`

Runs after the target terminates, whether it exited normally or was killed. The
target's exit code is available as `BAILEY_EXIT_CODE`.

A failing `post_exit` hook does not change the run's exit status; the failure is
reported and the target's status is still propagated.

```toml
[hooks]
post_exit = ["rsync -a ./saves/ ~/backups/game-saves/"]
```

## What happened to `on_violation`

There used to be a third hook, meant to run when an access was denied. It was
removed, because nothing could ever trigger it: Landlock denies silently, and
seeing a denial requires the kernel's audit subsystem enabled at boot plus
permission to read its records, which a normal desktop gives neither.

A config that still sets it keeps working. The key is ignored with an
explanation rather than rejected:

```
bailey: warning: `hooks.on_violation` in ./bailey.toml is ignored; it was
removed because Landlock denies silently and no signal reaches bailey to
trigger it. Use `bailey audit` to see what a program wanted.
```

For the question the hook was there to answer, "what is this program trying to
reach", [`bailey audit`](/guide/audit) answers it more completely and works
today.

## Exit status

`bailey run` exits with the target's exit status, so it composes in scripts:

```sh
bailey run ./build.sh || echo "build failed"
```

The one exception is bailey's own failures, such as a policy that cannot be
resolved or a sandbox that cannot be established, which exit non-zero with a
message on stderr prefixed `bailey:`.

## Hooks are not sandboxed

Hook commands run with your full authority, outside the sandbox, before or after
the target. They are your code, not the target's. Do not build a hook that passes
untrusted input to a shell.
