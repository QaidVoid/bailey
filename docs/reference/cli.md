# CLI reference

```
bailey <COMMAND>

Commands:
  run      Run a target under enforcement
  shell    Run a shell confined to this directory, covering everything it starts
  audit    Run a target under audit, recording its access and reconciling it
  show     Resolve and print the effective policy for a target
  profile  Inspect bundled profiles and generate profiles from audit traces
  trust    Accept a discovered config file, or list what has been accepted
  untrust  Withdraw a config file's acceptance
  hook     Emit shell integration, so a directory's policy announces itself
  doctor   Report what this host can enforce, and what each gap costs
```

## `bailey run`

```
bailey run [OPTIONS] <TARGET> [ARGS]...
```

Resolves the policy for `TARGET`, runs any `pre_launch` hooks, launches the
target under enforcement, runs any `post_exit` hooks, and exits with the target's
exit status.

| Option | Description |
| --- | --- |
| `-c, --config <FILE>` | Explicit config file, highest precedence |
| `-p, --profile <NAME>` | Profile used as the base, bundled or your own. Defaults to one that claims the target, else `untrusted` |
| `--no-isolate` | Run without namespace isolation, leaving Landlock and seccomp |
| `--isolate` | Accepted and redundant: isolation is the default |
| `--quiet` | Do not print what the run enforced |
| `--json` | Print what the run enforced as JSON |

`ARGS` are passed to the target untouched. Bailey stops interpreting options at
the target, so `bailey run ./tool -c ./tool.conf` gives `-c ./tool.conf` to
`./tool`. Bailey's own options go before the target.

A target with no `/` in it is looked up on `PATH`, the way a shell would, so
`bailey run curl` means what it appears to. A target that resolves to nothing is
an error rather than a policy for a file that does not exist.

The target executable is granted read and execute implicitly, as the lowest
config layer, so a binary outside the system paths runs without config. Any user
layer can retract that grant.

## `bailey shell`

```
bailey shell [OPTIONS]
```

Runs a shell under the policy resolved for the current directory. The
confinement is inherited, so every process started from that shell is covered by
the same policy without being invoked through bailey.

| Option | Description |
| --- | --- |
| `--shell <PATH>` | The shell to run. Defaults to `$SHELL`, then `/bin/sh` |
| `-c, --config <FILE>` | Explicit config file, highest precedence |
| `-p, --profile <NAME>` | Profile used as the base |
| `--no-isolate` | Run without namespace isolation, leaving Landlock and seccomp |

The launch directory is granted read, write, and execute as the lowest layer, so
a shell is useful in a directory with no config; any layer can retract it. The
shell gets a private home derived from that directory, and its environment
carries `BAILEY_SANDBOX` and `BAILEY_SANDBOX_DIR`.

What was enforced is printed before the shell takes the terminal, rather than on
exit as `run` does. Exits with the shell's status. See
[a confined shell](/guide/shell).

## `bailey audit`

```
bailey audit [OPTIONS] <TARGET> [ARGS]...
```

Runs the target while recording its filesystem and network access, then prints the
accesses the current policy does not grant, split into high-risk and routine.

| Option | Description |
| --- | --- |
| `-c, --config <FILE>` | Explicit config file |
| `-p, --profile <NAME>` | Profile used as the base, as for `run` |
| `--save-trace <FILE>` | Write the recorded trace as JSON |
| `--unconfined` | Run with no confinement at all, reported when used |

The resolved policy applies during an audit; the accesses it denies are recorded
rather than permitted. `--unconfined` lifts that.

Audit the target by its absolute path. A path opened relatively cannot be
resolved after the fact, and an unresolved finding is reported but never
generated into a profile. See [auditing a program](/guide/audit).

Unlike `run`, audit does not isolate. The recorder needs the target held at
`exec`, and that stop is not inherited across the fork that puts it in a PID
namespace, so `--isolate` is rejected with an explanation rather than ignored.

Requires the privileged audit helper. See [installation](/guide/installation).

## `bailey show`

```
bailey show [OPTIONS] <TARGET>
```

Prints the profile base, every config file that was found in precedence order,
and the merged policy. Exits 0.

| Option | Description |
| --- | --- |
| `-c, --config <FILE>` | Explicit config file |
| `-p, --profile <NAME>` | Bundled profile used as the base |

A discovered file that did not apply is listed with the reason, followed by the
command that would accept it, so the policy explains its own gaps.

## `bailey trust`

```
bailey trust <PATH>
bailey trust --list
```

Accepts a discovered config file, recording it as it currently reads, so that
discovery may apply it. With `--list`, prints each accepted path and whether it
still applies: `ok`, `changed`, `not yours`, `writable`, or `unreadable`.

A file owned by another user, or writable by group or by everyone, is refused.

## `bailey untrust`

```
bailey untrust <PATH>
```

Withdraws acceptance, so the file stops contributing. Exits non-zero if the path
was not accepted in the first place.

See [trusting a config](/guide/trusting-a-config).

## `bailey hook`

```
bailey hook fish [--ask] [--wrap]
bailey hook bash [--ask] [--wrap]
bailey hook status [--porcelain]
bailey hook list-wrapped
```

Emits shell integration code to evaluate from your shell config. Entering a
directory that contains a `bailey.toml` then announces it, once.

| Option | Description |
| --- | --- |
| `--ask` | Offer to enter a confined shell rather than only mentioning one. Never offers to trust a config |
| `--wrap` | Define a function for each program your own profiles claim with `applies_to` |

`bailey hook status` prints what the hook would say about the current directory,
and is what the emitted code calls; `--porcelain` prefixes a state and a tab.
`bailey hook list-wrapped` names the programs `--wrap` shadows.

A shell with no integration is refused rather than given untested code. See
[shell integration](/guide/hook).

## `bailey doctor`

Reports what this host can enforce and what each gap costs: the Landlock ABI and
which policy elements it covers, user namespaces, cgroup delegation, kernel BTF,
and whether the audit helper can actually load its programs. See
[knowing what was enforced](/guide/diagnostics).

## `bailey completions <shell>` and `bailey man`

Emit a shell completion script or a man page, generated from the command
definitions.

## `bailey profile list`

Lists the bundled profiles with their descriptions, marking the default base, and
then any profiles of your own with the file each came from.

## `bailey profile show`

```
bailey profile show <NAME>
```

Prints a profile's TOML, bundled or your own, so it can be copied and edited.

## `bailey profile generate`

```
bailey profile generate --trace <FILE> --target <PATH> [OPTIONS]
```

Reads a saved trace, diffs it against the resolved policy for `--target`, and
writes a deny-by-default profile to stdout granting the routine findings.

| Option | Description |
| --- | --- |
| `--trace <FILE>` | Trace written by `audit --save-trace` |
| `--target <PATH>` | The target the trace was recorded for |
| `-c, --config <FILE>` | Explicit config file used when resolving the base policy |
| `-p, --profile <NAME>` | Bundled profile used as the base when resolving |
| `--include-high-risk` | Include network egress and credential access |
| `--accept-truncated` | Generate from a trace known to be missing events |

High-risk findings are excluded unless `--include-high-risk` is given, and the
number excluded is reported on stderr.

## Environment variables

| Variable | Effect |
| --- | --- |
| `BAILEY_BPF_HELPER` | Path to the privileged audit helper |
| `BAILEY_CGROUP_ROOT` | Cgroup to create runs in, when the search finds the wrong one |
| `XDG_CONFIG_HOME` | Location of the global config, `$XDG_CONFIG_HOME/bailey/config.toml` |
| `XDG_DATA_HOME` | Location of the trust store, `$XDG_DATA_HOME/bailey/trusted.toml`, and of private homes |
| `HOME` | Used for `~` expansion in config, and for the global config fallback |

Set by bailey, inside the sandbox:

| Variable | Meaning |
| --- | --- |
| `BAILEY_SANDBOX` | `1` in every confined run |
| `BAILEY_SANDBOX_NET` | `isolated` or `host`, the network the run was given |
| `BAILEY_SANDBOX_DIR` | The directory a confined shell resolved its policy for |

Set for hook commands:

| Variable | Where |
| --- | --- |
| `BAILEY_EXIT_CODE` | `post_exit` hooks |

## Exit status

`bailey run` and `bailey audit` exit with the target's status. Bailey's own
failures exit non-zero with a message on stderr prefixed `bailey:`. A target
killed by a signal reports `-1`, which surfaces as 255.
