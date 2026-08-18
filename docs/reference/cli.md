# CLI reference

```
bailey <COMMAND>

Commands:
  run      Run a target under enforcement
  audit    Run a target under audit, recording its access and reconciling it
  show     Resolve and print the effective policy for a target
  profile  Inspect bundled profiles and generate profiles from audit traces
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
| `-p, --profile <NAME>` | Bundled profile used as the base. Default `untrusted` |
| `--isolate` | Rebuild the target's world with user, mount, and PID namespaces |
| `--quiet` | Do not print what the run enforced |
| `--json` | Print what the run enforced as JSON |

`ARGS` are passed to the target untouched. Bailey stops interpreting options at
the target, so `bailey run ./tool -c ./tool.conf` gives `-c ./tool.conf` to
`./tool`. Bailey's own options go before the target.

The target executable is granted read and execute implicitly, as the lowest
config layer, so a binary outside the system paths runs without config. Any user
layer can retract that grant.

## `bailey audit`

```
bailey audit [OPTIONS] <TARGET> [ARGS]...
```

Runs the target while recording its filesystem and network access, then prints the
accesses the current policy does not grant, split into high-risk and routine.

| Option | Description |
| --- | --- |
| `-c, --config <FILE>` | Explicit config file |
| `-p, --profile <NAME>` | Bundled profile used as the base. Default `untrusted` |
| `--save-trace <FILE>` | Write the recorded trace as JSON |
| `--isolate` | Rebuild the target's world with namespaces during the audit |
| `--unconfined` | Run with no confinement at all, reported when used |

Requires the privileged audit helper. See [installation](/guide/installation).

## `bailey show`

```
bailey show [OPTIONS] <TARGET>
```

Prints the profile base, every config file that contributed in precedence order,
and the merged policy. Exits 0.

| Option | Description |
| --- | --- |
| `-c, --config <FILE>` | Explicit config file |
| `-p, --profile <NAME>` | Bundled profile used as the base |

## `bailey doctor`

Reports what this host can enforce and what each gap costs: the Landlock ABI and
which policy elements it covers, user namespaces, cgroup delegation, kernel BTF,
whether the audit helper can load, and whether violation hooks can fire. See
[knowing what was enforced](/guide/diagnostics).

## `bailey completions <shell>` and `bailey man`

Emit a shell completion script or a man page, generated from the command
definitions.

## `bailey profile list`

Lists the bundled profiles with their descriptions, marking the default base.

## `bailey profile show`

```
bailey profile show <NAME>
```

Prints a bundled profile's TOML, so it can be copied and edited.

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
| `XDG_CONFIG_HOME` | Location of the global config, `$XDG_CONFIG_HOME/bailey/config.toml` |
| `HOME` | Used for `~` expansion in config, and for the global config fallback |

Set for hook commands:

| Variable | Where |
| --- | --- |
| `BAILEY_EXIT_CODE` | `post_exit` hooks |
| `BAILEY_VIOLATION` | `on_violation` hooks, which do not currently fire |

## Exit status

`bailey run` and `bailey audit` exit with the target's status. Bailey's own
failures exit non-zero with a message on stderr prefixed `bailey:`. A target
killed by a signal reports `-1`, which surfaces as 255.
