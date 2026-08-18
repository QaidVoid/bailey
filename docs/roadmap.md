# Project status

What is implemented, what was deliberately not built, and what is out of scope.
Every gap named here is also in [known limitations](/security/limitations), with
the detail.

## Implemented

- **Policy that means what it says.** Denials survive resolution and are enforced
  under `--isolate` by covering the path; unenforceable network rules fail at
  resolution rather than silently inverting; the target executable is granted
  implicitly; config discovery covers the working directory as well as the
  target's; arguments after the target are passed through untouched.
- **The world the target sees.** The environment is built rather than inherited,
  so credentials do not cross unless named. Each target gets a private home that
  persists, a private `/tmp` and `/dev/shm` under isolation, and the directory it
  was invoked from.
- **Network confinement.** A policy that denies egress puts the target in its own
  network namespace with only loopback, so every protocol fails rather than TCP
  alone. Landlock scoping keeps host abstract sockets and host processes out of
  reach on Linux 6.12 and later.
- **Audit you can trust.** Runs are confined by default, the target is held at
  `exec` until the recorder is watching, observation is scoped to the run's
  cgroup, and traces are versioned and say what they lost.
- **Knowing what happened.** `bailey doctor` reports what this host can enforce
  and what each gap costs; every run reports what it enforced and what the host
  took away.

## Decided against

Each of these was specified, investigated, and dropped.

- **`on_violation` hooks.** Landlock denies silently, and seeing a denial needs
  the kernel's audit subsystem enabled at boot as well as permission to read its
  records. On a kernel with the log made readable but audit disabled, a
  deliberately triggered denial produced zero records: the hook could never have
  fired. Removed rather than carried as config that does nothing.
  [`bailey audit`](/guide/audit) answers the same question.
- **A user-mode network stack** for policies that allow some egress. It would
  genuinely help, putting the host's loopback out of reach and allowing UDP and
  ICMP to be switched off, but it needs an external binary, interface
  configuration inside the sandbox, and a synchronised attach, for a gain that
  applies only once egress has been deliberately allowed. What that mode does not
  cover is [documented](/guide/network) instead.

## Not planned

- **Transparent interception**, so that every program launched by a store client
  is automatically sandboxed. Explicit launcher only.
- **BPF-LSM enforcement.** It would raise the privilege floor for every run and
  depend on a kernel config the user cannot change without a reboot.
- **X11 nesting.** Wayland first.
- **Non-Linux platforms.**
