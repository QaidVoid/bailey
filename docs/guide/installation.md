# Installation

Bailey is Linux only. It builds with a stable Rust toolchain and has no system
dependencies for the enforcement path.

## From source

```sh
git clone https://github.com/QaidVoid/bailey
cd bailey
cargo build --release
```

The binary is at `target/release/bailey`. Put it somewhere on your `PATH`.

This build gives you everything except audit recording: the policy model, the
cascading config, all enforcement layers, namespace isolation, reconciliation,
profile generation, and the CLI.

## The audit recorder

Audit mode records access with eBPF. The eBPF programs are loaded by a separate,
minimal binary, `bailey-bpf-helper`, which is the only component that needs
privilege. Keeping it separate means the main tool carries no eBPF code and needs
no capabilities.

Building it needs a nightly toolchain and `bpf-linker`:

```sh
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
cargo build --release -p bailey-bpf-helper
```

Then grant the helper its capabilities, once:

```sh
sudo setcap cap_bpf,cap_perfmon+ep ./target/release/bailey-bpf-helper
```

With that in place, `bailey audit` runs unprivileged and drives the helper. If you
would rather not use file capabilities, run the audit under `sudo` instead.

::: tip The target never runs privileged
The helper does not spawn the program being audited. The unprivileged main tool
runs it and tells the helper which process to observe, so the program itself never
inherits elevated privilege.
:::

### How the helper is found

In order:

1. The path in the `BAILEY_BPF_HELPER` environment variable.
2. A `bailey-bpf-helper` next to the `bailey` executable.
3. `bailey-bpf-helper` on `PATH`.

## Checking your kernel

Bailey adapts to what the kernel offers, and reports what it cannot enforce. Ask
it before running anything:

```sh
bailey doctor
```

That covers the Landlock ABI and what it does not reach, user namespaces, cgroup
delegation, kernel BTF, and whether the audit helper can load its programs, each
with what its absence costs. See
[knowing what was enforced](/guide/diagnostics).

By hand, if you want the raw answers:

```sh
# Landlock present?
grep -q landlock /sys/kernel/security/lsm && echo "landlock: yes"

# Unprivileged user namespaces, for the isolation layer?
cat /proc/sys/user/max_user_namespaces

# BTF, for the audit backend?
test -e /sys/kernel/btf/vmlinux && echo "btf: yes"
```

See [kernel requirements](/reference/kernel) for what each feature affects and
which kernel version introduced it.

## Building and testing the workspace

```sh
cargo build              # the main tool and the shared crate
cargo test               # and their tests
```

Both act on the default members, so a stable toolchain and no system
dependencies are enough.

```sh
cargo build --workspace
cargo test --workspace
```

These add the privileged helper, which needs nightly and `bpf-linker`. Without
them the build stops with a message naming what to install; nothing else in the
workspace depends on that toolchain.

The eBPF programs themselves sit behind a `bpf` feature that only the helper's
build script enables. They compile for the BPF target and nothing else, so
without the gate every `--workspace` command would try to link them for your
machine and fail.

Some tests need more than a toolchain: a delegated cgroup, unprivileged user
namespaces, or the audit helper with its capabilities. Each of those self-skips
with a note rather than failing, so a passing run on a restricted host is not
proof that everything was exercised.
