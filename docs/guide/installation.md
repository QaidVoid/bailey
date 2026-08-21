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

## Building the whole workspace

`cargo build` acts on the default members, which are the main tool and the shared
crate. The eBPF program crate and the privileged helper are excluded, because they
need the nightly toolchain and `bpf-linker`. Build them explicitly with
`-p bailey-bpf-helper`.
