# The kernel matrix

The `kernels` CI job runs the test suite inside a virtual machine, one job per
pinned kernel, and asserts exactly which tests skip on each. A green run is a
claim about what ran, not only about what passed.

## What the matrix covers

Every entry is one line in `ci/kernels.json` plus two expectation files,
`ci/kernels/<id>.doctor` and `ci/kernels/<id>.skips`.

| Entry | Kernel | Landlock | Why it is in the matrix |
| --- | --- | --- | --- |
| `5.15` | v5.15.225 | ABI 1 | Oldest supported kernel. Filesystem rules only. |
| `6.1` | v6.1.192 | ABI 2 | Adds `refer`. Still no network rules. |
| `6.12` | v6.12.118 | ABI 6 | Network rules and scoping, plus a delegated cgroup. |
| `6.12-nolandlock` | v6.12.118 | none | The `lsm=` line omits `landlock`: every degradation bailey reports when Landlock is absent. |
| `6.12-nocgroup` | v6.12.118 | ABI 6 | `"cgroup": false`: no delegated cgroup, so the rlimit fallback paths run and the cgroup tests skip. |
| `6.12-cgroup-nojoin` | v6.12.118 | ABI 6 | Delegated cgroup, but the caller stays outside the subtree: the skip-with-warning behaviour for a caller that cannot join. |
| `mainline` | v6.19.14 | ABI 7 | Newest pinned kernel; the version is bumped deliberately. |

Each entry passes `lsm=` on the kernel command line, so the LSM set never
depends on the kernel build's `CONFIG_LSM`.

## Reproducing one kernel locally

```sh
cargo test --no-run          # the guest runs the binaries the host built
vng --network user --cpus 8 -m 8192 -r v6.12.118 \
    --append "lsm=landlock,yama" -- \
    sh -c "sleep 3; ci/guest.sh 6.12 \
           CARGO_HOME=$HOME/.local/share/cargo RUSTUP_HOME=$HOME/.local/share/rustup"
```

`<id>` selects the entry, and the `KEY=VALUE` pairs are exported into the
dropped user's environment. Point the two homes at wherever this machine keeps
its toolchain; the guest shares the repository tree but not those directories.

Things a local boot needs that CI's runner already has:

- `--network user`: without it the guest has no interface at all, and
  `ci/guest.sh`'s address setup silently does nothing.
- A statically linked busybox on `PATH`, under one of the names
  `busybox-static`, `busybox.static`, or `busybox`. virtme-ng packs it into the
  guest's initramfs and does not ship one; a dynamically linked system busybox
  cannot run there because the initramfs runs before any shared libraries are
  mounted.
- `--cpus` at or above the four test threads `ci/guest.sh` pins. Two vcpus
  starve the libtest threads, which shows up as deadline failures in the
  network tests and hangs in the mount tests.
- The `sleep 3` before `ci/guest.sh`: the guest console drops the writes of a
  boot's first seconds, and the doctor output is printed early.

## Reading a run

stdout and stderr leave the guest by different routes, and merging them with
`2>&1` at the host loses early console content. Keep them apart:

```sh
vng ... -- sh -c "sleep 3; ci/guest.sh 6.12 ..." \
    > 6.12.out 2> 6.12.err
cat 6.12.out 6.12.err > 6.12.log
```

The guest's filesystem is an overlay, so nothing written inside the guest ever
reaches the host tree. The doctor output and the skip log travel through the
job log instead, between these markers:

```
=== bailey doctor (6.12) ===
=== cargo test status (6.12): 0
=== skip log (6.12) ===
```

## Regenerating an expectation

After a deliberate change, such as a new kernel version or a new test that
skips somewhere, run the entry, then replace the expectation with what the
guest actually printed:

```sh
sed -n '/^=== bailey doctor (6.12) ===$/,/^=== cargo test status/p' \
    6.12.log | sed '1d;$d' > ci/kernels/6.12.doctor
sed -n '/^=== skip log (6.12) ===$/,$p' \
    6.12.log | sed '1d' > ci/kernels/6.12.skips
```

Read the diff before committing it: the checker treats every line as a claim,
and a regenerated file that silently drops a required line weakens the job.

## What `?` means

A line in a `.skips` file may start with `?`:

```
?network::auto_mode_uses_the_private_namespace # the host's address is the sandbox's own (QEMU slirp)
```

It says the skip may happen but is not required to, for skips that depend on
the moment rather than the kernel, such as a pid reuse race. A listed skip
without `?` must happen on every run of that entry: if the kernel gained the
feature and the test stopped skipping, the job fails until the expectation is
updated on purpose.

Each line carries a trailing `# reason`. The reason is documentation, not a
match key; the checker compares only the key before the `#`.

## The shell test

`ci/test-check-expectations.sh` feeds the checker fixtures for every failure
mode and the passing case. It runs anywhere with a POSIX shell:

```sh
ci/test-check-expectations.sh
```
