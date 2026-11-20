#!/bin/sh
# Exercise ci/check-expectations.sh against fixtures for every verdict it
# can return: the passing shape, each distinct failure, and the `?` entry
# that is allowed to stay absent. Exits nonzero if any verdict is wrong.
set -u

check=$(dirname "$0")/check-expectations.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

expect_ok() {
    label=$1
    if BAILEY_KERNELS_DIR="$work/kernels" sh "$check" t "$work/doctor.txt" "$work/log.txt" >/dev/null 2>&1; then
        echo "ok: $label"
    else
        echo "FAIL: $label was expected to pass"
        exit 1
    fi
}

expect_fail() {
    label=$1
    if BAILEY_KERNELS_DIR="$work/kernels" sh "$check" t "$work/doctor.txt" "$work/log.txt" >/dev/null 2>&1; then
        echo "FAIL: $label was expected to fail"
        exit 1
    else
        echo "ok: $label fails as it should"
    fi
}

reset() {
    mkdir -p "$work/kernels"
    printf '  landlock: ABI 6\n  user namespaces: yes\n' > "$work/kernels/t.doctor"
    : > "$work/kernels/t.skips"
    printf '  landlock: ABI 6\n  user namespaces: yes\n' > "$work/doctor.txt"
    : > "$work/log.txt"
}

reset
expect_ok "a matching doctor and an empty skip log"

reset
: > "$work/doctor.txt"
expect_fail "a missing doctor line"

reset
printf 'reporting::a_test\tsome reason\n' > "$work/log.txt"
printf 'reporting::a_test # it cannot run here\n' > "$work/kernels/t.skips"
expect_ok "a listed skip that happened"

reset
printf 'reporting::a_test\tsome reason\n' > "$work/log.txt"
expect_fail "a skip that is not listed"

reset
printf 'reporting::a_test # it cannot run here\n' > "$work/kernels/t.skips"
expect_fail "a required skip that did not happen"

reset
printf '? reporting::a_test # the pid may be reused\n' > "$work/kernels/t.skips"
expect_ok "an optional skip that did not happen"

reset
printf 'reporting::a_test # once\nreporting::a_test # twice\n' > "$work/kernels/t.skips"
printf 'reporting::a_test\tsome reason\nreporting::a_test\tsome reason\n' > "$work/log.txt"
expect_fail "a key logged twice"

reset
printf 'reporting::unknown\tsome reason\n' > "$work/log.txt"
expect_fail "a skip with the test name unknown"

reset
printf 'reporting::a_variant[first]\tone\nreporting::a_variant[second]\ttwo\n' > "$work/log.txt"
printf 'reporting::a_variant[first] # a\nreporting::a_variant[second] # b\n' > "$work/kernels/t.skips"
expect_ok "distinct variant keys under one test"

reset
printf 'reporting::a_variant[first]\tone\nreporting::a_variant[first]\ttwo\n' > "$work/log.txt"
printf 'reporting::a_variant[first] # a\n' > "$work/kernels/t.skips"
expect_fail "one variant key logged twice"
