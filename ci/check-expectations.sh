#!/bin/sh
# Compare one kernel guest's results with its expectations.
#
# Usage: check-expectations.sh <id> <doctor-output> <skip-log>
#
# <id> selects ci/kernels/<id>.doctor and ci/kernels/<id>.skips. Every
# non-empty, non-`#` line of the .doctor file must appear verbatim in the
# doctor output. The .skips file lists log keys (`<crate>::<test>` or
# `<crate>::<test>[<variant>]`), one per line, each optionally with a
# trailing `# reason` comment; a line may begin with `?` to say the skip is
# allowed but not required, for the skips that depend on the moment rather
# than the kernel, such as a pid reuse race.
#
# Fails when: a key is logged twice, a required doctor line is missing, a
# skip is logged that the file does not list, a listed skip without `?` did
# not happen, or any skip carries the test name `unknown`, which would mean
# no test owned it. Exits 0 only when doctor and log both match.
#
# BAILEY_KERNELS_DIR overrides where the expectation files live, so the
# shell test can feed fixtures instead of the real matrix.
set -u

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <id> <doctor-output> <skip-log>" >&2
    exit 2
fi
id=$1
doctor_output=$2
skip_log=$3
kernels_dir=${BAILEY_KERNELS_DIR:-$(dirname "$0")/kernels}
expect_doctor=$kernels_dir/$id.doctor
expect_skips=$kernels_dir/$id.skips

for file in "$doctor_output" "$skip_log" "$expect_doctor" "$expect_skips"; do
    if [ ! -f "$file" ]; then
        echo "FAIL: missing file: $file" >&2
        exit 2
    fi
done

status=0
fail() {
    echo "FAIL [$id]: $1"
    status=1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# A skip no test owned names no expectation and could hide behind any other
# key, so it is refused before anything else reads the log.
awk -F'\t' '$1 ~ /::unknown$/ { print }' "$skip_log" > "$tmp/unknown"
if [ -s "$tmp/unknown" ]; then
    fail "a skip was logged with the test name 'unknown':"
    cat "$tmp/unknown" >&2
fi

# One key, one line. A duplicate means one test skipped twice under one
# name, so a variant that stopped running would hide behind one that still
# skips.
cut -f1 "$skip_log" | sort | uniq -d > "$tmp/duplicate"
if [ -s "$tmp/duplicate" ]; then
    fail "a skip key was logged more than once:"
    cat "$tmp/duplicate" >&2
fi

# Every required doctor line must be there verbatim.
while IFS= read -r line || [ -n "$line" ]; do
    case $line in
        '' | '#'*) continue ;;
    esac
    if ! grep -Fxq -- "$line" "$doctor_output"; then
        fail "doctor does not name: $line"
    fi
done < "$expect_doctor"

# The keys split into those that must skip and those that merely may.
cut -f1 "$skip_log" | sort -u > "$tmp/logged"
sed 's/[[:space:]]*#.*//' "$expect_skips" |
    sed 's/^[[:space:]]*//' |
    sed '/^$/d' > "$tmp/all"
grep '^[^?]' "$tmp/all" | sort -u > "$tmp/required"
sed -n 's/^?[[:space:]]*//p' "$tmp/all" | sort -u > "$tmp/optional"
cat "$tmp/required" "$tmp/optional" | sort -u > "$tmp/allowed"

# A skip the file does not list: the kernel or the suite changed shape, and
# the expectation must say so on purpose.
comm -23 "$tmp/logged" "$tmp/allowed" > "$tmp/unlisted"
if [ -s "$tmp/unlisted" ]; then
    fail "a test skipped that is not listed in $expect_skips:"
    cat "$tmp/unlisted" >&2
fi

# A required skip that did not happen: the kernel gained the feature, and
# the expectation must be updated on purpose.
comm -13 "$tmp/logged" "$tmp/required" > "$tmp/missing"
if [ -s "$tmp/missing" ]; then
    fail "an expected skip did not happen:"
    cat "$tmp/missing" >&2
fi

if [ "$status" -eq 0 ]; then
    echo "ok [$id]: doctor and skips match the expectations"
fi
exit "$status"
