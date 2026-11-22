#!/bin/sh
# The kernel matrix guest: prepare what the dropped user needs, run doctor
# and the suite as that user, and hold the results to the kernel's
# expectations.
#
# Usage (from the host, through vng): ci/guest.sh <id> [KEY=VALUE ...]
#
# <id> selects the entry with the same name in ci/kernels.json. KEY=VALUE
# pairs are exported into the dropped user's environment; CI passes the
# toolchain homes this way, since they live outside the tree the guest
# shares. Exits nonzero when the suite or the expectation check fails, so
# vng's exit status is the job's verdict.
#
# The guest boots as root, and bailey refuses root, so everything here runs
# as the uid that owns the checkout. Two properties of a virtme guest need
# preparing first, and both were learned by booting one:
#
#   The shared tree is writable, but a fresh /tmp entry lands in an upper
#   directory only root may write, so bailey's namespace probe, which
#   creates a directory under /tmp, fails for an ordinary user until /tmp
#   is made world-writable again. Without this, doctor reports user
#   namespaces unavailable no matter what the kernel provides.
#
#   The user-mode network interface vng creates stays down, so it is
#   addressed by hand: 10.0.2.15 with 10.0.2.2 as its route, the addresses
#   QEMU's user networking answers on. pasta needs an interface with a
#   route to configure the private namespace from.
set -eu

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <id> [KEY=VALUE ...]" >&2
    exit 2
fi
id=$1
shift

repo=$(cd "$(dirname "$0")/.." && pwd)
uid=$(stat -c '%u' "$repo")
gid=$(stat -c '%g' "$repo")

# The network interface and a writable /tmp, before anything drops
# privileges.
ip link set eth0 up 2>/dev/null || true
ip addr add 10.0.2.15/24 dev eth0 2>/dev/null || true
ip route add default via 10.0.2.2 2>/dev/null || true
chmod 1777 /tmp

# The entry decides whether this guest gets a delegated cgroup. The one
# entry that answers no exists to assert the rlimit fallbacks bailey takes
# when the runner uid owns no cgroup at all.
#
# "session" adds the other half of a working delegation: the dropped user's
# process is moved into a leaf of the delegated subtree before anything
# runs. The kernel lets a non-root writer move a process only between
# cgroups whose common ancestor's `cgroup.procs` it may write, so a caller
# sitting in the hierarchy root can create a run's cgroup but never join
# it. Real sessions are always placed inside the subtree they were handed;
# the entry that keeps the caller outside (6.12-cgroup-nojoin) pins the
# skip-with-warning behaviour that answers.
cgroup_and_session=$(python3 -c '
import json, sys
entries = {e["id"]: e for e in json.load(open(sys.argv[1]))["kernel"]}
entry = entries[sys.argv[2]]
print(str(entry.get("cgroup", True)).lower())
print(str(entry.get("session", False)).lower())
' "$repo/ci/kernels.json" "$id") || exit 2
cgroup=$(printf '%s\n' "$cgroup_and_session" | sed -n 1p)
session=$(printf '%s\n' "$cgroup_and_session" | sed -n 2p)

home=/tmp/bailey-home-$id
mkdir -p "$home/.local/share"
chown -R "$uid:$gid" "$home"
# The skip log is pre-created so the first skip does not depend on write
# permission in /tmp's upper layer, and pre-created owned: a root-owned log
# would silently swallow every append the dropped user makes.
skip_log=/tmp/bailey-skips-$id.log
touch "$skip_log"
chown "$uid:$gid" "$skip_log"
doctor_out=/tmp/bailey-doctor-$id.log
test_status_file=/tmp/bailey-test-status-$id
inner=/tmp/bailey-inner-$id.sh

if [ "$cgroup" = true ]; then
    if ! mountpoint -q /sys/fs/cgroup; then
        mount -t cgroup2 none /sys/fs/cgroup
    fi
    printf '+memory +pids +cpu\n' > /sys/fs/cgroup/cgroup.subtree_control
    mkdir -p /sys/fs/cgroup/ci
    printf '+memory +pids +cpu\n' > /sys/fs/cgroup/ci/cgroup.subtree_control
    # The session leaf exists before the chown, so its interface files end
    # up owned by the user: they are the common ancestor's files the join
    # permission check looks at.
    mkdir -p /sys/fs/cgroup/ci/session
    chown -R "$uid:$gid" /sys/fs/cgroup/ci
    set -- "$@" "BAILEY_CGROUP_ROOT=/sys/fs/cgroup/ci"
fi

# The dropped user's PATH must reach the toolchain. cargo lives in
# CARGO_HOME's bin, which the host's PATH may name anywhere, so whatever
# CARGO_HOME the caller passed, its bin goes first.
cargo_home=
for kv in "$@"; do
    case $kv in
        CARGO_HOME=*) cargo_home=${kv#CARGO_HOME=} ;;
    esac
done
path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[ -n "$cargo_home" ] && path=$cargo_home/bin:$path

# What the dropped user runs. The doctor output is captured for the
# expectation check and printed; the suite's own output streams as it
# goes. The doctor runs without the build directory on its PATH, so its
# helper line describes what a plain install would see rather than the
# checkout's own helper; the suite runs with it, so the audit tests find
# the helper they exercise. The wait line holds the dropped user until its
# process sits in the session leaf, since doctor answers the join question
# from the caller's own cgroup. The suite's thread count is pinned below
# the vcpu count: deadline and mount tests need a scheduler that is not
# drowning, and libtest otherwise spawns one thread per host cpu.
if [ "$session" = true ]; then
    session_wait="/tmp/bailey-session-ready-$id"
    rm -f "$session_wait"
    wait_line="n=0; while [ ! -e '$session_wait' ] && [ \$n -lt 200 ]; do sleep 0.05; n=\$((n+1)); done"
else
    session_wait=
    wait_line=
fi
cat > "$inner" <<INNER
set -u
$wait_line
PATH="$path" $repo/target/debug/bailey doctor 2>&1 | tee "$doctor_out"
cd $repo
PATH="$path:$repo/target/debug" RUST_TEST_THREADS=4 cargo test --offline --no-fail-fast
status=\$?
echo \$status > $test_status_file
exit \$status
INNER

echo "=== bailey doctor ($id) ==="
set +e
if [ "$session" = true ]; then
    # The session leaf is written by root: a non-root process cannot move
    # itself out of the hierarchy root, which is precisely the containment
    # this placement exists to satisfy.
    setpriv --reuid "$uid" --regid "$gid" --init-groups \
        env HOME="$home" \
        XDG_DATA_HOME="$home/.local/share" \
        BAILEY_TEST_SKIP_LOG="$skip_log" \
        PATH="$path" \
        "$@" \
        sh "$inner" &
    inner_pid=$!
    echo "$inner_pid" > /sys/fs/cgroup/ci/session/cgroup.procs
    touch "$session_wait"
    wait "$inner_pid"
    inner_status=$?
else
    setpriv --reuid "$uid" --regid "$gid" --init-groups \
        env HOME="$home" \
        XDG_DATA_HOME="$home/.local/share" \
        BAILEY_TEST_SKIP_LOG="$skip_log" \
        PATH="$path" \
        "$@" \
        sh "$inner"
    inner_status=$?
fi
set -e

echo "=== cargo test status ($id): $(cat "$test_status_file")"
echo "=== skip log ($id) ==="
cat "$skip_log"

# CI reads everything above from the job log, and so does expectation
# generation: the guest's filesystem is an overlay whose writes never
# reach the shared tree, so the doctor output and the skip log between
# their `=== ` markers are the only way they leave the guest.
check_status=0
"$repo/ci/check-expectations.sh" "$id" "$doctor_out" "$skip_log" || check_status=$?

# The worse of the two: a suite failure and a failed expectation check are
# both reasons to fail the job, and either one alone is enough.
if [ "$inner_status" -ne 0 ]; then
    exit "$inner_status"
fi
exit "$check_status"
