#!/usr/bin/env python3
"""Measure what bailey costs, layer by layer.

The front page claims near-zero overhead. This is what that claim is checked
against: every number in the documentation comes from running this.

    scripts/overhead.py [--bailey PATH] [--runs N]

Each case is timed as a whole process, so the figures include bailey's own
startup: reading config, checking the trust store, and probing the host. That is
the honest unit, because it is what a user waits for.
"""

from __future__ import annotations

import argparse
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DEVNULL = subprocess.DEVNULL


def once(argv: list[str], cwd: str, env: dict[str, str]) -> float:
    start = time.perf_counter()
    result = subprocess.run(argv, cwd=cwd, env=env, stdout=DEVNULL, stderr=DEVNULL)
    elapsed = (time.perf_counter() - start) * 1000
    if result.returncode != 0:
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(argv)}")
    return elapsed


def compare(
    cases: list[tuple[str, list[str]]],
    cwd: str,
    env: dict[str, str],
    runs: int,
    warmup: int,
) -> list[tuple[str, dict]]:
    """Time several commands against each other, one round at a time.

    Running each case to completion in turn makes the later ones look faster,
    because the page cache is warmer by the time they run. Measured that way the
    isolated case came out faster than the one with less confinement, which is
    not a thing that can be true. Interleaving cancels the drift, and rotating
    which case leads each round cancels any advantage in going first.
    """
    for _ in range(warmup):
        for _, argv in cases:
            once(argv, cwd, env)

    samples: dict[str, list[float]] = {name: [] for name, _ in cases}
    for round_ in range(runs):
        order = cases[round_ % len(cases):] + cases[: round_ % len(cases)]
        for name, argv in order:
            samples[name].append(once(argv, cwd, env))

    return [
        (
            name,
            {
                "median": statistics.median(s),
                "mean": statistics.fmean(s),
                "stdev": statistics.stdev(s) if len(s) > 1 else 0.0,
                "min": min(s),
            },
        )
        for name, s in samples.items()
    ]


def table(rows: list[tuple[str, dict]], baseline: float | None) -> None:
    width = max(len(name) for name, _ in rows)
    print(f"{'case'.ljust(width)}   median      mean ± stdev       min    vs bare")
    for name, r in rows:
        against = f"{r['median'] - baseline:+7.1f} ms" if baseline is not None else " " * 10
        print(
            f"{name.ljust(width)}  {r['median']:6.1f}ms  "
            f"{r['mean']:6.1f} ± {r['stdev']:4.1f}ms  {r['min']:6.1f}ms  {against}"
        )
    print()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bailey", default="target/release/bailey")
    parser.add_argument("--runs", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=20)
    args = parser.parse_args()

    bailey = str(Path(args.bailey).resolve())
    if not os.access(bailey, os.X_OK):
        raise SystemExit(f"no bailey at {bailey}; cargo build --release -p bailey")

    workspace = tempfile.TemporaryDirectory()
    root = workspace.name
    env = dict(os.environ)
    # A store and a data directory of their own, so the numbers do not depend on
    # how much the person running this has trusted.
    env["XDG_DATA_HOME"] = os.path.join(root, "data")

    # A policy that allows egress keeps the target in the host's network
    # namespace, which is how the cost of the namespace itself is separated from
    # the cost of Landlock and seccomp.
    open(os.path.join(root, "allow-egress.toml"), "w").write(
        "[network]\negress = \"allow\"\n"
    )

    print(f"bailey: {bailey}")
    print(f"runs:   {args.runs} (after {args.warmup} warmup)\n")

    print("== starting a program that does nothing ==\n")
    rows = compare(
        [
            ("/bin/true, no bailey", ["/bin/true"]),
            # Exits before resolving anything, so the gap to the cases below is
            # what the sandbox costs rather than what starting bailey costs.
            ("bailey --version", [bailey, "--version"]),
            (
                "landlock + seccomp",
                [bailey, "run", "--no-isolate", "-c", f"{root}/allow-egress.toml", "/bin/true"],
            ),
            ("+ network namespace", [bailey, "run", "--no-isolate", "/bin/true"]),
            ("+ namespace isolation", [bailey, "run", "/bin/true"]),
        ],
        root,
        env,
        args.runs,
        args.warmup,
    )
    table(rows, rows[0][1]["median"])

    print("== how many grants the policy has ==\n")
    rows = compare(
        [
            (name, [bailey, "run", "--profile", profile, "/bin/true"])
            for name, profile in [
                ("untrusted floor", "untrusted"),
                ("desktop-app", "desktop-app"),
                ("native-game", "native-game"),
            ]
        ],
        root,
        env,
        args.runs,
        args.warmup,
    )
    table(rows, rows[0][1]["median"])

    print("== a workload that opens a great many files ==\n")
    work = "find /usr/include -type f -name '*.h' -exec cat {} + > /dev/null"
    files = subprocess.run(
        ["sh", "-c", "find /usr/include -type f -name '*.h' | wc -l"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    print(f"({files} files)\n")

    heavy_runs = max(10, args.runs // 10)
    rows = compare(
        [
            ("no bailey", ["/bin/sh", "-c", work]),
            ("--no-isolate", [bailey, "run", "--no-isolate", "/bin/sh", "-c", work]),
            ("isolated", [bailey, "run", "/bin/sh", "-c", work]),
        ],
        root,
        env,
        heavy_runs,
        2,
    )
    table(rows, rows[0][1]["median"])


if __name__ == "__main__":
    sys.exit(main())
