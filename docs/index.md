---
layout: home

hero:
  name: bailey
  text: A sandbox you can reason about
  tagline: Layered, deny-by-default confinement for untrusted programs on Linux. Unprivileged, near-zero overhead, and able to show you what a program actually touches.
  actions:
    - theme: brand
      text: Get started
      link: /guide/quick-start
    - theme: alt
      text: What is bailey
      link: /guide/what-is-bailey
    - theme: alt
      text: View on GitHub
      link: https://github.com/QaidVoid/bailey

features:
  - title: Deny by default
    details: A program reaches nothing it was not granted. Filesystem, network, and devices all start closed, and the bundled floor profile grants only what a dynamically linked binary needs to start.
  - title: Layers that cover each other
    details: Landlock for path and port rules, seccomp to trim the syscall surface, cgroups for resource caps, and namespaces to rebuild the world so ungranted paths are absent rather than merely denied.
  - title: Cascading configuration
    details: Global defaults under per-directory rules under per-program overrides, merged deterministically. One command shows you the resolved policy and every file that shaped it.
  - title: Evidence, not guesswork
    details: Audit mode records what a program opens and connects to, then diffs that against your policy and flags the parts worth arguing about before you grant them.
  - title: Unprivileged
    details: No setuid binary, no daemon, no container runtime. Only the optional audit recorder needs capabilities, and it lives in a separate minimal binary.
  - title: Honest about its edges
    details: Every mechanism can be absent or partial on a given kernel. Bailey negotiates what it can, reports what it could not enforce after every run, and documents the gaps it does not close.
---
