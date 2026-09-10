# Changelog

## [0.1.2](https://github.com/QaidVoid/bailey/compare/v0.1.1...v0.1.2) - 2026-09-10

### ⛰️  Features

- *(network)* Give the private namespace IPv6 where the host has it - ([89f3900](https://github.com/QaidVoid/bailey/commit/89f390043c428a6d46bcbb4d5d8fc658b4c61c20))
- *(network)* Hide the host address behind a private namespace - ([6bccff8](https://github.com/QaidVoid/bailey/commit/6bccff86aa0c7710c4597275c75e5ebcdcae202e))

### 🐛 Bug Fixes

- *(seccomp)* Deny the new mount API, not just mount(2) - ([572899a](https://github.com/QaidVoid/bailey/commit/572899a77caabab2525c0916aab87a84ab6a5f1a))

## [0.1.1](https://github.com/QaidVoid/bailey/compare/v0.1.0...v0.1.1) - 2026-09-07

### ⛰️  Features

- *(config)* Expand variables and tilde in env values - ([e54e2ef](https://github.com/QaidVoid/bailey/commit/e54e2effc158a1d32bee4b41bfbdeffbddc69ab5))
- *(filesystem)* Let a grant be placed at another path - ([e8db2d8](https://github.com/QaidVoid/bailey/commit/e8db2d8291f6c3d27ed05aeb0c51c49a5023f6e2))
- *(isolation)* Withhold the machine name with a UTS namespace - ([bbccb4a](https://github.com/QaidVoid/bailey/commit/bbccb4a66b1e40eeef507a595c074d44636e478c))
- *(reconcile)* Generate readable policies from real traces - ([25eed1b](https://github.com/QaidVoid/bailey/commit/25eed1b15a4f751e1eff2cfee17052edae019d35))
- *(resources)* Cap the size of any file a target writes - ([3eda2b6](https://github.com/QaidVoid/bailey/commit/3eda2b689e2d5f905e51bf8d6e583f6957b6f707))

### 🐛 Bug Fixes

- *(audit)* Stop reporting a target's own private home as a finding - ([02b7bbd](https://github.com/QaidVoid/bailey/commit/02b7bbd4b4dfb553ea67137cf20999b353447daa))
- *(audit)* Report the exit status, and find the helper on PATH - ([b899655](https://github.com/QaidVoid/bailey/commit/b8996557955ba05e23d838de0814bcb161e18e55))
- *(isolation)* Recreate a symlink instead of binding through it - ([8cf3a92](https://github.com/QaidVoid/bailey/commit/8cf3a92bbe52d0db2047c792aa5149ea855fdc1e))
- *(isolation)* Sweep staging dirs left by interrupted runs - ([1639fa2](https://github.com/QaidVoid/bailey/commit/1639fa2b2f961b0e9a2c6915d38ccb6da658d1ef))
- *(policy)* Check profiles for exposure, and provide the terminal - ([a573429](https://github.com/QaidVoid/bailey/commit/a573429279ef9e710810e1653585dbf4baf5f50f))
- *(profiles)* Make the runtime dir and shader cache readable - ([b0843af](https://github.com/QaidVoid/bailey/commit/b0843afa5c551dd08186aad2ec4c26f1d2113f2d))
- *(reconcile)* Count unresolved findings apart from high-risk - ([6af724d](https://github.com/QaidVoid/bailey/commit/6af724dd52c69adae2b4ffe1778c520216ae2fe4))

## [0.1.0] - 2026-08-21

### ⛰️  Features

- *(audit)* Scope observation by cgroup, not by polling /proc - ([0d96b28](https://github.com/QaidVoid/bailey/commit/0d96b2832a2945b3a3f6da972288c30f2bfd1dd4))
- *(audit)* Confine audit runs and record what they miss - ([ff37bc6](https://github.com/QaidVoid/bailey/commit/ff37bc613de49fc22e36adfc569bcd2a80166829))
- *(audit)* Ebpf observation backend via aya - ([25329d0](https://github.com/QaidVoid/bailey/commit/25329d05bcdd159d031c780e7413b32c8cfce0b2))
- *(cli)* Add shell integration for fish and bash - ([ff8a236](https://github.com/QaidVoid/bailey/commit/ff8a2362bf1308eb5c3a81bffc1ef1696419a2dc))
- *(cli)* Add a confined shell that covers what it starts - ([745b12d](https://github.com/QaidVoid/bailey/commit/745b12df099127acb1e175c51f7767e073dd31a9))
- *(cli)* Isolate by default, with --no-isolate to opt out - ([c3aacd8](https://github.com/QaidVoid/bailey/commit/c3aacd80371baadcd68aee603d2cee67f7e59f25))
- *(cli)* Report what a host can enforce and what a run did - ([b155637](https://github.com/QaidVoid/bailey/commit/b155637462bab349ba5c7cf6c1c43d4b9a8fed6a))
- *(cli)* Bundled profiles, reconciliation, audit wiring - ([c2d8517](https://github.com/QaidVoid/bailey/commit/c2d85170c71b4d784f823f63247814b8f05e8ffc))
- *(config)* Apply a discovered config only once trusted - ([d86ab86](https://github.com/QaidVoid/bailey/commit/d86ab860c4852676a53858252db20a25e02decd0))
- *(enforce)* Enforce nested denials by concealment - ([09bd4e1](https://github.com/QaidVoid/bailey/commit/09bd4e1e0933d2aa218c61e0a35eb0268382b8fa))
- *(enforce)* Namespace isolation with pivot_root defense-in-depth - ([748c2a3](https://github.com/QaidVoid/bailey/commit/748c2a3353537d9613958e71928d15d31cc3901c))
- *(enforce)* Landlock, seccomp, cgroup enforcement backend - ([3a932a3](https://github.com/QaidVoid/bailey/commit/3a932a3773e9886245385acf4c2522c3e76a689e))
- *(network)* Deny egress at every protocol, not just TCP - ([8cbe22d](https://github.com/QaidVoid/bailey/commit/8cbe22d886eef177f4cc60a408e12d38a1691f81))
- *(policy)* Read-only islands, and ${PWD} for per-program grants - ([05412be](https://github.com/QaidVoid/bailey/commit/05412be7d00654105296d9f668aa1afe5505cfd3))
- *(profile)* Generate profiles from saved audit traces - ([4da4f9a](https://github.com/QaidVoid/bailey/commit/4da4f9a2ee4cb4868755c9f386a32658a678716d))
- *(profiles)* User-written profiles that can claim a target - ([1888f85](https://github.com/QaidVoid/bailey/commit/1888f856d6c1843c7b806c30ac5b812f06785023))
- *(world)* Build the target's environment, home, and storage - ([3a6b200](https://github.com/QaidVoid/bailey/commit/3a6b200b3f8eccf0aeecfe4c76a8ccc175915442))
- Scaffold bailey with policy model and config resolver - ([77da5d3](https://github.com/QaidVoid/bailey/commit/77da5d32624ca5699e7379c820f6432575c881e3))

### 🐛 Bug Fixes

- *(backend)* Build for musl on x86_64 and aarch64 - ([d9848a0](https://github.com/QaidVoid/bailey/commit/d9848a0c54396571f842aae5c9f2df696a9854b4))
- *(cgroup)* Create the run's cgroup as a sibling, not a child - ([19385f1](https://github.com/QaidVoid/bailey/commit/19385f156f4b741ac2fd7718c72107fd0644a7cd))
- *(policy)* Keep implicit grants from widening explicit ones - ([e3c0572](https://github.com/QaidVoid/bailey/commit/e3c05720fe7d748d1939a13834111a038ead7144))
- *(policy)* Make config directives reach enforcement - ([6ed5d57](https://github.com/QaidVoid/bailey/commit/6ed5d57e717c98d7866b1699d211e9791f45c714))
- *(profiles)* Let the agent profile reach its API - ([b01b9db](https://github.com/QaidVoid/bailey/commit/b01b9db43c7cd021f582fe5beaa47bc9c521966d))
- *(report)* Name the private home when the cwd is dropped - ([75f275e](https://github.com/QaidVoid/bailey/commit/75f275e9827836168175883f0f2da38069b33a4f))
- *(world)* Keep the private home for targets under $HOME - ([70e5c16](https://github.com/QaidVoid/bailey/commit/70e5c167287df7bd913f825297af196048678042))

### 🚜 Refactor

- *(audit)* Move ebpf into minimal privileged helper binary - ([bd6c08e](https://github.com/QaidVoid/bailey/commit/bd6c08ece6cecabe811b9b6265a5c3b6e6aff8bf))
- *(hooks)* Remove on_violation, which nothing could trigger - ([0022b28](https://github.com/QaidVoid/bailey/commit/0022b28ea6ad5c9186fc64641f89aae7f5c772e6))

### 📚 Documentation

- *(doctor)* Say what can and cannot be checked about denials - ([74e20e6](https://github.com/QaidVoid/bailey/commit/74e20e69c9b719d77a9e633cabbd09aef1724ade))
- Report unenforceable denials and refresh docs - ([9b6432f](https://github.com/QaidVoid/bailey/commit/9b6432fa406d6176c188f61be71eb0e16d038b81))

### 🧪 Testing

- Walk the audit, generate, enforce loop end to end - ([03d8964](https://github.com/QaidVoid/bailey/commit/03d8964e1cf3c904ff629f746e07573cc23d6c7d))

### ⚙️ Miscellaneous Tasks

- Publish to crates.io with trusted publishing - ([c95198e](https://github.com/QaidVoid/bailey/commit/c95198e2092f9535c17ff81a41b14bd77aeac7b1))
- Release with release-plz, and attach signed binaries - ([a6795d6](https://github.com/QaidVoid/bailey/commit/a6795d6e4b4c21450dbb813a961a2428c750b4d0))
- Fix the docs lockfile, and check eBPF without a linker - ([42811de](https://github.com/QaidVoid/bailey/commit/42811de3880cedbe43c0e141ff9a134251744076))
- Broaden crate description beyond games - ([c9dd6a2](https://github.com/QaidVoid/bailey/commit/c9dd6a2dc3ba275038483a00e410e5f178690de6))
- Rust 2024 edition and robust isolation probe - ([141b7ab](https://github.com/QaidVoid/bailey/commit/141b7ab05d876560d7e982b87a65641b56216f2e))
