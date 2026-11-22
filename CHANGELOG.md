# Changelog

## [0.3.0](https://github.com/QaidVoid/bailey/compare/v0.2.4...v0.3.0) - 2026-11-22

### ⛰️  Features

- *(audit)* Add unprivileged seccomp fallback observer - ([e061c29](https://github.com/QaidVoid/bailey/commit/e061c299e5bd1481de7d32a6670ba19e4c22bf01))
- *(audit)* Measure peaks and suggest resources - ([5b13fe9](https://github.com/QaidVoid/bailey/commit/5b13fe97778ca7b909ddeb65bff41a4e3f38b5f7))
- *(broker)* Log one json line per decision and stop on sigterm - ([8c05ed3](https://github.com/QaidVoid/bailey/commit/8c05ed3b6acf924e7a4c3f7a9e3a126eaa5d6be2))
- *(broker)* Add the request codec, tls ca and tunnel engine - ([d8d78e3](https://github.com/QaidVoid/bailey/commit/d8d78e3efaf3e096db709488868b35d8ce02acf4))
- *(config)* Parse destination, deny and dns egress rules - ([14cf9f2](https://github.com/QaidVoid/bailey/commit/14cf9f2fd5b2c822e373c8e575610b0e8f644edc))
- *(egress)* Report destination rules and dns in the summary - ([b8c44f9](https://github.com/QaidVoid/bailey/commit/b8c44f9489e237f46b9a1f726b4a64d7da51f172))
- *(egress)* Enforce destination rules in the private namespace - ([0d88c9e](https://github.com/QaidVoid/bailey/commit/0d88c9e1005b3523b7fb6ae676ead054d0770804))
- *(egress)* Resolve and pin hostname rules before the run - ([6317383](https://github.com/QaidVoid/bailey/commit/631738342d256a48b3e1b8d26a559d9b67ef22a7))
- *(enforce)* [**breaking**] Connect needs a listed socket - ([3f57248](https://github.com/QaidVoid/bailey/commit/3f572485ae809238209f2460740fd68fa99dd34e))
- *(http)* Wire the builtin broker into runs and the summary - ([c1f32bd](https://github.com/QaidVoid/bailey/commit/c1f32bd645c7043c79448b7a27b0c3857e8f9202))
- *(http)* Add the bailey-broker crate and the wire protocol - ([4818e30](https://github.com/QaidVoid/bailey/commit/4818e3022bba104a2d86b27c28e357020252cc1b))
- *(http)* Report the broker rules and credentials in show - ([ea6c961](https://github.com/QaidVoid/bailey/commit/ea6c961d267b5d472ab32f79f98620c2fc13c30a))
- *(http)* Add the http quick grants and the builtin broker flag - ([3615f15](https://github.com/QaidVoid/bailey/commit/3615f1510c2ab61d4c30ca7c0b3b3cf56e28c371))
- *(http)* Gate credential and log keys by layer origin - ([b3478da](https://github.com/QaidVoid/bailey/commit/b3478daf1825081dbbca0b7cb06532bd88be4c8b))
- *(http)* Resolve intercept coverage and broker requirements - ([c9c99b6](https://github.com/QaidVoid/bailey/commit/c9c99b6c0b175d108100eeb1299518e5bd303e91))
- *(http)* Parse the http tables and the builtin broker value - ([15e0a39](https://github.com/QaidVoid/bailey/commit/15e0a39cda659eb48cf9eee65128618dfeb82ea7))
- *(http)* Add the canonical path and request host checks - ([03d5d06](https://github.com/QaidVoid/bailey/commit/03d5d06d200c1a5ea55bbdd57a43df0362dfbf81))
- *(http)* Add the http rule model and matcher - ([ec6a138](https://github.com/QaidVoid/bailey/commit/ec6a1381e563f4b9337e132f088dc1f5df6ced24))
- *(network)* Choose the network mode from the policy - ([ecab72d](https://github.com/QaidVoid/bailey/commit/ecab72d392c1ac1306904211bcc0cf131308277d))
- *(network)* Forward and publish ports under --proxy-net - ([4fb8580](https://github.com/QaidVoid/bailey/commit/4fb85800d9e9a8ade2774c08e3d428b158f0dffe))
- *(resources)* Ask the user manager for a delegated scope - ([8015eb9](https://github.com/QaidVoid/bailey/commit/8015eb96b6e90cab3d3c8f609af6ce68e3533ba3))
- *(resources)* Add open-file and address-space rlimit fallbacks - ([51e407a](https://github.com/QaidVoid/bailey/commit/51e407a612ff6ae201849953093a216be5c1b4c2))

### 🐛 Bug Fixes

- *(audit)* Read an int syscall argument from its low half - ([5ad91a2](https://github.com/QaidVoid/bailey/commit/5ad91a223e4c027d539cb62bb7751b125b189c04))
- *(audit)* Give a target memory read a second - ([9ab2d77](https://github.com/QaidVoid/bailey/commit/9ab2d77fecf432627c69d9c67c810e68c78ddfda))
- *(broker)* Grant no connect port below landlock abi 4 - ([4fd64e6](https://github.com/QaidVoid/bailey/commit/4fd64e67b60f1f1c7d273eee6f81cbd62c850642))
- *(cli)* Refuse all root-to-root uid mappings in the guard - ([4ca46ef](https://github.com/QaidVoid/bailey/commit/4ca46ef7fa1ec053e7fb4f2f0d103c928d8265dc))
- *(enforce)* Carry a sandbox setup refusal to the user - ([ed222fb](https://github.com/QaidVoid/bailey/commit/ed222fb3ce573d6f3b641220246eac840a7ab512))
- *(enforce)* Remove generated-file staging on the host - ([dc33bef](https://github.com/QaidVoid/bailey/commit/dc33bef01e0e62f3e4f845746c5adca68bb6881d))
- *(enforce)* Refuse MPTCP and SMC sockets to close egress bypass - ([0c80828](https://github.com/QaidVoid/bailey/commit/0c8082877ca75e011fd8ef0a2ca81e43288791dc))
- *(enforce)* Name the signal that killed the target - ([98d74a6](https://github.com/QaidVoid/bailey/commit/98d74a6b14a57c5280c76ae5b0366d4d27fd01df))
- *(isolation)* Remount read-only paths where links lead - ([396da05](https://github.com/QaidVoid/bailey/commit/396da05de0b6dc08aa9e94ddce694000365d7dab))
- *(isolation)* Refuse nested namespaces with a kernel limit - ([e6ec414](https://github.com/QaidVoid/bailey/commit/e6ec4140719a0ccf351e5c101da04c63dd05817f))
- *(network)* Refuse a broker when pasta cannot map loopback - ([0748af9](https://github.com/QaidVoid/bailey/commit/0748af97071398197d74a8ad8ea03a2272eb67cc))
- *(network)* Place a generated resolver where its link leads - ([d065b35](https://github.com/QaidVoid/bailey/commit/d065b35b8c7b8dff4a153add4a64ee0e54f8b462))
- *(run)* Drop the stale-justified loopback rules in broker mode - ([212b521](https://github.com/QaidVoid/bailey/commit/212b521cc014cb538653a9b1ae53ec0509122f09))
- *(run)* Drop the broker credentials once handed over - ([c489471](https://github.com/QaidVoid/bailey/commit/c48947100a6454b419ee4ffc8f4b19c0ae05ea8b))
- *(tests)* Drop a needless format in the credential hook probe - ([54b0b6c](https://github.com/QaidVoid/bailey/commit/54b0b6cf23cd34f8164ef2a49db272e03a0b3ce2))
- Hold ci on ubuntu runners and old pasta - ([115c85d](https://github.com/QaidVoid/bailey/commit/115c85dd4f17f8841e3e0d918e319982644a83e3))
- Correct network mode handling and root guard detection - ([32b7390](https://github.com/QaidVoid/bailey/commit/32b73902be8d4e77b869945378bf4e8b6440d7aa))

### 📚 Documentation

- *(egress)* Document destination rules, dns and their limits - ([40d8c8e](https://github.com/QaidVoid/bailey/commit/40d8c8efbfa9106350b80b0eb6768889a2972332))
- *(enforce)* Hold the enforcement page to the filter - ([3b6e4ee](https://github.com/QaidVoid/bailey/commit/3b6e4ee4b2de4a5f30d01bfe4b47bd0e3794d8e3))

### 🎨 Styling

- Apply rustfmt to the network files - ([cb47fe0](https://github.com/QaidVoid/bailey/commit/cb47fe0d8b1357c3403ba738a28e7b34eddcf324))

### 🧪 Testing

- *(egress)* Cover destination rules, dns and the broker - ([2efc483](https://github.com/QaidVoid/bailey/commit/2efc483183d9cc8518a0b3231fa128bbcb0bf331))
- *(http)* Cover the log refusals and the counts line - ([ad9dcc6](https://github.com/QaidVoid/bailey/commit/ad9dcc63e940a50404c61722c7a4d3b55fee73cc))
- *(http)* Cover broker runs, the ca bundle and credentials - ([a315532](https://github.com/QaidVoid/bailey/commit/a315532d91c37436f8f590073667fad48f1f0717))
- *(nesting)* Cover what a nested run refuses and reports - ([f2ab16e](https://github.com/QaidVoid/bailey/commit/f2ab16e164a8657ef72ba81a971d0fcf0daa57c1))
- Tell the private-mode refusals apart by their cause - ([aed9259](https://github.com/QaidVoid/bailey/commit/aed92594b5897cdc597300eeefdc613319bca0e2))
- Hold the suite on ci runners and older kernels - ([ea4925c](https://github.com/QaidVoid/bailey/commit/ea4925c9ab0fb68196ca88ccb100503b73109b4f))

### ⚙️ Miscellaneous Tasks

- *(ci)* Track kernel matrix fixtures and skip log canary - ([daf5f9b](https://github.com/QaidVoid/bailey/commit/daf5f9b7683ad5bcebaa3fe7f80f4564a946db41))
- *(fmt)* Apply the current rustfmt to the workspace - ([810290c](https://github.com/QaidVoid/bailey/commit/810290cecdc502edc1e13d6bb3b49ca9f5671aa3))
- Run the suite on a kernel matrix - ([3a98976](https://github.com/QaidVoid/bailey/commit/3a989763bee6bc70571609aa746022a44480174a))

## [0.2.4](https://github.com/QaidVoid/bailey/compare/v0.2.3...v0.2.4) - 2026-10-12

### ⛰️  Features

- *(cli)* Add quick-grant flags above all config layers - ([64a8215](https://github.com/QaidVoid/bailey/commit/64a821534b5e704a4760fa443db50a8b9d76bc9f))
- *(config)* Let the target mount its own FUSE filesystems - ([f196c6d](https://github.com/QaidVoid/bailey/commit/f196c6d1cf22406d79930820879310d945671448))
- *(config)* Forward host TCP ports into the sandbox - ([73cca6f](https://github.com/QaidVoid/bailey/commit/73cca6f79df4cd983a07706eed621626ff9f0c8e))
- *(config)* Broker URL opens from inside the sandbox - ([78b8954](https://github.com/QaidVoid/bailey/commit/78b895464c1c37b6f43ea25b991c65fab57d7928))
- *(config)* Relay desktop service sockets into the sandbox - ([bf26fdd](https://github.com/QaidVoid/bailey/commit/bf26fdd2a3698afe2f9faa8a442a0dcc3d2a346f))
- *(config)* Mount FUSE filesystems for the target - ([f2bdef0](https://github.com/QaidVoid/bailey/commit/f2bdef010183350993d294775e7bd4f7e62b0876))
- *(isolation)* Refuse the run when a granted path is unreadable - ([785eaca](https://github.com/QaidVoid/bailey/commit/785eacab4121add4dfcf654cb1c7f259760e952d))

### 🐛 Bug Fixes

- *(cli)* Report the hooks a config runs in trust and show ([#65](https://github.com/QaidVoid/bailey/pull/65)) - ([5cdfc13](https://github.com/QaidVoid/bailey/commit/5cdfc135e986d8edc40baae0bd5ab646e24ad1c1))
- *(config)* Compare grant and deny paths in one canonical form ([#71](https://github.com/QaidVoid/bailey/pull/71)) - ([87c545e](https://github.com/QaidVoid/bailey/commit/87c545ecceae3873782ca1c997a2afada5b1db30))
- *(config)* Ignore a relative XDG_CONFIG_HOME value ([#63](https://github.com/QaidVoid/bailey/pull/63)) - ([6df4b1c](https://github.com/QaidVoid/bailey/commit/6df4b1ca25a0ecedc1cd4df324f587eb4e1b239b))
- *(config)* Hash and apply one read of each config layer ([#62](https://github.com/QaidVoid/bailey/pull/62)) - ([19f32f4](https://github.com/QaidVoid/bailey/commit/19f32f42e9b2a6fcf09b6b2740e84b3c3c25a9d8))
- *(config)* Refuse self_fuse beside a partial egress allowance ([#58](https://github.com/QaidVoid/bailey/pull/58)) - ([5d987c1](https://github.com/QaidVoid/bailey/commit/5d987c1da77c929d39120ecc65cb2efd6dd73414))
- *(enforce)* Build the reconstructed root in a fresh directory ([#70](https://github.com/QaidVoid/bailey/pull/70)) - ([ef5ace5](https://github.com/QaidVoid/bailey/commit/ef5ace5539fd912cc9261741df965153e046637e))
- *(enforce)* Report landlock only when its ruleset applied ([#59](https://github.com/QaidVoid/bailey/pull/59)) - ([2bbf882](https://github.com/QaidVoid/bailey/commit/2bbf882a6a747f552add55e43ef62904f434d60d))
- *(forward)* Close an idle forwarded connection at a deadline ([#66](https://github.com/QaidVoid/bailey/pull/66)) - ([a579335](https://github.com/QaidVoid/bailey/commit/a5793359a1980eb7ee1a8bcb18bcc0774d5c50ed))
- *(forward)* Name the egress allowance when refusing forwards - ([da44294](https://github.com/QaidVoid/bailey/commit/da4429408569ce4f1a3f6e728860ac420b4727f2))
- *(forward)* Serve the relay while the target runs - ([06b1859](https://github.com/QaidVoid/bailey/commit/06b185997cf91e06f7c3483ab02c21aa7337757f))
- *(isolation)* Name the host path a read-only island lost ([#61](https://github.com/QaidVoid/bailey/pull/61)) - ([7391425](https://github.com/QaidVoid/bailey/commit/7391425dbcaa72b6982d45f8cf3155d7e6e309ae))
- *(isolation)* Refuse a read-only entry the sandbox root lost ([#60](https://github.com/QaidVoid/bailey/pull/60)) - ([b73ee60](https://github.com/QaidVoid/bailey/commit/b73ee60d543e5d3b3fd060d4b800fff4129121c9))
- *(isolation)* Reap sandbox orphans from a supervisor init - ([fc433bc](https://github.com/QaidVoid/bailey/commit/fc433bc7c44a680d149b826fedea5c6c2f80875d))
- *(probe)* Answer cgroup delegation the way the run behaves ([#69](https://github.com/QaidVoid/bailey/pull/69)) - ([f3e5746](https://github.com/QaidVoid/bailey/commit/f3e57468ac2b001e99e91c42535db8ade8958236))
- *(trust)* Refuse a record whose parent directories are exposed ([#72](https://github.com/QaidVoid/bailey/pull/72)) - ([8e4f240](https://github.com/QaidVoid/bailey/commit/8e4f240e1a21c4b52a386e94394a14610ff87c56))
- *(trust)* Resolve symlinks in the exposed-parents walk ([#68](https://github.com/QaidVoid/bailey/pull/68)) - ([25f3a07](https://github.com/QaidVoid/bailey/commit/25f3a0710cf9b08c62732f998370b6bb47473261))
- *(trust)* Open the staging file exclusively ([#64](https://github.com/QaidVoid/bailey/pull/64)) - ([2902684](https://github.com/QaidVoid/bailey/commit/2902684a2a29955422dc2a7b7de00b6a291e32aa))

### 🎨 Styling

- Apply rustfmt's stock defaults ([#40](https://github.com/QaidVoid/bailey/pull/40)) - ([891436d](https://github.com/QaidVoid/bailey/commit/891436d41091bc0f4e46f458311a6bc83a7da9f8))

### ⚙️ Miscellaneous Tasks

- Satisfy the lints the current toolchain flags ([#41](https://github.com/QaidVoid/bailey/pull/41)) - ([3f1790a](https://github.com/QaidVoid/bailey/commit/3f1790a0a2e6041d188cfb675a925f47acf00c88))

## [0.2.3](https://github.com/QaidVoid/bailey/compare/v0.2.2...v0.2.3) - 2026-09-29

### 🐛 Bug Fixes

- *(cli)* Report brokered egress as broker, not host - ([ecff5d7](https://github.com/QaidVoid/bailey/commit/ecff5d7e41f5f9fc0e5564c0c85d5e829a71e0a7))
- *(enforce)* Close the planted-config and denylist gaps - ([5d5c36a](https://github.com/QaidVoid/bailey/commit/5d5c36a2a11c7dc30171b9d6d24ad966065b5567))
- *(isolation)* Keep locked mount flags on read-only remount - ([5ff43c4](https://github.com/QaidVoid/bailey/commit/5ff43c433b6f4edbc5e964d78b43928ed41c4f86))

## [0.2.2](https://github.com/QaidVoid/bailey/compare/v0.2.1...v0.2.2) - 2026-09-21

### ⛰️  Features

- *(isolation)* Let the private /tmp be backed by a disk directory - ([64c555e](https://github.com/QaidVoid/bailey/commit/64c555e36c19ce05312a2f3745ca5d38da4cea04))
- *(isolation)* Give a granted /dev/pts an instance of its own - ([1d82f37](https://github.com/QaidVoid/bailey/commit/1d82f37acd06beec6c491d9a98765b81b3068379))

### 🐛 Bug Fixes

- *(isolation)* Name a concealed file's cover by its real path - ([11e7c1d](https://github.com/QaidVoid/bailey/commit/11e7c1d0338bbe93b47ee20d09dfaafbde06d456))
- *(network)* Forward no port between the host and the namespace - ([a3d73c7](https://github.com/QaidVoid/bailey/commit/a3d73c78b4c2358ece3621b0a933096a4bfa7144))

## [0.2.1](https://github.com/QaidVoid/bailey/compare/v0.2.0...v0.2.1) - 2026-09-18

### ⛰️  Features

- *(enforce)* Apply pids_max as an rlimit without a cgroup - ([2f453a6](https://github.com/QaidVoid/bailey/commit/2f453a6fc0bcd70d5937393e34779f1edf4ca4ae))

### 🐛 Bug Fixes

- *(enforce)* Open grant descriptors with a real O_PATH ([#34](https://github.com/QaidVoid/bailey/pull/34)) - ([45dde0c](https://github.com/QaidVoid/bailey/commit/45dde0ca381f0e858f90eb209bfb0231b9977449))
- *(tests)* Read the host before expecting a process limit - ([be9060b](https://github.com/QaidVoid/bailey/commit/be9060b43b36b1022c7c8135bfdb68172c574d7b))

## [0.2.0](https://github.com/QaidVoid/bailey/compare/v0.1.4...v0.2.0) - 2026-09-16

### ⚠️ Behaviour changes

- **A read grant no longer carries execute.** The two are separate rights now.
  A policy that granted `read` on a directory and relied on running something
  from it must grant `execute` there as well, or the `execve` is refused.
- **bailey refuses to run as real root.** As uid 0 the target was uid 0 on the
  host and ordinary permissions stopped being a barrier. Being uid 0 inside a
  user namespace is still fine, which is what a run under pasta is.
- **Helper programs come only from system directories.** `pasta` and `nft` are
  resolved from a fixed list and refused if writable by anyone but their owner,
  never from `PATH`.
- **A bound port is no longer published to the host.** A policy that denies
  egress keeps its own network namespace even when it binds a port, so the port
  is reachable from inside the sandbox and nowhere else. Allow egress if it must
  be reachable from outside.
- **A grant that cannot be installed fails the run.** Only a path that does not
  exist is skipped; one that exists but cannot be opened used to be dropped
  while the run still reported Landlock as applied.


### 🐛 Bug Fixes

- *(cli)* Create the egress namespace before pasta configures it - ([aff5641](https://github.com/QaidVoid/bailey/commit/aff5641a5807924e1b8442b5ba61c2cb165bcf3f))
- *(cli)* Take helper programs only from trusted locations - ([0981949](https://github.com/QaidVoid/bailey/commit/0981949f8462191e21f84ec99d3654f67841708a))
- *(config)* Keep the relocation of the layer that resets - ([d974f0a](https://github.com/QaidVoid/bailey/commit/d974f0a24189d3b23127c41112732a27b17beca0))
- *(config)* Clear relocations when filesystem resets - ([4788184](https://github.com/QaidVoid/bailey/commit/47881840ec57ec037ba300ae385930f6c81ad07f))
- *(config)* Refuse a negative or unrepresentable size - ([6efcef7](https://github.com/QaidVoid/bailey/commit/6efcef7e1ab12611e881f1da4538b85c31cb25b8))
- *(enforce)* Say when a read grant is widened to write - ([9b10dd9](https://github.com/QaidVoid/bailey/commit/9b10dd93fa6e32096234415714ccf93fff1dcb7c))
- *(enforce)* Honour a deny written where the target sees it - ([6bc2f73](https://github.com/QaidVoid/bailey/commit/6bc2f736ddadd6356834b54125f3dff5ca4970ae))
- *(enforce)* Name a relocated grant by what will exist - ([53b9557](https://github.com/QaidVoid/bailey/commit/53b9557d6f591d40fc9027a618601d2bdb6e577d))
- *(enforce)* Pin core dumps off and close same-uid reach - ([f018bd0](https://github.com/QaidVoid/bailey/commit/f018bd05b6f5c054333a3e1fdcfc4b89bdba0bf3))
- *(enforce)* Refuse a grant that cannot be installed - ([708c47f](https://github.com/QaidVoid/bailey/commit/708c47f90536c2d4f9d680b08bbcc543e277694a))
- *(isolation)* Build graft points without following a symlink - ([a80bb73](https://github.com/QaidVoid/bailey/commit/a80bb736342edb232e5d5a1a85a4c6b39c7e83af))
- *(isolation)* Give the sandbox its own IPC namespace - ([b7430c8](https://github.com/QaidVoid/bailey/commit/b7430c8380ffcf599ae2b19d2e5af85e68a40ad4))
- *(network)* Keep the private namespace when a port is bound - ([6b1c478](https://github.com/QaidVoid/bailey/commit/6b1c47871a960200bc06a493e99da996329f3f7d))
- *(privilege)* Refuse to run as root and drop capabilities - ([cb9fbab](https://github.com/QaidVoid/bailey/commit/cb9fbab84b8cf0f1ed2a0f1f64f84f2a7863cb78))
- *(seccomp)* Deny terminal input injection - ([bb68575](https://github.com/QaidVoid/bailey/commit/bb68575b8cb4f66baa0fdb9cd2861fffd4e7173c))
- *(seccomp)* Deny descriptor passing and io_uring - ([458a426](https://github.com/QaidVoid/bailey/commit/458a426c5a32e80180949c6aad65776d8fc79765))
- *(state)* Keep the private home and trust store to the owner - ([b7254ee](https://github.com/QaidVoid/bailey/commit/b7254ee0530b8130098453ca93d104a81997d23c))
- *(trust)* Weigh the directories a config sits in - ([66573be](https://github.com/QaidVoid/bailey/commit/66573be74d6e9925df84e700950f5b28f85c8b6e))
- *(trust)* Never read the store from inside a sandbox - ([ab377dd](https://github.com/QaidVoid/bailey/commit/ab377ddfba394dd3d31a2a909b9253fe8d05b477))
- Stop a stale cgroup, an unaligned read, and a name - ([6c80b50](https://github.com/QaidVoid/bailey/commit/6c80b50875fbc7be8fe04abec39bc181f8be98a3))
- Refuse a port of 0, escape the report, widen the digest - ([858174c](https://github.com/QaidVoid/bailey/commit/858174c316b5c0e385061b16dbfcc7d9d4066473))
- Stop grants and egress reaching past the policy ([#15](https://github.com/QaidVoid/bailey/pull/15)) - ([e260672](https://github.com/QaidVoid/bailey/commit/e2606724898254e75fc3624e4259de9a94fd55dc))

### 📚 Documentation

- *(cli)* Say what the proxy namespace check does not do - ([28884bd](https://github.com/QaidVoid/bailey/commit/28884bdc345d9e9183e2d7e7f641d34ca599b225))
- *(security)* Name the limits a policy cannot express - ([97d68e6](https://github.com/QaidVoid/bailey/commit/97d68e6ae612b2d78119aeb706f5745aceee7106))

## [0.1.4](https://github.com/QaidVoid/bailey/compare/v0.1.3...v0.1.4) - 2026-09-14

### ⛰️  Features

- *(cli)* Add --egress-proxy to lock a session to a single broker - ([9656f22](https://github.com/QaidVoid/bailey/commit/9656f2259ec5952937725a3f41477b0dacbc5dbc))

### 🐛 Bug Fixes

- *(cli)* Drop the namespace's forwarded loopback to the host - ([8570d3c](https://github.com/QaidVoid/bailey/commit/8570d3cc2f0cecf4b3b9ee32c25039dda6c415ff))
- *(world)* Keep a relocated grant covering its own source - ([b8a7eea](https://github.com/QaidVoid/bailey/commit/b8a7eea8996d95e069b2d5922112525ed99f8759))

## [0.1.3](https://github.com/QaidVoid/bailey/compare/v0.1.2...v0.1.3) - 2026-09-14

### 🐛 Bug Fixes

- *(enforce)* Validate the architecture so a denied syscall cannot slip past - ([51a30ab](https://github.com/QaidVoid/bailey/commit/51a30ab7936652be2adfaae1557e533228391900))
- *(enforce)* Deny btrfs ioctls that Landlock does not mediate - ([587fc6f](https://github.com/QaidVoid/bailey/commit/587fc6f226717b8e16b8fb9c33ad1aa75d20d810))

## [0.1.2](https://github.com/QaidVoid/bailey/compare/v0.1.1...v0.1.2) - 2026-09-13

### ⛰️  Features

- *(network)* Give the private namespace IPv6 where the host has it - ([89f3900](https://github.com/QaidVoid/bailey/commit/89f390043c428a6d46bcbb4d5d8fc658b4c61c20))
- *(network)* Hide the host address behind a private namespace - ([6bccff8](https://github.com/QaidVoid/bailey/commit/6bccff86aa0c7710c4597275c75e5ebcdcae202e))

### 🐛 Bug Fixes

- *(isolation)* Map the caller's uid, not 0 - ([92fa57e](https://github.com/QaidVoid/bailey/commit/92fa57ed530ffbce6c0c3ed2c75bed9acd989836))
- *(seccomp)* Deny the new mount API, not just mount(2) - ([572899a](https://github.com/QaidVoid/bailey/commit/572899a77caabab2525c0916aab87a84ab6a5f1a))
- *(world)* A relocated grant keeps the private /tmp - ([a083848](https://github.com/QaidVoid/bailey/commit/a0838487a2fe1419f34c7fc14520dbe7fc24455d))

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
