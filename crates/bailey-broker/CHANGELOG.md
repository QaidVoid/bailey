# Changelog

## [0.2.4] - 2026-11-22

### ⛰️  Features

- *(broker)* Log one json line per decision and stop on sigterm - ([8c05ed3](https://github.com/QaidVoid/bailey/commit/8c05ed3b6acf924e7a4c3f7a9e3a126eaa5d6be2))
- *(broker)* Add the request codec, tls ca and tunnel engine - ([d8d78e3](https://github.com/QaidVoid/bailey/commit/d8d78e3efaf3e096db709488868b35d8ce02acf4))
- *(http)* Add the bailey-broker crate and the wire protocol - ([4818e30](https://github.com/QaidVoid/bailey/commit/4818e3022bba104a2d86b27c28e357020252cc1b))

### 🐛 Bug Fixes

- *(broker)* Close the log descriptor when no log is given - ([a50e0b6](https://github.com/QaidVoid/bailey/commit/a50e0b6946932255f15c26c9655bffdc1bf501d4))
- *(broker)* Refuse the whole ipv4 multicast range - ([46153f4](https://github.com/QaidVoid/bailey/commit/46153f42aa37e7ee848268223eb9d7633a736387))
- *(broker)* Grant a tunnel whose clienthello has no sni - ([901eebe](https://github.com/QaidVoid/bailey/commit/901eebe48ad02b74bc2a3e66c62c0c3750c61299))
- *(broker)* Refuse request methods outside uppercase letters - ([619b9e8](https://github.com/QaidVoid/bailey/commit/619b9e83cdea6ad296952d9274a1af77a2f5b6b5))

### ⚙️ Miscellaneous Tasks

- *(fmt)* Apply the current rustfmt to the workspace - ([810290c](https://github.com/QaidVoid/bailey/commit/810290cecdc502edc1e13d6bb3b49ca9f5671aa3))
