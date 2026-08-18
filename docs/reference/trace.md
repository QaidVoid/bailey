# Trace format

`bailey audit --save-trace <file>` writes a JSON array of access events. The same
format is read by `bailey profile generate --trace`.

## Shape

```json
[
  {
    "kind": "read",
    "resource": { "path": "/usr/lib/libc.so.6" },
    "pid": 44821,
    "timestamp_ns": 0
  },
  {
    "kind": "connect",
    "resource": { "net": { "host": "93.184.216.34", "port": 443 } },
    "pid": 44821,
    "timestamp_ns": 0
  }
]
```

## Fields

| Field | Type | Description |
| --- | --- | --- |
| `kind` | string | `read`, `write`, `execute`, `connect`, or `bind` |
| `resource` | object | Either `{ "path": ... }` or `{ "net": { "host": ..., "port": ... } }` |
| `pid` | integer | PID of the accessing process |
| `timestamp_ns` | integer | Monotonic timestamp. Currently always `0` |

`host` is optional and may be `null` for a bind event.

## Current caveats

- **`timestamp_ns` is always zero.** The field exists in the schema; the eBPF
  programs do not populate it yet.
- **Paths are as the program passed them**, not resolved. A relative open produces
  a relative path, which will not match an absolute policy grant.
- **Only IPv4** destinations are recorded. IPv6 connections are skipped.
- **Only `openat`** is observed for filesystem access. Other path-opening syscalls
  and `execve` do not appear.
- **The event count is capped** at 200,000 per run, and events beyond the cap are
  dropped without any marker in the trace.

Each of these is on the [roadmap](/roadmap). The trace format will gain a version
field when it changes.

## Working with a trace

```sh
# What did it connect to?
jq '[.[] | select(.kind == "connect") | .resource.net] | unique' trace.json

# What did it write?
jq -r '.[] | select(.kind == "write") | .resource.path' trace.json | sort -u

# What did it read outside its own directory?
jq -r '.[] | select(.kind == "read") | .resource.path' trace.json \
  | grep -v '^/usr\|^/etc\|^/lib' | sort -u
```
