# Trace format

`bailey audit --save-trace <file>` writes a recorded session as JSON. The same
format is read by `bailey profile generate --trace`.

## Shape

```json
{
  "version": 1,
  "dropped": 0,
  "events": [
    {
      "kind": "read",
      "resource": { "path": "/usr/lib/libc.so.6" },
      "pid": 44821,
      "timestamp_ns": 194523870114,
      "resolution": "absolute"
    },
    {
      "kind": "connect",
      "resource": { "net": { "host": "93.184.216.34", "port": 443 } },
      "pid": 44821,
      "timestamp_ns": 194523912550,
      "resolution": "not_applicable"
    }
  ]
}
```

`version` is checked on load: a trace from a different format version is rejected
by name rather than misread. `dropped` is the number of accesses the recorder
could not deliver; anything above zero makes the trace truncated, and
`profile generate` refuses it without `--accept-truncated`.

## Fields

| Field | Type | Description |
| --- | --- | --- |
| `kind` | string | `read`, `write`, `execute`, `connect`, or `bind` |
| `resource` | object | Either `{ "path": ... }` or `{ "net": { "host": ..., "port": ... } }` |
| `pid` | integer | PID of the accessing process |
| `timestamp_ns` | integer | Monotonic kernel timestamp |
| `resolution` | string | `absolute`, `userspace`, `unresolved`, or `not_applicable` |

`host` is optional and may be `null` for a bind event.

`resolution` says how the path was arrived at: `absolute` when the program named
one, `userspace` when a relative path was resolved against the accessing
process's working directory, and `unresolved` when it could not be. An
unresolved event is listed separately and is never turned into a grant, since a
relative path names nothing in particular.

## Caveats

- **The event count is capped** at 200,000 per run. Events beyond the cap count
  towards `dropped`, so the trace is marked truncated rather than looking
  complete.
- **A short-lived child can be missed.** See
  [known limitations](/security/limitations).

## Working with a trace

```sh
# What did it connect to?
jq '[.events[] | select(.kind == "connect") | .resource.net] | unique' trace.json

# What did it write?
jq -r '.events[] | select(.kind == "write") | .resource.path' trace.json | sort -u

# What did it read outside its own directory?
jq -r '.events[] | select(.kind == "read") | .resource.path' trace.json \
  | grep -v '^/usr\|^/etc\|^/lib' | sort -u
```
