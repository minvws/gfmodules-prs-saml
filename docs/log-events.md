# Log events

<!-- markdownlint-disable MD013 -->

Generated from `app.logging.events:Log` by `gfmodules.logging.event_overview`.
Do not edit by hand.

Each stream lists the events that reach it and the fields they carry there besides the context fields.
*any* means the event has no allow-list, so every field it is logged with reaches the stream.
*none* means the event carries only the context fields there.

## Context fields

Every event carries these on every stream, whenever the request context holds a value for them.

- `request_id`
- `ip`
- `user_agent`
- `client_trace_id`
- `correlation_id`
- `endpoint`
- `method`
- `scope`

## Stream `app`

| Event | Id | Level | Fields |
| --- | --- | --- | --- |
| `SYS_APP_STARTED` | 270401 | INFO | `version`, `config_path` |
| `SYS_APP_STOPPED` | 270402 | INFO | `shutdown_reason`, `last_exception_type` |
| `SYS_APP_CRASHED` | 270402 | CRITICAL | `shutdown_reason`, `last_exception_type` |
| `SYS_UNHANDLED_EXCEPTION` | 270404 | ERROR | `exception_type`, `endpoint`, `method` |
| `SYS_MISSING_CORRELATION_ID` | 270428 | ERROR | `endpoint`, `method` |
| `ACCESS_REQUEST` | 100 | INFO | `endpoint`, `method`, `status_code`, `status_code_missing`, `duration_ms`, `body`, `body_truncated` |

## Stream `siem`

| Event | Id | Level | Fields |
| --- | --- | --- | --- |
| `SYS_APP_STOPPED` | 270402 | INFO | `shutdown_reason` |
| `SYS_APP_CRASHED` | 270402 | CRITICAL | `shutdown_reason` |
| `SYS_UNHANDLED_EXCEPTION` | 270404 | ERROR | `exception_type`, `endpoint`, `method` |
