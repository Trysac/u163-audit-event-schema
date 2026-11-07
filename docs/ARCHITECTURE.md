# Architecture

`trysac-audit-event-schema` provides a strict model and canonical serialization format for single audit events.

## Structure

- `audit_event_schema.errors`: Defines `AuditEventError` with specific `ErrorCode` enumeration. Error messages include field paths and rule violations without echoing untrusted values.
- `audit_event_schema.models`: Frozen dataclasses `Actor`, `Target`, and `AuditEvent` implementing validation rules in `__post_init__`.
- `new_event()`: Factory injecting clocks and ID generators.
- `to_json()` / `from_json()`: Deterministic JSON serialization and deserialization with size and depth protection.
- `JSON_SCHEMA`: Draft 2020-12 schema object matching library invariants.
