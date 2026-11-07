# Strict Audit Event Schema and Canonical JSON Encoding

Status: accepted (generated, pending human review)

## Context

Free-form structured logging leads to inconsistent audit trails across services, naive timestamps, and accidental logging of passwords or tokens. A strict contract for audit records is needed.

## Decision

Implement frozen dataclasses (Actor, Target, AuditEvent) with strict validation on post_init, timezone-aware UTC millisecond timestamps, automatic rejection of sensitive attribute keys, and deterministic JSON serialization.

## Consequences

Audit events have a uniform, tamper-friendly schema matching Draft 2020-12 JSON Schema. Secret-named attributes are blocked at event creation, and wire-format round trips are guaranteed.
