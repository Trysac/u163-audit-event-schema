"""A strict audit event model with canonical JSON."""

from __future__ import annotations

from audit_event_schema.errors import AuditEventError, ErrorCode
from audit_event_schema.models import (
    JSON_SCHEMA,
    Actor,
    AuditEvent,
    Outcome,
    Target,
    from_json,
    new_event,
    to_json,
)

__version__ = "0.1.0"

__all__ = [
    "JSON_SCHEMA",
    "Actor",
    "AuditEvent",
    "AuditEventError",
    "ErrorCode",
    "Outcome",
    "Target",
    "__version__",
    "from_json",
    "new_event",
    "to_json",
]
