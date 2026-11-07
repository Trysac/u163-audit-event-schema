"""Error classes for audit event schema validation and parsing."""

from __future__ import annotations

from typing import Literal

ErrorCode = Literal[
    "invalid_json",
    "too_large",
    "unknown_field",
    "missing_field",
    "invalid_type",
    "invalid_id",
    "invalid_time",
    "invalid_actor",
    "invalid_target",
    "invalid_action",
    "invalid_outcome",
    "invalid_ip",
    "sensitive_attribute",
    "too_many_attributes",
    "invalid_attribute",
    "invalid_reason",
]


class AuditEventError(ValueError):
    """Raised when an audit event fails validation or serialization/deserialization rules.

    Messages describe the path and the rule broken, never untrusted input or secret values.
    """

    def __init__(self, code: ErrorCode, path: str, message: str) -> None:
        super().__init__(f"{path}: {message} ({code})")
        self.code: ErrorCode = code
        self.path: str = path
