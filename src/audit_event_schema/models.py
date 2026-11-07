"""Models, validation, canonical serialization, and schema definition."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Literal

from audit_event_schema.errors import AuditEventError

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

ActorType = Literal["user", "service", "system"]
Outcome = Literal["success", "failure", "denied"]
SchemaVersion = Literal["1.0"]
AttributeValue = str | int | bool | None

ID_REGEX = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
TARGET_TYPE_REGEX = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
ACTION_REGEX = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,4}$")
ATTR_KEY_REGEX = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
TIME_WIRE_REGEX = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$")

SENSITIVE_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "api_key",
    "private_key",
)

MAX_REASON_LENGTH = 500
MAX_ATTR_KEY_COUNT = 32
MAX_ATTR_STRING_LENGTH = 1024
MAX_SAFE_INT = (1 << 53) - 1


def _has_control_chars(s: str) -> bool:
    for ch in s:
        cp = ord(ch)
        if cp < 32 or cp == 127:
            return True
    return False


@dataclass(frozen=True)
class Actor:
    """Actor performing an action."""

    type: ActorType
    id: str

    def __post_init__(self) -> None:
        if self.type not in ("user", "service", "system"):
            raise AuditEventError(
                "invalid_actor", "actor.type", "type must be user, service, or system"
            )
        if (
            not isinstance(self.id, str)
            or len(self.id) < 1
            or len(self.id) > 256
            or _has_control_chars(self.id)
        ):
            raise AuditEventError(
                "invalid_actor", "actor.id", "id must be 1-256 non-control characters"
            )


@dataclass(frozen=True)
class Target:
    """Target entity of an action."""

    type: str
    id: str

    def __post_init__(self) -> None:
        if not isinstance(self.type, str) or not TARGET_TYPE_REGEX.fullmatch(self.type):
            raise AuditEventError(
                "invalid_target", "target.type", "type must match ^[a-z][a-z0-9_]{0,63}$"
            )
        if (
            not isinstance(self.id, str)
            or len(self.id) < 1
            or len(self.id) > 256
            or _has_control_chars(self.id)
        ):
            raise AuditEventError(
                "invalid_target", "target.id", "id must be 1-256 non-control characters"
            )


@dataclass(frozen=True)
class AuditEvent:
    """A strictly validated audit event."""

    id: str
    time: datetime
    actor: Actor
    action: str
    outcome: Outcome
    target: Target | None = None
    reason: str | None = None
    source_ip: str | None = None
    request_id: str | None = None
    attributes: Mapping[str, AttributeValue] = field(default_factory=lambda: MappingProxyType({}))
    schema_version: SchemaVersion = "1.0"

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not ID_REGEX.fullmatch(self.id):
            raise AuditEventError("invalid_id", "id", "id must match ^[A-Za-z0-9._:-]{1,128}$")

        if (
            not isinstance(self.time, datetime)
            or self.time.tzinfo is None
            or self.time.utcoffset() is None
        ):
            raise AuditEventError("invalid_time", "time", "time must be timezone-aware datetime")

        # Convert to UTC and truncate to milliseconds
        utc_dt = self.time.astimezone(timezone.utc)
        truncated_ms = (utc_dt.microsecond // 1000) * 1000
        normalized_time = datetime(
            utc_dt.year,
            utc_dt.month,
            utc_dt.day,
            utc_dt.hour,
            utc_dt.minute,
            utc_dt.second,
            truncated_ms,
            tzinfo=timezone.utc,
        )
        object.__setattr__(self, "time", normalized_time)

        if not isinstance(self.actor, Actor):
            raise AuditEventError("invalid_actor", "actor", "actor must be an Actor instance")

        if not isinstance(self.action, str) or not ACTION_REGEX.fullmatch(self.action):
            raise AuditEventError(
                "invalid_action",
                "action",
                "action must match ^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*){1,4}$",
            )

        if self.outcome not in ("success", "failure", "denied"):
            raise AuditEventError(
                "invalid_outcome", "outcome", "outcome must be success, failure, or denied"
            )

        if self.target is not None and not isinstance(self.target, Target):
            raise AuditEventError("invalid_target", "target", "target must be a Target instance")

        if self.reason is not None and (
            not isinstance(self.reason, str) or len(self.reason) > MAX_REASON_LENGTH
        ):
            raise AuditEventError(
                "invalid_reason",
                "reason",
                f"reason must be at most {MAX_REASON_LENGTH} characters",
            )

        if self.source_ip is not None:
            if not isinstance(self.source_ip, str):
                raise AuditEventError(
                    "invalid_ip", "source_ip", "source_ip must be a valid IP address string"
                )
            try:
                parsed_ip = ipaddress.ip_address(self.source_ip)
            except ValueError as err:
                raise AuditEventError(
                    "invalid_ip", "source_ip", "source_ip must be a valid IPv4 or IPv6 address"
                ) from err
            object.__setattr__(self, "source_ip", str(parsed_ip))

        if self.request_id is not None and (
            not isinstance(self.request_id, str) or not ID_REGEX.fullmatch(self.request_id)
        ):
            raise AuditEventError(
                "invalid_id", "request_id", "request_id must match ^[A-Za-z0-9._:-]{1,128}$"
            )

        if not isinstance(self.attributes, Mapping):
            raise AuditEventError("invalid_type", "attributes", "attributes must be a mapping")

        if len(self.attributes) > MAX_ATTR_KEY_COUNT:
            raise AuditEventError(
                "too_many_attributes",
                "attributes",
                f"at most {MAX_ATTR_KEY_COUNT} attributes allowed",
            )

        clean_attrs: dict[str, AttributeValue] = {}
        for key, val in self.attributes.items():
            if not isinstance(key, str) or not ATTR_KEY_REGEX.fullmatch(key):
                raise AuditEventError(
                    "invalid_attribute",
                    f"attributes.{key}",
                    "key must match ^[a-z][a-z0-9_]{0,63}$",
                )
            key_lower = key.lower()
            for sensitive in SENSITIVE_SUBSTRINGS:
                if sensitive in key_lower:
                    raise AuditEventError(
                        "sensitive_attribute",
                        f"attributes.{key}",
                        "attribute key contains sensitive keyword",
                    )
            if val is None or isinstance(val, bool):
                clean_attrs[key] = val
            elif isinstance(val, int):
                if abs(val) > MAX_SAFE_INT:
                    raise AuditEventError(
                        "invalid_attribute",
                        f"attributes.{key}",
                        "integer magnitude must not exceed 2^53 - 1",
                    )
                clean_attrs[key] = val
            elif isinstance(val, str):
                if len(val) > MAX_ATTR_STRING_LENGTH:
                    raise AuditEventError(
                        "invalid_attribute",
                        f"attributes.{key}",
                        f"string attribute value must be at most "
                        f"{MAX_ATTR_STRING_LENGTH} characters",
                    )
                clean_attrs[key] = val
            else:
                raise AuditEventError(
                    "invalid_attribute",
                    f"attributes.{key}",
                    "value must be str, int, bool, or None",
                )

        object.__setattr__(self, "attributes", MappingProxyType(clean_attrs))

        if self.schema_version != "1.0":
            raise AuditEventError("invalid_type", "schema_version", "schema_version must be '1.0'")


def new_event(
    *,
    actor: Actor,
    action: str,
    outcome: Outcome,
    target: Target | None = None,
    reason: str | None = None,
    source_ip: str | None = None,
    request_id: str | None = None,
    attributes: Mapping[str, AttributeValue] | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
) -> AuditEvent:
    """Factory to create a new validated AuditEvent."""
    event_id = id_factory()
    event_time = clock()
    attrs: Mapping[str, AttributeValue] = attributes if attributes is not None else {}
    return AuditEvent(
        id=event_id,
        time=event_time,
        actor=actor,
        action=action,
        outcome=outcome,
        target=target,
        reason=reason,
        source_ip=source_ip,
        request_id=request_id,
        attributes=attrs,
    )


def _format_time_wire(dt: datetime) -> str:
    ms = dt.microsecond // 1000
    date_part = f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}"
    time_part = f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}.{ms:03d}Z"
    return f"{date_part}T{time_part}"


def to_json(event: AuditEvent) -> str:
    """Serialize AuditEvent to canonical JSON string."""
    doc: dict[str, Any] = {
        "schema_version": event.schema_version,
        "id": event.id,
        "time": _format_time_wire(event.time),
        "actor": {
            "type": event.actor.type,
            "id": event.actor.id,
        },
        "action": event.action,
        "outcome": event.outcome,
    }
    if event.target is not None:
        doc["target"] = {
            "type": event.target.type,
            "id": event.target.id,
        }
    if event.reason is not None:
        doc["reason"] = event.reason
    if event.source_ip is not None:
        doc["source_ip"] = event.source_ip
    if event.request_id is not None:
        doc["request_id"] = event.request_id
    if event.attributes:
        doc["attributes"] = dict(event.attributes)

    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _parse_wire_time(wire: str) -> datetime:
    m = TIME_WIRE_REGEX.fullmatch(wire)
    if not m:
        raise AuditEventError("invalid_time", "time", "time must match YYYY-MM-DDTHH:MM:SS.mmmZ")
    year, month, day, hour, minute, second, ms_str = (
        int(m.group(1)),
        int(m.group(2)),
        int(m.group(3)),
        int(m.group(4)),
        int(m.group(5)),
        int(m.group(6)),
        int(m.group(7)),
    )
    try:
        return datetime(year, month, day, hour, minute, second, ms_str * 1000, tzinfo=timezone.utc)
    except ValueError as err:
        raise AuditEventError("invalid_time", "time", "time components out of range") from err


def from_json(text: str, *, max_bytes: int = 16_384) -> AuditEvent:
    """Deserialize canonical JSON string into AuditEvent."""
    if not isinstance(text, str):
        raise AuditEventError("invalid_type", "", "text must be a string")
    byte_len = len(text.encode("utf-8"))
    if byte_len > max_bytes:
        raise AuditEventError(
            "too_large", "", f"input size {byte_len} exceeds max {max_bytes} bytes"
        )

    try:
        doc = json.loads(text)
    except RecursionError as err:
        raise AuditEventError("invalid_json", "", "json recursion limit exceeded") from err
    except json.JSONDecodeError as err:
        raise AuditEventError("invalid_json", "", "malformed json") from err

    if not isinstance(doc, dict):
        raise AuditEventError("invalid_type", "", "root JSON must be an object")

    allowed_top_level = {
        "schema_version",
        "id",
        "time",
        "actor",
        "action",
        "outcome",
        "target",
        "reason",
        "source_ip",
        "request_id",
        "attributes",
    }
    for k in doc:
        if k not in allowed_top_level:
            raise AuditEventError("unknown_field", k, f"unknown field: {k}")

    required_fields = ["schema_version", "id", "time", "actor", "action", "outcome"]
    for rf in required_fields:
        if rf not in doc:
            raise AuditEventError("missing_field", rf, f"missing required field: {rf}")

    if not isinstance(doc["schema_version"], str):
        raise AuditEventError("invalid_type", "schema_version", "schema_version must be string")
    if doc["schema_version"] != "1.0":
        raise AuditEventError("invalid_type", "schema_version", "schema_version must be '1.0'")

    if not isinstance(doc["id"], str):
        raise AuditEventError("invalid_type", "id", "id must be string")

    if not isinstance(doc["time"], str):
        raise AuditEventError("invalid_type", "time", "time must be string")
    time_val = _parse_wire_time(doc["time"])

    actor_raw = doc["actor"]
    if not isinstance(actor_raw, dict):
        raise AuditEventError("invalid_type", "actor", "actor must be an object")
    for k in actor_raw:
        if k not in ("type", "id"):
            raise AuditEventError("unknown_field", f"actor.{k}", f"unknown field: actor.{k}")
    for rf in ("type", "id"):
        if rf not in actor_raw:
            raise AuditEventError(
                "missing_field", f"actor.{rf}", f"missing required actor field: {rf}"
            )
    if not isinstance(actor_raw["type"], str):
        raise AuditEventError("invalid_type", "actor.type", "actor.type must be string")
    if not isinstance(actor_raw["id"], str):
        raise AuditEventError("invalid_type", "actor.id", "actor.id must be string")
    actor = Actor(type=actor_raw["type"], id=actor_raw["id"])  # type: ignore[arg-type]

    if not isinstance(doc["action"], str):
        raise AuditEventError("invalid_type", "action", "action must be string")
    if not isinstance(doc["outcome"], str):
        raise AuditEventError("invalid_type", "outcome", "outcome must be string")

    target: Target | None = None
    if "target" in doc and doc["target"] is not None:
        target_raw = doc["target"]
        if not isinstance(target_raw, dict):
            raise AuditEventError("invalid_type", "target", "target must be an object")
        for k in target_raw:
            if k not in ("type", "id"):
                raise AuditEventError("unknown_field", f"target.{k}", f"unknown field: target.{k}")
        for rf in ("type", "id"):
            if rf not in target_raw:
                raise AuditEventError(
                    "missing_field", f"target.{rf}", f"missing required target field: {rf}"
                )
        if not isinstance(target_raw["type"], str):
            raise AuditEventError("invalid_type", "target.type", "target.type must be string")
        if not isinstance(target_raw["id"], str):
            raise AuditEventError("invalid_type", "target.id", "target.id must be string")
        target = Target(type=target_raw["type"], id=target_raw["id"])

    reason: str | None = None
    if "reason" in doc and doc["reason"] is not None:
        if not isinstance(doc["reason"], str):
            raise AuditEventError("invalid_type", "reason", "reason must be string")
        reason = doc["reason"]

    source_ip: str | None = None
    if "source_ip" in doc and doc["source_ip"] is not None:
        if not isinstance(doc["source_ip"], str):
            raise AuditEventError("invalid_type", "source_ip", "source_ip must be string")
        source_ip = doc["source_ip"]

    request_id: str | None = None
    if "request_id" in doc and doc["request_id"] is not None:
        if not isinstance(doc["request_id"], str):
            raise AuditEventError("invalid_type", "request_id", "request_id must be string")
        request_id = doc["request_id"]

    attributes: dict[str, AttributeValue] = {}
    if "attributes" in doc and doc["attributes"] is not None:
        attrs_raw = doc["attributes"]
        if not isinstance(attrs_raw, dict):
            raise AuditEventError("invalid_type", "attributes", "attributes must be an object")
        for k, v in attrs_raw.items():
            if not isinstance(k, str):
                raise AuditEventError("invalid_type", "attributes", "attribute key must be string")
            if v is not None and not isinstance(v, (str, int, bool)):
                raise AuditEventError(
                    "invalid_attribute", f"attributes.{k}", "unsupported value type"
                )
            if isinstance(v, float) and not isinstance(v, bool):
                raise AuditEventError("invalid_attribute", f"attributes.{k}", "float not allowed")
            attributes[k] = v

    return AuditEvent(
        id=doc["id"],
        time=time_val,
        actor=actor,
        action=doc["action"],
        outcome=doc["outcome"],  # type: ignore[arg-type]
        target=target,
        reason=reason,
        source_ip=source_ip,
        request_id=request_id,
        attributes=attributes,
        schema_version=doc["schema_version"],  # type: ignore[arg-type]
    )


JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "AuditEvent",
    "type": "object",
    "required": ["schema_version", "id", "time", "actor", "action", "outcome"],
    "additionalProperties": False,
    "properties": {
        "schema_version": {
            "type": "string",
            "const": "1.0",
        },
        "id": {
            "type": "string",
            "pattern": "^[A-Za-z0-9._:-]{1,128}$",
        },
        "time": {
            "type": "string",
            "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$",
        },
        "actor": {
            "type": "object",
            "required": ["type", "id"],
            "additionalProperties": False,
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["user", "service", "system"],
                },
                "id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                },
            },
        },
        "action": {
            "type": "string",
            "pattern": r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,4}$",
        },
        "outcome": {
            "type": "string",
            "enum": ["success", "failure", "denied"],
        },
        "target": {
            "type": "object",
            "required": ["type", "id"],
            "additionalProperties": False,
            "properties": {
                "type": {
                    "type": "string",
                    "pattern": "^[a-z][a-z0-9_]{0,63}$",
                },
                "id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                },
            },
        },
        "reason": {
            "type": "string",
            "maxLength": 500,
        },
        "source_ip": {
            "type": "string",
        },
        "request_id": {
            "type": "string",
            "pattern": "^[A-Za-z0-9._:-]{1,128}$",
        },
        "attributes": {
            "type": "object",
            "maxProperties": 32,
            "propertyNames": {
                "pattern": "^[a-z][a-z0-9_]{0,63}$",
            },
            "additionalProperties": {
                "anyOf": [
                    {"type": "string", "maxLength": 1024},
                    {"type": "integer", "minimum": -(2**53 - 1), "maximum": 2**53 - 1},
                    {"type": "boolean"},
                    {"type": "null"},
                ],
            },
        },
    },
}
