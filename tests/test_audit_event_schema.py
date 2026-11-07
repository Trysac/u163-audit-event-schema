"""Unit tests for trysac-audit-event-schema."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from audit_event_schema.models import (
    ACTION_REGEX,
    JSON_SCHEMA,
    Actor,
    AuditEventError,
    Target,
    from_json,
    new_event,
    to_json,
)


def test_acceptance_new_event_serialisation() -> None:
    evt = new_event(
        actor=Actor("user", "u-1"),
        action="invoice.update",
        target=Target("invoice", "inv-9"),
        outcome="success",
        clock=lambda: datetime(2026, 11, 6, 12, 0, 0, 123456, tzinfo=timezone.utc),
        id_factory=lambda: "evt-1",
    )
    expected = '{"action":"invoice.update","actor":{"id":"u-1","type":"user"},"id":"evt-1","outcome":"success","schema_version":"1.0","target":{"id":"inv-9","type":"invoice"},"time":"2026-11-06T12:00:00.123Z"}'
    assert to_json(evt) == expected


def test_acceptance_round_trip_and_time_validation() -> None:
    evt = new_event(
        actor=Actor("service", "srv-auth"),
        action="token.issue",
        target=Target("session", "s-42"),
        outcome="success",
        reason="Valid token exchange",
        source_ip="127.0.0.1",
        request_id="req-123",
        attributes={"env": "prod", "retries": 0, "active": True, "note": None},
        clock=lambda: datetime(2026, 11, 6, 12, 0, 0, 123000, tzinfo=timezone.utc),
        id_factory=lambda: "evt-rt",
    )
    json_str = to_json(evt)
    deserialized = from_json(json_str)
    assert deserialized == evt
    assert from_json(to_json(evt)) == evt

    # '+00:00' wire time format must be rejected
    invalid_time_json = json_str.replace("12:00:00.123Z", "12:00:00.123+00:00")
    assert "2026-11-06T12:00:00.123+00:00" in invalid_time_json
    with pytest.raises(AuditEventError) as exc_info:
        from_json(invalid_time_json)
    assert exc_info.value.code == "invalid_time"
    assert exc_info.value.path == "time"

    # Naive clock raises invalid_time
    with pytest.raises(AuditEventError) as exc_info2:
        new_event(
            actor=Actor("user", "u-1"),
            action="user.login",
            outcome="success",
            clock=lambda: datetime(2026, 11, 6, 12, 0, 0),  # naive
        )
    assert exc_info2.value.code == "invalid_time"
    assert exc_info2.value.path == "time"


def test_acceptance_action_outcome_actor_validation() -> None:
    with pytest.raises(AuditEventError) as exc:
        new_event(actor=Actor("user", "u-1"), action="Invoice.Update", outcome="success")
    assert exc.value.code == "invalid_action"

    with pytest.raises(AuditEventError) as exc2:
        new_event(actor=Actor("user", "u-1"), action="invoice", outcome="success")
    assert exc2.value.code == "invalid_action"

    with pytest.raises(AuditEventError) as exc3:
        new_event(actor=Actor("user", "u-1"), action="invoice.update", outcome="ok")  # type: ignore[arg-type]
    assert exc3.value.code == "invalid_outcome"

    with pytest.raises(AuditEventError) as exc4:
        Actor("robot", "x")  # type: ignore[arg-type]
    assert exc4.value.code == "invalid_actor"


def test_acceptance_attributes_validation() -> None:
    # Sensitive attribute
    with pytest.raises(AuditEventError) as exc:
        new_event(
            actor=Actor("user", "u-1"),
            action="user.login",
            outcome="success",
            attributes={"password": "x"},
        )
    assert exc.value.code == "sensitive_attribute"
    assert exc.value.path == "attributes.password"

    # 33 attributes raise too_many_attributes
    too_many = {f"key_{i}": i for i in range(33)}
    with pytest.raises(AuditEventError) as exc2:
        new_event(
            actor=Actor("user", "u-1"),
            action="user.login",
            outcome="success",
            attributes=too_many,
        )
    assert exc2.value.code == "too_many_attributes"

    # Values 2**53, 1.5, ['a'] raise invalid_attribute
    with pytest.raises(AuditEventError) as exc_int:
        new_event(
            actor=Actor("user", "u-1"),
            action="user.login",
            outcome="success",
            attributes={"val": 2**53},
        )
    assert exc_int.value.code == "invalid_attribute"

    with pytest.raises(AuditEventError) as exc_float:
        new_event(
            actor=Actor("user", "u-1"),
            action="user.login",
            outcome="success",
            attributes={"val": 1.5},  # type: ignore[dict-item]
        )
    assert exc_float.value.code == "invalid_attribute"

    with pytest.raises(AuditEventError) as exc_list:
        new_event(
            actor=Actor("user", "u-1"),
            action="user.login",
            outcome="success",
            attributes={"val": ["a"]},  # type: ignore[dict-item]
        )
    assert exc_list.value.code == "invalid_attribute"

    # Accepted values: True, None, -5, 'ok'
    ok_event = new_event(
        actor=Actor("user", "u-1"),
        action="user.login",
        outcome="success",
        attributes={"b": True, "n": None, "i": -5, "s": "ok"},
    )
    assert ok_event.attributes["b"] is True
    assert ok_event.attributes["n"] is None
    assert ok_event.attributes["i"] == -5
    assert ok_event.attributes["s"] == "ok"


def test_acceptance_source_ip_validation() -> None:
    evt = new_event(
        actor=Actor("user", "u-1"),
        action="user.login",
        outcome="success",
        source_ip="2001:DB8::1",
    )
    assert evt.source_ip == "2001:db8::1"

    with pytest.raises(AuditEventError) as exc:
        new_event(
            actor=Actor("user", "u-1"),
            action="user.login",
            outcome="success",
            source_ip="999.1.1.1",
        )
    assert exc.value.code == "invalid_ip"


def test_acceptance_from_json_size_unknown_field_malformed() -> None:
    # 16_385 bytes raises too_large before parsing
    payload_large = "{" + " " * 16383 + "}"
    assert len(payload_large.encode("utf-8")) == 16385
    with pytest.raises(AuditEventError) as exc:
        from_json(payload_large)
    assert exc.value.code == "too_large"

    # Unknown field 'extra'
    valid_json = to_json(
        new_event(actor=Actor("user", "u-1"), action="user.login", outcome="success")
    )
    doc = json.loads(valid_json)
    doc["extra"] = "val"
    with pytest.raises(AuditEventError) as exc2:
        from_json(json.dumps(doc))
    assert exc2.value.code == "unknown_field"
    assert exc2.value.path == "extra"

    # Malformed json '{'
    with pytest.raises(AuditEventError) as exc3:
        from_json("{")
    assert exc3.value.code == "invalid_json"


def test_acceptance_secret_value_sanitized_in_error() -> None:
    secret_val = "S3CRET" * 200
    with pytest.raises(AuditEventError) as exc:
        new_event(
            actor=Actor("user", "u-1"),
            action="user.login",
            outcome="success",
            attributes={"info": secret_val},
        )
    assert exc.value.code == "invalid_attribute"
    assert "S3CRET" not in str(exc.value)


def test_acceptance_json_schema() -> None:
    assert JSON_SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert JSON_SCHEMA["required"] == ["schema_version", "id", "time", "actor", "action", "outcome"]
    assert JSON_SCHEMA["additionalProperties"] is False


def test_actor_target_control_chars_and_lengths() -> None:
    with pytest.raises(AuditEventError) as exc:
        Actor("user", "")
    assert exc.value.code == "invalid_actor"

    with pytest.raises(AuditEventError) as exc2:
        Actor("user", "x" * 257)
    assert exc2.value.code == "invalid_actor"

    with pytest.raises(AuditEventError) as exc3:
        Actor("user", "user\nname")
    assert exc3.value.code == "invalid_actor"

    with pytest.raises(AuditEventError) as exc4:
        Target("123bad", "t-1")
    assert exc4.value.code == "invalid_target"

    with pytest.raises(AuditEventError) as exc5:
        Target("invoice", "")
    assert exc5.value.code == "invalid_target"

    with pytest.raises(AuditEventError) as exc6:
        Target("invoice", "inv\x00")
    assert exc6.value.code == "invalid_target"


def test_event_id_and_request_id_validation() -> None:
    with pytest.raises(AuditEventError) as exc:
        new_event(
            actor=Actor("user", "u-1"),
            action="user.login",
            outcome="success",
            id_factory=lambda: "bad id with spaces",
        )
    assert exc.value.code == "invalid_id"

    with pytest.raises(AuditEventError) as exc2:
        new_event(
            actor=Actor("user", "u-1"),
            action="user.login",
            outcome="success",
            request_id="req with spaces",
        )
    assert exc2.value.code == "invalid_id"


def test_event_reason_length() -> None:
    with pytest.raises(AuditEventError) as exc:
        new_event(
            actor=Actor("user", "u-1"),
            action="user.login",
            outcome="failure",
            reason="a" * 501,
        )
    assert exc.value.code == "invalid_reason"


def test_sensitive_attributes_keywords() -> None:
    keywords = [
        "password",
        "my_passwd",
        "client_secret",
        "session_token",
        "authorization_header",
        "session_cookie",
        "api_key_v2",
        "private_key_pem",
    ]
    for kw in keywords:
        with pytest.raises(AuditEventError) as exc:
            new_event(
                actor=Actor("user", "u-1"),
                action="user.login",
                outcome="success",
                attributes={kw: "123"},
            )
        assert exc.value.code == "sensitive_attribute"


def test_invalid_attr_key_format() -> None:
    with pytest.raises(AuditEventError) as exc:
        new_event(
            actor=Actor("user", "u-1"),
            action="user.login",
            outcome="success",
            attributes={"BadKey": "123"},
        )
    assert exc.value.code == "invalid_attribute"


def test_from_json_error_cases() -> None:
    # Root not object
    with pytest.raises(AuditEventError) as exc:
        from_json("[]")
    assert exc.value.code == "invalid_type"

    # Non-string input
    with pytest.raises(AuditEventError) as exc_type:
        from_json(123)  # type: ignore[arg-type]
    assert exc_type.value.code == "invalid_type"

    # Missing required field
    base = {
        "schema_version": "1.0",
        "id": "evt-1",
        "time": "2026-11-06T12:00:00.000Z",
        "actor": {"type": "user", "id": "u-1"},
        "action": "user.login",
    }
    with pytest.raises(AuditEventError) as exc_miss:
        from_json(json.dumps(base))
    assert exc_miss.value.code == "missing_field"
    assert exc_miss.value.path == "outcome"

    # Invalid schema version
    bad_ver = dict(base, outcome="success", schema_version="2.0")
    with pytest.raises(AuditEventError) as exc_v:
        from_json(json.dumps(bad_ver))
    assert exc_v.value.code == "invalid_type"

    # Actor unknown field
    bad_actor = dict(base, outcome="success", actor={"type": "user", "id": "u-1", "extra": 1})
    with pytest.raises(AuditEventError) as exc_af:
        from_json(json.dumps(bad_actor))
    assert exc_af.value.code == "unknown_field"
    assert exc_af.value.path == "actor.extra"

    # Target unknown field
    bad_target = dict(
        base, outcome="success", target={"type": "invoice", "id": "inv-1", "extra": 1}
    )
    with pytest.raises(AuditEventError) as exc_tf:
        from_json(json.dumps(bad_target))
    assert exc_tf.value.code == "unknown_field"
    assert exc_tf.value.path == "target.extra"

    # Invalid target types
    bad_t_type = dict(base, outcome="success", target={"type": 123, "id": "inv-1"})
    with pytest.raises(AuditEventError) as exc_tt:
        from_json(json.dumps(bad_t_type))
    assert exc_tt.value.code == "invalid_type"

    # Target not object
    bad_t_obj = dict(base, outcome="success", target="not-an-object")
    with pytest.raises(AuditEventError) as exc_to:
        from_json(json.dumps(bad_t_obj))
    assert exc_to.value.code == "invalid_type"

    # Float in attributes via JSON
    bad_attrs = dict(base, outcome="success", attributes={"pi": 3.14})
    with pytest.raises(AuditEventError) as exc_attr:
        from_json(json.dumps(bad_attrs))
    assert exc_attr.value.code == "invalid_attribute"

    # Actor not an object
    bad_actor_obj = dict(base, outcome="success", actor="user-1")
    with pytest.raises(AuditEventError) as exc_ao:
        from_json(json.dumps(bad_actor_obj))
    assert exc_ao.value.code == "invalid_type"


def test_adversarial_tokens_and_boundaries() -> None:
    # Action depth levels: 1 dot (2 parts) to 4 dots (5 parts)
    assert ACTION_REGEX.fullmatch("a.b")
    assert ACTION_REGEX.fullmatch("a.b.c.d.e")
    assert not ACTION_REGEX.fullmatch("a.b.c.d.e.f")  # 6 parts rejected
    assert not ACTION_REGEX.fullmatch(".a.b")
    assert not ACTION_REGEX.fullmatch("a.b.")
    assert not ACTION_REGEX.fullmatch("a..b")
    assert not ACTION_REGEX.fullmatch("a-b.c")

    # Truncation check (not rounding): 999 microseconds = .000Z, not .001Z
    evt_trunc = new_event(
        actor=Actor("user", "u-1"),
        action="user.login",
        outcome="success",
        clock=lambda: datetime(2026, 1, 1, 0, 0, 0, 999, tzinfo=timezone.utc),
    )
    assert to_json(evt_trunc).find("2026-01-01T00:00:00.000Z") != -1

    # Negative boundary for integers: -(2**53 - 1) accepted, -(2**53) rejected
    safe_min = -(2**53 - 1)
    e_min = new_event(
        actor=Actor("user", "u-1"),
        action="user.login",
        outcome="success",
        attributes={"min_safe": safe_min},
    )
    assert e_min.attributes["min_safe"] == safe_min

    with pytest.raises(AuditEventError):
        new_event(
            actor=Actor("user", "u-1"),
            action="user.login",
            outcome="success",
            attributes={"min_unsafe": -(2**53)},
        )
