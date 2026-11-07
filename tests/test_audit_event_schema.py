"""Behavior tests for the public API of audit_event_schema."""

from __future__ import annotations

import pytest

import audit_event_schema


def test_normalize_trims_and_lowercases() -> None:
    assert audit_event_schema.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        audit_event_schema.normalize(value)


def test_version_is_semver() -> None:
    parts = audit_event_schema.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
