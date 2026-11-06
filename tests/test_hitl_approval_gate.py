"""Behavior tests for the public API of hitl_approval_gate."""

from __future__ import annotations

import pytest

import hitl_approval_gate


def test_normalize_trims_and_lowercases() -> None:
    assert hitl_approval_gate.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        hitl_approval_gate.normalize(value)


def test_version_is_semver() -> None:
    parts = hitl_approval_gate.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
