"""Shared fixtures: the repository root and a fresh, mutable copy of the lab spec document."""

from __future__ import annotations

import copy
import tomllib
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "lab" / "lab.toml"
_DOC = tomllib.loads(SPEC.read_text(encoding="utf-8"))


@pytest.fixture
def doc() -> dict[str, Any]:
    """A deep copy of lab/lab.toml as decoded TOML, safe to mutate."""
    return copy.deepcopy(_DOC)
