"""Shared helpers for the black-box CLI tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"


def run_app(*args: str, stdin: bytes = b"") -> subprocess.CompletedProcess:
    """Run ./app through the current interpreter and capture its streams."""
    return subprocess.run(
        [sys.executable, str(APP), *args],
        input=stdin,
        capture_output=True,
        check=False,
    )


@pytest.fixture
def run():
    return run_app
