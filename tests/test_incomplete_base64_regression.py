"""A six-bit tail cannot decode into a complete byte."""

import base64

import pytest


@pytest.mark.parametrize("encoded", ["Z", "YWJjZ", "YWJjZGVmZ"])
@pytest.mark.parametrize("output", ["text", "hex"])
def test_incomplete_tail_is_rejected(run, encoded, output):
    result = run("decode", "base64", encoded, "--output", output)
    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr


@pytest.mark.parametrize("raw", [b"f", b"fo", b"foo", b"four"])
def test_complete_bytes_allow_omitted_padding(run, raw):
    encoded = base64.b64encode(raw).decode("ascii").rstrip("=")
    result = run("decode", "base64", encoded)
    assert result.returncode == 0, result.stderr
    assert result.stdout == raw + b"\n"
