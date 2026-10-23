"""Acceptance criteria AC-1 .. AC-30 from the specification."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from conftest import APP


def test_ac01_base64_encode_text(run):
    result = run("encode", "base64", "test")
    assert result.returncode == 0
    assert result.stdout == b"dGVzdA==\n"
    assert result.stderr == b""


def test_ac02_base64_decode(run):
    result = run("decode", "base64", "dGVzdA==")
    assert result.returncode == 0
    assert result.stdout == b"test\n"


def test_ac03_base64_decode_invalid(run):
    result = run("decode", "base64", "!!!!")
    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr


def test_ac04_hex_encode(run):
    result = run("encode", "hex", "AB")
    assert result.returncode == 0
    assert result.stdout == b"4142\n"


def test_ac05_hex_decode_with_whitespace(run):
    result = run("decode", "hex", stdin=b"41 42\n43")
    assert result.returncode == 0
    assert result.stdout == b"414243\n"

    text = run("decode", "hex", "--output", "text", stdin=b"41 42\n43")
    assert text.returncode == 0
    assert text.stdout == b"ABC\n"


def test_ac06_url_encode_space(run):
    result = run("encode", "url", "hello world")
    assert result.returncode == 0
    assert result.stdout == b"hello%20world\n"


def test_ac07_url_decode(run):
    result = run("decode", "url", "hello%20world")
    assert result.returncode == 0
    assert result.stdout == b"hello world\n"


def test_ac08_xor_encode(run):
    result = run("encode", "xor:42", "A")
    assert result.returncode == 0
    assert result.stdout == b"03\n"


def test_ac09_xor_decode_hex(run):
    result = run("decode", "xor:42", "03")
    assert result.returncode == 0
    assert result.stdout == b"41\n"

    text = run("decode", "xor:42", "03", "--output", "text")
    assert text.returncode == 0
    assert text.stdout == b"A\n"


def test_ac10_xor_invalid_key(run):
    result = run("encode", "xor:GG", "test")
    assert result.returncode == 2
    assert result.stdout == b""


def test_ac11_xor_two_byte_key(run):
    result = run("encode", "xor:4242", "test")
    assert result.returncode == 2


def test_ac12_analyze_frequency(run):
    result = run("analyze", "aabbcc")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["total_chars"] == 6
    assert payload["unique_chars"] == 3
    assert len(payload["histogram"]) == 3
    assert [entry["char"] for entry in payload["histogram"]] == ["a", "b", "c"]
    assert all(entry["count"] == 2 for entry in payload["histogram"])
    assert all(entry["percentage"] == 33.3 for entry in payload["histogram"])


def test_ac13_analyze_json_order(run):
    result = run("analyze", "aabbbcccc")
    assert result.returncode == 0
    histogram = json.loads(result.stdout)["histogram"]
    assert [(entry["char"], entry["count"]) for entry in histogram] == [
        ("c", 4),
        ("b", 3),
        ("a", 2),
    ]


def test_ac14_encode_output_hex(run):
    result = run("encode", "base64", "test", "--output", "hex")
    assert result.returncode == 0
    assert result.stdout == b"6447567a64413d3d\n"


def test_ac15_decode_output_hex(run):
    result = run("decode", "base64", "dGVzdA==", "--output", "hex")
    assert result.returncode == 0
    assert result.stdout == b"74657374\n"


def test_ac16_decode_text_non_utf8(run):
    result = run("decode", "hex", "FF", "--output", "text")
    assert result.returncode == 1
    assert result.stdout == b""


def test_ac17_input_from_file(run, tmp_path):
    path = tmp_path / "test.txt"
    path.write_bytes(b"hello")
    result = run("encode", "base64", "--input", str(path))
    assert result.returncode == 0
    assert result.stdout == b"aGVsbG8=\n"


def test_ac18_stdin_pipe(run):
    result = run("encode", "base64", stdin=b"test")
    assert result.returncode == 0
    assert result.stdout == b"dGVzdA==\n"


def test_ac19_json_encode(run):
    result = run("encode", "base64", "test", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["operation"] == "encode"
    assert payload["codec"] == "base64"
    assert payload["output"] == "dGVzdA=="
    assert payload["output_format"] == "text"
    assert payload["input_length"] == 4


def test_ac20_json_analyze(run):
    result = run("analyze", "aabb", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["total_chars"] == 4
    assert payload["unique_chars"] == 2


def test_ac21_empty_input(run):
    result = run("encode", "base64", "")
    assert result.returncode == 0
    assert result.stdout == b"\n"


def test_ac22_help(run):
    result = run("--help")
    assert result.returncode == 0
    assert result.stdout
    lowered = result.stdout.lower()
    assert b"usage" in lowered or b"commands" in lowered


def test_ac23_version(run):
    result = run("--version")
    assert result.returncode == 0
    assert result.stdout == b"ctf-codec-toolkit 0.1.0\n"


def test_ac24_unknown_codec(run):
    result = run("encode", "rot13", "test")
    assert result.returncode == 2
    assert result.stdout == b""


def test_ac25_unknown_command(run):
    result = run("scramble", "test")
    assert result.returncode == 2
    assert result.stdout == b""


def test_ac26_analyze_non_utf8(run):
    result = run("analyze", stdin=b"\xff")
    assert result.returncode == 1


def test_ac27_url_plus_as_space(run):
    result = run("decode", "url", "hello+world")
    assert result.returncode == 0
    assert result.stdout == b"hello world\n"


def test_ac28_base64_decode_without_padding(run):
    result = run("decode", "base64", "dGVzdA")
    assert result.returncode == 0
    assert result.stdout == b"test\n"


def test_ac29_hex_decode_case_insensitive(run):
    lower = run("decode", "hex", "4a4b")
    upper = run("decode", "hex", "4A4B")
    assert lower.returncode == 0
    assert upper.returncode == 0
    assert lower.stdout == b"4a4b\n"
    assert upper.stdout == b"4a4b\n"


def test_ac30_determinism(run):
    outputs = {run("encode", "base64", "test", "--json").stdout for _ in range(10)}
    assert len(outputs) == 1


def test_help_command(run):
    result = run("help")
    assert result.returncode == 0
    assert b"usage" in result.stdout.lower()


def test_version_command(run):
    result = run("version")
    assert result.returncode == 0
    assert result.stdout == b"ctf-codec-toolkit 0.1.0\n"


def test_app_is_directly_executable():
    result = subprocess.run(
        [str(APP), "version"], input=b"", capture_output=True, check=False
    )
    assert result.returncode == 0
    assert result.stdout == b"ctf-codec-toolkit 0.1.0\n"
    assert os.access(APP, os.X_OK)


def test_app_works_from_repository_root():
    result = subprocess.run(
        [str(APP), "encode", "base64", "test"],
        cwd=Path(__file__).resolve().parents[1],
        input=b"",
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout == b"dGVzdA==\n"


def test_no_arguments_is_usage_error():
    result = subprocess.run(
        [sys.executable, str(APP)], input=b"", capture_output=True, check=False
    )
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"usage" in result.stderr.lower()
