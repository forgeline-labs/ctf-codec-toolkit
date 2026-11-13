"""Edge cases from section 7 of the specification, plus regression coverage."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_empty_input_every_codec(run):
    for args in (
        ("encode", "base64"),
        ("encode", "hex"),
        ("encode", "url"),
        ("encode", "xor:00"),
        ("decode", "base64"),
        ("decode", "hex"),
        ("decode", "url"),
        ("decode", "xor:00"),
    ):
        result = run(*args, stdin=b"")
        assert result.returncode == 0, args
        assert result.stdout == b"\n", args


def test_base64_single_character_no_padding(run):
    result = run("decode", "base64", "a")
    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr


def test_base64_excessive_padding_fails(run):
    assert run("decode", "base64", "a=====").returncode == 1
    assert run("decode", "base64", "====").returncode == 1
    assert run("decode", "base64", "dGVzdA===").returncode == 1


def test_base64_misplaced_padding_fails(run):
    assert run("decode", "base64", "==a").returncode == 1
    assert run("decode", "base64", "dG=Vz").returncode == 1


def test_base64_decode_binary_to_hex(run):
    result = run("decode", "base64", "/w==", "--output", "hex")
    assert result.returncode == 0
    assert result.stdout == b"ff\n"

    text = run("decode", "base64", "/w==")
    assert text.returncode == 1


def test_hex_odd_digits_fail(run):
    assert run("decode", "hex", "4").returncode == 1


def test_hex_ascii_a(run):
    text = run("decode", "hex", "41", "--output", "text")
    assert text.returncode == 0
    assert text.stdout == b"A\n"
    raw = run("decode", "hex", "41")
    assert raw.returncode == 0
    assert raw.stdout == b"41\n"


def test_hex_non_hex_character_fails(run):
    assert run("decode", "hex", "4g").returncode == 1
    assert run("decode", "hex", "GG").returncode == 1


def test_url_space_is_percent20(run):
    result = run("encode", "url", "a b")
    assert result.stdout == b"a%20b\n"


def test_url_decode_plus(run):
    assert run("decode", "url", "hello+world").stdout == b"hello world\n"


def test_url_encode_unreserved_and_uppercase_hex(run):
    result = run("encode", "url", "a-b_c.d~é")
    assert result.returncode == 0
    assert result.stdout == b"a-b_c.d~%C3%A9\n"


def test_url_decode_invalid_escape(run):
    assert run("decode", "url", "%GG").returncode == 1
    assert run("decode", "url", "%4").returncode == 1
    assert run("decode", "url", "%").returncode == 1


def test_url_decode_invalid_utf8(run):
    assert run("decode", "url", "%FF").returncode == 1
    assert run("decode", "url", "%FF", "--output", "hex").stdout == b"ff\n"


def test_url_decode_whitespace_is_literal(run):
    result = run("decode", "url", "a b")
    assert result.returncode == 0
    assert result.stdout == b"a b\n"


def test_xor_null_key_keeps_bytes(run):
    result = run("encode", "xor:00", "test")
    assert result.returncode == 0
    assert result.stdout == b"74657374\n"


def test_xor_ff_example(run):
    result = run("encode", "xor:FF", "A")
    assert result.stdout == b"be\n"


def test_xor_keys_are_case_insensitive(run):
    assert run("encode", "xor:4a", "A").stdout == b"0b\n"
    assert run("encode", "xor:4A", "A").stdout == b"0b\n"


def test_xor_invalid_keys(run):
    for key in ("xor:GG", "xor:4G", "xor:", "xor", "xor:0042", "xor:4200"):
        result = run("encode", key, "test")
        assert result.returncode == 2, key


def test_xor_decode_text_input(run):
    result = run("decode", "xor:42", "hello")
    assert result.returncode == 0
    expected = bytes(byte ^ 0x42 for byte in b"hello").hex()
    assert result.stdout == expected.encode() + b"\n"


def test_xor_decode_whitespace_in_hex(run):
    result = run("decode", "xor:42", "0 3")
    assert result.returncode == 0
    assert result.stdout == b"41\n"


def test_stdin_multiline_is_not_trimmed(run):
    result = run("encode", "base64", stdin=b"line1\nline2\n")
    assert result.returncode == 0
    assert result.stdout == base64.b64encode(b"line1\nline2\n") + b"\n"


def test_utf8_bom_is_a_normal_character(run):
    raw = b"\xef\xbb\xbfhi"
    encoded = run("encode", "base64", stdin=raw)
    assert encoded.returncode == 0
    assert encoded.stdout == base64.b64encode(raw) + b"\n"

    analysis = run("analyze", stdin=raw)
    payload = json.loads(analysis.stdout)
    assert payload["total_chars"] == 3
    assert payload["unique_chars"] == 3
    assert "﻿" in {entry["char"] for entry in payload["histogram"]}


def test_analysis_counts_emoji_once(run):
    payload = json.loads(run("analyze", "😀").stdout)
    assert payload["total_chars"] == 1
    assert payload["unique_chars"] == 1
    assert payload["histogram"][0]["char"] == "😀"


def test_analysis_escapes_control_characters(run):
    result = run("analyze", stdin=b"a\x00b")
    assert result.returncode == 0
    assert b"\\u0000" in result.stdout
    payload = json.loads(result.stdout)
    chars = [entry["char"] for entry in payload["histogram"]]
    assert "\x00" in chars


def test_analysis_escapes_non_ascii(run):
    result = run("analyze", "é")
    assert result.returncode == 0
    assert b"\\u00e9" in result.stdout
    assert json.loads(result.stdout)["histogram"][0]["char"] == "é"


def test_analysis_percentage_has_one_decimal(run):
    result = run("analyze", "aab")
    raw = result.stdout.decode()
    assert "66.7" in raw
    assert "33.3" in raw


def test_analysis_empty(run):
    payload = json.loads(run("analyze", stdin=b"").stdout)
    assert payload == {"total_chars": 0, "unique_chars": 0, "histogram": []}


def test_encode_hex_output_text_roundtrips(run):
    assert run("encode", "hex", "hé", "--output", "text").stdout == "hé\n".encode()


def test_encode_hex_non_utf8_output_text_fails(run):
    result = run("encode", "hex", "--output", "text", stdin=b"\xff")
    assert result.returncode == 1


def test_encode_xor_text_non_utf8_fails(run):
    assert run("encode", "xor:ff", "A", "--output", "text").returncode == 1


def test_decode_xor_text_non_utf8_fails(run):
    assert run("decode", "xor:00", "ff", "--output", "text").returncode == 1


def test_input_file_priority_over_positional(run, tmp_path):
    path = tmp_path / "input.bin"
    path.write_bytes(b"hello")
    result = run("encode", "base64", "--input", str(path), "ignored")
    assert result.returncode == 0
    assert result.stdout == b"aGVsbG8=\n"


def test_missing_input_file_is_usage_error(run, tmp_path):
    result = run("encode", "base64", "--input", str(tmp_path / "missing"))
    assert result.returncode == 2
    assert result.stdout == b""


def test_dev_null_input(run):
    result = run("encode", "base64", "--input", os.devnull)
    assert result.returncode == 0
    assert result.stdout == b"\n"


def test_binary_input_roundtrip(run):
    raw = bytes(range(256))
    encoded = run("encode", "base64", stdin=raw)
    assert encoded.returncode == 0
    token = encoded.stdout.strip().decode()
    decoded = run("decode", "base64", token, "--output", "hex")
    assert decoded.returncode == 0
    assert decoded.stdout.strip() == raw.hex().encode()


def test_flags_may_appear_before_command(run):
    result = run("--json", "encode", "base64", "test")
    assert json.loads(result.stdout)["output"] == "dGVzdA=="


def test_flags_may_appear_between_command_and_codec(run):
    result = run("encode", "--output", "hex", "base64", "test")
    assert result.stdout == b"6447567a64413d3d\n"


def test_unknown_flag_is_usage_error(run):
    assert run("encode", "base64", "--bogus", "test").returncode == 2
    assert run("encode", "base64", "-z", "test").returncode == 2


def test_invalid_output_format(run):
    assert run("encode", "base64", "test", "--output", "invalid").returncode == 2


def test_missing_arguments(run):
    assert run("encode").returncode == 2
    assert run("decode").returncode == 2
    assert run("encode", "base64", "a", "b").returncode == 2


def test_empty_string_argument_with_empty_stdin(run):
    # An explicit empty INPUT with an empty attached stream still yields empty
    # data; this mirrors AC-21.
    result = run("encode", "base64", "", stdin=b"")
    assert result.returncode == 0
    assert result.stdout == b"\n"


def test_empty_string_argument_reads_available_stdin(run):
    # Section 3.2: an empty INPUT falls back to stdin when a stream is attached.
    result = run("encode", "base64", "", stdin=b"test")
    assert result.returncode == 0
    assert result.stdout == b"dGVzdA==\n"


def test_empty_string_argument_waits_for_late_stdin():
    # Reading must be deterministic: bytes written after the process starts
    # still belong to the stream and are read until EOF.
    process = subprocess.Popen(
        [sys.executable, str(APP), "encode", "base64", ""],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        time.sleep(0.3)
        stdout, stderr = process.communicate(b"test", timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    assert process.returncode == 0, stderr
    assert stdout == b"dGVzdA==\n"


@pytest.mark.skipif(os.name != "posix", reason="closing fd 0 is POSIX-specific")
def test_empty_string_argument_with_closed_stdin():
    # A closed stdin leaves sys.stdin as None; that must not crash (exit 4).
    result = subprocess.run(
        [sys.executable, str(APP), "encode", "base64", ""],
        capture_output=True,
        check=False,
        preexec_fn=lambda: os.close(0),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == b"\n"


def test_fixture_file_with_hex_whitespace(run):
    result = run("decode", "hex", "--input", str(FIXTURES / "hex-whitespace.txt"))
    assert result.returncode == 0
    assert result.stdout == b"414243\n"


def test_fixture_binary_file_roundtrip(run):
    raw = (FIXTURES / "binary.bin").read_bytes()
    encoded = run("encode", "base64", "--input", str(FIXTURES / "binary.bin"))
    assert encoded.returncode == 0
    token = encoded.stdout.strip().decode()
    decoded = run("decode", "base64", token, "--output", "hex")
    assert decoded.returncode == 0
    assert decoded.stdout.strip() == raw.hex().encode()


def test_fixture_hello_file(run):
    result = run("encode", "base64", "--input", str(FIXTURES / "hello.txt"))
    assert result.returncode == 0
    assert result.stdout == base64.b64encode(b"hello\n") + b"\n"
