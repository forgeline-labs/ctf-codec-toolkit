"""ctf-codec-toolkit: deterministic codecs and frequency analysis for CTF work.

This module contains the whole implementation.  It only depends on the Python
standard library and is intentionally free of network access or hidden state so
that every operation is byte-for-byte deterministic.
"""

from __future__ import annotations

import binascii
import json
import os
import sys
from collections.abc import Iterable, Sequence

VERSION = "0.1.0"
PROGRAM = "ctf-codec-toolkit"

BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
BASE64_VALUES = {char: index for index, char in enumerate(BASE64_ALPHABET)}

UNRESERVED = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
)
HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")
HEX_WHITESPACE = frozenset(b" \t\r\n\v\f")

VALID_CODECS = ("base64", "hex", "url")
OUTPUT_FORMATS = ("text", "hex")

HELP_TEXT = """\
usage: ./app <COMMAND> [OPTIONS] [INPUT]

Deterministic encoders, decoders and frequency analysis for CTF workflows.

COMMANDS:
  encode <CODEC> [INPUT]   Encode INPUT with CODEC.
  decode <CODEC> [INPUT]   Decode INPUT with CODEC.
  analyze [INPUT]          Print a JSON character-frequency report.
  help                     Show this help and exit.
  version                  Show the version and exit.

CODECS:
  base64                   Base64 (RFC 4648, standard alphabet).
  hex                      Hexadecimal (case-insensitive on input).
  url                      URL / percent encoding (RFC 3986 query string).
  xor:<HEX_KEY>            XOR with a single-byte key given as two hex digits
                           (for example xor:42 or xor:ff).

OPTIONS:
  -i, --input FILE         Read raw bytes from FILE instead of stdin/INPUT.
  -o, --output FORMAT      Output format: text (default for base64/url) or hex
                           (default for hex/xor). analyze always emits JSON.
      --json               Emit a single JSON document on stdout.
      --quiet              Suppress informational logs (errors still print).
  -h, --help               Show this help and exit.
      --version            Print the version and exit.

INPUT PRIORITY:
  --input FILE > [INPUT] > stdin

EXIT CODES:
  0  success
  1  validation/conversion failure
  2  usage or input-source error
  4  unexpected internal error
"""


class CodecError(Exception):
    """A conversion or validation failure (exit code 1)."""


class UsageError(Exception):
    """A command-line or input-source error (exit code 2)."""


class HelpRequest(Exception):
    """Raised when --help / -h is present."""


class VersionRequest(Exception):
    """Raised when --version is present."""


# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------


def base64_encode(data: bytes) -> str:
    """Encode bytes with the standard RFC 4648 alphabet, always padded."""
    return binascii.b2a_base64(data, newline=False).decode("ascii")


def base64_decode(data: bytes) -> bytes:
    """Decode Base64 with optional padding.

    Padding must be trailing and at most two characters.  Unpadded input is
    accepted; a single trailing data character (for example "a") is treated as
    if followed by implicit "===" padding, matching the specification.
    """
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CodecError("invalid base64: input must be ASCII") from exc

    for char in text:
        if char not in BASE64_VALUES and char != "=":
            raise CodecError(f"invalid base64 character: {char!r}")

    if "=" in text:
        first_pad = text.index("=")
        if any(char != "=" for char in text[first_pad:]):
            raise CodecError("invalid base64 padding: '=' must be trailing")
        pad_len = len(text) - first_pad
        if pad_len > 2:
            raise CodecError("invalid base64 padding: too many '=' characters")
        if len(text) % 4 != 0:
            raise CodecError("invalid base64 padding: length is not a multiple of 4")
        data_len = first_pad
        if data_len % 4 != (4 - pad_len) % 4:
            raise CodecError("invalid base64 padding")
    else:
        data_len = len(text)
        pad_len = (4 - data_len % 4) % 4

    normalized = text if "=" in text else text + "=" * pad_len
    output = bytearray()
    for offset in range(0, len(normalized), 4):
        chunk = normalized[offset : offset + 4]
        values = []
        padding = 0
        for char in chunk:
            if char == "=":
                values.append(0)
                padding += 1
            else:
                values.append(BASE64_VALUES[char])
        combined = (
            (values[0] << 18) | (values[1] << 12) | (values[2] << 6) | values[3]
        )
        produced = 3 - padding
        if produced >= 1:
            output.append((combined >> 16) & 0xFF)
        if produced >= 2:
            output.append((combined >> 8) & 0xFF)
        if produced >= 3:
            output.append(combined & 0xFF)
    return bytes(output)


# ---------------------------------------------------------------------------
# Hexadecimal
# ---------------------------------------------------------------------------


def hex_encode(data: bytes) -> str:
    """Encode bytes as a continuous lowercase hexadecimal string."""
    return binascii.hexlify(data).decode("ascii")


def hex_decode(data: bytes) -> bytes:
    """Decode hexadecimal, silently ignoring ASCII whitespace."""
    cleaned = bytes(byte for byte in data if byte not in HEX_WHITESPACE)
    if len(cleaned) % 2 != 0:
        raise CodecError("invalid hex: odd number of digits")
    for byte in cleaned:
        if byte not in HEX_DIGITS:
            raise CodecError("invalid hex: non-hexadecimal character")
    return binascii.unhexlify(cleaned)


# ---------------------------------------------------------------------------
# URL / percent encoding
# ---------------------------------------------------------------------------


def url_encode(data: bytes) -> str:
    """Percent-encode bytes for a query string; space becomes %20."""
    pieces = []
    for byte in data:
        if byte in UNRESERVED:
            pieces.append(chr(byte))
        else:
            pieces.append(f"%{byte:02X}")
    return "".join(pieces)


def url_decode(data: bytes) -> bytes:
    """Decode percent escapes and '+' as space."""
    output = bytearray()
    index = 0
    length = len(data)
    while index < length:
        byte = data[index]
        if byte == 0x2B:  # '+'
            output.append(0x20)
            index += 1
        elif byte == 0x25:  # '%'
            if index + 2 >= length:
                raise CodecError("invalid URL encoding: truncated percent escape")
            pair = data[index + 1 : index + 3]
            if any(char not in HEX_DIGITS for char in pair):
                raise CodecError("invalid URL encoding: percent escape is not hex")
            output.append(int(pair, 16))
            index += 3
        else:
            output.append(byte)
            index += 1
    return bytes(output)


# ---------------------------------------------------------------------------
# XOR
# ---------------------------------------------------------------------------


def xor_bytes(data: bytes, key: int) -> bytes:
    """XOR every byte with a single-byte key."""
    return bytes(byte ^ key for byte in data)


# ---------------------------------------------------------------------------
# Frequency analysis
# ---------------------------------------------------------------------------


def analyze_text(text: str) -> dict:
    """Build the deterministic character-frequency report."""
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1

    total = len(text)
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    histogram = [
        {
            "char": char,
            "count": count,
            "percentage": round(count * 100.0 / total, 1) if total else 0.0,
        }
        for char, count in ordered
    ]
    return {
        "total_chars": total,
        "unique_chars": len(counts),
        "histogram": histogram,
    }


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


class Options:
    def __init__(self) -> None:
        self.input_path: str | None = None
        self.output_format: str | None = None
        self.json = False
        self.quiet = False
        self.positionals: list[str] = []


def parse_argv(argv: Sequence[str]) -> Options:
    """Parse flags that may appear before, between or after positionals."""
    options = Options()
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in ("--help", "-h"):
            raise HelpRequest
        if token == "--version":
            raise VersionRequest
        if token == "--json":
            options.json = True
        elif token == "--quiet":
            options.quiet = True
        elif token in ("--input", "-i"):
            index += 1
            if index >= len(argv):
                raise UsageError("option --input requires a FILE argument")
            options.input_path = argv[index]
        elif token.startswith("--input="):
            options.input_path = token[len("--input=") :]
            if options.input_path == "":
                raise UsageError("option --input requires a FILE argument")
        elif token in ("--output", "-o"):
            index += 1
            if index >= len(argv):
                raise UsageError("option --output requires a FORMAT argument")
            options.output_format = argv[index]
        elif token.startswith("--output="):
            options.output_format = token[len("--output=") :]
        elif token.startswith("-") and token != "-":
            raise UsageError(f"unknown option: {token}")
        else:
            options.positionals.append(token)
        index += 1

    if options.output_format is not None and options.output_format not in OUTPUT_FORMATS:
        raise UsageError(
            f"invalid output format: {options.output_format!r} "
            "(expected 'text' or 'hex')"
        )
    return options


def parse_codec(name: str) -> tuple[str, int | None]:
    """Return (codec_kind, xor_key), raising UsageError for invalid codecs."""
    if name in VALID_CODECS:
        return name, None
    if name == "xor":
        raise UsageError("invalid XOR key: expected 'xor:<HEX_KEY>'")
    if name.startswith("xor:"):
        key_text = name[len("xor:") :]
        if len(key_text) != 2:
            raise UsageError(
                "invalid XOR key: exactly two hexadecimal digits are required"
            )
        if not key_text.isascii() or any(
            byte not in HEX_DIGITS for byte in key_text.encode("ascii")
        ):
            raise UsageError("invalid XOR key: not hexadecimal")
        return "xor", int(key_text, 16)
    raise UsageError(f"unknown codec: {name}")


# ---------------------------------------------------------------------------
# Input and output helpers
# ---------------------------------------------------------------------------


def read_input(options: Options, positional: str | None) -> bytes:
    """Resolve input using the documented priority: file > positional > stdin."""
    if options.input_path is not None:
        try:
            with open(options.input_path, "rb") as handle:
                return handle.read()
        except OSError as exc:
            raise UsageError(f"cannot read input file {options.input_path!r}: {exc}") from exc

    if positional is not None:
        if positional == "":
            # An explicitly empty INPUT defers to stdin, exactly like an
            # omitted INPUT: read the stream until EOF.  Reading to EOF keeps
            # the result independent of when a pipe writer happens to deliver
            # its bytes (AC-21 covers the empty-stream case).
            return _read_empty_argument_stdin()
        return os.fsencode(positional)

    return sys.stdin.buffer.read()


def _read_empty_argument_stdin() -> bytes:
    """Read stdin to EOF for an explicitly empty INPUT argument.

    A terminal is left untouched so the command never waits for interactive
    input, and a missing stream (for example a closed fd 0) contributes no
    data.
    """
    stream = sys.stdin
    if stream is None:
        return b""
    try:
        if stream.isatty():
            return b""
        return stream.buffer.read()
    except (AttributeError, OSError, ValueError):
        return b""


def decode_utf8(data: bytes, context: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CodecError(f"{context}: result is not valid UTF-8") from exc


def format_encode(codec: str, encoded: bytes | str, output_format: str) -> str:
    """Render an encoded value according to the requested output format."""
    if codec == "hex":
        # The native representation is already hexadecimal.
        assert isinstance(encoded, str)
        if output_format == "hex":
            return encoded
        # Converting each pair back yields the original bytes; interpreting
        # those as UTF-8 is what text output means for this codec.
        return decode_utf8(binascii.unhexlify(encoded), codec)
    if codec == "xor":
        assert isinstance(encoded, bytes)
        if output_format == "hex":
            return binascii.hexlify(encoded).decode("ascii")
        return decode_utf8(encoded, codec)
    # base64 and url produce ASCII text.
    assert isinstance(encoded, str)
    if output_format == "hex":
        return binascii.hexlify(encoded.encode("ascii")).decode("ascii")
    return encoded


def format_decode(decoded: bytes, output_format: str) -> str:
    if output_format == "hex":
        return binascii.hexlify(decoded).decode("ascii")
    return decode_utf8(decoded, "decode")


def default_output_format(codec: str) -> str:
    return "hex" if codec in ("hex", "xor") else "text"


def emit(text: str) -> None:
    sys.stdout.buffer.write(text.encode("utf-8") + b"\n")
    sys.stdout.buffer.flush()


def json_document(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=True, separators=(", ", ": "))


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------


def run_encode(
    codec: str,
    key: int | None,
    data: bytes,
    output_format: str,
) -> tuple[str, int]:
    if codec == "base64":
        encoded: bytes | str = base64_encode(data)
    elif codec == "hex":
        encoded = hex_encode(data)
    elif codec == "url":
        encoded = url_encode(data)
    else:  # xor
        assert key is not None
        encoded = xor_bytes(data, key)
    return format_encode(codec, encoded, output_format), len(data)


def run_decode(
    codec: str,
    key: int | None,
    data: bytes,
    output_format: str,
) -> tuple[str, int]:
    if codec == "base64":
        decoded = base64_decode(data)
    elif codec == "hex":
        decoded = hex_decode(data)
    elif codec == "url":
        decoded = url_decode(data)
    else:  # xor
        assert key is not None
        xor_input = _xor_decode_input(data)
        decoded = xor_bytes(xor_input, key)
    return format_decode(decoded, output_format), len(decoded)


def _xor_decode_input(data: bytes) -> bytes:
    """Interpret XOR decode input as hex when it is purely hex, else text."""
    cleaned = bytes(byte for byte in data if byte not in HEX_WHITESPACE)
    if cleaned and all(byte in HEX_DIGITS for byte in cleaned):
        return hex_decode(cleaned)
    # Text input: it must be valid UTF-8, though the bytes are used verbatim.
    decode_utf8(data, "xor")
    return data


def execute(argv: Sequence[str]) -> int:
    try:
        options = parse_argv(argv)
    except HelpRequest:
        sys.stdout.write(HELP_TEXT)
        return 0
    except VersionRequest:
        print(f"{PROGRAM} {VERSION}")
        return 0

    positionals = options.positionals
    if not positionals:
        raise UsageError("missing command")

    command = positionals[0]
    rest = positionals[1:]

    if command == "help":
        sys.stdout.write(HELP_TEXT)
        return 0
    if command == "version":
        print(f"{PROGRAM} {VERSION}")
        return 0

    if command not in ("encode", "decode", "analyze"):
        raise UsageError(f"unknown command: {command}")

    if command == "analyze":
        if len(rest) > 1:
            raise UsageError("analyze accepts at most one INPUT argument")
        positional = rest[0] if rest else None
        data = read_input(options, positional)
        text = decode_utf8(data, "analyze")
        emit(json_document(analyze_text(text)))
        return 0

    if not rest:
        raise UsageError(f"{command} requires a CODEC argument")
    if len(rest) > 2:
        raise UsageError(f"{command} accepts at most one INPUT argument")

    codec_name = rest[0]
    codec, key = parse_codec(codec_name)
    positional = rest[1] if len(rest) > 1 else None
    data = read_input(options, positional)
    output_format = options.output_format or default_output_format(codec)

    if command == "encode":
        output, input_length = run_encode(codec, key, data, output_format)
    else:
        output, input_length = run_decode(codec, key, data, output_format)

    if options.json:
        emit(
            json_document(
                {
                    "operation": command,
                    "codec": codec_name,
                    "input_length": input_length,
                    "output": output,
                    "output_format": output_format,
                }
            )
        )
    else:
        emit(output)
    return 0


def _colorize(text: str) -> str:
    if sys.stderr.isatty() and "NO_COLOR" not in os.environ:
        return f"\033[31m{text}\033[0m"
    return text


def main(argv: Iterable[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        return execute(args)
    except UsageError as exc:
        print(_colorize(f"error: {exc}"), file=sys.stderr)
        sys.stderr.write(HELP_TEXT)
        return 2
    except CodecError as exc:
        print(_colorize(f"error: {exc}"), file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 0
    except Exception as exc:  # pragma: no cover - defensive fallback
        print(_colorize(f"internal error: {exc}"), file=sys.stderr)
        return 4


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
