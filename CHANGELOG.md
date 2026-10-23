# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-08

### Added

- Executable `./app` exposing `encode`, `decode`, `analyze`, `help`, and `version`
  commands.
- Base64 codec (RFC 4648): padded output, optional input padding, strict validation of
  the alphabet and padding.
- Hexadecimal codec: lowercase output, case-insensitive input, whitespace-tolerant
  decoding.
- URL codec (RFC 3986 query string): `%20` for spaces and `+` accepted as space on
  decode.
- Single-byte XOR codec (`xor:<HEX_KEY>`), with input auto-detection between hex and
  UTF-8 text when decoding.
- Deterministic character-frequency analysis with a stable JSON schema and ordering.
- Input from stdin, positional argument, or `--input FILE` (binary-safe).
- Text, hex, and JSON output modes with stable exit codes (`0`, `1`, `2`, `4`).
- Public black-box test suite covering AC-1 through AC-30 and the documented edge cases.
- Ruff lint configuration and GitHub Actions CI for Python 3.10 and 3.12.
- README with architecture diagram, usage reference, and honest authorship disclosure.
- MIT license (2026).
