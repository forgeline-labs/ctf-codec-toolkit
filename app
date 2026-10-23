#!/usr/bin/env python3
"""Entry point for the ctf-codec-toolkit command-line interface."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from codec_toolkit import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
