#!/usr/bin/env python3
"""Test double for the Nmap binary. Writes fixture XML to the -oX path."""

from __future__ import annotations

import os
import sys
from pathlib import Path

FIXTURE = Path(__file__).resolve().parent / "host_22_80.xml"


def _xml_path(argv: list[str]) -> str | None:
    if "-oX" not in argv:
        return None
    idx = argv.index("-oX")
    if idx + 1 >= len(argv):
        return None
    return argv[idx + 1]


def main(argv: list[str]) -> int:
    src = Path(os.environ.get("CYBERX_FAKE_NMAP_XML", str(FIXTURE)))
    dest = _xml_path(argv)
    if dest is None:
        sys.stderr.write("fake_nmap: missing -oX path\n")
        return 2
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    Path(dest).write_bytes(src.read_bytes())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
