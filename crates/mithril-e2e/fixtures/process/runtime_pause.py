#!/usr/bin/python3
from pathlib import Path
import sys


if len(sys.argv) > 1:
    (Path(sys.argv[1]) / "started").touch()
print("CRI_SANDBOX_ALLOWED", end="", flush=True)
