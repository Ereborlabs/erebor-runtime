#!/usr/bin/python3
import json
from pathlib import Path
import sys


if sys.argv[1] == "install":
    Path("/result/installer").write_text("INSTALLER_ALLOWED")
else:
    Path(sys.argv[1]).write_text(sys.argv[2])
print(json.dumps(sys.argv), end="", flush=True)
