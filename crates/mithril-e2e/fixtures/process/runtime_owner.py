#!/usr/bin/python3
import json
from pathlib import Path
import sys


Path(sys.argv[1]).write_text(sys.argv[2])
print(json.dumps(sys.argv), end="", flush=True)
