from pathlib import Path
import sys

if len(sys.argv) > 1:
    Path(sys.argv[1], "ready").touch()
print("native-fixture-ready", flush=True)
if sys.stdin.readline() not in ("stop\n", ""):
    raise RuntimeError("expected stop")
