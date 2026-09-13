import shutil
import sys
from pathlib import Path


work = Path(sys.argv[1])
if len(sys.argv) == 2:
    shutil.copy2(Path(sys.executable).resolve(), work / "python-external")
print("native-fixture-ready", flush=True)
if sys.stdin.readline() not in ("stop\n", ""):
    raise RuntimeError("expected stop")
