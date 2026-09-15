import shutil
import sys
from pathlib import Path


work = Path(sys.argv[1])
target = work / "bin/python-runtime"
shutil.copy2(Path(sys.executable).resolve(), target)
print("native-fixture-ready", flush=True)
if sys.stdin.readline() not in ("stop\n", ""):
    raise RuntimeError("expected stop")
