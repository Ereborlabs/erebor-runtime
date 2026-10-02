from pathlib import Path
import sys


work = Path(sys.argv[1])
(work / "started").touch()
with Path("/host/etc/shadow").open() as target:
    target.readline()
(work / "hostile").touch()
print("native-fixture-ready", flush=True)
