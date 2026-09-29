import os
from pathlib import Path
import sys
import time


work = Path(sys.argv[1])
release = work / f"{os.environ['MITHRIL_PROBE_SLOT']}.release"
deadline = time.monotonic() + 60
while not release.exists():
    if time.monotonic() >= deadline:
        raise TimeoutError(f"probe waited for {release}")
    time.sleep(0.01)
