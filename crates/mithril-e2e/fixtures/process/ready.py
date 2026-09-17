from pathlib import Path
import signal
import sys

signal.signal(signal.SIGCHLD, signal.SIG_IGN)
if len(sys.argv) > 1:
    Path(sys.argv[1], "ready").touch()
print("native-fixture-ready", flush=True)
if sys.stdin.readline() not in ("stop\n", ""):
    raise RuntimeError("expected stop")
