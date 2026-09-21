import os
from pathlib import Path
import sys
import threading

count = int(sys.argv[2])
state = Path(sys.argv[1], "churn-state")
state.write_text("waiting\n", encoding="ascii")
print("native-fixture-ready", flush=True)
stage = "command"
try:
    command = sys.stdin.readline()
    state.write_text(f"command:{command!r}\n", encoding="ascii")
    if command != "churn\n":
        raise RuntimeError("expected churn")
    for index in range(count):
        stage = str(index)
        thread = threading.Thread(target=lambda: None)
        thread.start()
        thread.join()
    state.write_text("threads-complete\n", encoding="ascii")
except BaseException as error:
    state.write_text(f"error:{stage}:{type(error).__name__}:{error}\n", encoding="ascii")
    Path(sys.argv[1], "churn").write_text(
        f"error:{stage}:{type(error).__name__}:{error}\n", encoding="ascii"
    )
    raise

Path(sys.argv[1], "churn").write_text(f"ok:{os.getpid()}\n", encoding="ascii")
if sys.stdin.readline() not in ("stop\n", ""):
    raise RuntimeError("expected stop")
