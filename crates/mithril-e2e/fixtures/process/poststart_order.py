import json
import os
import pathlib
import sys
import time


work = pathlib.Path(sys.argv[1])
role = sys.argv[2]
order = sys.argv[3]


def wait_for(name):
    path = work / name
    deadline = time.monotonic() + 30
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"{role} waited for {path}")
        time.sleep(0.01)


if role == "main":
    (work / "ready").write_text("ready")
    print("native-fixture-ready", flush=True)
    if order == "hook-first":
        wait_for("hook.json")
elif role == "hook":
    if order == "actor-first":
        wait_for("main.json")
else:
    raise ValueError(f"unknown role: {role}")

(work / f"{role}.json").write_text(
    json.dumps({"pid": os.getpid(), "at": time.monotonic_ns()})
)
if role == "hook":
    print("native-fixture-ready", flush=True)
if role == "main":
    if sys.stdin.readline().strip() != "stop":
        raise ValueError("main did not get stop")
else:
    wait_for("release")
