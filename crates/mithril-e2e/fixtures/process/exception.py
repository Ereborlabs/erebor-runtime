import json
import os
from pathlib import Path
import sys
import threading


work = Path(sys.argv[1])
mode = sys.argv[2]


def open_errno(path):
    try:
        descriptor = os.open(path, os.O_WRONLY)
        os.close(descriptor)
        return 0
    except OSError as error:
        return error.errno


def write(name, value):
    with (work / name).open("w", encoding="ascii") as output:
        output.write(value)


if mode == "single":
    print("native-fixture-ready", flush=True)
    for command, name in [
        ("before", "expired-result"),
        ("first", "again-result"),
        ("second", "race-result"),
    ]:
        if sys.stdin.readline() != f"{command}\n":
            raise RuntimeError(f"expected {command}")
        write(name, str(open_errno(work / "expired-secret")))
elif mode == "race":
    started = threading.Barrier(9)
    release = threading.Event()
    tids = [0] * 8
    errors = [0] * 8

    def attempt(index):
        tids[index] = threading.get_native_id()
        started.wait()
        release.wait()
        errors[index] = open_errno(work / "bounded-secret")

    threads = [threading.Thread(target=attempt, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    started.wait()
    write("thread-ids", json.dumps(tids))
    print("native-fixture-ready", flush=True)
    if sys.stdin.readline() != "race\n":
        raise RuntimeError("expected race")
    release.set()
    for thread in threads:
        thread.join()
    write("race-result", json.dumps(errors))
    command = sys.stdin.readline()
    if command == "stop\n":
        sys.exit(0)
    if command != "again\n":
        raise RuntimeError("expected again")
    write("again-result", str(open_errno(work / "bounded-secret")))
else:
    print("native-fixture-ready", flush=True)
    if sys.stdin.readline() != "expired\n":
        raise RuntimeError("expected expired")
    write("expired-result", str(open_errno(work / "expired-secret")))

if sys.stdin.readline() not in ("stop\n", ""):
    raise RuntimeError("expected stop")
