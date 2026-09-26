import json
import os
import pathlib
import sys


work = pathlib.Path(sys.argv[1])
print("native-fixture-ready", flush=True)
for index, line in enumerate(sys.stdin):
    error, size = 0, 0
    try:
        with open(line.strip(), "rb") as source:
            size = len(source.read())
    except OSError as failure:
        error = failure.errno
    temporary = work / "read.tmp"
    temporary.write_text(json.dumps([error, size]))
    os.replace(temporary, work / f"{index}.json")
