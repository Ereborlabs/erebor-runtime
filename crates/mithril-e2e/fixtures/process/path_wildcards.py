import json
import os
import sys


if len(sys.argv) == 2:
    mode = "wildcards"
elif len(sys.argv) == 3 and sys.argv[2] == "late":
    mode = "late"
else:
    sys.exit(2)

root = os.path.join(sys.argv[1], "wildcard")
if mode == "wildcards":
    paths = {
        "single": os.path.join(root, "home/alice/secrets/models/secret"),
        "recursive": os.path.join(root, "srv/team/blue/secrets/models/secret"),
        "allowed": os.path.join(root, "allowed/open"),
    }
else:
    paths = {
        "late": os.path.join(root, "srv/team/green/secrets/created-after"),
        "allowed": os.path.join(root, "allowed/open"),
    }
for name, path in paths.items():
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if mode == "late" and name == "late":
        continue
    with open(path, "w", encoding="utf-8") as output:
        output.write("allowed control\n" if path == paths["allowed"] else "secret\n")

print("native-fixture-ready", flush=True)
command = "read\n" if mode == "wildcards" else "create-read\n"
if sys.stdin.readline() != command:
    sys.exit(2)

result = {}
if mode == "late":
    try:
        with open(paths["late"], "w", encoding="utf-8") as output:
            output.write("created after activation\n")
        result["created"] = True
    except OSError as error:
        result["created"] = error.errno
for name, path in paths.items():
    try:
        with open(path, encoding="utf-8") as source:
            result[name] = source.read()
    except OSError as error:
        result[name] = error.errno
with open(os.path.join(sys.argv[1], "wildcard-result.json"), "w", encoding="utf-8") as output:
    json.dump(result, output)
