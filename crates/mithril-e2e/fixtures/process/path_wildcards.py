import json
import os
import sys


if len(sys.argv) == 2:
    mode = "wildcards"
elif len(sys.argv) == 3 and sys.argv[2] in ("late", "replace"):
    mode = sys.argv[2]
else:
    sys.exit(2)

root = os.path.join(sys.argv[1], "wildcard")
if mode == "wildcards":
    paths = {
        "single": os.path.join(root, "home/alice/secrets/models/secret"),
        "recursive": os.path.join(root, "srv/team/blue/secrets/models/secret"),
        "allowed": os.path.join(root, "allowed/open"),
    }
elif mode == "late":
    paths = {
        "late": os.path.join(root, "srv/team/green/secrets/created-after"),
        "allowed": os.path.join(root, "allowed/open"),
    }
else:
    paths = {
        "replacement": os.path.join(root, "srv/team/red/secrets/replacement"),
        "allowed": os.path.join(root, "allowed/open"),
    }
for name, path in paths.items():
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if mode == "late" and name == "late":
        continue
    with open(path, "w", encoding="utf-8") as output:
        output.write("allowed control\n" if path == paths["allowed"] else "secret\n")

print("native-fixture-ready", flush=True)
command = {
    "wildcards": "read\n",
    "late": "create-read\n",
    "replace": "replace-read\n",
}[mode]
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
elif mode == "replace":
    try:
        with open(paths["replacement"], encoding="utf-8") as source:
            result["initial"] = source.read()
    except OSError as error:
        result["initial"] = error.errno
    try:
        os.remove(paths["replacement"])
        result["removed"] = True
    except OSError as error:
        result["removed"] = error.errno
    try:
        with open(paths["replacement"], "w", encoding="utf-8") as output:
            output.write("replacement object\n")
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
