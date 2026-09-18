import json
import os
import sys


if len(sys.argv) == 2:
    mode = "wildcards"
elif len(sys.argv) == 3 and sys.argv[2] in (
    "late",
    "replace",
    "deny-create",
    "max-depth",
):
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
elif mode == "replace":
    paths = {
        "replacement": os.path.join(root, "srv/team/red/secrets/replacement"),
        "allowed": os.path.join(root, "allowed/open"),
    }
elif mode == "deny-create":
    paths = {
        "create": os.path.join(root, "create-denied/actor-created"),
        "allowed": os.path.join(root, "allowed/open"),
    }
else:
    floor = os.path.join(root, *(f"d{index}" for index in range(2, 254)))
    paths = {
        "depth": os.path.join(floor, "pre-existing"),
        "allowed": os.path.join(root, "allowed/open"),
    }
for name, path in paths.items():
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if (mode, name) in (("late", "late"), ("deny-create", "create")):
        continue
    with open(path, "w", encoding="utf-8") as output:
        output.write("allowed control\n" if path == paths["allowed"] else "secret\n")

print("native-fixture-ready", flush=True)
command = {
    "wildcards": "read\n",
    "late": "create-read\n",
    "replace": "replace-read\n",
    "deny-create": "create\n",
    "max-depth": "read\n",
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
elif mode == "deny-create":
    try:
        with open(paths["create"], "w", encoding="utf-8") as output:
            output.write("forbidden child\n")
        result["created"] = True
    except OSError as error:
        result["created"] = error.errno
elif mode == "max-depth":
    result["floor_components"] = len([part for part in floor.split(os.sep) if part])
    result["components"] = len(
        [part for part in paths["depth"].split(os.sep) if part]
    )
for name, path in paths.items():
    if mode == "deny-create" and name == "create":
        continue
    try:
        with open(path, encoding="utf-8") as source:
            result[name] = source.read()
    except OSError as error:
        result[name] = error.errno
with open(os.path.join(sys.argv[1], "wildcard-result.json"), "w", encoding="utf-8") as output:
    json.dump(result, output)
