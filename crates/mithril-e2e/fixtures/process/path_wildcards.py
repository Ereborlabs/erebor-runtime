import json
import os
import sys


root = os.path.join(sys.argv[1], "wildcard")
paths = {
    "single": os.path.join(root, "home/alice/secrets/models/secret"),
    "recursive": os.path.join(root, "srv/team/blue/secrets/models/secret"),
    "allowed": os.path.join(root, "allowed/open"),
}
for path in paths.values():
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as output:
        output.write("allowed control\n" if path == paths["allowed"] else "secret\n")

print("native-fixture-ready", flush=True)
if sys.stdin.readline() != "read\n":
    sys.exit(2)

result = {}
for name, path in paths.items():
    try:
        with open(path, encoding="utf-8") as source:
            result[name] = source.read()
    except OSError as error:
        result[name] = error.errno
with open(os.path.join(sys.argv[1], "wildcard-result.json"), "w", encoding="utf-8") as output:
    json.dump(result, output)
