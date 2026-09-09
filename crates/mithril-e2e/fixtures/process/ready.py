import sys

print("native-fixture-ready", flush=True)
if sys.stdin.readline() != "stop\n":
    raise RuntimeError("expected stop")
