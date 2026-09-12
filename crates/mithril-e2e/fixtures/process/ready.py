import sys

print("native-fixture-ready", flush=True)
if sys.stdin.readline() not in ("stop\n", ""):
    raise RuntimeError("expected stop")
