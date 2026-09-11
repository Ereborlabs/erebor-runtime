import os
import sys
import threading

target = sys.argv[1]
ready = os.path.join(target, "thread") if os.path.isdir(target) else target
release = threading.Event()
print("native-fixture-ready", flush=True)
sys.stdin.readline()

def execute():
    with open(ready, "x", encoding="ascii") as output:
        output.write(f"{threading.get_native_id()}\n")
    release.wait()
    os.execv("/usr/bin/sleep", ["/usr/bin/sleep", "300"])

thread = threading.Thread(target=execute)
thread.start()
sys.stdin.readline()
release.set()
thread.join()
