import os
import sys
import threading

ready = sys.argv[1]
release = threading.Event()
print("native-fixture-ready", flush=True)
sys.stdin.readline()

def execute():
    with open(ready, "x", encoding="ascii") as output:
        output.write(f"{threading.get_native_id()}\n")
    release.wait()
    os.execv("/bin/sleep", ["/bin/sleep", "300"])

thread = threading.Thread(target=execute)
thread.start()
sys.stdin.readline()
release.set()
thread.join()

