import os
import sys
import threading

ready = sys.argv[1]
print("native-fixture-ready", flush=True)
sys.stdin.readline()
release = threading.Event()
started = threading.Barrier(3)
racing = threading.Barrier(2)
thread_ids = []
thread_ids_lock = threading.Lock()

def execute():
    with thread_ids_lock:
        thread_ids.append(threading.get_native_id())
    started.wait()
    release.wait()
    racing.wait()
    os.execv("/bin/sleep", ["/bin/sleep", "300"])

first = threading.Thread(target=execute)
second = threading.Thread(target=execute)
first.start()
second.start()
started.wait()
temporary = f"{ready}.tmp"
with open(temporary, "x", encoding="ascii") as output:
    output.write("\n".join(str(thread_id) for thread_id in thread_ids))
    output.write("\n")
os.replace(temporary, ready)
sys.stdin.readline()
release.set()
first.join()
second.join()

