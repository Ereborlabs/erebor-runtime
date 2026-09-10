import os
import sys
import threading
import time


work = sys.argv[1]
first_tid = None


def path(name):
    return os.path.join(work, name)


def mark(name, value="ready"):
    temp = f"{path(name)}.tmp"
    with open(temp, "x", encoding="ascii") as output:
        output.write(f"{value}\n")
    os.replace(temp, path(name))


def wait(name):
    while not os.path.exists(path(name)):
        time.sleep(0.01)


def worker(name, release):
    global first_tid
    tid = threading.get_native_id()
    if first_tid is None:
        first_tid = tid
    mark(name, tid)
    wait(release)


print("native-fixture-ready", flush=True)
sys.stdin.readline()

first = threading.Thread(target=worker, args=("first", "release-first"))
first.start()
first.join()
mark("first-done")

sys.stdin.readline()
with open("/proc/sys/kernel/ns_last_pid", "w", encoding="ascii") as output:
    output.write(str(first_tid - 1))

second = threading.Thread(target=worker, args=("second", "release-second"))
second.start()
second.join()
