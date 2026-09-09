import os
import sys
import threading
import time

work = sys.argv[1]
print("native-fixture-ready", flush=True)
sys.stdin.readline()

def path(name):
    return os.path.join(work, name)

def mark(name, value="ready"):
    temporary = f"{path(name)}.tmp"
    with open(temporary, "x", encoding="ascii") as output:
        output.write(f"{value}\n")
    os.replace(temporary, path(name))

def wait_for(name):
    while not os.path.exists(path(name)):
        time.sleep(0.01)

def process(name, release):
    mark(name, os.getpid())
    wait_for(release)
    os._exit(0)

first = os.fork()
if first == 0:
    process("process-first", "release-process-first")
os.waitpid(first, 0)
with open("/proc/sys/kernel/ns_last_pid", "w", encoding="ascii") as output:
    output.write(str(first - 1))
second = os.fork()
if second == 0:
    process("process-second", "release-process-second")
os.waitpid(second, 0)
mark("processes-done")

thread_ids = []
def worker(name, release):
    thread_ids.append(threading.get_native_id())
    mark(name, thread_ids[-1])
    wait_for(release)

wait_for("start-thread-first")
first_thread = threading.Thread(
    target=worker, args=("thread-first", "release-thread-first"))
first_thread.start()
first_thread.join()
mark("thread-first-done")
wait_for("start-thread-second")
with open("/proc/sys/kernel/ns_last_pid", "w", encoding="ascii") as output:
    output.write(str(thread_ids[0] - 1))
second_thread = threading.Thread(
    target=worker, args=("thread-second", "release-thread-second"))
second_thread.start()
second_thread.join()
mark("complete")

