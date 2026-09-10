import os
import sys
import time


work = sys.argv[1]


def path(name):
    return os.path.join(work, name)


def mark(name, value):
    temp = f"{path(name)}.tmp"
    with open(temp, "x", encoding="ascii") as output:
        output.write(f"{value}\n")
    os.replace(temp, path(name))


def wait(name):
    while not os.path.exists(path(name)):
        time.sleep(0.01)


def child(name, release):
    mark(name, os.getpid())
    wait(release)
    os._exit(0)


print("native-fixture-ready", flush=True)
sys.stdin.readline()

first = os.fork()
if first == 0:
    child("first", "release-first")
os.waitpid(first, 0)

with open("/proc/sys/kernel/ns_last_pid", "w", encoding="ascii") as output:
    output.write(str(first - 1))

second = os.fork()
if second == 0:
    child("second", "release-second")
os.waitpid(second, 0)
