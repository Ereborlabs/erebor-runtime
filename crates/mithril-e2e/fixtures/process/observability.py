import errno
import ctypes
import os
import sys
import time

work = sys.argv[1]
sample_count = 5_000
libc = ctypes.CDLL(None, use_errno=True)
print("native-fixture-ready", flush=True)
for run in range(10):
    while not os.path.exists(f"{work}/trace-run-{run}"):
        time.sleep(0.01)
    samples = []
    denied = 0
    for _ in range(sample_count):
        start = time.perf_counter_ns()
        try:
            fd = os.open("/fixtures/policy_replace.py", os.O_RDONLY)
        except OSError as error:
            denied += error.errno == errno.EACCES
        else:
            os.close(fd)
        samples.append(time.perf_counter_ns() - start)
        time.sleep(0.001)
    if denied != sample_count:
        raise RuntimeError("physical denial decisions changed")
    samples.sort()
    p99 = samples[(99 * len(samples) + 99) // 100 - 1]
    name = f"tr{run}:{p99}".encode("ascii")
    if len(name) > 15 or libc.prctl(15, ctypes.c_char_p(name), 0, 0, 0) != 0:
        raise RuntimeError("cannot publish latency through task status")
while not os.path.exists(f"{work}/release"):
    time.sleep(0.01)
