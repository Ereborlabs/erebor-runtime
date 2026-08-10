#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase3_preload_probe python3 -c '
import errno, os, signal, sys, threading
ready, path = sys.argv[1:]
barrier = threading.Barrier(9)
release = threading.Event()
results = []
def acquire_write_fd():
    barrier.wait()
    release.wait()
    try:
        descriptor = os.open(path, os.O_WRONLY)
    except PermissionError as error:
        results.append((False, error.errno))
    else:
        os.close(descriptor)
        results.append((True, None))
threads = [threading.Thread(target=acquire_write_fd) for _ in range(8)]
for thread in threads:
    thread.start()
barrier.wait()
signal.signal(signal.SIGUSR1, lambda _signum, _frame: release.set())
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
for thread in threads:
    thread.join()
allowed = sum(result for result, _error in results)
denied = sum(not result and error in (errno.EACCES, errno.EPERM)
             for result, error in results)
if (allowed, denied, len(results)) != (2, 6, 8):
    raise SystemExit(f"expected exactly two exception uses: {results}")
' "$phase3_probe_ready" "$3"
phase3_release_probe
phase3_wait_for_observation 'reason=EXACT_POLICY_ALLOW' "$phase2_work/effects.txt"
phase3_wait_for_observation 'reason=EXCEPTION_UNAVAILABLE' "$phase2_work/effects.txt"
[[ $(grep -c 'reason=EXACT_POLICY_ALLOW' "$phase2_work/effects.txt") -eq 2 ]]
[[ $(grep -c 'reason=EXCEPTION_UNAVAILABLE' "$phase2_work/effects.txt") -eq 6 ]]
phase2_pass "PASS: eight concurrent consumers received exactly N=2 bounded write-open uses."
