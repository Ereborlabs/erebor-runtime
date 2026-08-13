#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
observation_preload_probe python3 -c '
import errno, os, sys, threading
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
gate_path = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(gate_path, 0o600)
gate = os.open(gate_path, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(gate, 1)
os.close(gate)
release.set()
for thread in threads:
    thread.join()
allowed = sum(result for result, _error in results)
denied = sum(not result and error in (errno.EACCES, errno.EPERM)
             for result, error in results)
if (allowed, denied, len(results)) != (2, 6, 8):
    raise SystemExit(f"expected exactly two exception uses: {results}")
' "$observation_probe_ready" "$3"
observation_release_probe
observation_wait_for_observation 'reason=EXACT_POLICY_ALLOW' "$identity_work/effects.txt"
observation_wait_for_observation 'reason=EXCEPTION_UNAVAILABLE' "$identity_work/effects.txt"
[[ $(grep -c 'reason=EXACT_POLICY_ALLOW' "$identity_work/effects.txt") -eq 2 ]]
[[ $(grep -c 'reason=EXCEPTION_UNAVAILABLE' "$identity_work/effects.txt") -eq 6 ]]
identity_pass "PASS: eight concurrent consumers received exactly N=2 bounded write-open uses."
