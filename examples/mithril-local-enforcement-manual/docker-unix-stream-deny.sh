#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
enforcement_socket=/tmp/mithril-local-enforcement-$$.sock
enforcement_cleanup_socket() {
  rm -f -- "/proc/$identity_init_pid/root$enforcement_socket"
}
identity_cleanup_functions+=(enforcement_cleanup_socket)
observation_preload_probe python3 -c '
import errno, mmap, os, socket, sys, time
ready, path = sys.argv[1:]
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(path)
listener.listen(1)
release_gate = mmap.mmap(-1, 1)
client = os.fork()
if client == 0:
    listener.close()
    while release_gate[0] == 0:
        time.sleep(0.001)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        try:
            connection.connect(path)
        except OSError as error:
            os._exit(0 if error.errno in (errno.EACCES, errno.EPERM) else 3)
    os._exit(2)
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
release_gate[0] = 1
_pid, status = os.waitpid(client, 0)
release_gate.close()
listener.close()
os.unlink(path)
if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
    raise SystemExit(f"Mithril did not deny Unix-stream connect: wait status {status}")
' "$observation_probe_ready" "$enforcement_socket"
observation_release_probe
observation_wait_for_observation 'reason=EXACT_POLICY_DENY' "$identity_work/effects.txt"
identity_pass "PASS: unmatched Unix-stream connect was denied."
