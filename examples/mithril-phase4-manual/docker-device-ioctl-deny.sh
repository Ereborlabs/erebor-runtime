#!/usr/bin/env bash
set -euo pipefail

# Acquire the device fd before activation, then exercise ioctl under the
# current protected actor. ENOTTY is not accepted; the result must be EACCES.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase3_preload_probe python3 -c '
import errno, fcntl, os, signal, sys, termios
ready = sys.argv[1]
descriptor = os.open("/dev/null", os.O_RDONLY)
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
try:
    fcntl.ioctl(descriptor, termios.FIONREAD, bytearray(4))
except PermissionError as error:
    denied = error.errno in (errno.EACCES, errno.EPERM)
else:
    denied = False
os.close(descriptor)
if denied:
    raise SystemExit(0)
raise SystemExit("Mithril did not deny the inherited device ioctl")
' "$phase3_probe_ready"
phase3_release_probe
phase4_expect_hard_close UNSUPPORTED_OBJECT
phase2_pass "PASS: a device fd acquired before activation could not issue ioctl."
