#!/usr/bin/env bash
set -euo pipefail

# Acquire both device fds before activation. The signed policy allows the
# exact PTMX request and denies the exact /dev/zero request.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
enforcement_add_device_object /dev/pts/ptmx 13 MANUAL_DEVICE_ALLOWED PTMX_DEVICE
enforcement_add_device_object /dev/zero 14 MANUAL_DEVICE_DENIED ZERO_DEVICE
observation_preload_probe python3 -c '
import errno, fcntl, os, sys
ready = sys.argv[1]
allowed = os.open("/dev/pts/ptmx", os.O_RDWR | os.O_NOCTTY)
denied = os.open("/dev/zero", os.O_RDONLY)
tiocgptn = 2147767344
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
pty_number = bytearray(b"\xff" * 4)
fcntl.ioctl(allowed, tiocgptn, pty_number, True)
if pty_number == bytearray(b"\xff" * 4):
    raise SystemExit("TIOCGPTN returned no PTY number")
try:
    fcntl.ioctl(denied, tiocgptn, bytearray(4), True)
except OSError as error:
    if error.errno not in (errno.EACCES, errno.EPERM):
        raise
else:
    raise SystemExit("Mithril allowed the signed denied device ioctl")
finally:
    os.close(allowed)
    os.close(denied)
' "$observation_probe_ready"
observation_release_probe
observation_wait_for_observation 'reason=EXACT_POLICY_ALLOW' "$identity_work/effects.txt"
enforcement_expect_exact_denial
identity_pass "PASS: exact device policy returned a PTY number and denied the /dev/zero ioctl."
