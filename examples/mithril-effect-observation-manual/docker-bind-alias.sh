#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/observation-runtime.sh"
[[ $# -eq 4 ]] || {
  echo "usage: sudo $0 <node.json> <container> <mounted-secret-path> <alias-directory>" >&2
  exit 2
}

identity_prepare_docker "$1" "$2"
identity_require_command nsenter
observation_bind_secret=$3
observation_bind_original=$(dirname -- "$observation_bind_secret")
observation_bind_name=${observation_bind_secret##*/}
observation_bind_alias=$4
[[ $observation_bind_secret == /* && $observation_bind_alias == /* ]] || {
  echo "secret and alias paths must be absolute" >&2
  exit 2
}

observation_cleanup_bind_alias() {
  nsenter -t "$identity_init_pid" -m -r -- umount "$observation_bind_alias" 2>/dev/null || true
  rmdir -- "/proc/$identity_init_pid/root$observation_bind_alias" 2>/dev/null || true
}
identity_cleanup_functions+=(observation_cleanup_bind_alias)

nsenter -t "$identity_init_pid" -m -r -- sh -c '
  mkdir -p "$2"
  mount --bind "$1" "$2"
' sh "$observation_bind_original" "$observation_bind_alias"

observation_configure_secret "$observation_bind_secret"
observation_preload_probe python3 -c '
import os, sys
ready, alias = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
with open(alias, "rb") as source:
    source.read(1)
' "$observation_probe_ready" "$observation_bind_alias/$observation_bind_name"
observation_release_probe
observation_wait_for_observation 'reason=WOULD_DENY' "$identity_work/effects.txt"
grep -q 'result=UNKNOWN_AFTER_PRE_EFFECT' "$identity_work/effects.txt"
identity_pass "PASS: the later bind alias canonicalized to the original tracked mount and simulated denial."
