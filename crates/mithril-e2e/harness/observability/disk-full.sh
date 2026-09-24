#!/usr/bin/env bash
set -euo pipefail
if (($# != 2)); then
  echo "usage: $0 NODE_TEST_BINARY OUTPUT_LOG" >&2
  exit 2
fi
[[ $(id -u) == 0 && -x $1 && $2 == /* && ! -e $2 ]] || exit 2
disk=$(mktemp -d /tmp/araphor-observability-disk-XXXXXXXX)
mounted=false
cleanup() {
  if [[ $mounted == true ]]; then umount -- "$disk"; fi
  rmdir -- "$disk"
}
trap cleanup EXIT
mount -t tmpfs -o size=384m,nosuid,nodev tmpfs "$disk"
mounted=true
MITHRIL_TEST_TRACE_DISK=$disk "$1" \
  observability::tests::observability_recovery_disk_full_retains_unacknowledged_terminal \
  --ignored --exact --nocapture >"$2" 2>&1
