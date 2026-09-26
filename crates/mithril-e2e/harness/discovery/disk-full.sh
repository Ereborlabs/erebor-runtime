#!/usr/bin/env bash
set -euo pipefail
if (($# != 2)); then
  echo "usage: $0 E2E_TEST_BINARY OUTPUT_LOG" >&2
  exit 2
fi
[[ $(id -u) == 0 && -x $1 && $2 == /* && ! -e $2 ]] || exit 2
disk=$(mktemp -d /tmp/araphor-data-disk-XXXXXXXX)
mounted=false
cleanup() {
  if [[ $mounted == true ]]; then umount -- "$disk"; fi
  rmdir -- "$disk"
}
trap cleanup EXIT
mount -t tmpfs -o size=1g,nosuid,nodev tmpfs "$disk"
mounted=true
set -o noclobber
{
  git rev-parse HEAD
  git status --short
  uname -srmo
  sha256sum -- "$1"
  "$1" discovery::data_store::tests::data_capacity_recovery --exact --nocapture
  ARAPHOR_TEST_DATA_DISK=$disk "$1" \
    discovery::data_store::tests::data_full_disk --ignored --exact --nocapture
} >"$2" 2>&1
