#!/usr/bin/env bash
set -euo pipefail
if (($# != 4)); then
  echo "usage: $0 TEST_BINARY FIXTURE_ARCHIVE OUTPUT_DIRECTORY QUALIFIED_CONFIG|--test-admission" >&2
  exit 2
fi
test_binary=$1
fixtures=$2
output=$3
config=$4
[[ $(id -u) == 0 && -x $test_binary && -r $fixtures ]] || exit 2
[[ $config == --test-admission || -r $config ]] || exit 2
[[ $output == /* && ! -e $output ]] || exit 2
mkdir -- "$output"
mkdir -- "$output/source"
tar -xzf "$fixtures" -C "$output/source"
export MITHRIL_TEST_ROOT="$output/source"
export MITHRIL_TEST_OUTPUT="$output/lifecycle"
export MITHRIL_TEST_PIN="/sys/fs/bpf/araphor-observability-disk-$$"
export MITHRIL_TEST_LEASE="$output/lease"
export MITHRIL_TEST_CGROUP="/sys/fs/cgroup/araphor-observability-disk-$$"
if [[ $config == --test-admission ]]; then
  export MITHRIL_TRACE_TEST_ADMISSION=1
  export MITHRIL_TRACE_EXECUTABLE=/usr/bin/bpftrace
  unset MITHRIL_TRACE_CONFIG
else
  unset MITHRIL_TRACE_TEST_ADMISSION
  export MITHRIL_TRACE_CONFIG=$config
fi
export MITHRIL_TRACE_PROOF="$output/storage.json"
"$test_binary" observability::tests::observability_owned_upload \
  --exact --nocapture >"$output/lightweight.log" 2>&1
disk=$(mktemp -d /tmp/araphor-observability-disk-XXXXXXXX)
mounted=false
cleanup() {
  if [[ $mounted == true ]]; then umount -- "$disk"; fi
  rmdir -- "$disk"
}
trap cleanup EXIT
mount -t tmpfs -o size=1g,nosuid,nodev tmpfs "$disk"
mounted=true
MITHRIL_TEST_TRACE_DISK=$disk "$1" \
  platform::host::observability_owned_storage \
  --ignored --exact --nocapture >"$output/test.log" 2>&1
[[ -s $MITHRIL_TRACE_PROOF ]]
