#!/usr/bin/env bash
set -euo pipefail

if (($# < 4 || $# > 5)); then
  echo "usage: $0 TEST_BINARY FIXTURE_ARCHIVE OUTPUT_DIRECTORY MAX_OVERHEAD_BP [QUALIFIED_CONFIG]" >&2
  exit 2
fi
test_binary=$1
fixtures=$2
output=$3
limit=$4
[[ $(id -u) == 0 && -x $test_binary && -r $fixtures && $output == /* && ! -e $output ]] || exit 2
[[ $limit =~ ^[1-9][0-9]*$ ]] || exit 2
mkdir -- "$output"
mkdir -- "$output/source"
tar -xzf "$fixtures" -C "$output/source"
export MITHRIL_TEST_ROOT="$output/source"
export MITHRIL_TEST_OUTPUT="$output/lifecycle"
export MITHRIL_TEST_PIN="/sys/fs/bpf/araphor-observability-owned-$$"
export MITHRIL_TEST_LEASE="$output/lease"
export MITHRIL_TEST_CGROUP="/sys/fs/cgroup/araphor-observability-owned-$$"
export MITHRIL_TRACE_EXECUTABLE=/usr/bin/bpftrace
export MITHRIL_TRACE_PROOF="$output/capture-pairs.json"
export MITHRIL_TRACE_MAX_OVERHEAD_BP=$limit
test_name=platform::host::observability_owned_capture_five_pairs
if (($# == 5)); then
  [[ -r $5 ]] || exit 2
  export MITHRIL_TRACE_CONFIG=$5
  test_name=platform::host::observability_owned_capture_failures
fi
"$test_binary" "$test_name" --ignored --exact --nocapture \
  >"$output/test.log" 2>&1
