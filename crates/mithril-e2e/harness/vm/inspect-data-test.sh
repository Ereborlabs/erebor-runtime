#!/usr/bin/env bash

set -euo pipefail

[[ $(id -u) == 0 ]] || {
  echo "the isolated inspection permission test requires root" >&2
  exit 2
}
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
test_root=$(mktemp -d /tmp/mithril-inspection-test.XXXXXX)
cleanup() {
  local status=$?
  trap - EXIT
  if mountpoint -q "$test_root/checker/data"; then
    echo "inspection left a mount; test files remain at $test_root" >&2
    exit 1
  fi
  rm -rf -- "$test_root"
  exit "$status"
}
trap cleanup EXIT
chmod 755 "$test_root"
install -d -m 700 "$test_root/private"
install -d -m 700 -o 65532 -g 65532 "$test_root/private/analysis"
install -d -m 755 "$test_root/checker" "$test_root/checker/data"
install -d -m 700 -o 65532 -g 65532 "$test_root/checker/results"
install -m 755 /bin/sh "$test_root/checker/check"
install -m 600 -o 65532 -g 65532 /dev/null "$test_root/private/analysis/evidence"
if setpriv --reuid=65532 --regid=65532 --clear-groups -- \
    test -r "$test_root/private/analysis/evidence"; then
  echo "the fixture does not reproduce the private parent" >&2
  exit 1
fi
bash "$directory/inspect-data.sh" "$test_root/private/analysis" \
  "$test_root/checker" -ec '
    test "$(id -u)" = 65532
    test "$(id -g)" = 65532
    test -r "$1/data/evidence"
    test ! -r "$2/evidence"
    : >"$1/data/probe"
    : >"$1/results/proof"
  ' check "$test_root/checker" "$test_root/private/analysis"
[[ $(stat -c '%u:%g' "$test_root/private/analysis/probe") == 65532:65532 ]]
[[ $(stat -c '%a:%u:%g' "$test_root/private") == 700:0:0 ]]
[[ -f $test_root/checker/results/proof && ! -e $test_root/checker/data/probe ]]
status=0
bash "$directory/inspect-data.sh" "$test_root/private/analysis" \
  "$test_root/checker" -c 'exit 23' || status=$?
[[ $status -eq 23 ]]
! mountpoint -q "$test_root/checker/data"
echo "Isolated non-root inspection checks passed"
