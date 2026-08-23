#!/usr/bin/env bash

set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
owner_script=$directory/../files/runtime-hook-owner.sh
test_root=$(mktemp -d /tmp/mithril-runtime-hook-owner.XXXXXX)
trap 'rm -rf -- "$test_root"' EXIT

binary_source=$test_root/mithril-oci-hook
config_source=$test_root/99-mithril.json
binary_directory=$test_root/bin
config_directory=$test_root/hooks
owner=mithril-system/mithril
mkdir "$binary_directory" "$config_directory"
printf 'binary-v1\n' >"$binary_source"
printf '{"version":1}\n' >"$config_source"

run_owner() {
  /bin/sh "$owner_script" "$@"
}

run_owner install "$owner" "$binary_source" "$config_source" \
  "$binary_directory" "$config_directory"
cmp "$binary_source" "$binary_directory/mithril-oci-hook"
cmp "$config_source" "$config_directory/99-mithril.json"
[[ $(<"$binary_directory/.mithril-oci-hook.helm-owner") == "$owner" ]]
[[ $(<"$config_directory/.99-mithril.json.helm-owner") == "$owner" ]]
[[ $(stat -c %a "$binary_directory/mithril-oci-hook") == 755 ]]
[[ $(stat -c %a "$config_directory/99-mithril.json") == 644 ]]

printf 'binary-v2\n' >"$binary_source"
printf '{"version":2}\n' >"$config_source"
run_owner install "$owner" "$binary_source" "$config_source" \
  "$binary_directory" "$config_directory"
cmp "$binary_source" "$binary_directory/mithril-oci-hook"
cmp "$config_source" "$config_directory/99-mithril.json"
[[ -z $(find "$binary_directory" "$config_directory" -name '*.tmp.*' -print -quit) ]]

run_owner cleanup "$owner" "$binary_directory" "$config_directory"
[[ ! -e $binary_directory/mithril-oci-hook ]]
[[ ! -e $binary_directory/.mithril-oci-hook.helm-owner ]]
[[ ! -e $config_directory/99-mithril.json ]]
[[ ! -e $config_directory/.99-mithril.json.helm-owner ]]
run_owner cleanup "$owner" "$binary_directory" "$config_directory"

run_owner install "$owner" "$binary_source" "$config_source" \
  "$binary_directory" "$config_directory"

# The uninstall action removes owned files before it waits for Helm.
completion_file=$test_root/cleanup-complete
set +e
timeout 1s /bin/sh "$owner_script" cleanup-and-hold "$owner" \
  "$binary_directory" "$config_directory" "$completion_file"
status=$?
set -e
[[ $status == 124 ]]
[[ -f $completion_file ]]
[[ ! -e $binary_directory/mithril-oci-hook ]]
[[ ! -e $binary_directory/.mithril-oci-hook.helm-owner ]]
[[ ! -e $config_directory/99-mithril.json ]]
[[ ! -e $config_directory/.99-mithril.json.helm-owner ]]

run_owner install "$owner" "$binary_source" "$config_source" \
  "$binary_directory" "$config_directory"
printf 'another-system/another-release\n' \
  >"$binary_directory/.mithril-oci-hook.helm-owner"
run_owner cleanup "$owner" "$binary_directory" "$config_directory"
[[ -e $binary_directory/mithril-oci-hook ]]
[[ -e $binary_directory/.mithril-oci-hook.helm-owner ]]
[[ ! -e $config_directory/99-mithril.json ]]
run_owner cleanup another-system/another-release \
  "$binary_directory" "$config_directory"
[[ ! -e $binary_directory/mithril-oci-hook ]]

printf 'operator-owned\n' >"$config_directory/99-mithril.json"
if run_owner install "$owner" "$binary_source" "$config_source" \
    "$binary_directory" "$config_directory" >/dev/null 2>&1; then
  echo "runtime-hook owner replaced an unowned hook file" >&2
  exit 1
fi
[[ $(<"$config_directory/99-mithril.json") == operator-owned ]]
[[ ! -e $binary_directory/mithril-oci-hook ]]
[[ ! -e $binary_directory/.mithril-oci-hook.helm-owner ]]
run_owner cleanup "$owner" "$binary_directory" "$config_directory"
[[ $(<"$config_directory/99-mithril.json") == operator-owned ]]
rm "$config_directory/99-mithril.json"

run_owner install "$owner" "$binary_source" "$config_source" \
  "$binary_directory" "$config_directory"
run_owner cleanup "$owner" "$binary_directory" "$config_directory"

echo "Runtime-hook ownership behavior checks passed"
