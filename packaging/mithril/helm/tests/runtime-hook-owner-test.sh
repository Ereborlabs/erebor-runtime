#!/usr/bin/env bash

set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
owner_script=$directory/../files/runtime-hook-owner.sh
test_root=$(mktemp -d /tmp/mithril-runtime-hook-owner.XXXXXX)
trap 'rm -rf -- "$test_root"' EXIT

binary_source=$test_root/mithril-oci-hook
create_config_source=$test_root/98-mithril-create-container.json
prestart_config_source=$test_root/99-mithril-prestart.json
binary_directory=$test_root/bin
config_directory=$test_root/hooks
owner=mithril-system/mithril
mkdir "$binary_directory" "$config_directory"
printf 'binary-v1\n' >"$binary_source"
printf '{"create":1}\n' >"$create_config_source"
printf '{"prestart":1}\n' >"$prestart_config_source"
printf 'legacy-binary\n' >"$binary_directory/mithril-oci-hook"
printf '%s\n' "$owner" >"$binary_directory/.mithril-oci-hook.helm-owner"
printf '{"create":0}\n' >"$config_directory/98-mithril-create-container.json"
printf '%s\n' "$owner" \
  >"$config_directory/.98-mithril-create-container.json.helm-owner"
printf '{"prestart":0}\n' >"$config_directory/99-mithril-prestart.json"
printf '%s\n' "$owner" \
  >"$config_directory/.99-mithril-prestart.json.helm-owner"
printf '{"legacy":1}\n' >"$config_directory/99-mithril.json"
printf '%s\n' "$owner" >"$config_directory/.99-mithril.json.helm-owner"

run_owner() {
  /bin/sh "$owner_script" "$@"
}

install_owned_hook() {
  run_owner install "$owner" "$binary_source" "$create_config_source" \
    "$prestart_config_source" "$binary_directory" "$config_directory"
}

assert_configs_absent() {
  [[ ! -e $config_directory/98-mithril-create-container.json ]]
  [[ ! -e $binary_directory/.98-mithril-create-container.json.helm-owner ]]
  [[ ! -e $config_directory/99-mithril-prestart.json ]]
  [[ ! -e $binary_directory/.99-mithril-prestart.json.helm-owner ]]
}

install_owned_hook
cmp "$binary_source" "$binary_directory/mithril-oci-hook"
cmp "$create_config_source" "$config_directory/98-mithril-create-container.json"
cmp "$prestart_config_source" "$config_directory/99-mithril-prestart.json"
[[ $(<"$binary_directory/.mithril-oci-hook.helm-owner") == "$owner" ]]
[[ $(<"$binary_directory/.98-mithril-create-container.json.helm-owner") == "$owner" ]]
[[ $(<"$binary_directory/.99-mithril-prestart.json.helm-owner") == "$owner" ]]
[[ ! -e $config_directory/.98-mithril-create-container.json.helm-owner ]]
[[ ! -e $config_directory/.99-mithril-prestart.json.helm-owner ]]
[[ $(stat -c %a "$binary_directory/mithril-oci-hook") == 755 ]]
[[ $(stat -c %a "$config_directory/98-mithril-create-container.json") == 644 ]]
[[ $(stat -c %a "$config_directory/99-mithril-prestart.json") == 644 ]]
[[ ! -e $config_directory/99-mithril.json ]]
[[ ! -e $binary_directory/.99-mithril.json.helm-owner ]]

printf 'binary-v2\n' >"$binary_source"
printf '{"create":2}\n' >"$create_config_source"
printf '{"prestart":2}\n' >"$prestart_config_source"
install_owned_hook
cmp "$binary_source" "$binary_directory/mithril-oci-hook"
cmp "$create_config_source" "$config_directory/98-mithril-create-container.json"
cmp "$prestart_config_source" "$config_directory/99-mithril-prestart.json"
[[ -z $(find "$binary_directory" "$config_directory" -name '*.tmp.*' -print -quit) ]]

run_owner cleanup "$owner" "$binary_directory" "$config_directory"
[[ ! -e $binary_directory/mithril-oci-hook ]]
[[ ! -e $binary_directory/.mithril-oci-hook.helm-owner ]]
assert_configs_absent
run_owner cleanup "$owner" "$binary_directory" "$config_directory"

legacy_binary_directory=$test_root/legacy-bin
mkdir "$legacy_binary_directory"
printf 'legacy-binary\n' >"$legacy_binary_directory/mithril-oci-hook"
printf '%s\n' "$owner" \
  >"$legacy_binary_directory/.mithril-oci-hook.helm-owner"
printf '{"create":0}\n' >"$config_directory/98-mithril-create-container.json"
printf '%s\n' "$owner" \
  >"$legacy_binary_directory/.98-mithril-create-container.json.helm-owner"
printf '{"prestart":0}\n' >"$config_directory/99-mithril-prestart.json"
printf '%s\n' "$owner" \
  >"$legacy_binary_directory/.99-mithril-prestart.json.helm-owner"
run_owner install "$owner" "$binary_source" "$create_config_source" \
  "$prestart_config_source" "$binary_directory" "$config_directory" \
  "$legacy_binary_directory"
[[ ! -e $legacy_binary_directory/mithril-oci-hook ]]
[[ ! -e $legacy_binary_directory/.mithril-oci-hook.helm-owner ]]
cmp "$create_config_source" "$config_directory/98-mithril-create-container.json"
cmp "$prestart_config_source" "$config_directory/99-mithril-prestart.json"
run_owner cleanup "$owner" "$binary_directory" "$config_directory" \
  "$legacy_binary_directory"
assert_configs_absent

install_owned_hook

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
assert_configs_absent

install_owned_hook
printf 'another-system/another-release\n' \
  >"$binary_directory/.mithril-oci-hook.helm-owner"
run_owner cleanup "$owner" "$binary_directory" "$config_directory"
[[ -e $binary_directory/mithril-oci-hook ]]
[[ -e $binary_directory/.mithril-oci-hook.helm-owner ]]
assert_configs_absent
run_owner cleanup another-system/another-release \
  "$binary_directory" "$config_directory"
[[ ! -e $binary_directory/mithril-oci-hook ]]

printf 'operator-owned\n' >"$config_directory/98-mithril-create-container.json"
if install_owned_hook >/dev/null 2>&1; then
  echo "runtime-hook owner replaced an unowned hook file" >&2
  exit 1
fi
[[ $(<"$config_directory/98-mithril-create-container.json") == operator-owned ]]
[[ ! -e $binary_directory/mithril-oci-hook ]]
[[ ! -e $binary_directory/.mithril-oci-hook.helm-owner ]]
run_owner cleanup "$owner" "$binary_directory" "$config_directory"
[[ $(<"$config_directory/98-mithril-create-container.json") == operator-owned ]]
rm "$config_directory/98-mithril-create-container.json"

install_owned_hook
run_owner cleanup "$owner" "$binary_directory" "$config_directory"

echo "Runtime-hook ownership behavior checks passed"
