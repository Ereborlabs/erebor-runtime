#!/bin/sh

set -eu

fail() {
  echo "Mithril runtime-hook ownership failed: $1" >&2
  exit 1
}

marker_is_owned() {
  marker=$1
  expected_owner=$2
  [ -f "$marker" ] && [ ! -L "$marker" ] &&
    [ "$(cat -- "$marker")" = "$expected_owner" ]
}

require_owned_or_absent() {
  target=$1
  marker=$2
  expected_owner=$3
  if [ -e "$target" ] || [ -L "$target" ] ||
     [ -e "$marker" ] || [ -L "$marker" ]; then
    marker_is_owned "$marker" "$expected_owner" ||
      fail "refusing to replace unowned path $target"
  fi
}

publish_owner() {
  marker=$1
  marker_owner=$2
  temporary=$(mktemp "${marker}.tmp.XXXXXX")
  if ! chmod 0600 "$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  if ! printf '%s\n' "$marker_owner" >"$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  if ! mv -fT -- "$temporary" "$marker"; then
    rm -f -- "$temporary"
    return 1
  fi
}

publish_file() {
  source=$1
  target=$2
  mode=$3
  temporary=$(mktemp "${target}.tmp.XXXXXX")
  if ! install -m "$mode" "$source" "$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  if ! mv -fT -- "$temporary" "$target"; then
    rm -f -- "$temporary"
    return 1
  fi
}

install_hook() {
  hook_owner=$1
  binary_source=$2
  config_source=$3
  binary_directory=$4
  config_directory=$5
  binary_target=$binary_directory/mithril-oci-hook
  binary_marker=$binary_directory/.mithril-oci-hook.helm-owner
  config_target=$config_directory/99-mithril.json
  config_marker=$config_directory/.99-mithril.json.helm-owner

  [ -d "$binary_directory" ] || fail "binary directory does not exist"
  [ -d "$config_directory" ] || fail "hook configuration directory does not exist"
  [ -f "$binary_source" ] || fail "hook binary source does not exist"
  [ -f "$config_source" ] || fail "hook configuration source does not exist"
  require_owned_or_absent "$binary_target" "$binary_marker" "$hook_owner"
  require_owned_or_absent "$config_target" "$config_marker" "$hook_owner"

  # Publish ownership before content. An interrupted first install can retry,
  # but it cannot leave content that a later release can claim as unowned.
  publish_owner "$binary_marker" "$hook_owner"
  publish_owner "$config_marker" "$hook_owner"
  publish_file "$binary_source" "$binary_target" 0755
  publish_file "$config_source" "$config_target" 0644
}

remove_owned() {
  target=$1
  marker=$2
  expected_owner=$3
  marker_is_owned "$marker" "$expected_owner" || return 0
  if [ -e "$target" ] || [ -L "$target" ]; then
    [ ! -d "$target" ] || fail "refusing to remove directory at owned path $target"
    rm -f -- "$target"
  fi
  rm -f -- "$marker"
}

cleanup_hook() {
  hook_owner=$1
  binary_directory=$2
  config_directory=$3
  # Remove the registration first so that the runtime cannot call a missing hook.
  remove_owned "$config_directory/99-mithril.json" \
    "$config_directory/.99-mithril.json.helm-owner" "$hook_owner"
  remove_owned "$binary_directory/mithril-oci-hook" \
    "$binary_directory/.mithril-oci-hook.helm-owner" "$hook_owner"
}

action=${1:-}
owner=${2:-}
case $owner in
  */*) ;;
  *) fail "owner must contain the release namespace and name" ;;
esac

case $action in
  install)
    [ "$#" -eq 6 ] || fail "install requires owner, sources, and target directories"
    install_hook "$owner" "$3" "$4" "$5" "$6"
    ;;
  cleanup)
    [ "$#" -eq 4 ] || fail "cleanup requires owner and target directories"
    cleanup_hook "$owner" "$3" "$4"
    ;;
  cleanup-and-hold)
    [ "$#" -eq 5 ] ||
      fail "cleanup-and-hold requires owner, target directories, and readiness file"
    cleanup_hook "$owner" "$3" "$4"
    printf 'complete\n' >"$5"
    exec sleep 3600
    ;;
  *) fail "action must be install, cleanup, or cleanup-and-hold" ;;
esac
