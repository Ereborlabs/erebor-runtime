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

migrate_owned_marker() {
  [ -e "$1" ] || [ -L "$1" ] || return 0
  marker_is_owned "$1" "$3" ||
    fail "refusing to migrate unowned marker $1"
  if [ -e "$2" ] || [ -L "$2" ]; then
    marker_is_owned "$2" "$3" ||
      fail "refusing to replace unowned marker $2"
  else
    publish_owner "$2" "$3"
  fi
  rm -f -- "$1"
}

publish_file() {
  source=$1
  target=$2
  mode=$3
  staging_directory=${4:-${target%/*}}
  temporary=$(mktemp "$staging_directory/.mithril-runtime-hook.tmp.XXXXXX")
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
  stage_config_source=$3
  admission_config_source=$4
  entry_config_source=$5
  binary_directory=$6
  config_directory=$7
  legacy_binary_directory=${8:-}
  binary_target=$binary_directory/mithril-oci-hook
  binary_marker=$binary_directory/.mithril-oci-hook.helm-owner
  stage_config_target=$config_directory/98-mithril-runtime-stage.json
  stage_config_marker=$binary_directory/.98-mithril-runtime-stage.json.helm-owner
  admission_config_target=$config_directory/99-mithril-runtime-admission.json
  admission_config_marker=$binary_directory/.99-mithril-runtime-admission.json.helm-owner
  entry_config_target=$config_directory/99-mithril-runtime-entry-preparation.json
  entry_config_marker=$binary_directory/.99-mithril-runtime-entry-preparation.json.helm-owner
  old_create_config_target=$config_directory/98-mithril-create-container.json
  old_create_config_marker=$binary_directory/.98-mithril-create-container.json.helm-owner
  old_prestart_config_target=$config_directory/99-mithril-prestart.json
  old_prestart_config_marker=$binary_directory/.99-mithril-prestart.json.helm-owner
  legacy_config_target=$config_directory/99-mithril.json
  legacy_config_marker=$binary_directory/.99-mithril.json.helm-owner

  [ -d "$binary_directory" ] || fail "binary directory does not exist"
  [ -d "$config_directory" ] || fail "hook configuration directory does not exist"
  [ -f "$binary_source" ] || fail "hook binary source does not exist"
  [ -f "$stage_config_source" ] || fail "runtime-fact hook source does not exist"
  [ -f "$admission_config_source" ] || fail "runtime-admission hook source does not exist"
  [ -f "$entry_config_source" ] || fail "entry-preparation hook source does not exist"
  # Releases before the NRI-compatible layout kept markers in the watched
  # directory. Move only markers that belong to this exact Helm release.
  migrate_owned_marker \
    "$config_directory/.98-mithril-create-container.json.helm-owner" \
    "$old_create_config_marker" "$hook_owner"
  migrate_owned_marker \
    "$config_directory/.99-mithril-prestart.json.helm-owner" \
    "$old_prestart_config_marker" "$hook_owner"
  migrate_owned_marker "$config_directory/.99-mithril.json.helm-owner" \
    "$legacy_config_marker" "$hook_owner"
  if [ -n "$legacy_binary_directory" ]; then
    migrate_owned_marker \
      "$legacy_binary_directory/.98-mithril-create-container.json.helm-owner" \
      "$old_create_config_marker" "$hook_owner"
    migrate_owned_marker \
      "$legacy_binary_directory/.99-mithril-prestart.json.helm-owner" \
      "$old_prestart_config_marker" "$hook_owner"
    migrate_owned_marker "$legacy_binary_directory/.99-mithril.json.helm-owner" \
      "$legacy_config_marker" "$hook_owner"
  fi
  require_owned_or_absent "$binary_target" "$binary_marker" "$hook_owner"
  require_owned_or_absent "$stage_config_target" "$stage_config_marker" "$hook_owner"
  require_owned_or_absent "$admission_config_target" "$admission_config_marker" "$hook_owner"
  require_owned_or_absent "$entry_config_target" "$entry_config_marker" "$hook_owner"
  require_owned_or_absent "$old_create_config_target" "$old_create_config_marker" "$hook_owner"
  require_owned_or_absent "$old_prestart_config_target" "$old_prestart_config_marker" "$hook_owner"
  require_owned_or_absent "$legacy_config_target" "$legacy_config_marker" "$hook_owner"

  # Keep ownership and staging files outside the watched configuration directory.
  # The NRI hook manager must observe only complete hook documents.
  publish_owner "$binary_marker" "$hook_owner"
  publish_owner "$stage_config_marker" "$hook_owner"
  publish_owner "$admission_config_marker" "$hook_owner"
  publish_owner "$entry_config_marker" "$hook_owner"
  publish_file "$binary_source" "$binary_target" 0755
  # Keep the old denial active until both ordered replacements are complete.
  remove_owned "$old_create_config_target" "$old_create_config_marker" "$hook_owner"
  publish_file "$stage_config_source" "$stage_config_target" 0644 \
    "${config_directory%/*}"
  publish_file "$admission_config_source" "$admission_config_target" 0644 \
    "${config_directory%/*}"
  publish_file "$entry_config_source" "$entry_config_target" 0644 \
    "${config_directory%/*}"
  remove_owned "$old_prestart_config_target" "$old_prestart_config_marker" "$hook_owner"
  remove_owned "$legacy_config_target" "$legacy_config_marker" "$hook_owner"
  if [ -n "$legacy_binary_directory" ]; then
    remove_owned "$legacy_binary_directory/mithril-oci-hook" \
      "$legacy_binary_directory/.mithril-oci-hook.helm-owner" "$hook_owner"
  fi
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
  legacy_binary_directory=${4:-}
  # Remove staging first. Concurrent admission then denies because it has no stage.
  remove_owned "$config_directory/98-mithril-runtime-stage.json" \
    "$binary_directory/.98-mithril-runtime-stage.json.helm-owner" "$hook_owner"
  remove_owned "$config_directory/99-mithril-runtime-admission.json" \
    "$binary_directory/.99-mithril-runtime-admission.json.helm-owner" "$hook_owner"
  remove_owned "$config_directory/99-mithril-runtime-entry-preparation.json" \
    "$binary_directory/.99-mithril-runtime-entry-preparation.json.helm-owner" "$hook_owner"
  remove_owned "$config_directory/98-mithril-create-container.json" \
    "$binary_directory/.98-mithril-create-container.json.helm-owner" "$hook_owner"
  remove_owned "$config_directory/99-mithril-prestart.json" \
    "$binary_directory/.99-mithril-prestart.json.helm-owner" "$hook_owner"
  remove_owned "$config_directory/99-mithril.json" \
    "$binary_directory/.99-mithril.json.helm-owner" "$hook_owner"
  remove_owned "$binary_directory/mithril-oci-hook" \
    "$binary_directory/.mithril-oci-hook.helm-owner" "$hook_owner"
  if [ -n "$legacy_binary_directory" ]; then
    remove_owned "$legacy_binary_directory/mithril-oci-hook" \
      "$legacy_binary_directory/.mithril-oci-hook.helm-owner" "$hook_owner"
  fi
}

action=${1:-}
owner=${2:-}
case $owner in
  */*) ;;
  *) fail "owner must contain the release namespace and name" ;;
esac

case $action in
  install)
    { [ "$#" -eq 8 ] || [ "$#" -eq 9 ]; } ||
      fail "install requires owner, sources, and target directories"
    install_hook "$owner" "$3" "$4" "$5" "$6" "$7" "$8" "${9:-}"
    ;;
  cleanup)
    { [ "$#" -eq 4 ] || [ "$#" -eq 5 ]; } ||
      fail "cleanup requires owner and target directories"
    cleanup_hook "$owner" "$3" "$4" "${5:-}"
    ;;
  cleanup-and-hold)
    { [ "$#" -eq 5 ] || [ "$#" -eq 6 ]; } ||
      fail "cleanup-and-hold requires owner, target directories, and readiness file"
    cleanup_hook "$owner" "$3" "$4" "${6:-}"
    printf 'complete\n' >"$5"
    exec sleep 3600
    ;;
  *) fail "action must be install, cleanup, or cleanup-and-hold" ;;
esac
