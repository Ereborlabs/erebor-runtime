#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $0 {installed ROOT OWNER SOCKET TIMEOUT_MS RUNTIME_TIMEOUT_SECONDS|removed ROOT SOCKET}" >&2
}

host_path() {
  if [[ $root == / ]]; then
    printf '%s\n' "$1"
  else
    printf '%s\n' "$root$1"
  fi
}

case ${1:-} in
  installed)
    (($# == 6)) || { usage; exit 2; }
    root=${2%/}
    [[ -n $root ]] || root=/
    owner=$3
    socket=$4
    timeout_ms=$5
    runtime_timeout=$6
    [[ $root == /* && -d $root && $owner == */* &&
       ${socket%/*} == /run/mithril && ${socket##*/} != "" &&
       $timeout_ms =~ ^[1-9][0-9]*$ && $runtime_timeout =~ ^[1-9][0-9]*$ ]] || {
      echo "invalid runtime-hook oracle input" >&2
      exit 2
    }
    binary=$(host_path /opt/mithril/bin/mithril-oci-hook)
    binary_owner=$(host_path /opt/mithril/bin/.mithril-oci-hook.helm-owner)
    create_config=$(host_path /usr/share/containers/oci/hooks.d/98-mithril-create-container.json)
    create_config_owner=$(host_path /usr/share/containers/oci/hooks.d/.98-mithril-create-container.json.helm-owner)
    prestart_config=$(host_path /usr/share/containers/oci/hooks.d/99-mithril-prestart.json)
    prestart_config_owner=$(host_path /usr/share/containers/oci/hooks.d/.99-mithril-prestart.json.helm-owner)
    runtime_socket=$(host_path "$socket")

    [[ -f $binary && ! -L $binary && -x $binary ]]
    [[ -f $create_config && ! -L $create_config ]]
    [[ -f $prestart_config && ! -L $prestart_config ]]
    [[ -f $binary_owner && ! -L $binary_owner && $(<"$binary_owner") == "$owner" ]]
    [[ -f $create_config_owner && ! -L $create_config_owner && $(<"$create_config_owner") == "$owner" ]]
    [[ -f $prestart_config_owner && ! -L $prestart_config_owner && $(<"$prestart_config_owner") == "$owner" ]]
    [[ $(stat -c '%u:%g:%a' "$binary") == 0:0:755 ]]
    [[ $(stat -c '%u:%g:%a' "$create_config") == 0:0:644 ]]
    [[ $(stat -c '%u:%g:%a' "$prestart_config") == 0:0:644 ]]
    [[ $(stat -c '%u:%g:%a' "$binary_owner") == 0:0:600 ]]
    [[ $(stat -c '%u:%g:%a' "$create_config_owner") == 0:0:600 ]]
    [[ $(stat -c '%u:%g:%a' "$prestart_config_owner") == 0:0:600 ]]
    [[ ! -e $(host_path /usr/share/containers/oci/hooks.d/99-mithril.json) ]]
    [[ ! -e $(host_path /usr/share/containers/oci/hooks.d/.99-mithril.json.helm-owner) ]]
    jq -e --arg socket "$socket" --arg timeout_ms "$timeout_ms" \
      --argjson runtime_timeout "$runtime_timeout" '
        .version == "1.0.0" and
        .hook.path == "/opt/mithril/bin/mithril-oci-hook" and
        .hook.args == ["mithril-oci-hook", "--stage", "create-container", "--socket", $socket, "--timeout-ms", $timeout_ms] and
        .hook.timeout == $runtime_timeout and
        .when.annotations == {"^mithril\\.erebor\\.dev/profile-id$": ".+"} and
        .stages == ["createContainer"]
      ' "$create_config" >/dev/null
    jq -e --arg socket "$socket" --arg timeout_ms "$timeout_ms" \
      --argjson runtime_timeout "$runtime_timeout" '
        .version == "1.0.0" and
        .hook.path == "/opt/mithril/bin/mithril-oci-hook" and
        .hook.args == ["mithril-oci-hook", "--stage", "prestart", "--socket", $socket, "--timeout-ms", $timeout_ms] and
        .hook.timeout == $runtime_timeout and
        .when.annotations == {"^mithril\\.erebor\\.dev/profile-id$": ".+"} and
        .stages == ["prestart"]
      ' "$prestart_config" >/dev/null
    [[ $(stat -c '%F' "$runtime_socket") == socket ]]
    [[ $(stat -c '%u:%g:%a' "$runtime_socket") == 0:0:600 ]]
    ;;
  removed)
    (($# == 3)) || { usage; exit 2; }
    root=${2%/}
    [[ -n $root ]] || root=/
    socket=$3
    [[ $root == /* && -d $root && ${socket%/*} == /run/mithril &&
       ${socket##*/} != "" ]] || {
      echo "invalid runtime-hook oracle input" >&2
      exit 2
    }
    for path in \
      /opt/mithril/bin/mithril-oci-hook \
      /opt/mithril/bin/.mithril-oci-hook.helm-owner \
      /usr/share/containers/oci/hooks.d/98-mithril-create-container.json \
      /usr/share/containers/oci/hooks.d/.98-mithril-create-container.json.helm-owner \
      /usr/share/containers/oci/hooks.d/99-mithril-prestart.json \
      /usr/share/containers/oci/hooks.d/.99-mithril-prestart.json.helm-owner \
      /usr/share/containers/oci/hooks.d/99-mithril.json \
      /usr/share/containers/oci/hooks.d/.99-mithril.json.helm-owner \
      "$socket"; do
      target=$(host_path "$path")
      [[ ! -e $target && ! -L $target ]]
    done
    ;;
  *)
    usage
    exit 2
    ;;
esac
