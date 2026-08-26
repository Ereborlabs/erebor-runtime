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
    binary=$(host_path /usr/libexec/oci/hooks.d/mithril-oci-hook)
    binary_owner=$(host_path /usr/libexec/oci/hooks.d/.mithril-oci-hook.helm-owner)
    stage_config=$(host_path /usr/share/containers/oci/hooks.d/98-mithril-runtime-stage.json)
    stage_config_owner=$(host_path /usr/libexec/oci/hooks.d/.98-mithril-runtime-stage.json.helm-owner)
    admission_config=$(host_path /usr/share/containers/oci/hooks.d/99-mithril-runtime-admission.json)
    admission_config_owner=$(host_path /usr/libexec/oci/hooks.d/.99-mithril-runtime-admission.json.helm-owner)
    entry_config=$(host_path /usr/share/containers/oci/hooks.d/99-mithril-runtime-entry-preparation.json)
    entry_config_owner=$(host_path /usr/libexec/oci/hooks.d/.99-mithril-runtime-entry-preparation.json.helm-owner)
    runtime_socket=$(host_path "$socket")

    [[ -f $binary && ! -L $binary && -x $binary ]]
    [[ -f $stage_config && ! -L $stage_config ]]
    [[ -f $admission_config && ! -L $admission_config ]]
    [[ -f $entry_config && ! -L $entry_config ]]
    [[ -f $binary_owner && ! -L $binary_owner && $(<"$binary_owner") == "$owner" ]]
    [[ -f $stage_config_owner && ! -L $stage_config_owner && $(<"$stage_config_owner") == "$owner" ]]
    [[ -f $admission_config_owner && ! -L $admission_config_owner && $(<"$admission_config_owner") == "$owner" ]]
    [[ -f $entry_config_owner && ! -L $entry_config_owner && $(<"$entry_config_owner") == "$owner" ]]
    [[ $(stat -c '%u:%g:%a' "$binary") == 0:0:755 ]]
    [[ $(stat -c '%u:%g:%a' "$stage_config") == 0:0:644 ]]
    [[ $(stat -c '%u:%g:%a' "$admission_config") == 0:0:644 ]]
    [[ $(stat -c '%u:%g:%a' "$entry_config") == 0:0:644 ]]
    [[ $(stat -c '%u:%g:%a' "$binary_owner") == 0:0:600 ]]
    [[ $(stat -c '%u:%g:%a' "$stage_config_owner") == 0:0:600 ]]
    [[ $(stat -c '%u:%g:%a' "$admission_config_owner") == 0:0:600 ]]
    [[ $(stat -c '%u:%g:%a' "$entry_config_owner") == 0:0:600 ]]
    [[ ! -e $(host_path /usr/share/containers/oci/hooks.d/99-mithril.json) ]]
    [[ ! -e $(host_path /usr/share/containers/oci/hooks.d/.99-mithril.json.helm-owner) ]]
    jq -e --arg socket "$socket" --arg timeout_ms "$timeout_ms" \
      --argjson runtime_timeout "$runtime_timeout" '
        .version == "1.0.0" and
        .hook.path == "/usr/libexec/oci/hooks.d/mithril-oci-hook" and
        .hook.args == ["mithril-oci-hook", "--stage", "stage-runtime-facts", "--socket", $socket, "--timeout-ms", $timeout_ms] and
        .hook.timeout == $runtime_timeout and
        .when.annotations == {"^mithril\\.erebor\\.dev/profile-id$": ".+"} and
        .stages == ["createRuntime"]
      ' "$stage_config" >/dev/null
    jq -e --arg socket "$socket" --arg timeout_ms "$timeout_ms" \
      --argjson runtime_timeout "$runtime_timeout" '
        .version == "1.0.0" and
        .hook.path == "/usr/libexec/oci/hooks.d/mithril-oci-hook" and
        .hook.args == ["mithril-oci-hook", "--stage", "prepare-container", "--socket", $socket, "--timeout-ms", $timeout_ms] and
        .hook.timeout == $runtime_timeout and
        .when.annotations == {"^mithril\\.erebor\\.dev/profile-id$": ".+"} and
        .stages == ["createRuntime"]
      ' "$admission_config" >/dev/null
    jq -e --arg socket "$socket" --arg timeout_ms "$timeout_ms" \
      --argjson runtime_timeout "$runtime_timeout" '
        .version == "1.0.0" and
        .hook.path == "/usr/libexec/oci/hooks.d/mithril-oci-hook" and
        .hook.args == ["mithril-oci-hook", "--stage", "prepare-declared-entries", "--socket", $socket, "--timeout-ms", $timeout_ms] and
        .hook.timeout == $runtime_timeout and
        .when.annotations == {"^mithril\\.erebor\\.dev/profile-id$": ".+"} and
        .stages == ["createContainer"]
      ' "$entry_config" >/dev/null
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
    remaining=false
    for path in \
      /usr/libexec/oci/hooks.d/mithril-oci-hook \
      /usr/libexec/oci/hooks.d/.mithril-oci-hook.helm-owner \
      /usr/share/containers/oci/hooks.d/98-mithril-runtime-stage.json \
      /usr/libexec/oci/hooks.d/.98-mithril-runtime-stage.json.helm-owner \
      /usr/share/containers/oci/hooks.d/99-mithril-runtime-admission.json \
      /usr/libexec/oci/hooks.d/.99-mithril-runtime-admission.json.helm-owner \
      /usr/share/containers/oci/hooks.d/99-mithril-runtime-entry-preparation.json \
      /usr/libexec/oci/hooks.d/.99-mithril-runtime-entry-preparation.json.helm-owner \
      /usr/share/containers/oci/hooks.d/98-mithril-create-container.json \
      /usr/libexec/oci/hooks.d/.98-mithril-create-container.json.helm-owner \
      /usr/share/containers/oci/hooks.d/99-mithril-prestart.json \
      /usr/libexec/oci/hooks.d/.99-mithril-prestart.json.helm-owner \
      /usr/share/containers/oci/hooks.d/99-mithril.json \
      /usr/libexec/oci/hooks.d/.99-mithril.json.helm-owner \
      "$socket"; do
      target=$(host_path "$path")
      if [[ -e $target || -L $target ]]; then
        echo "runtime-hook path remains: $path" >&2
        remaining=true
      fi
    done
    [[ $remaining == false ]]
    ;;
  *)
    usage
    exit 2
    ;;
esac
