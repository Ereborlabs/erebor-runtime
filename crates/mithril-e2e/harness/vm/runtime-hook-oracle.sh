#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $0 {installed|retained ROOT OWNER SOCKET TIMEOUT_MS RUNTIME_TIMEOUT_SECONDS|node-state-path ROOT|recovery-inputs ROOT|removed ROOT SOCKET}" >&2
}

host_path() {
  if [[ $root == / ]]; then
    printf '%s\n' "$1"
  else
    printf '%s\n' "$root$1"
  fi
}

case ${1:-} in
  recovery-inputs)
    (($# == 2)) || { usage; exit 2; }
    root=${2%/}
    [[ -n $root ]] || root=/
    [[ $root == /* && -d $root ]] || {
      echo "invalid runtime-hook oracle input" >&2
      exit 2
    }
    node_config=$(host_path /etc/mithril/node.json)
    [[ -f $node_config && ! -L $node_config ]]
    [[ $(stat -c '%u:%g:%a' "$node_config") == 0:0:400 ]]
    ;;
  node-state-path)
    (($# == 2)) || { usage; exit 2; }
    root=${2%/}
    [[ -n $root ]] || root=/
    [[ $root == /* && -d $root ]] || {
      echo "invalid runtime-hook oracle input" >&2
      exit 2
    }
    recovery=$(host_path /var/lib/rancher/k3s/agent/etc/containerd/mithril-recovery.json)
    jq -er '
      [.entries[] |
        select(.executable == "/usr/local/bin/mithril-node") |
        .requiredMounts[] |
        select(.destination == "/var/lib/mithril" and .readOnly == false) |
        .source] as $paths |
      if ($paths | length) == 1 and
          ($paths[0] | test("^/var/lib/mithril-node-[0-9]{14}-[0-9]+$"))
      then $paths[0]
      else error("retained manifest has no exact harness Node state path")
      end
    ' "$recovery"
    ;;
  installed|retained)
    state=$1
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

    hook=$(host_path /usr/libexec/oci/hooks.d/mithril-oci-hook)
    hook_owner=$(host_path /usr/libexec/oci/hooks.d/.mithril-oci-hook.mithril-owner)
    containerd=$(host_path /var/lib/rancher/k3s/agent/etc/containerd)
    recovery=$containerd/mithril-recovery.json
    recovery_owner=$containerd/.mithril-recovery.json.mithril-owner
    base_spec=$containerd/mithril-base-spec.json
    base_spec_owner=$containerd/.mithril-base-spec.json.mithril-owner
    fragment=$containerd/config-v3.toml.d/99-mithril.toml
    fragment_owner=$containerd/config-v3.toml.d/.99-mithril.toml.mithril-owner
    generated=$containerd/config.toml
    runtime_socket=$(host_path "$socket")

    for path in "$hook" "$hook_owner" "$recovery" "$recovery_owner" \
        "$base_spec" "$base_spec_owner" "$fragment" "$fragment_owner"; do
      [[ -f $path && ! -L $path ]]
    done
    [[ -x $hook && $(stat -c '%u:%g:%a' "$hook") == 0:0:755 ]]
    for marker in "$hook_owner" "$recovery_owner" "$base_spec_owner" \
        "$fragment_owner"; do
      [[ $(<"$marker") == "$owner" ]]
      [[ $(stat -c '%u:%g:%a' "$marker") == 0:0:600 ]]
    done
    [[ $(stat -c '%u:%g:%a' "$recovery") == 0:0:600 ]]
    [[ $(stat -c '%u:%g:%a' "$base_spec") == 0:0:600 ]]
    [[ $(stat -c '%u:%g:%a' "$fragment") == 0:0:600 ]]

    jq -e '
      .version == 1 and
      (.entries | length) == 2 and
      all(.entries[];
        (.executable | startswith("/")) and
        (has("executableSha256") | not) and
        (.args | length) > 0 and
        (.args[0] == .executable) and
        (.requiredMounts | length) > 0) and
      (.controlEntries | length) == 1 and
      all(.controlEntries[];
        (.executable | startswith("/")) and
        (has("executableSha256") | not) and
        (.args | length) > 0 and
        (.args[0] == .executable) and
        .uid > 0 and .gid > 0 and
        (.requiredMounts | length) > 0)
    ' "$recovery" >/dev/null
    jq -e --arg socket "$socket" --arg timeout "$timeout_ms" \
      --argjson runtime_timeout "$runtime_timeout" '
      .hooks.createRuntime[0].path == "/usr/libexec/oci/hooks.d/mithril-oci-hook" and
      .hooks.createRuntime[0].args == [
        "mithril-oci-hook", "run", "--stage", "stage-runtime-facts",
        "--socket", $socket, "--recovery-manifest",
        "/var/lib/rancher/k3s/agent/etc/containerd/mithril-recovery.json",
        "--timeout-ms", $timeout
      ] and
      .hooks.createRuntime[0].timeout == $runtime_timeout and
      .hooks.createRuntime[1].args[3] == "prepare-container" and
      .hooks.createContainer[0].args[3] == "prepare-declared-entries"
    ' "$base_spec" >/dev/null
    grep -Fxq "base_runtime_spec = \"/var/lib/rancher/k3s/agent/etc/containerd/mithril-base-spec.json\"" \
      "$fragment"
    grep -Fxq 'imports = ["/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/*.toml"]' \
      "$generated"

    if [[ $state == installed ]]; then
      [[ $(stat -c '%F' "$runtime_socket") == socket ]]
      [[ $(stat -c '%u:%g:%a' "$runtime_socket") == 0:0:600 ]]
    else
      [[ ! -e $runtime_socket && ! -L $runtime_socket ]]
    fi
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
      /usr/libexec/oci/hooks.d/mithril-oci-hook \
      /usr/libexec/oci/hooks.d/.mithril-oci-hook.mithril-owner \
      /var/lib/rancher/k3s/agent/etc/containerd/mithril-recovery.json \
      /var/lib/rancher/k3s/agent/etc/containerd/.mithril-recovery.json.mithril-owner \
      /var/lib/rancher/k3s/agent/etc/containerd/mithril-base-spec.json \
      /var/lib/rancher/k3s/agent/etc/containerd/.mithril-base-spec.json.mithril-owner \
      /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/99-mithril.toml \
      /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/.99-mithril.toml.mithril-owner \
      "$socket"; do
      target=$(host_path "$path")
      if [[ -e $target || -L $target ]]; then
        echo "runtime integration path remains: $path" >&2
        exit 1
      fi
    done
    ;;
  *)
    usage
    exit 2
    ;;
esac
