#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 2 ]] || {
  echo "usage: sudo $0 NODE_CONFIG DOCKER_CONTAINER_OR_FULL_CRI_ID" >&2
  exit 2
}

identity_require_command nsenter
identity_prepare_auto "$1" "$2"
identity_start_node

echo "Run in another root terminal; namespace entry alone stays outside:"
printf "  nsenter -t %q -m -u -i -n -p sh -c %q &\n" \
  "$identity_init_pid" 'echo nsenter-ready; exec sleep 300'
printf '  helper=$!; echo "nsenter helper host PID: $helper"\n'
printf '  cat /proc/$helper/task/$helper/children\n'
identity_read_host_pid "nsenter helper host PID: "
nsenter_helper_pid=$identity_read_pid
identity_read_host_pid "nsenter sleep host PID: "
nsenter_pid=$identity_read_pid
nsenter_children=()
read -r -a nsenter_children \
  <"/proc/$nsenter_helper_pid/task/$nsenter_helper_pid/children" || true
[[ ${#nsenter_children[@]} -eq 1 && ${nsenter_children[0]} == "$nsenter_pid" ]] || {
  echo "nsenter sleep is not the helper's only direct child" >&2
  exit 1
}
[[ $(<"/proc/$nsenter_pid/comm") == sleep ]] || {
  echo "nsenter child is not sleep" >&2
  exit 1
}
[[ $(tr '\0' ' ' <"/proc/$nsenter_pid/cmdline") == 'sleep 300 ' ]] || {
  echo "nsenter child command is not exactly sleep 300" >&2
  exit 1
}
for namespace in mnt uts ipc net pid; do
  [[ $(readlink "/proc/$nsenter_pid/ns/$namespace") == \
    $(readlink "/proc/$identity_init_pid/ns/$namespace") ]] || {
    echo "nsenter sleep is outside the target $namespace namespace" >&2
    exit 1
  }
done
nsenter_cgroup=$(identity_cgroup_for_pid "$nsenter_pid")
case $nsenter_cgroup in
  "$identity_cgroup_path"|"$identity_cgroup_path"/*)
    echo "nsenter sleep is already in the configured cgroup" >&2
    exit 1
    ;;
esac
if no_identity_output=$("$identity_inspect" --pin-root "$identity_pin_root" \
  task --host-pid "$nsenter_pid" 2>&1); then
  echo "namespace entry alone incorrectly granted workload identity" >&2
  exit 1
elif [[ $no_identity_output != \
  "Mithril native identity state is invalid: host PID $nsenter_pid has no Mithril task identity" ]]; then
  echo "Mithril did not confirm the expected missing task identity:" >&2
  echo "$no_identity_output" >&2
  exit 1
fi

echo "$nsenter_pid" >"$identity_cgroup_path/cgroup.procs"
identity_inspect_task nsenter-after-move "$nsenter_pid"
identity_assert_external "$identity_work/nsenter-after-move.json"
external_role_id=$(jq -er '.workload_bindings[0].external_role_id' "$identity_config")
jq -e --argjson external_role_id "$external_role_id" \
  '.active_role_id == $external_role_id and .coordinate_state == 3' \
  "$identity_work/nsenter-after-move.json" >/dev/null
identity_pass "PASS: nsenter grants nothing; cgroup movement creates a restricted external root"
