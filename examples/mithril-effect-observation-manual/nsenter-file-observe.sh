#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/observation-runtime.sh"
case $# in
  3)
    observation_prepare_docker "$1" "$2" "$3"
    ;;
  5)
    observation_prepare_cri "$1" "$2" "$3" "$4" "$5"
    ;;
  *)
    echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
    echo "   or: sudo $0 <node.json> <container-id> <absolute-secret-path> <host-shared-directory> <container-shared-directory>" >&2
    exit 2
    ;;
esac

observation_preload_nsenter_probe sh -ec '
umask 077
printf "%s\n" "$$" >"$1"
while [ ! -s "$MITHRIL_MANUAL_RELEASE" ]; do
  :
done
exec 4<"$2"
IFS= read -r -n 1 _ <&4 || :
exec 4<&-
' sh "$observation_probe_ready" "$3"

if [[ $identity_mode == cri ]]; then
  identity_inspect_task cri-nsenter-effect-probe "$observation_probe_host_pid" >/dev/null
  identity_assert_external "$identity_work/cri-nsenter-effect-probe.json"
  task_cookie=$(jq -er '.task_cookie' "$identity_work/cri-nsenter-effect-probe.json")
  [[ $task_cookie =~ ^[1-9][0-9]*$ ]] || {
    echo "the CRI nsenter probe has no exact Mithril task cookie" >&2
    exit 1
  }
  external_role_id=$(jq -er '.workload_bindings[0].external_role_id' "$identity_config")
  jq -e --argjson external_role_id "$external_role_id" \
    '.active_role_id == $external_role_id and .coordinate_state == 3' \
    "$identity_work/cri-nsenter-effect-probe.json" >/dev/null
fi

observation_release_probe
if [[ $identity_mode == cri ]]; then
  expected_effect="task_cookie=$task_cookie family=2 operation=2 reason=WOULD_DENY result=UNKNOWN_AFTER_PRE_EFFECT"
  observation_wait_for_observation "$expected_effect" "$identity_work/effects.txt"
  grep -F "$expected_effect" "$identity_work/effects.txt" \
    | grep -Fq 'exact_object_key_id=7' || {
    echo "the CRI nsenter probe did not report the exact secret object" >&2
    exit 1
  }
  identity_pass "PASS: the CRI nsenter probe opened the exact secret and reported WOULD_DENY."
else
  observation_wait_for_observation 'reason=WOULD_DENY' "$identity_work/effects.txt"
  grep -q 'result=UNKNOWN_AFTER_PRE_EFFECT' "$identity_work/effects.txt"
  identity_pass "PASS: a raw nsenter process was attributed after cgroup join and reported WOULD_DENY."
fi
