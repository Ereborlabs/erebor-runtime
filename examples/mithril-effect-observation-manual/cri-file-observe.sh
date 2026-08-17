#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/observation-runtime.sh"
case $# in
  0)
    observation_prepare_k3s \
      docker.io/library/busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
    secret_path=$identity_k3s_secret_path
    ;;
  5)
    observation_prepare_cri "$1" "$2" "$3" "$4" "$5"
    secret_path=$3
    ;;
  *)
  echo "usage: sudo $0 <node.json> <container-id> <absolute-secret-path> <host-shared-directory> <container-shared-directory>" >&2
  echo "   or: sudo $0" >&2
  exit 2
    ;;
esac
observation_preload_probe sh -ec '
umask 077
printf "%s\n" "$$" >"$1"
while [ ! -s "$MITHRIL_MANUAL_RELEASE" ]; do
  :
done
exec 4<"$2"
IFS= read -r -n 1 _ <&4 || :
exec 4<&-
' sh "$observation_probe_ready" "$secret_path"
identity_inspect_task cri-effect-probe "$observation_probe_host_pid" >/dev/null
identity_assert_external "$identity_work/cri-effect-probe.json"
task_cookie=$(jq -er '.task_cookie' "$identity_work/cri-effect-probe.json")
[[ $task_cookie =~ ^[1-9][0-9]*$ ]] || {
  echo "the CRI probe has no exact Mithril task cookie" >&2
  exit 1
}
observation_release_probe
expected_effect="task_cookie=$task_cookie family=2 operation=2 reason=WOULD_DENY result=UNKNOWN_AFTER_PRE_EFFECT"
observation_wait_for_observation "$expected_effect" "$identity_work/effects.txt"
grep -F "$expected_effect" "$identity_work/effects.txt" \
  | grep -Fq 'exact_object_key_id=7' || {
  echo "the CRI workload did not report the exact secret object" >&2
  exit 1
}
identity_pass "PASS: the CRI workload read the exact secret and Mithril reported WOULD_DENY."
