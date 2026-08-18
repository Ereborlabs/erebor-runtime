#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

identity_prepare_k3s_lifecycle_sleep_case

container_id=
for ((attempt = 0; attempt < 300; attempt++)); do
  container_id=$(crictl ps -o json | jq -r \
    --arg namespace "$identity_k3s_namespace" \
    '.containers[]?
     | select(.metadata.name == "runtime")
     | select(.labels["io.kubernetes.pod.namespace"] == $namespace)
     | .id' | head -n 1)
  [[ -n $container_id ]] && break
  sleep 0.1
done
[[ -n $container_id ]] || {
  echo "the lifecycle-sleep container did not start" >&2
  exit 1
}

init_pid=$(crictl inspect "$container_id" | jq -er '.info.pid')
[[ $init_pid =~ ^[1-9][0-9]*$ ]] || {
  echo "CRI returned an invalid lifecycle-sleep PID" >&2
  exit 1
}
cgroup=$(identity_cgroup_for_pid "$init_pid")
mapfile -t tasks < <(tr ' ' '\n' <"$cgroup/cgroup.procs" | sed '/^$/d')
[[ ${#tasks[@]} -eq 1 && ${tasks[0]} == "$init_pid" ]] || {
  printf 'lifecycle sleep created an in-container task: %s\n' "${tasks[*]}" >&2
  exit 1
}

ready=$(kubectl -n "$identity_k3s_namespace" get pod mithril-sleep \
  -o json | jq -r '[.status.conditions[]? | select(.type == "Ready")][0].status // "False"')
[[ $ready != True ]] || {
  echo "the lifecycle sleep completed before the no-task observation" >&2
  exit 1
}
printf 'container PID: %s\ncgroup: %s\nin-container tasks: %s\n' \
  "$init_pid" "$cgroup" "${tasks[*]}"

kubectl -n "$identity_k3s_namespace" wait --for=condition=Ready \
  pod/mithril-sleep --timeout=120s >/dev/null
identity_pass "PASS: Kubernetes lifecycle sleep created no in-container task."
