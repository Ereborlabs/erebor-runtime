#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

identity_prepare_k3s_network_probe_case
kubectl -n "$identity_k3s_namespace" wait --for=condition=Ready \
  pod/mithril-network-probes --timeout=180s >/dev/null

pod=$(kubectl -n "$identity_k3s_namespace" get pod mithril-network-probes -o json)
jq -e '
  [.status.containerStatuses[]?
   | select(.name == "http" or .name == "tcp" or .name == "grpc")]
  | length == 3
    and all(.ready == true and .restartCount == 0)
' <<<"$pod" >/dev/null || {
  echo "not every network probe passed without a container restart" >&2
  exit 1
}

for container_name in http tcp grpc; do
  container_id=
  for ((attempt = 0; attempt < 300; attempt++)); do
    container_id=$(crictl ps -o json | jq -r \
      --arg namespace "$identity_k3s_namespace" \
      --arg name "$container_name" \
      '.containers[]?
       | select(.metadata.name == $name)
       | select(.labels["io.kubernetes.pod.namespace"] == $namespace)
       | .id' | head -n 1)
    [[ -n $container_id ]] && break
    sleep 0.1
  done
  [[ -n $container_id ]] || {
    echo "the $container_name network-probe container did not start" >&2
    exit 1
  }

  init_pid=$(crictl inspect "$container_id" | jq -er '.info.pid')
  [[ $init_pid =~ ^[1-9][0-9]*$ ]] || {
    echo "CRI returned an invalid $container_name network-probe PID" >&2
    exit 1
  }
  cgroup=$(identity_cgroup_for_pid "$init_pid")
  for ((sample = 0; sample < 400; sample++)); do
    mapfile -t tasks < <(tr ' ' '\n' <"$cgroup/cgroup.procs" | sed '/^$/d')
    [[ ${#tasks[@]} -eq 1 && ${tasks[0]} == "$init_pid" ]] || {
      printf '%s network probe created an in-container task: %s\n' \
        "$container_name" "${tasks[*]}" >&2
      exit 1
    }
    sleep 0.01
  done
  printf '%s probe: init PID %s; cgroup tasks %s\n' \
    "$container_name" "$init_pid" "${tasks[*]}"
done

identity_pass "PASS: HTTP, TCP, and gRPC probes created no in-container task."
