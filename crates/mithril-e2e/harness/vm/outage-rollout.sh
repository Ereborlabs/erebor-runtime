#!/usr/bin/env bash

wait_rollout() {
  local active=$1
  local updating=$2
  local api_restart=${3:-false}
  local recreated=false
  local deadline=$((SECONDS + 360))
  local policy_json pod_json
  while ((SECONDS < deadline)); do
    if [[ $api_restart == true ]]; then
      pod_json=$(remote_kubectl -n "$scenario_namespace" get \
        pod outage-a -o json) || return 1
      if pod_needs_api_restart_recreation "$pod_json"; then
        if [[ $recreated == true ]]; then
          echo "protected Pod outage-a failed admission again after API recovery" >&2
          return 1
        fi
        recreated=true
        wait_node_ready "$node_a_name" true || return 1
        remote_kubectl -n "$scenario_namespace" delete pod outage-a \
          --wait=true --timeout=120s >/dev/null || return 1
        "$provider" run "$vm_a" sudo rm -f \
          "$marker_root/outage-a.started" "$marker_root/outage-a.result" || return 1
        remote_kubectl create -f /var/tmp/mithril-outage-pod-a.yaml \
          >/dev/null || return 1
        remote_kubectl -n "$scenario_namespace" wait --for=condition=Ready \
          pod/outage-a --timeout=300s >/dev/null || return 1
        wait_application_started "$vm_a" outage-a || return 1
        wait_node_control_acknowledgement "$node_a_name" || return 1
        refresh_policy_status api-recovered || return 1
        continue
      elif ! jq -e '.status.phase == "Running"' <<<"$pod_json" >/dev/null; then
        echo "protected Pod outage-a entered an unrelated state after API recovery" >&2
        return 1
      fi
    fi
    policy_json=$(remote_kubectl -n "$scenario_namespace" get \
      workloadprotectionpolicy "$policy_name" -o json 2>/dev/null || true)
    if [[ -n $policy_json ]] && jq -e \
      --argjson active "$active" --argjson updating "$updating" '
        .status.observedGeneration == .metadata.generation and
        .status.rollout.desired == 2 and
        .status.rollout.active == $active and
        .status.rollout.updating == $updating and
        .status.rollout.failed == 0
      ' <<<"$policy_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "policy rollout did not reach active=$active updating=$updating" >&2
  return 1
}
