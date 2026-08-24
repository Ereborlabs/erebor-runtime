#!/usr/bin/env bash

collect_mithril_diagnostics() {
  local output_directory=$1
  local namespace=$2
  local workload_namespace=${3:-}
  local diagnostics=$output_directory/diagnostics

  install -d -m 700 "$diagnostics"
  # Each API request and log stream has a time and size bound. Diagnostics
  # must not replace the original failure with an unbounded cleanup wait.
  {
    diagnostic_kubectl get nodes -o wide
    diagnostic_kubectl -n "$namespace" get deployment/mithril-control -o wide
    diagnostic_kubectl -n "$namespace" get daemonset/mithril-node -o wide
    diagnostic_kubectl -n "$namespace" get pods -o wide
  } >"$diagnostics/resources.txt" 2>&1
  diagnostic_kubectl get nodes -o json >"$diagnostics/nodes.json" 2>&1
  diagnostic_kubectl -n "$namespace" logs deployment/mithril-control \
    --all-containers=true --tail=200 --limit-bytes=131072 \
    >"$diagnostics/control.log" 2>&1
  diagnostic_kubectl -n "$namespace" logs \
    -l app.kubernetes.io/name=mithril-node --all-containers=true \
    --prefix=true --tail=200 --limit-bytes=131072 \
    >"$diagnostics/nodes.log" 2>&1
  diagnostic_kubectl -n "$namespace" logs \
    -l app.kubernetes.io/name=mithril-node --all-containers=true --previous \
    --prefix=true --tail=200 --limit-bytes=131072 \
    >"$diagnostics/nodes-previous.log" 2>&1
  diagnostic_kubectl -n kube-system logs \
    -l app.kubernetes.io/name=nri-plugin-hook-injector --all-containers=true \
    --prefix=true --tail=200 --limit-bytes=131072 \
    >"$diagnostics/nri-hook-injector.log" 2>&1
  if [[ -n $workload_namespace ]]; then
    {
      diagnostic_kubectl -n "$workload_namespace" get pods -o wide
      diagnostic_kubectl -n "$workload_namespace" get \
        workloadprotectionpolicies.mithril.erebor.dev -o wide
      diagnostic_kubectl -n "$workload_namespace" get \
        workloadprotectionexceptions.mithril.erebor.dev -o wide
    } >"$diagnostics/workload.txt" 2>&1
    diagnostic_kubectl -n "$workload_namespace" get events \
      --field-selector involvedObject.name=protected --sort-by=.lastTimestamp \
      >"$diagnostics/workload-events.txt" 2>&1
    diagnostic_kubectl -n "$workload_namespace" logs pod/protected \
      --all-containers=true --tail=200 --limit-bytes=131072 \
      >"$diagnostics/workload.log" 2>&1
    diagnostic_kubectl -n "$workload_namespace" logs pod/protected \
      --all-containers=true --previous --tail=200 --limit-bytes=131072 \
      >"$diagnostics/workload-previous.log" 2>&1
  fi
  return 0
}

remove_mithril_release() {
  local cluster_created=$1
  local keep_vms=$2
  local manual_environment=$3
  local kubeconfig=$4
  local namespace=$5

  # Retained VMs keep the release and node state for diagnosis. The explicit
  # destroy command remains the owner of final environment removal.
  if [[ $cluster_created == true && $keep_vms == false &&
        $manual_environment == false && -r $kubeconfig ]]; then
    helm --kubeconfig "$kubeconfig" uninstall mithril -n "$namespace" \
      >/dev/null 2>&1
  fi
}

cleanup_result() {
  local original_status=$1
  local cleanup_failed=$2

  # Preserve the scenario failure. Cleanup changes only a successful result.
  if ((original_status != 0)); then
    return "$original_status"
  fi
  [[ $cleanup_failed == false ]]
}
