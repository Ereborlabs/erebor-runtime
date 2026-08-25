#!/usr/bin/env bash

assert_mithril_node_name_denial() {
  local output
  if output=$("$@" 2>&1); then
    echo "Kubernetes accepted a protected Pod with spec.nodeName" >&2
    return 1
  fi
  # Require both the registered webhook and its exact policy reason. Another
  # API failure does not prove that Mithril rejected the scheduler bypass.
  if [[ $output != *'admission webhook "pods.mithril.erebor.dev" denied the request'* ||
        $output != *'protected Pod cannot set spec.nodeName'* ]]; then
    echo "Kubernetes returned an unrelated protected-Pod error: $output" >&2
    return 1
  fi
}

assert_kubernetes_strict_field_denial() {
  local output
  if output=$("$@" 2>&1); then
    echo "Kubernetes accepted the unknown policy field" >&2
    return 1
  fi
  # Name the rejected field and the strict-validation path. A version conflict
  # or transport error must not satisfy this schema oracle.
  if [[ $output != *'unknown field'* || $output != *'unexpectedField'* ||
        ($output != *'strict decoding error'* &&
         $output != *'ValidationError'* &&
         $output != *'error validating data'*) ]]; then
    echo "Kubernetes returned an unrelated policy-schema error: $output" >&2
    return 1
  fi
}

assert_exact_policy_target() {
  local status_json=$1
  local node_json=$2
  local pod_json=$3
  local profile_id=$4
  local container_name=$5
  local expected_operation=$6
  local expected_predecessor=${7:-}

  jq -e -n --argjson status "$status_json" --argjson node "$node_json" \
    --argjson pod "$pod_json" --arg profile "$profile_id" \
    --arg container "$container_name" --arg operation "$expected_operation" \
    --arg predecessor "$expected_predecessor" '
      [$pod.spec.containers[] | select(.name == $container)] as $containers |
      [$pod.status.containerStatuses[] | select(.name == $container)] as $runtimes |
      ($status.active_targets[0]) as $target |
      ($runtimes[0].containerID | sub("^[^:]+://"; "")) as $runtime_id |
      ($containers | length) == 1 and
      ($runtimes | length) == 1 and
      $status.active_target_count == 1 and
      $status.active_targets_truncated == false and
      ($status.active_targets | length) == 1 and
      $target.profile_id == $profile and
      $target.candidate_content_id == $status.active_candidate_content_id and
      $target.operation == $operation and
      (if $predecessor == "" then
         $target.predecessor_candidate_content_id == null
       else
         $target.predecessor_candidate_content_id == $predecessor
       end) and
      $target.policy_source_revision_id ==
        $pod.metadata.annotations["mithril.erebor.dev/policy-source-revision"] and
      $target.node_id == $node.metadata.annotations["mithril.erebor.dev/node-id"] and
      $target.kubernetes_node_name == $pod.spec.nodeName and
      $target.kubernetes_node_name == $node.metadata.name and
      $target.kubernetes_node_uid == $node.metadata.uid and
      $target.kubernetes_node_uid ==
        $node.metadata.annotations["mithril.erebor.dev/node-uid"] and
      $target.node_boot_id ==
        $node.metadata.annotations["mithril.erebor.dev/node-boot-id"] and
      $target.label_epoch ==
        ($node.metadata.annotations["mithril.erebor.dev/label-epoch"] | tonumber) and
      $target.namespace_name == $pod.metadata.namespace and
      $target.pod_name == $pod.metadata.name and
      $target.pod_uid == $pod.metadata.uid and
      $target.container_name == $container and
      $target.image_digest == ($containers[0].image | split("@") | last) and
      $target.runtime_container_id == $runtime_id and
      ($target.runtime_binding_id | length) > 0 and
      $target.container_generation >= 1
    ' >/dev/null
}
