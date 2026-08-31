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

write_mithril_node_name_bypass() {
  local manifest=$1
  local node_name=$2
  local output=$3
  shift 3

  # A server dry-run contains admission-owned fields and tests a different denial.
  "$@" create --dry-run=client -f "$manifest" -o json |
    jq --arg node "$node_name" '.spec.nodeName = $node' >"$output"
}

assert_recreated_node_unbound() {
  local node_json=$1
  local old_uid=$2

  # Control can quarantine a recreated Node before the first poll observes it.
  # The durable boundary is the new UID with no inherited Mithril identity.
  jq -e --arg old_uid "$old_uid" '
    .metadata.uid != $old_uid and
    (.metadata.labels["mithril.erebor.dev/ready"] // "") == "" and
    (.metadata.annotations["mithril.erebor.dev/node-id"] // "") == "" and
    (.metadata.annotations["mithril.erebor.dev/node-uid"] // "") == "" and
    (.metadata.annotations["mithril.erebor.dev/node-boot-id"] // "") == "" and
    (.metadata.annotations["mithril.erebor.dev/label-epoch"] // "") == ""
  ' <<<"$node_json" >/dev/null
}

retained_mithril_state() {
  local environment=$1

  jq -er '
    if .mithril == null then
      ["fresh", "-", "-", "-"]
    elif
      (.mithril | type) == "object" and
      (.mithril.control_state_claim |
        test("^mithril-control-state-[0-9]{14}-[0-9]+$")) and
      (.mithril.control_config_secret |
        test("^mithril-control-config-[0-9]{14}-[0-9]+$")) and
      (.mithril.admission_tls_secret |
        test("^mithril-admission-tls-[0-9]{14}-[0-9]+$"))
    then
      [
        "retained",
        .mithril.control_state_claim,
        .mithril.control_config_secret,
        .mithril.admission_tls_secret
      ]
    else
      error("retained Mithril state is incomplete")
    end | @tsv
  ' "$environment"
}

write_retained_environment() {
  (($# == 11)) || {
    echo "invalid retained environment output" >&2
    return 2
  }
  local output=$1
  local mithril_state_ready=$2
  local node_a=$3
  local node_a_work_directory=$4
  local node_b=$5
  local node_b_work_directory=$6
  local provider=$7
  local known_hosts=$8
  local control_state_claim=$9
  local control_config_secret=${10}
  local admission_tls_secret=${11}
  [[ $mithril_state_ready == true || $mithril_state_ready == false ]] || {
    echo "invalid retained Mithril state" >&2
    return 2
  }

  jq -n \
    --arg node_a "$node_a" \
    --arg node_a_work_directory "$node_a_work_directory" \
    --arg node_b "$node_b" \
    --arg node_b_work_directory "$node_b_work_directory" \
    --arg provider "$provider" \
    --arg known_hosts "$known_hosts" \
    --arg control_state_claim "$control_state_claim" \
    --arg control_config_secret "$control_config_secret" \
    --arg admission_tls_secret "$admission_tls_secret" \
    --argjson mithril_state_ready "$mithril_state_ready" \
    '{
      schema_version: 2,
      node_a: $node_a,
      node_a_work_directory: $node_a_work_directory,
      node_b: $node_b,
      node_b_work_directory: $node_b_work_directory,
      provider: $provider,
      known_hosts: $known_hosts,
      mithril: (if $mithril_state_ready then {
        control_state_claim: $control_state_claim,
        control_config_secret: $control_config_secret,
        admission_tls_secret: $admission_tls_secret
      } else null end)
    }' >"$output"
}

assert_exact_policy_target() {
  local status_json=$1
  local node_json=$2
  local pod_json=$3
  local profile_id=$4
  local container_name=$5
  local expected_operation=$6
  local expected_predecessor=${7:-}
  local expected_source_revision=${8:-}

  if [[ -z $expected_source_revision ]]; then
    expected_source_revision=$(jq -er \
      '.metadata.annotations["mithril.erebor.dev/policy-source-revision"]' \
      <<<"$pod_json")
  fi

  jq -e -n --argjson status "$status_json" --argjson node "$node_json" \
    --argjson pod "$pod_json" --arg profile "$profile_id" \
    --arg container "$container_name" --arg operation "$expected_operation" \
    --arg predecessor "$expected_predecessor" \
    --arg source_revision "$expected_source_revision" '
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
      $target.policy_source_revision_id == $source_revision and
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
retry_kubernetes_command() {
  local maximum_attempts=$1
  local retry_delay_seconds=$2
  shift 2
  [[ $maximum_attempts =~ ^[1-9][0-9]*$ &&
     $retry_delay_seconds =~ ^[0-9]+$ && $# -gt 0 ]] || {
    echo "invalid Kubernetes retry input" >&2
    return 2
  }
  local attempt
  local status=1
  for ((attempt = 1; attempt <= maximum_attempts; attempt++)); do
    if "$@"; then
      return 0
    else
      status=$?
    fi
    if ((attempt < maximum_attempts)); then
      sleep "$retry_delay_seconds"
    fi
  done
  return "$status"
}
