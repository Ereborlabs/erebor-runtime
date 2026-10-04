#!/usr/bin/env bash
set -euo pipefail

if (($# != 4)); then
  echo "usage: $0 LIBTEST_BINARY QUALIFIED_CONFIG|--test-admission RUNTIME_BUNDLE OUTPUT_DIRECTORY" >&2
  exit 2
fi
test_binary=$1
trace_config=$2
runtime_bundle=$3
output=$4
[[ $(id -u) == 0 && -x $test_binary && $output == /* && ! -e $output ]] || exit 2
[[ $trace_config == --test-admission || -r $trace_config ]] || exit 2
[[ -d $runtime_bundle/lib && -f $runtime_bundle/bpftrace && -r $runtime_bundle/SHA256SUMS ]] || exit 2
: "${MITHRIL_TEST_ROOT:?set the extracted repository fixture root}"
: "${MITHRIL_TEST_NODE_IMAGE:?set the prepared Node image}"
: "${MITHRIL_TEST_CONTROL_IMAGE:?set the prepared Control image}"
: "${MITHRIL_TEST_ACTOR_IMAGE:?set the pinned actor image}"
mkdir -- "$output"
export MITHRIL_TEST_OUTPUT="$output/lifecycle"
if [[ $trace_config == --test-admission ]]; then
  export MITHRIL_TRACE_TEST_ADMISSION=1
  unset MITHRIL_TRACE_CONFIG
else
  unset MITHRIL_TRACE_TEST_ADMISSION
  export MITHRIL_TRACE_CONFIG="$trace_config"
fi
export MITHRIL_TRACE_RUNTIME="$runtime_bundle"
export MITHRIL_TRACE_PROOF="$output/result.json"
"$test_binary" observability::tests::observability_owned_upload \
  --exact --nocapture >"$output/lightweight.log" 2>&1
"$test_binary" platform::kubernetes::observability_pod_finish \
  --exact --nocapture >"$output/lightweight-finish.log" 2>&1
"$test_binary" platform::kubernetes::observability_pod_replacement \
  --ignored --exact --nocapture --test-threads=1 >"$output/test.log" 2>&1
[[ -s $MITHRIL_TRACE_PROOF ]]
jq -e --arg admission "${MITHRIL_TRACE_TEST_ADMISSION:-}" '
  .schema_version == 1 and .case == "owned-pod-replacement" and .result == "PASS"
  and .physical == true and .performance_claim == false and .discovery_enabled == false
  and (if $admission == "1" then
    .diagnostic_admission == "synthetic-test-only" and .performance_qualified == false
    and (has("qualification") | not)
  else true end)
  and .original_retry == true and .original_output_unchanged == true
  and .cleanup_observed == true and .enforcement_resources_unchanged == true
  and .resources.initial == .resources.final
  and (.physical_denials | length == 2 and all(.errno == 13 and .size == 0
    and .event.reason == "EXACT_POLICY_DENY" and .event.kernel_result == -13))
  and (.diagnostic_resources | all(.programs | length > 0) and all(.maps | length > 0))
  and .original.attachment_notifications == 1 and .replacement.attachment_notifications == 1
  and .original.terminal.reason == "TargetChanged" and .replacement.terminal.reason == "Cancelled"
  and .original.terminal.output_incomplete == true and .replacement.terminal.output_incomplete == true
  and .original.terminal.kernel_lost_events == null and .replacement.terminal.kernel_lost_events == null
  and .original.terminal.cleanup != "Failed" and .replacement.terminal.cleanup != "Failed"
  and .original.receipt.identity.execution_id == .original.terminal.execution_id
  and .replacement.receipt.identity.execution_id == .replacement.terminal.execution_id
  and .original.terminal.execution_id != .replacement.terminal.execution_id
  and .original.accepted.recipe == "FailedOpens" and .replacement.accepted.recipe == "FailedOpens"
  and .original.accepted.request.source == .replacement.accepted.request.source
  and .original.accepted.request.targets[0].fact.kubernetes.pod_name
    == .replacement.accepted.request.targets[0].fact.kubernetes.pod_name
  and .original.accepted.request.targets[0].fact.pod_uid
    != .replacement.accepted.request.targets[0].fact.pod_uid
  and .original.accepted.request.targets[0].runtime_container_id
    != .replacement.accepted.request.targets[0].runtime_container_id
  and .original.accepted.request.targets[0].cgroup_id
    != .replacement.accepted.request.targets[0].cgroup_id
  and .original.accepted.request.targets[0].root_cgroup_live_interval_id
    != .replacement.accepted.request.targets[0].root_cgroup_live_interval_id
' "$MITHRIL_TRACE_PROOF" >/dev/null
