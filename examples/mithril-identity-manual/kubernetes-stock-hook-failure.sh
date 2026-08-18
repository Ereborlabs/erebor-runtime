#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

wait_for_stock_hook_result() {
  local pod_name=$1
  local expected=$2
  local attempt pod_json events_json result
  for ((attempt = 0; attempt < 450; attempt++)); do
    pod_json=$(kubectl -n "$identity_k3s_namespace" get pod "$pod_name" \
      -o json 2>/dev/null || true)
    result=$(jq -r --arg expected "$expected" '
      .status.containerStatuses[0].state.waiting
      | select((.message // "") | contains($expected))
      | "\(.reason // "UNKNOWN"): \(.message)"
    ' <<<"${pod_json:-null}" 2>/dev/null || true)
    if [[ -n $result ]]; then
      printf '%s\n' "$result"
      return 0
    fi
    events_json=$(kubectl -n "$identity_k3s_namespace" get events \
      --field-selector "involvedObject.name=$pod_name" -o json 2>/dev/null || true)
    result=$(jq -r --arg expected "$expected" '
      first(.items[]?
        | select((.message // "") | contains($expected))
        | "\(.reason // "UNKNOWN"): \(.message)") // empty
    ' <<<"${events_json:-null}" 2>/dev/null || true)
    if [[ -n $result ]]; then
      printf '%s\n' "$result"
      return 0
    fi
    result=$(journalctl -u k3s --since '2 minutes ago' --no-pager -o cat \
      | awk -v expected="$expected" 'index($0, expected) { print "K3S_JOURNAL: " $0; exit }')
    if [[ -n $result ]]; then
      printf '%s\n' "$result"
      return 0
    fi
    sleep 0.1
  done
  echo "the stock hook did not return: $expected" >&2
  return 1
}

wait_for_failed_container_removal() {
  local container_id=$1
  local attempt count
  for ((attempt = 0; attempt < 300; attempt++)); do
    count=$(crictl ps -a --id "$container_id" -o json \
      | jq -er '.containers | length')
    [[ $count -eq 0 ]] && return 0
    sleep 0.1
  done
  echo "the failed stock-hook container remains in CRI: $container_id" >&2
  return 1
}

identity_prepare_k3s_stock_hook_failure_case

for case_name in timeout mismatch missing-field; do
  pod_name=mithril-stock-hook-$case_name
  identity_create_stock_hook_failure_pod "$case_name"
  request=$(identity_wait_prestart_request "$pod_name" application)
  container_id=${request##*/}
  container_id=${container_id%.json}
  [[ $container_id =~ ^[0-9a-f]{64}$ ]] || {
    echo "the stock-hook request has an invalid container ID" >&2
    exit 1
  }

  case $case_name in
    timeout)
      identity_prestart_binding_json application application \
        11111111-1111-4111-8111-111111111701 \
        22222222-2222-4222-8222-222222222801 "$pod_name" \
        33333333-3333-4333-8333-333333333333 7 >/dev/null
      expected="Mithril prestart admission timed out for $container_id"
      ;;
    mismatch)
      temporary=$identity_work/mismatch-request.json
      jq '.state.id = ("0" * 64)' "$request" >"$temporary"
      chmod 0600 -- "$temporary"
      mv -- "$temporary" "$request"
      if validation_result=$(identity_prestart_binding_json application application \
        11111111-1111-4111-8111-111111111702 \
        22222222-2222-4222-8222-222222222802 "$pod_name" \
        33333333-3333-4333-8333-333333333333 7 2>&1); then
        echo "the mismatched prestart identity was accepted" >&2
        exit 1
      fi
      [[ $validation_result == *"prestart OCI state does not match"* ]] || {
        echo "the mismatch returned an unexpected validation result: $validation_result" >&2
        exit 1
      }
      printf 'rejected\n' >"${request%.json}.release"
      expected="Mithril rejected prestart admission for $container_id"
      ;;
    missing-field)
      temporary=$identity_work/missing-field-request.json
      jq 'del(.annotations["io.kubernetes.cri.sandbox-uid"])' \
        "$request" >"$temporary"
      chmod 0600 -- "$temporary"
      mv -- "$temporary" "$request"
      if validation_result=$(identity_prestart_binding_json application application \
        11111111-1111-4111-8111-111111111703 \
        22222222-2222-4222-8222-222222222803 "$pod_name" \
        33333333-3333-4333-8333-333333333333 7 2>&1); then
        echo "the prestart request without a Pod UID was accepted" >&2
        exit 1
      fi
      [[ $validation_result == *"prestart request has no Pod UID"* ]] || {
        echo "the missing field returned an unexpected validation result: $validation_result" >&2
        exit 1
      }
      printf 'rejected\n' >"${request%.json}.release"
      expected="Mithril rejected prestart admission for $container_id"
      ;;
  esac

  result=$(wait_for_stock_hook_result "$pod_name" "$expected")
  [[ ! -e $identity_k3s_shared_directory/$case_name.started ]] || {
    echo "the $case_name payload started after the stock-hook failure" >&2
    exit 1
  }
  kubectl -n "$identity_k3s_namespace" delete pod "$pod_name" \
    --wait=false >/dev/null
  identity_settle_stock_hook_requests
  kubectl -n "$identity_k3s_namespace" wait --for=delete "pod/$pod_name" \
    --timeout=120s >/dev/null
  wait_for_failed_container_removal "$container_id"
  printf '%s: %s\n' "$case_name" "$result"
done

identity_success_message='PASS: timeout, mismatched identity, and missing Pod UID each stopped container creation before the payload.'
