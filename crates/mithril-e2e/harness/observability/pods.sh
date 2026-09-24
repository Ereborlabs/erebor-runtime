#!/usr/bin/env bash
set -euo pipefail

if (($# != 4)); then
  echo "usage: $0 TEST_BINARY BPFTRACE_SHA256 POD_MANIFEST OUTPUT_DIRECTORY" >&2
  exit 2
fi
test_binary=$1
backend_sha256=$2
manifest=$3
output=$4
[[ $(id -u) == 0 && -x $test_binary && -r $manifest && ! -e $output ]] || exit 2
k3s=/usr/local/bin/k3s
namespace=araphor-observability-qualification
owned=false
cleanup() {
  if [[ $owned == true ]]; then
    "$k3s" kubectl delete namespace "$namespace" --wait=true --timeout=120s
  fi
}
trap cleanup EXIT
"$k3s" kubectl create namespace "$namespace"
owned=true
"$k3s" kubectl apply -f "$manifest"
"$k3s" kubectl -n "$namespace" wait --for=condition=Ready pod/target pod/foreign --timeout=180s
container=$("$k3s" kubectl -n "$namespace" get pod target -o jsonpath='{.status.containerStatuses[0].containerID}')
[[ $container == containerd://* ]] || exit 1
pid=$("$k3s" crictl inspect "${container#containerd://}" | jq -er '.info.pid')
[[ $pid =~ ^[0-9]+$ && $pid -gt 1 ]] || exit 1
cgroup=$(awk -F: '$1 == "0" {print $3}' "/proc/$pid/cgroup")
[[ $cgroup == /* && $cgroup != / && $cgroup != *..* ]] || exit 1
status=0
"$test_binary" --executable /usr/bin/bpftrace --sha256 "$backend_sha256" \
  --output-directory "$output" --pod-cgroup "/sys/fs/cgroup$cgroup" || status=$?
"$k3s" kubectl -n "$namespace" get pods -o json >"$output/pods.json"
"$k3s" crictl inspect "${container#containerd://}" >"$output/target-cri.json"
exit "$status"
