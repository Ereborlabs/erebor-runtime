#!/usr/bin/env bash

set -euo pipefail

chart_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

bash "$chart_directory/tests/runtime-hook-owner-test.sh"

helm lint "$chart_directory" --values "$chart_directory/tests/values.yaml"
helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" >/dev/null

default_node_logs=$(helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --show-only templates/daemonset.yaml)
grep -Fq 'value: "info"' <<<"$default_node_logs"

default_control_logs=$(helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --show-only templates/control-deployment.yaml)
grep -Fq 'value: "info"' <<<"$default_control_logs"
grep -Fq 'key: mithril.erebor.dev/not-ready' <<<"$default_control_logs"
grep -Fq 'effect: NoSchedule' <<<"$default_control_logs"

node_logs=$(helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --show-only templates/daemonset.yaml \
  --set-string 'node.logFilter=mithril_node::runtime_admission=debug')
grep -Fq 'value: "mithril_node::runtime_admission=debug"' <<<"$node_logs"

control_logs=$(helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --show-only templates/control-deployment.yaml \
  --set-string 'control.logFilter=mithril_control::store=trace')
grep -Fq 'value: "mithril_control::store=trace"' <<<"$control_logs"

hook_logs=$(helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --show-only templates/runtime-hook-configmap.yaml \
  --set-string 'node.logFilter=mithril_oci_hook=debug')
[[ $(grep -Fc '"env": ["RUST_LOG=mithril_oci_hook=debug"]' <<<"$hook_logs") -eq 3 ]]

if helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --set-string 'control.logFilter=' >/dev/null 2>&1; then
  echo 'chart accepted an empty Control log filter' >&2
  exit 1
fi

if helm template mithril "$chart_directory" --namespace mithril-system >/dev/null 2>&1; then
  echo 'chart accepted a missing admission CA bundle' >&2
  exit 1
fi

if helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --set control.admission.webhookTimeoutSeconds=31 >/dev/null 2>&1; then
  echo 'chart accepted an unbounded admission timeout' >&2
  exit 1
fi

helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --set node.runtimeHook.install=false >/dev/null

if helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --set node.runtimeHook.timeoutMs=5000 >/dev/null 2>&1; then
  echo 'chart accepted an OCI client timeout without outer runtime margin' >&2
  exit 1
fi

helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --set node.runtimeHook.socketPath=/run/mithril/custom-runtime-admission.sock \
  >/dev/null

if helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --set node.runtimeHook.socketPath=/tmp/runtime-admission.sock >/dev/null 2>&1; then
  echo 'chart accepted a runtime-admission socket outside /run/mithril' >&2
  exit 1
fi

if helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --set node.runtimeHook.socketPath=/run/mithril/nested/runtime-admission.sock \
  >/dev/null 2>&1; then
  echo 'chart accepted a socket parent that the chart does not create' >&2
  exit 1
fi

if helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --set node.runtimeHook.socketPath=/run/mithril/../runtime-admission.sock \
  >/dev/null 2>&1; then
  echo 'chart accepted a non-normalized runtime-admission socket path' >&2
  exit 1
fi
