#!/usr/bin/env bash

set -euo pipefail

chart_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

bash "$chart_directory/tests/runtime-hook-owner-test.sh"

helm lint "$chart_directory" --values "$chart_directory/tests/values.yaml"
helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" >/dev/null

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
