#!/usr/bin/env bash

set -euo pipefail

chart_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

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

if helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --set node.runtimeHook.timeoutMs=5000 >/dev/null 2>&1; then
  echo 'chart accepted an OCI client timeout without outer runtime margin' >&2
  exit 1
fi
