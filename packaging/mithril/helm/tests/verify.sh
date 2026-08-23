#!/usr/bin/env bash

set -euo pipefail

chart_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
rendered=$(mktemp)
trap 'rm -f "$rendered"' EXIT

helm lint "$chart_directory" --values "$chart_directory/tests/values.yaml"
helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" >"$rendered"

require() {
  local pattern=$1
  local reason=$2
  if ! rg --quiet --multiline "$pattern" "$rendered"; then
    echo "missing rendered contract: $reason" >&2
    exit 1
  fi
}

reject() {
  local pattern=$1
  local reason=$2
  if rg --quiet --multiline "$pattern" "$rendered"; then
    echo "forbidden rendered contract: $reason" >&2
    exit 1
  fi
}

require 'kind: MutatingWebhookConfiguration' 'mutating admission registration'
require 'kind: ValidatingWebhookConfiguration' 'binding admission registration'
require 'failurePolicy: Fail' 'fail-closed webhooks'
require 'resources: \["pods/binding"\]' 'scheduler binding validation'
require 'operations: \["CREATE"\][[:space:]]+resources: \["pods"\]' 'create-only Pod mutation'
reject 'operations: \["CREATE", "UPDATE"\][[:space:]]+resources: \["pods"\]' 'bound Pod mutation'
require 'timeoutSeconds: 5' 'bounded Kubernetes webhook timeout'
require 'path: /healthz' 'admission health probes'
require 'name: admission-tls' 'admission TLS mount'
require 'key: mithril\.erebor\.dev/not-ready' 'DaemonSet quarantine toleration'
require 'name: MITHRIL_KUBERNETES_NODE_NAME' 'downward Node identity input'
require 'fieldPath: spec\.nodeName' 'scheduler-selected Node name source'
require 'mithril\.example/pool: protected' 'DaemonSet node selector'
require 'requiredDuringSchedulingIgnoredDuringExecution' 'DaemonSet required affinity'
require 'mithril-oci-hook' 'OCI prestart adapter installation'
require '"timeout": 5' 'bounded OCI runtime hook timeout'
require 'automountServiceAccountToken: false' 'node Kubernetes credential denial'
require 'resources: \["workloadprotectionprofiles"\]' 'cluster-wide profile read'
require 'resources: \["workloadprotectionprofiles/status"\]' 'profile status projection'
require 'resourceNames: \["mithril-node"\]' 'one DaemonSet RBAC scope'
require 'resources: \["daemonsets"\][[:space:]]+resourceNames: \["mithril-node"\][[:space:]]+verbs: \["get", "watch"\]' 'least-privilege DaemonSet read'
require 'resources: \["workloadprotectionprofiles/status"\][[:space:]]+verbs: \["patch"\]' 'least-privilege status projection'
require 'resources: \["nodes"\][[:space:]]+verbs: \["get", "list", "watch", "patch"\]' 'node readiness projection'
reject 'resources: \["workloadprotectionprofiles"\][[:space:]]+verbs: \[[^]]*(create|patch|update|delete)' 'policy desired-state write'
reject 'kind: ClusterRole[[:space:]]+metadata:[[:space:]]+name: mithril-node' 'node Kubernetes RBAC'

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
