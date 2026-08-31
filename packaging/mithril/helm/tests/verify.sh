#!/usr/bin/env bash

set -euo pipefail

chart_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

helm lint "$chart_directory" --values "$chart_directory/tests/values.yaml"
rendered=$(helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml")
if grep -Fq 'helm.sh/hook: pre-delete' <<<"$rendered" ||
   grep -Fq 'mithril-runtime-hook-cleanup' <<<"$rendered"; then
  echo 'chart rendered Kubernetes-authorized host cleanup' >&2
  exit 1
fi

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
grep -Fq 'name: install-runtime-gate' <<<"$node_logs"
grep -Fq 'command: ["/usr/local/bin/mithril-oci-hook", "install"]' <<<"$node_logs"
[[ $(grep -Fc 'value: "mithril_node::runtime_admission=debug"' <<<"$node_logs") -eq 2 ]]
grep -Fq 'path: "/var/lib/rancher/k3s/agent/etc/containerd"' <<<"$node_logs"
grep -Fq 'path: "/usr/local/bin/k3s"' <<<"$node_logs"
grep -Fq -- '--node-read-only-mount' <<<"$node_logs"
grep -Fq -- '--node-read-write-mount' <<<"$node_logs"
if grep -Fq 'runtime-hook-injector' <<<"$node_logs" ||
   grep -Fq '/var/run/nri/nri.sock' <<<"$node_logs"; then
  echo 'chart rendered an NRI runtime-hook owner' >&2
  exit 1
fi

runtime_mounts=$(helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --show-only templates/daemonset.yaml \
  --set-string 'node.containerRuntimeSocket=/run/k3s/containerd/containerd.sock')
grep -Fq 'mountPath: "/run/k3s/containerd"' <<<"$runtime_mounts"
grep -Fq 'path: "/run/k3s/containerd"' <<<"$runtime_mounts"
grep -Fq 'type: Directory' <<<"$runtime_mounts"
if grep -Fq '/run/k3s/containerd/containerd.sock' <<<"$runtime_mounts"; then
  echo 'chart bind-mounted a replaceable runtime socket inode' >&2
  exit 1
fi

if helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --set-string 'node.containerRuntimeSocket=/run/k3s/containerd/../containerd.sock' \
  >/dev/null 2>&1; then
  echo 'chart accepted a non-normalized container-runtime socket path' >&2
  exit 1
fi

control_logs=$(helm template mithril "$chart_directory" \
  --namespace mithril-system \
  --values "$chart_directory/tests/values.yaml" \
  --show-only templates/control-deployment.yaml \
  --set-string 'control.logFilter=mithril_control::store=trace')
grep -Fq 'value: "mithril_control::store=trace"' <<<"$control_logs"

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
