#!/usr/bin/env bash

assert_mithril_node_name_denial() {
  local output
  if output=$("$@" 2>&1); then
    echo "Kubernetes accepted a protected Pod with spec.nodeName" >&2
    return 1
  fi
  # Require the webhook and its policy reason. A transport error is not a denial.
  if [[ $output != *'admission webhook "pods.mithril.erebor.dev" denied the request'* ||
        $output != *'protected Pod cannot set spec.nodeName'* ]]; then
    echo "Kubernetes returned an unrelated protected-Pod error: $output" >&2
    return 1
  fi
}
