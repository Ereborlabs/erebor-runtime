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
