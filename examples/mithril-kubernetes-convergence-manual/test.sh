#!/usr/bin/env bash

set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
test_root=$(mktemp -d /tmp/mithril-convergence-example-test.XXXXXX)
test_cleanup() {
  local status=$?
  trap - EXIT
  rm -rf -- "$test_root"
  exit "$status"
}
trap test_cleanup EXIT

oracles=$directory/kubernetes-oracles.sh
source "$oracles"

mkdir "$test_root/oracle-bin"
cat >"$test_root/oracle-bin/kubectl" <<'EOF'
#!/usr/bin/env bash
case ${FAKE_KUBECTL_RESULT:?} in
  node-name)
    echo 'Error from server: admission webhook "pods.mithril.erebor.dev" denied the request: Mithril Control configuration is invalid: protected Pod cannot set spec.nodeName' >&2
    exit 1
    ;;
  unrelated)
    echo 'Unable to connect to the server' >&2
    exit 1
    ;;
  success)
    exit 0
    ;;
esac
EOF
chmod +x "$test_root/oracle-bin/kubectl"

PATH="$test_root/oracle-bin:$PATH" FAKE_KUBECTL_RESULT=node-name \
  assert_mithril_node_name_denial kubectl create -f bypass.json
if PATH="$test_root/oracle-bin:$PATH" FAKE_KUBECTL_RESULT=unrelated \
    assert_mithril_node_name_denial kubectl create -f bypass.json >/dev/null 2>&1; then
  echo "an unrelated API failure satisfied the nodeName denial oracle" >&2
  exit 1
fi
if PATH="$test_root/oracle-bin:$PATH" FAKE_KUBECTL_RESULT=success \
    assert_mithril_node_name_denial kubectl create -f bypass.json >/dev/null 2>&1; then
  echo "a successful Pod create satisfied the nodeName denial oracle" >&2
  exit 1
fi

manual_bin=$test_root/manual-bin
mkdir "$manual_bin"
cat >"$manual_bin/id" <<'EOF'
#!/usr/bin/env bash
if [[ ${1:-} == -u ]]; then
  echo 0
else
  exec /usr/bin/id "$@"
fi
EOF
chmod +x "$manual_bin/id"
cat >"$manual_bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${TEST_KUBECTL_LOG:?}"

not_found() {
  echo "Error from server (NotFound): the requested resource was not found" >&2
  exit 1
}

if [[ ${TEST_MANUAL_MODE:?} == refusal ]]; then
  if [[ ${1:-} == get && ${2:-} == namespace ]]; then
    [[ ${TEST_EXISTING_RESOURCE:?} == namespace ]] && exit 0
    not_found
  fi
  if [[ ${1:-} == get && ${2:-} == runtimeclass ]]; then
    if [[ ${TEST_EXISTING_RESOURCE:?} == runtimeclass &&
          ${3:-} == mithril-convergence-manual ]]; then
      exit 0
    fi
    not_found
  fi
  [[ $* == "get --raw=/readyz" ]] && exit 0
  [[ ${1:-} == -n && ${3:-} == rollout && ${4:-} == status ]] && exit 0
  exit 98
fi

if [[ $* == "get --raw=/readyz" ||
      (${1:-} == -n && ${3:-} == rollout && ${4:-} == status) ]]; then
  exit 0
fi
if [[ ${1:-} == get && ${2:-} == namespace ]] ||
   [[ ${1:-} == get && ${2:-} == runtimeclass ]]; then
  not_found
fi
if [[ ${1:-} == -n && ${3:-} == get && ${4:-} == pods &&
      ${!#} == json ]]; then
  printf '%s\n' '{"items":[{"spec":{"nodeName":"node-a"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"spec":{"nodeName":"node-b"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}'
  exit 0
fi
if [[ ${1:-} == get && ${2:-} == node ]]; then
  printf '%s\n' '{"metadata":{"labels":{"mithril.erebor.dev/ready":"true"}},"spec":{"taints":[]}}'
  exit 0
fi
if [[ ${1:-} == -n && ${3:-} == get && ${4:-} == pods &&
      $* == *"jsonpath="* ]]; then
  printf '%s' mithril-node
  exit 0
fi
if [[ $* == *"mithril-inspect policy-delivery"* ]]; then
  printf '%s\n' '{"active_candidate_content_id":null,"active_profile_ids":[],"scheduled_binding_count":0,"runtime_binding_count":0,"pending_exception_count":0,"active_exception_count":0,"terminal_exception_count":0}'
  exit 0
fi
if [[ ${1:-} == -n && $* == *" exec "* ]]; then
  exit 0
fi
if [[ ${1:-} == create && ${2:-} == --raw ]]; then
  counter=$(<"${TEST_RBAC_COUNTER:?}")
  # These decisions match the status-only Control boundary before resource creation.
  decisions=(true true true true true false false false)
  printf '%s' "$((counter + 1))" >"$TEST_RBAC_COUNTER"
  printf '{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","status":{"allowed":%s}}\n' \
    "${decisions[$counter]}"
  exit 0
fi
if [[ ${1:-} == apply ]]; then
  exit 0
fi
if [[ ${1:-} == create && ${2:-} == namespace ]]; then
  exit 0
fi
if [[ ${1:-} == -n && ${3:-} == create && ${4:-} == serviceaccount &&
      ${5:-} == converter ]]; then
  exit 42
fi
if [[ ${1:-} == delete && ${2:-} == namespace ]]; then
  exit 55
fi
if [[ ${1:-} == delete && ${2:-} == runtimeclass ]]; then
  exit 0
fi
exit 97
EOF
chmod +x "$manual_bin/kubectl"

for existing_resource in namespace runtimeclass; do
  manual_log=$test_root/manual-$existing_resource.log
  set +e
  manual_refusal=$(PATH="$manual_bin:$PATH" TEST_MANUAL_MODE=refusal \
    TEST_KUBECTL_LOG="$manual_log" TEST_EXISTING_RESOURCE="$existing_resource" \
    "$directory/run.sh" 2>&1)
  status=$?
  set -e
  [[ $status -eq 2 && $manual_refusal == \
    *"manual scenario refuses to replace an existing resource"* ]]
  ! grep -q ' delete ' "$manual_log"
done

cleanup_log=$test_root/manual-cleanup.log
rbac_counter=$test_root/rbac-counter
printf '0' >"$rbac_counter"
set +e
PATH="$manual_bin:$PATH" TEST_MANUAL_MODE=cleanup \
  TEST_KUBECTL_LOG="$cleanup_log" TEST_RBAC_COUNTER="$rbac_counter" \
  "$directory/run.sh" >/dev/null 2>&1
status=$?
set -e
[[ $status -eq 42 ]]
grep -q '^delete namespace mithril-convergence-manual ' "$cleanup_log"
grep -q '^delete runtimeclass mithril-convergence-manual ' "$cleanup_log"
grep -q '^delete runtimeclass mithril-convergence-manual-fail ' "$cleanup_log"
[[ $(grep -c '^get namespace mithril-convergence-manual$' "$cleanup_log") -eq 2 ]]
[[ $(grep -c '^get runtimeclass mithril-convergence-manual$' "$cleanup_log") -eq 2 ]]
[[ $(grep -c '^get runtimeclass mithril-convergence-manual-fail$' "$cleanup_log") -eq 2 ]]
[[ $(grep -c ' exec .* rm -f /var/lib/mithril/markers/' "$cleanup_log") -eq 24 ]]
[[ $(grep -c ' exec .* test ! -e /var/lib/mithril/markers/' "$cleanup_log") -eq 12 ]]

echo "Manual convergence example behavior checks passed"
