#!/usr/bin/env bash

set -euo pipefail

stage=${1:-}
request_directory=${2:-/run/mithril-identity-create-runtime}
[[ $stage == createRuntime ]] || {
  echo "Mithril OCI admission requires createRuntime" >&2
  exit 1
}
[[ -d $request_directory && ! -L $request_directory \
  && $(stat -c %u "$request_directory") -eq 0 \
  && $(stat -c %a "$request_directory") == 700 ]] || {
  echo "Mithril createRuntime request directory is not a root-owned mode-0700 directory" >&2
  exit 1
}

state=$(mktemp "$request_directory/.state.XXXXXX")
cleanup() {
  rm -f -- "$state"
}
trap cleanup EXIT

jq -e 'select(type == "object")' >"$state"
pid=$(jq -er '.pid | select(type == "number" and . > 0)' "$state")
[[ -r /proc/$pid/status ]] || {
  echo "Mithril createRuntime OCI state PID is not live" >&2
  exit 1
}
cgroup=$(awk -F: '$1 == "0" && $2 == "" { print $3; found = 1 } END { exit !found }' "/proc/$pid/cgroup")
procs=/sys/fs/cgroup${cgroup}/cgroup.procs
mapfile -t live_pids <"$procs"
[[ ${#live_pids[@]} -eq 1 && ${live_pids[0]} == "$pid" ]] || {
  echo "Mithril createRuntime cgroup does not contain only the OCI state PID" >&2
  exit 1
}

container_type=$(jq -er '.annotations["io.kubernetes.cri.container-type"]' "$state")
[[ $container_type == container ]] || exit 0
container_id=$(jq -er '.id' "$state")
[[ $container_id =~ ^[0-9a-f]{64}$ ]] || {
  echo "Mithril createRuntime state has no exact containerd container ID" >&2
  exit 1
}

request=$request_directory/$container_id.createRuntime.json
release=$request_directory/$container_id.createRuntime.release
[[ ! -e $request && ! -e $release ]] || {
  echo "Mithril createRuntime request already exists for $container_id" >&2
  exit 1
}
temporary=$(mktemp "$request_directory/.request.XXXXXX")
trap 'rm -f -- "$state" "$temporary"' EXIT
jq -n \
  --arg stage "$stage" \
  --argjson pid "$pid" \
  --arg cgroup "$cgroup" \
  --argjson state "$(<"$state")" \
  --argjson annotations "$(jq -ec '.annotations | select(type == "object")' "$state")" \
  '{
    stage: $stage,
    pid: $pid,
    cgroup: $cgroup,
    state: $state,
    annotations: $annotations
  }' >"$temporary"
chmod 0600 -- "$temporary"
mv -- "$temporary" "$request"
trap cleanup EXIT

for ((attempt = 0; attempt < 600; attempt++)); do
  if [[ -f $release ]]; then
    response=$(<"$release")
    rm -f -- "$request" "$release"
    [[ $response == "accepted:$pid" ]] || {
      echo "Mithril rejected createRuntime admission for $container_id" >&2
      exit 1
    }
    exit 0
  fi
  sleep 0.05
done

echo "Mithril createRuntime admission timed out for $container_id" >&2
exit 1
