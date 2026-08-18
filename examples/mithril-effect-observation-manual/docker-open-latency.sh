#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/observation-runtime.sh"
[[ $# -eq 3 || $# -eq 4 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path> [opens]" >&2
  exit 2
}

observation_opens=${4:-10000}
[[ $observation_opens =~ ^[1-9][0-9]*$ ]] || {
  echo "opens must be a positive integer" >&2
  exit 2
}
observation_measure='import json, mmap, os, sys, time
ready, path, iterations, output = sys.argv[1:]
iterations = int(iterations)
output_map = None
if ready != "-":
    release = os.environ["MITHRIL_MANUAL_RELEASE"]
    output_file = open(output, "r+b", buffering=0)
    output_map = mmap.mmap(output_file.fileno(), 4096, access=mmap.ACCESS_WRITE)
    os.mkfifo(release, 0o600)
    release_fd = os.open(release, os.O_RDWR)
    with open(ready, "w", encoding="ascii") as target:
        target.write(str(os.getpid()))
    os.read(release_fd, 1)
    os.close(release_fd)
for _ in range(min(iterations, 1000)):
    with open(path, "rb"):
        pass
started = time.perf_counter_ns()
for _ in range(iterations):
    with open(path, "rb"):
        pass
elapsed = time.perf_counter_ns() - started
result = {"opens": iterations, "elapsed_ns": elapsed, "ns_per_open": elapsed / iterations}
result_json = json.dumps(result)
if output_map is None:
    print(result_json)
else:
    payload = (result_json + "\n").encode("ascii")
    output_map[:len(payload)] = payload'

observation_baseline=$(docker exec "$2" python3 -c "$observation_measure" \
  - "$3" "$observation_opens" -)
observation_prepare_docker "$1" "$2" "$3"
observation_latency_name=mithril-effect-observation-latency-$$.json
observation_latency_result=${MITHRIL_MANUAL_DOCKER_CONTAINER_SHARED_DIRECTORY:?}/$observation_latency_name
observation_latency_result_host=${MITHRIL_MANUAL_DOCKER_HOST_SHARED_DIRECTORY:?}/$observation_latency_name
truncate -s 4096 -- "$observation_latency_result_host"
observation_cleanup_latency() {
  rm -f -- "$observation_latency_result_host"
}
identity_cleanup_functions+=(observation_cleanup_latency)

observation_preload_probe python3 -c "$observation_measure" \
  "$observation_probe_ready" "$3" "$observation_opens" "$observation_latency_result"
if ! observation_release_probe; then
  tr -d '\0' <"$observation_latency_result_host" >&2
  "$identity_inspect" effects --socket-path "$observation_socket" \
    --cgroup-scope "$observation_scope" >"$identity_work/effects-failure.txt" || true
  cat "$identity_work/effects-failure.txt" >&2
  exit 1
fi
observation_wait_for_observation 'reason=WOULD_DENY' "$identity_work/effects.txt"
observation_lost=$(observation_health_field lost "$identity_work/effects.txt")
observation_attempted=$(observation_health_field attempted "$identity_work/effects.txt")
observation_emitted=$(observation_health_field emitted "$identity_work/effects.txt")
[[ $observation_lost -eq 0 && $observation_attempted -eq $observation_emitted \
  && $observation_attempted -ge $observation_opens ]] || {
  cat "$identity_work/effects.txt" >&2
  echo "latency run has incomplete observations; its timing is not valid evidence" >&2
  exit 1
}
observation_observe=$(tr -d '\0' <"$observation_latency_result_host")
jq -n --argjson baseline "$observation_baseline" --argjson observe "$observation_observe" \
  '{schema_version: 1, baseline: $baseline, observe: $observe,
    added_ns_per_open: ($observe.ns_per_open - $baseline.ns_per_open),
    ratio: ($observe.ns_per_open / $baseline.ns_per_open)}' \
  | tee "$identity_work/latency.json"
identity_pass "PASS: baseline and live observe-only open latency were measured with zero reported ring loss."
