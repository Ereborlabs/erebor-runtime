#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/observation-runtime.sh"
[[ $# -eq 3 || $# -eq 4 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path> [opens]" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
observation_opens=${4:-10000}
[[ $observation_opens =~ ^[1-9][0-9]*$ ]] || {
  echo "opens must be a positive integer" >&2
  exit 2
}
observation_measure='import json, sys, time
path, iterations, output = sys.argv[1:]
iterations = int(iterations)
for _ in range(min(iterations, 1000)):
    with open(path, "rb"):
        pass
started = time.perf_counter_ns()
for _ in range(iterations):
    with open(path, "rb"):
        pass
elapsed = time.perf_counter_ns() - started
result = {"opens": iterations, "elapsed_ns": elapsed, "ns_per_open": elapsed / iterations}
if output == "-":
    print(json.dumps(result))
else:
    with open(output, "w", encoding="utf-8") as target:
        json.dump(result, target)'

observation_baseline=$(docker exec "$2" python3 -c "$observation_measure" "$3" "$observation_opens" -)
observation_latency_result=/tmp/mithril-effect-observation-latency-$$.json
observation_cleanup_latency() {
  rm -f -- "/proc/$identity_init_pid/root$observation_latency_result"
}
identity_cleanup_functions+=(observation_cleanup_latency)

observation_preload_probe python3 -c '
import os, sys
ready, measurement, path, iterations, output = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as target:
    target.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
sys.argv = [sys.argv[0], path, iterations, output]
exec(measurement)
' "$observation_probe_ready" "$observation_measure" "$3" "$observation_opens" "$observation_latency_result"
observation_release_probe
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
observation_observe=$(<"/proc/$identity_init_pid/root$observation_latency_result")
jq -n --argjson baseline "$observation_baseline" --argjson observe "$observation_observe" \
  '{schema_version: 1, baseline: $baseline, observe: $observe,
    added_ns_per_open: ($observe.ns_per_open - $baseline.ns_per_open),
    ratio: ($observe.ns_per_open / $baseline.ns_per_open)}' \
  | tee "$identity_work/latency.json"
identity_pass "PASS: baseline and live observe-only open latency were measured with zero reported ring loss."
