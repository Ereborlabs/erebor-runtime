#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 || $# -eq 4 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path> [opens]" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase3_opens=${4:-10000}
[[ $phase3_opens =~ ^[1-9][0-9]*$ ]] || {
  echo "opens must be a positive integer" >&2
  exit 2
}
phase3_measure='import json, sys, time
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

phase3_baseline=$(docker exec "$2" python3 -c "$phase3_measure" "$3" "$phase3_opens" -)
phase3_latency_result=/tmp/mithril-phase3-latency-$$.json
phase3_cleanup_latency() {
  rm -f -- "/proc/$phase2_init_pid/root$phase3_latency_result"
}
phase2_cleanup_functions+=(phase3_cleanup_latency)

phase3_preload_probe python3 -c '
import os, signal, sys
ready, measurement, path, iterations, output = sys.argv[1:]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as target:
    target.write(str(os.getpid()))
signal.pause()
sys.argv = [sys.argv[0], path, iterations, output]
exec(measurement)
' "$phase3_probe_ready" "$phase3_measure" "$3" "$phase3_opens" "$phase3_latency_result"
phase3_release_probe
phase3_wait_for_observation 'reason=WOULD_DENY' "$phase2_work/effects.txt"
phase3_lost=$(phase3_health_field lost "$phase2_work/effects.txt")
phase3_attempted=$(phase3_health_field attempted "$phase2_work/effects.txt")
phase3_emitted=$(phase3_health_field emitted "$phase2_work/effects.txt")
[[ $phase3_lost -eq 0 && $phase3_attempted -eq $phase3_emitted \
  && $phase3_attempted -ge $phase3_opens ]] || {
  cat "$phase2_work/effects.txt" >&2
  echo "latency run has incomplete observations; its timing is not valid evidence" >&2
  exit 1
}
phase3_observe=$(<"/proc/$phase2_init_pid/root$phase3_latency_result")
jq -n --argjson baseline "$phase3_baseline" --argjson observe "$phase3_observe" \
  '{schema_version: 1, baseline: $baseline, observe: $observe,
    added_ns_per_open: ($observe.ns_per_open - $baseline.ns_per_open),
    ratio: ($observe.ns_per_open / $baseline.ns_per_open)}' \
  | tee "$phase2_work/latency.json"
phase2_pass "PASS: baseline and live observe-only open latency were measured with zero reported ring loss."
