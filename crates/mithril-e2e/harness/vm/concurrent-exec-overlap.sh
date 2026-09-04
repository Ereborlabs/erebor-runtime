#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $0 START_FIFO OUTPUT_DIRECTORY CONTAINER_ID EXEC_COUNT" >&2
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  usage
  exit 0
fi

(($# == 4)) || {
  usage
  exit 2
}

start_fifo=$1
output_directory=$2
container_id=$3
exec_count=$4
k3s_path=${MITHRIL_K3S_PATH:-/usr/local/bin/k3s}

[[ $start_fifo == /* && -p $start_fifo ]] || {
  echo "the concurrent-read start path is not an absolute FIFO: $start_fifo" >&2
  exit 2
}
[[ $output_directory == /* && ! -e $output_directory ]] || {
  echo "the concurrent-exec output path is not new and absolute: $output_directory" >&2
  exit 2
}
[[ $container_id =~ ^[0-9a-f]{64}$ ]] || {
  echo "the concurrent-exec container ID is invalid" >&2
  exit 2
}
[[ $exec_count =~ ^[0-9]+$ ]] && ((exec_count >= 1 && exec_count <= 32)) || {
  echo "the concurrent-exec count must be from 1 through 32" >&2
  exit 2
}
[[ $k3s_path == /* && -x $k3s_path ]] || {
  echo "the K3s executable is unavailable: $k3s_path" >&2
  exit 2
}

mkdir -p -- "$output_directory"
printf 'start\n' >"$start_fifo"

pids=()
for ((slot = 0; slot < exec_count; slot++)); do
  (
    status=0
    "$k3s_path" crictl exec "$container_id" /bin/sleep 5 \
      >"$output_directory/$slot.out" 2>&1 || status=$?
    printf '%s\n' "$status" >"$output_directory/$slot.status"
  ) &
  pids+=("$!")
done
for pid in "${pids[@]}"; do
  wait "$pid"
done

all_denied=true
for ((slot = 0; slot < exec_count; slot++)); do
  status=$(<"$output_directory/$slot.status")
  [[ $status =~ ^[0-9]+$ ]] || {
    echo "concurrent exec $slot did not record an exit status" >&2
    exit 1
  }
  printf 'slot=%s status=%s\n' "$slot" "$status"
  ((status != 0)) || all_denied=false
done
[[ $all_denied == true ]] || {
  echo "a concurrent external exec entered the protected container" >&2
  exit 1
}
