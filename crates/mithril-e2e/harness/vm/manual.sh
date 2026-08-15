#!/usr/bin/env bash

set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$directory/../../../.." && pwd)
run=$directory/run.sh
state_directory=${XDG_STATE_HOME:-$HOME/.local/state}/mithril-manual-vm
state=$state_directory/retained-vm.txt

usage() {
  echo "usage: $0 {start|ssh|destroy}" >&2
}

load_state() {
  [[ -r $state ]] || {
    echo "no manual VM exists; run: $0 start" >&2
    exit 2
  }
  set -a
  # The harness writes this file with shell-quoted values.
  . "$state"
  set +a
  [[ -n ${vm_name:-} && -n ${work_directory:-} && -x ${provider:-} ]] || {
    echo "manual VM state is invalid: $state" >&2
    exit 2
  }
}

case ${1:-} in
  start)
    (($# == 1)) || { usage; exit 2; }
    [[ ! -e $state ]] || {
      echo "a manual VM already exists; run: $0 ssh or $0 destroy" >&2
      exit 2
    }
    mkdir -p -- "$state_directory"
    output_directory=$(mktemp -d "$state_directory/run.XXXXXX")
    set +e
    MITHRIL_VM_SOURCE_MOUNT="$repo_root" "$run" --manual \
      --output-directory "$output_directory"
    status=$?
    set -e
    if [[ -r $output_directory/retained-vm.txt ]]; then
      install -m 600 "$output_directory/retained-vm.txt" "$state"
    fi
    if ((status != 0)); then
      echo "manual VM start failed; run: $0 destroy" >&2
      exit "$status"
    fi
    [[ -r $state ]] || {
      echo "manual VM start did not write state" >&2
      exit 1
    }
    echo "Manual VM ready. Run: $0 ssh"
    ;;
  ssh)
    (($# == 1)) || { usage; exit 2; }
    load_state
    exec "$provider" ssh "$vm_name"
    ;;
  destroy)
    (($# == 1)) || { usage; exit 2; }
    load_state
    "$provider" destroy "$vm_name" "$work_directory"
    rm -f -- "$state"
    echo "Manual VM removed."
    ;;
  *)
    usage
    exit 2
    ;;
esac
