#!/usr/bin/env bash

set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$directory/../../../.." && pwd)
run=$directory/run.sh
two_node_convergence=$directory/two-node-convergence.sh
state_directory=${XDG_STATE_HOME:-$HOME/.local/state}/mithril-manual-vm
state=$state_directory/retained-vm.txt
convergence_state_directory=${XDG_STATE_HOME:-$HOME/.local/state}/mithril-convergence-manual-vm
convergence_state=$convergence_state_directory/retained-vms.txt

usage() {
  echo "usage: $0 {start|ssh|destroy|start-convergence|ssh-convergence|destroy-convergence}" >&2
}

load_convergence_state() {
  [[ -r $convergence_state ]] || {
    echo "no convergence VMs exist; run: $0 start-convergence" >&2
    exit 2
  }
  set -a
  # The harness writes this file with shell-quoted values.
  . "$convergence_state"
  set +a
  [[ ${manual_environment:-} == true && -n ${node_a:-} &&
     -n ${node_a_work_directory:-} && -n ${node_b:-} &&
     -n ${node_b_work_directory:-} && -x ${provider:-} ]] || {
    echo "manual convergence VM state is invalid: $convergence_state" >&2
    exit 2
  }
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
    rm -rf -- "$work_directory"
    rm -f -- "$state"
    echo "Manual VM removed."
    ;;
  start-convergence)
    (($# == 1)) || { usage; exit 2; }
    [[ ! -e $convergence_state ]] || {
      echo "a convergence environment already exists; run: $0 ssh-convergence or $0 destroy-convergence" >&2
      exit 2
    }
    mkdir -p -- "$convergence_state_directory"
    output_directory=$(mktemp -d "$convergence_state_directory/run.XXXXXX")
    set +e
    MITHRIL_VM_SOURCE_MOUNT="$repo_root" "$two_node_convergence" \
      --manual-environment --output-directory "$output_directory"
    status=$?
    set -e
    if [[ -r $output_directory/retained-vms.txt ]]; then
      install -m 600 "$output_directory/retained-vms.txt" "$convergence_state"
      printf 'output_directory=%q\n' "$output_directory" >>"$convergence_state"
    fi
    if ((status != 0)); then
      echo "manual convergence environment start failed; run: $0 destroy-convergence" >&2
      exit "$status"
    fi
    [[ -r $convergence_state ]] || {
      echo "manual convergence environment did not write state" >&2
      exit 1
    }
    echo "Manual convergence environment ready. Run: $0 ssh-convergence"
    ;;
  ssh-convergence)
    (($# == 1)) || { usage; exit 2; }
    load_convergence_state
    exec "$provider" ssh "$node_a"
    ;;
  destroy-convergence)
    (($# == 1)) || { usage; exit 2; }
    load_convergence_state
    "$provider" destroy "$node_b" "$node_b_work_directory"
    "$provider" destroy "$node_a" "$node_a_work_directory"
    [[ $node_a_work_directory == /tmp/mithril-vm-test.* ]] || exit 2
    [[ $node_b_work_directory == /tmp/mithril-vm-test.* ]] || exit 2
    rm -rf -- "$node_a_work_directory" "$node_b_work_directory"
    if [[ -n ${output_directory:-} ]]; then
      [[ $output_directory == "$convergence_state_directory"/run.* ]] || exit 2
      rm -rf -- "$output_directory"
    fi
    rm -f -- "$convergence_state"
    echo "Manual convergence environment removed."
    ;;
  *)
    usage
    exit 2
    ;;
esac
