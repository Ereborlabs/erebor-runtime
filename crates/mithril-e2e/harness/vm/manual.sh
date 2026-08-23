#!/usr/bin/env bash

set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$directory/../../../.." && pwd)
. "$directory/identity.sh"
current_branch_name=$(mithril_vm_branch_name "$repo_root")
current_branch_key=$(mithril_vm_branch_key "$current_branch_name")
run=$directory/run.sh
two_node_convergence=$directory/two-node-convergence.sh
state_directory=${XDG_STATE_HOME:-$HOME/.local/state}/mithril-manual-vm/$current_branch_key
state=$state_directory/retained-vm.txt
convergence_state_directory=${XDG_STATE_HOME:-$HOME/.local/state}/mithril-convergence-manual-vm/$current_branch_key
convergence_state=$convergence_state_directory/retained-vms.txt

usage() {
  echo "usage: $0 {create|status|reconnect|destroy|create-convergence|status-convergence|reconnect-convergence|destroy-convergence}" >&2
}

load_convergence_state() {
  [[ -r $convergence_state ]] || {
    echo "no convergence VMs exist for $current_branch_name; run: $0 create-convergence" >&2
    exit 2
  }
  set -a
  # The harness writes this file with shell-quoted values.
  . "$convergence_state"
  set +a
  [[ ${branch_name:-} == "$current_branch_name" &&
     ${branch_key:-} == "$current_branch_key" &&
     ${manual_environment:-} == true && -n ${node_a:-} &&
     -n ${node_a_work_directory:-} && -n ${node_b:-} &&
     -n ${node_b_work_directory:-} && -x ${provider:-} ]] || {
    echo "manual convergence VM state is invalid: $convergence_state" >&2
    exit 2
  }
}

load_state() {
  [[ -r $state ]] || {
    echo "no manual VM exists for $current_branch_name; run: $0 create" >&2
    exit 2
  }
  set -a
  # The harness writes this file with shell-quoted values.
  . "$state"
  set +a
  [[ ${branch_name:-} == "$current_branch_name" &&
     ${branch_key:-} == "$current_branch_key" &&
     -n ${vm_name:-} && -n ${work_directory:-} && -x ${provider:-} ]] || {
    echo "manual VM state is invalid: $state" >&2
    exit 2
  }
}

case ${1:-} in
  create|start)
    (($# == 1)) || { usage; exit 2; }
    [[ ! -e $state ]] || {
      echo "a manual VM already exists for $current_branch_name; run: $0 reconnect or $0 destroy" >&2
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
    echo "Manual VM ready for $current_branch_name. Run: $0 reconnect"
    ;;
  status)
    (($# == 1)) || { usage; exit 2; }
    load_state
    printf 'branch=%s\nvm=%s\n' "$current_branch_name" "$vm_name"
    "$provider" status "$vm_name" "$work_directory"
    ;;
  reconnect|ssh)
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
  create-convergence|start-convergence)
    (($# == 1)) || { usage; exit 2; }
    [[ ! -e $convergence_state ]] || {
      echo "a convergence environment already exists for $current_branch_name; run: $0 reconnect-convergence or $0 destroy-convergence" >&2
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
    echo "Manual convergence environment ready for $current_branch_name. Run: $0 reconnect-convergence"
    ;;
  status-convergence)
    (($# == 1)) || { usage; exit 2; }
    load_convergence_state
    status=0
    printf 'branch=%s\nvm=%s\n' "$current_branch_name" "$node_a"
    "$provider" status "$node_a" "$node_a_work_directory" || status=1
    printf 'vm=%s\n' "$node_b"
    "$provider" status "$node_b" "$node_b_work_directory" || status=1
    exit "$status"
    ;;
  reconnect-convergence|ssh-convergence)
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
