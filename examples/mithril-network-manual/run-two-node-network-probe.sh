#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository=$(cd -- "$directory/../.." && pwd)
harness=$repository/crates/mithril-e2e/harness/vm/two-node-network.sh
output_directory=${MITHRIL_NETWORK_TWO_NODE_OUTPUT:-/tmp/mithril-network-two-node-manual}
provider=
keep_vms=false

usage() {
  echo "usage: $0 [--provider PATH] [--output-directory PATH] [--keep-vms]" >&2
}

while (($#)); do
  case $1 in
    --provider)
      (($# >= 2)) || { usage; exit 2; }
      provider=$2
      shift 2
      ;;
    --output-directory)
      (($# >= 2)) || { usage; exit 2; }
      output_directory=$2
      shift 2
      ;;
    --keep-vms)
      keep_vms=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

arguments=(--output-directory "$output_directory")
if [[ -n $provider ]]; then
  arguments+=(--provider "$provider")
fi
if [[ $keep_vms == true ]]; then
  arguments+=(--keep-vms)
fi

exec "$harness" "${arguments[@]}"
