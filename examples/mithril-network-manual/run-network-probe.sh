#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root after building mithril-network-test" >&2
  exit 2
fi

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository=$(cd -- "$directory/../.." && pwd)
binary=${MITHRIL_NETWORK_TEST_BINARY:-$repository/target/debug/mithril-network-test}
run_name=${MITHRIL_NETWORK_RUN_NAME:-manual}

if [[ ! $run_name =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "MITHRIL_NETWORK_RUN_NAME contains an unsupported character" >&2
  exit 2
fi
if [[ ! -x $binary ]]; then
  echo "missing executable: $binary" >&2
  echo "run: cargo build -p mithril-e2e --bin mithril-network-test" >&2
  exit 2
fi

output_directory=/tmp/mithril-network-$run_name
pin_root=/sys/fs/bpf/mithril-network-$run_name
lease_path=/tmp/mithril-network-$run_name.lock
cgroup_path=/sys/fs/cgroup/mithril-network-$run_name

for path in "$output_directory" "$pin_root" "$lease_path" "$cgroup_path"; do
  if [[ -e $path ]]; then
    echo "run path already exists: $path" >&2
    exit 2
  fi
done

"$binary" \
  --repo-root "$repository" \
  physical-probe \
  --output-directory "$output_directory" \
  --pin-root "$pin_root" \
  --lease-path "$lease_path" \
  --cgroup-path "$cgroup_path"

echo "result: $output_directory/network-physical-probe.json"
