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
if ! command -v jq >/dev/null 2>&1; then
  echo "missing executable: jq" >&2
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

result=$output_directory/network-physical-probe.json
jq -e '
  .schema_version == 1 and
  ([.fixture_results[].fixture_id] == [
    "FILE-DELEGATED-EGRESS-001",
    "HF-004-RESULT-001",
    "HF-011-READ-RESULT-001",
    "HF-NET-001",
    "IPC-LOCAL-INET-008",
    "NET-ACCEPT-PASS-001",
    "NET-DNS-EXFIL-001",
    "NET-NS-PASS-001",
    "NET-RECV-001",
    "NET-REWRITE-001",
    "NET-SHARED-RESPONSE-002",
    "NET-SOCKCTL-001",
    "NET-SOCKET-LIFE-001"
  ]) and
  all(.fixture_results[]; .result == "PASS" and (.physical_oracle | length > 0)) and
  (to_entries | all(
    .key == "schema_version" or
    .key == "fixture_results" or
    .value == true
  ))
' "$result" >/dev/null

echo "all 13 network fixtures passed"
echo "result: $result"
