#!/usr/bin/env bash
set -Eeuo pipefail

# Build the exact local binaries consumed by run-host-lab.sh. This does not
# install anything and does not create or remove an Erebor runtime directory.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"

cd -- "$repo_root"
cargo build --package erebor-runtime-cli --bin erebor
cargo build --package erebor-runtime-daemon --bin erebord --bin erebor-path-broker
cargo build --package erebor-runtime-session --bin erebor-linux-session-controller
cargo build --package erebor-runtime-session \
  --features editor-process-guard-target \
  --bin erebor-linux-process-guard
cargo build --package erebor-runtime-e2e --bin codex-v1-fixture

printf 'host-lab binaries are ready under %s/target/debug\n' "$repo_root"
