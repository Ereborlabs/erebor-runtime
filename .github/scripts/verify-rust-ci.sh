#!/usr/bin/env bash

set -euo pipefail

cargo fmt --all --check
cargo check --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
