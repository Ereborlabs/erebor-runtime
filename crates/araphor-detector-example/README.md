# Compiled Detector Example

`BurstDetector` counts selected observations for each exact lifetime and task.
At the configured `threshold`, it returns one contextual finding with all
selected record ordinals as evidence. Different lifetimes remain separate.
The `example-burst.THRESHOLD` reason has UInt64 `threshold` and `count` details.
The next `graph.state.v1` checkpoint records the selected row count.

The host supplies the normalized `records`, `facts`, and `manifest` inputs.
The graph owner retains identity, evidence, coverage, finding, and notification
checks. The result has `confirmed: false` and the `CONTEXTUAL_ACTIVITY` limit.
A match does not establish malicious intent or grant response authority.

## Build the folder

Install the Rust `wasm32-unknown-unknown` target on the author machine. Build
from the repository root with the pinned lock file and a fixed compile-time
seed:

```sh
rtk proxy env CARGO_TARGET_DIR=/tmp/araphor-wasm-build CARGO_INCREMENTAL=0 CONST_RANDOM_SEED=araphor-analysis-v1 cargo build --locked --release --target wasm32-unknown-unknown -p araphor-detector-example
rtk proxy env CARGO_TARGET_DIR=/tmp/araphor-wasm-build cargo run --locked -p araphor-detector-example --example build_package -- /tmp/araphor-wasm-build/wasm32-unknown-unknown/release/araphor_detector_example.wasm /tmp/araphor-burst-package
rtk proxy cargo test -p araphor-detector-example --lib
```

The folder has the SDK declarations, the validated `detector.wasm`, and the
complete `package.json`. The manifest embeds the exact component bytes. The
folder builder depends on the SDK and the Rust component encoder. It does not
require an Araphor host build.

Use the same source, lock file, target, and Rust compiler to reproduce the
artifact. The checked-in artifact uses Rust 1.97.1. The fixed
`CONST_RANDOM_SEED` controls the compile-time hash seed in Arrow dependencies.
Recorded evaluation time and seed remain separate contract values.

## Install the built folder

Compute the bundle digest and pin it in the existing Control `package_trust`
configuration. Use the package mutation grant for the selected tenant. Read
the [package operations guide](../../docs/plans/mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/phase-7-5-graphs-findings-and-notifications/package-operations.md)
for the grant and trust format.

```sh
rtk proxy araphor package digest /tmp/araphor-burst-package
rtk proxy araphor --profile ./operator.json package --scope analysis install /tmp/araphor-burst-package --parameters '{"example-burst":{"detect":{"threshold":3}}}'
rtk proxy araphor --profile ./operator.json package --scope analysis inspect example-burst
```

The graph owner supplies the authorized prepared inputs when it invokes the
installed detector. The operator needs no Rust compiler. Installation runs no hook
and does not rebuild Araphor. Restart and retry use the package owner's durable
receipts and checkpoints.
