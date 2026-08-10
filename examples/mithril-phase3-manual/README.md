# Mithril Phase 3 Manual Cases

These scripts run the real `mithril-node`; they are not wrappers around Rust
tests. Each script owns a temporary node state directory, observation socket,
lease, and BPF pin root and removes them through the shared Phase 2 cleanup
trap.

Build once:

```sh
cargo build -p mithril-node --bins -p mithril-control --bin mithril-policy
```

Cases:

- `compile-and-simulate.sh` compiles and verifies the signed observe candidate,
  then compares a normal simulated denial with a hard-safety denial.
- `docker-file-observe.sh <phase2-node.json> <container> <absolute-secret-path>`
  starts Mithril, reads the file through `docker exec`, and requires the read to
  succeed while the kernel stream reports `WOULD_DENY`.
- `unsupported-network-hard-deny.sh <phase2-node.json> <container>
  <absolute-secret-path>` starts the same observe candidate, then requires an
  attempted Python TCP connect to fail with an explicit `UNSUPPORTED_OBJECT`
  observation. Observe mode must not turn an unimplemented object classifier
  into allow.

The full case catalog and required oracles remain in the
[Phase 3 acceptance plan](../../docs/plans/mithril-hugging-face-intrusion-prevention/manual-testing/phase-3-manual-acceptance.md).
The current implementation is deliberately limited to exact file objects. It
does not claim that the remaining catalog rows are implemented.

