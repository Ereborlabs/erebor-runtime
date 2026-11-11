# Unapplied Causal input experiment

Result: **Not applied**. The package source uses the last committed Causal
implementation. The user directs migration completion before more latency work.

`causal-canonical-inputs.patch.gz` contains six package modules and three Query
fixture files. The draft replaces business edges with shared claim identities
and exact origin-record links. A native change pair supplies inserted and removed
canonical record keys. The generic Graph owner has no package policy changes.

The real Wasm index cases pass for late canonical arrival with equal coverage,
an audit-only cross-actor lease conflict, unrelated-record isolation, physical
raw expiry, and reopen. Eighteen native Query cases pass. These index cases do
not separately prove complete Detect contradiction and repair behavior.

The combined grouped-pin candidate passes the unchanged incident but regresses
creation after bulk input to 98.712–117.841 ms. Stable native controls measure
62.308–64.630 ms at that point. The draft is not a qualified latency improvement.
The generic grouped witness pins remain active and are outside this patch.

`causal-canonical-inputs-source.json` records the source parent and file hashes.
The patch checksum is SHA-256 5da2d0a8d402fffe28aeb872af773b518558a044df5f58b51dc77261d559ac40.
The patch reapplication check passes after restoration of the package source.

Read `grouped-pins-build.json`, `grouped-pins-comparison.json`, and the
`causal-incidence` evidence under `output/araphor-fjall-migration-20261110`.
No incident workload, assertion, timeout, or default definition is changed.
