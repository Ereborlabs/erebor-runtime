# How To Manually Accept Phase 6

Status: Verified runbook for the qualified x86_64 single-node and two-node
K3s tier.

Phase: [Durable Evidence, Coverage, And Recovery](../phase-6-durable-evidence-coverage-and-recovery.md)  
Setup: [`SINGLE-NODE`](./environment-setup.md), with disposable WAL storage

## Outcome

Prove evidence is ordered, durable, replayable, and loss-aware while physical
local decisions remain independent from userspace delivery. Restart must retain
restrictions and refuse reconstructed authority.

## Automated Companion

```sh
bash .github/scripts/verify-rust-ci.sh
cargo test --workspace --all-targets --all-features -- \
  --skip verification_bundle_is_frozen_only_for_recorded_physical_surfaces

crates/mithril-e2e/harness/vm/run.sh --with-k3s \
  --skip-administrative-exec \
  --output-directory /tmp/mithril-phase6-physical

crates/mithril-e2e/harness/vm/two-node-network.sh \
  --output-directory /tmp/mithril-phase6-two-node
```

The repository gate must pass every source check. For a source-only delivery
that must not update generated qualification evidence, record the expected
stale generated-record assertion separately. Do not treat that artifact
exception as a source-test failure or a green release result.

## Procedure

1. Begin with healthy local decisions, source epochs, WAL, upload cursor, and
   Control acknowledgement.
2. Run one allowed and one denied local effect and retain their physical
   results before injecting faults.
3. Inject ring, reader, queue, WAL, upload, map/link/pin, daemon, runtime, and
   node failures one at a time and in selected combinations.
4. Restart the node owner and reconcile tasks, generations, exceptions,
   objects, sockets, topology, response floors, and coverage before admission.
5. Replay to Control with duplicates, delay, reorder, corruption, and cursor
   rollback attempts.

## Fixture Matrix

| Fixture | Operator stimulus | Required oracle and control |
| --- | --- | --- |
| `IPC-ENDPOINT-RESTART-006` | restart either/both channel endpoints and reuse names/coordinates | old relationship never attaches to new endpoint generation; newly declared peers reconnect |
| `IPC-RELATIONSHIP-LOSS-002` | drop peer/relationship evidence while communication is attempted | configured unmatched/hard-safe physical result and gapped relationship proof; healthy relationship control works |
| `LSM-DENY-SATURATION-001` rerun | saturate ring/queue/WAL during repeated forbidden effects | every local effect remains denied; loss counters/interval close exactly; allowed control remains correct |
| `SOURCE-KA-READER-LOSS-003` rerun | kill/close/stall sole reader | no healthy negative interval after loss; pinned decisions continue only while their mechanism remains intact |
| `SOURCE-KA-CAPACITY-005` rerun | fill authoritative maps, ring, WAL, and pending state to N/N+1 | exact failure and health transition; no overwrite-to-allow or false clean coverage |
| `SOURCE-KA-PARTIAL-ATTACH-001` rerun | lose/detach/replace one required live link/map | affected capability closes; recovery verifies exact object/digest and opens a new epoch only after probe |

## Additional Fault Matrix

| Fault | Manual verification |
| --- | --- |
| ring reservation failure | fixed decision unchanged; pinned loss count rises; gap begins at exact sequence |
| WAL full/corrupt segment | retention/backpressure/gap follows policy; no guessed repair or duplicate observation |
| mTLS upload outage | local WAL continues within bound; reconnect resumes from acknowledged cursor |
| node process death | no hidden second writer; pinned enforcement truth and later evidence gap remain distinct |
| runtime/kubelet restart | live roots reconcile without stale purpose; missing interval stays open |
| node reboot | old boot subjects close; new epoch and re-admission; old response keys cannot target new tasks |
| generation retirement/restart | every typed holder/receipt is retained or exact cleanup tombstone exists |
| stale pin/path with live object | recoverability is degraded even if live link still enforces |

## Required Artifacts And Pass Rule

Retain raw source sequences, epochs, gap/suppression counters, WAL segments and
digests, ack cursors, corruption/replay results, link/map/pin manifests,
reconciliation reports, pre/post physical effects, and local finding windows.
Pass requires that no gap supports a negative conclusion and no recovery uses
PID/name/cache guesses.

## Executed Acceptance Record

The closure run used source commit `df80630` on 2026-08-19. The source-only
workspace suite passed 948 tests, ignored 15 declared tests, and filtered 5
fixture lanes. The repository CI command passed formatting, workspace check,
Clippy, and every ordinary test. It rejected only the unchanged generated
`kernel-qualification-x86_64.json` record as stale. No generated CI/CD digest
or qualification artifact was committed.

The final single-node evidence is in
`/tmp/mithril-phase6-physical-20260819-r12`. The disposable Ubuntu 24.04 VM ran
Linux 6.8.0-137-generic on x86_64 with cgroup v2, BPF filesystem, runtime BTF,
and the lockdown, capability, Landlock, Yama, AppArmor, and BPF LSMs active.
The K3s version was v1.35.5+k3s1.

| Fixture | Result and physical oracle |
| --- | --- |
| `IPC-ENDPOINT-RESTART-006` | Pass. Restart preserved the exact task, socket, response floor, mount view, and active generation. A new whole-socket fence denied send and shutdown, no post-fence bytes or bypass packets arrived, and final close released the reference. |
| `IPC-RELATIONSHIP-LOSS-002` | Pass. An unclassified connect was denied while the declared socket control remained allowed. Denied delegated and rewritten traffic had no peer receipt. |
| `LSM-DENY-SATURATION-001` | Pass in OBSERVE and PROTECT. Each mode attempted 50,000 saturation opens and reported 42,293 lost ring records. The fixed network denial and benign allow remained correct. |
| `SOURCE-KA-READER-LOSS-003` | Pass. Reader loss opened a durable gap, blocked the negative claim, and did not change the fixed kernel result. Exact recovery opened a later interval without repairing the old gap. |
| `SOURCE-KA-CAPACITY-005` | Pass. WAL capacity and ring loss opened separate gaps. The durable batch contained 256 integrity-checked records. No authoritative row was overwritten to allow. |
| `SOURCE-KA-PARTIAL-ATTACH-001` | Pass. Live manifest reconciliation verified the exact lease, maps, links, programs, and tags. A missing or changed owner closed capability and coverage until an exact probe completed. |

The K3s CRI OBSERVE lane allowed the exact file open and recorded
`WOULD_DENY`. The PROTECT lane returned `-EACCES` before the exact file effect
and recorded `EXACT_POLICY_DENY`. Both lanes allowed the benign control. The
native and Kubernetes identity probes passed their init, sidecar, application,
ephemeral-container, exec-probe, PostStart, PreStop, reuse, restart, and replay
checks.

The final two-node evidence is in
`/tmp/mithril-phase6-two-node-20260819-r2`. K3s reported two Ready nodes with
different boot identities. The node-A-to-node-B and node-B-to-node-A paths both
passed. Each node-local network record passed all 13 allocated network fixture
rows. The harness removed the namespace, K3s installations, and both VMs.

The OPEN benchmark used 100,000 warmup operations and 1,000,000 measured
operations per concurrency. The measured rates were:

| Mode | Workers | Operations/s | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline | 1 | 167,317 | 4,892 ns | 5,588 ns | 21,148 ns |
| Baseline | 32 | 317,599 | 5,320 ns | 6,205 ns | 15,988 ns |
| Protected | 1 | 155,272 | 5,310 ns | 6,662 ns | 20,402 ns |
| Protected | 32 | 297,459 | 5,628 ns | 6,742 ns | 17,798 ns |

The retained artifact digests are:

| Artifact | SHA-256 |
| --- | --- |
| effect observation | `b2fd96f0219cfc7ff949a26ca76db02e9ceefd79b81f5df421a90cd3c07ca74c` |
| Kubernetes identity | `855f29e53ed408199a4a00a1b3cadfa4da9fad7b38b03cbdddf4e2b11a02f1bb` |
| local enforcement | `9aab4af62332b7244e3a8246e881c318e54f14b8f76a486301727e65a46f6064` |
| network recovery | `9e210aeb04394cc82da65f846585b769753002dbc96c782914acbfe67cd609bb` |
| physical file-open probe | `ae06bf9dc59bb46ffec42bad0881ee7e53082e252cd2649246405530944ecf0e` |
| baseline benchmark | `5f088a169e3ad5ae33515453e9047a4c7f5be1601bf68c64e2dc548fb2cc7a64` |
| protected benchmark | `3e199115591eb1e6a723b677d9cc69b1727520b3b1a07ee22de3106269da8e76` |
| single-node qualification record | `86134f997a97c2bda1cd80eec44f99a6d192526be4db855924c9ed849a0e6c10` |
| two-node summary | `cc4e0dc20551caf9cdb04cbf7d9f9d5bd7c3ea93f6a6617d9804068210d6b1b6` |

These artifacts remain outside the repository. They qualify only the recorded
x86_64 tier and the tested K3s Flannel topology.

## Troubleshooting

- Do not call enforcement failed merely because upload failed; verify the
  actual program/link/map state and report evidence separately.
- Do not call enforcement healthy when a required link or map cannot be read
  back, even if prior events looked normal.
- A lost restrictive reference leaks restriction until reconciled; it never
  authorizes early cleanup.
