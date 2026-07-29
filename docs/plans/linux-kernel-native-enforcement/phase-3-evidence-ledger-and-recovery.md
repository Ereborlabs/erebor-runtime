# Phase 3: Evidence Ledger, Fencing, And Recovery

Status: Proposed. Requires Phase 2 and explicit approval.

Parent plan: [Linux Kernel-Native Effect Enforcement Master Plan](README.md)

## Purpose

Replace the current per-effect synchronous JSONL durability barrier only with a
bounded, ordered, recoverable kernel-evidence pipeline. The result must make an
unrecorded allowed physical effect impossible within the stated Session
contract.

## Scope

- Define `KernelEffectEvent` and its stable Session, policy-image, cgroup,
  action, object identity, outcome, and monotonic ordering fields.
- Have the BPF LSM enforcer reserve and commit an event before returning allow
  or deny. If reservation fails, return a fail-closed error; do not drop the
  event and continue.
- Add a daemon-owned collector that validates event identity, persists the
  ordered ledger, reports a durable cursor, and exposes Session health to the
  existing session/audit owners.
- Define bounded batching, flush, sync, retry, collector restart, daemon
  restart, and evidence-channel-full behavior. The chosen policy must be
  measured and recorded, not inferred from an in-memory queue.
- Reconcile Session filesystem COW/OSTree state with the sealed ledger on
  abnormal exit. A recovery result must identify evidence incompleteness rather
  than produce an unqualified success claim.
- Keep current JSONL evidence readable or provide an explicitly approved,
  versioned migration/read path. Do not strand existing session-review tools.

## Non-Negotiables

- A BPF ring buffer is transport, not durable evidence by itself.
- Collector lag may create backpressure; it must never create silent allow.
- Audit failure cannot be merely logged while the physical effect proceeds.
- No consumer may reorder records from different workload threads without a
  defined Session ordering rule.
- Do not degrade denial, Session attribution, or crash recovery guarantees to
  reduce latency.

## Checkpoint

- Tests force ring-buffer reservation failure, paused collector, collector
  crash, daemon restart, workload crash, and normal high-rate operation.
- Each failure produces the documented kernel error/fence state and a durable
  recovery result. No forbidden or unrecorded effect is accepted.
- Benchmarks report p50/p95/p99 effect-hook cost, collector lag, durable batch
  cost, queue occupancy, and fencing behavior against the current ptrace path.

## Acceptance

- Every completed Session has a sealed, ordered evidence ledger or an explicit
  evidence-incomplete recovery state with no misleading success receipt.
- The current per-decision `sync_data()` path is removed only for a
  kernel-enforced Session and only after tests prove the replacement contract.
- Existing filesystem storage/recovery remains the owner of contents and
  checkpoints; the ledger owner does not duplicate it.

## Stop Point

Do not expose production backend selection or alter defaults until the user
approves the recovery and evidence contract.

## Phase Result

Not started.
