# Phase 6: Durable Evidence, Coverage, And Recovery

Status: Not started.

Master plan: [Mithril Hugging Face Intrusion Prevention](./README.md)

## Purpose

Make source quality, local durability, acknowledgement, recovery, and
enforcement continuity first-class security state before central correlation is
allowed to make multi-source conclusions.

## Depends On

Phase 5 must be `Done`, with the local task/effect/network decision path and
program generations fully tested.

## Phase Scope

### One Node Event Pipeline

The `mithril-node` evidence owner is the only normalized userspace path for
owned kernel events:

```text
per-CPU ABI records
  → ABI validation and source sequence merge
  → identity/effect normalization
  → append-only local WAL commit
  → outbound batch with contiguous acknowledgement
  → segment retention/compaction
```

Preserve the raw ABI envelope or an exact hash-addressed representation needed
for replay. Normalization cannot erase the source record, program/profile
generation, loss state, or coverage reference.

### Local WAL

Implement:

- append-before-acknowledge;
- checksummed framed records;
- segment identity, sequence bounds, and boot/label epoch;
- atomic segment rotation;
- acknowledgement of highest contiguous durable sequence;
- replay after disconnect/restart;
- duplicate and reorder handling;
- bounded disk policy;
- corruption isolation;
- retention and secure deletion policy; and
- diagnostics that do not expose credential contents.

Phase 0 must approve the exact storage implementation. A log line or stdout is
not the WAL.

### Coverage Intervals

Create an explicit coverage owner:

```text
CoverageInterval {
  source_id
  node_or_authority_scope
  start
  end
  state
  capability_generation
  program_generation
  policy_generation
  label_epoch
  first_sequence
  last_sequence
  dropped_or_missing_count
  reason
}
```

Supported states:

- `observing`;
- `enforcing_without_observation`;
- `degraded`; and
- `uncovered`.

Inputs include:

- kernel reservation/per-CPU sequence loss;
- ABI rejection;
- identity/enrichment failure;
- userspace queue overflow;
- WAL failure/full/corruption;
- outbound sequence discontinuity/backlog;
- BPF link/map/program/profile mismatch;
- capability transition;
- root-admission/CRI loss;
- clock error; and
- source restart.

### Restart And Generation Reconciliation

On startup:

1. acquire/revalidate the one-owner lease;
2. inventory pinned programs, links, maps, ABI, label epoch, counters, profiles,
   response roots, and socket fences;
3. compare them with the durable node state;
4. reuse only compatible verified generations;
5. preserve working enforcement while observation recovers;
6. iterate/revalidate live tasks and cgroups;
7. explicitly close/open coverage intervals; and
8. refuse policy work until reconciliation is complete.

An incompatible or corrupt state follows the Phase 0 fail behavior and cannot
silently reset identity or remove denial.

### Negative-Conclusion Gate

Provide an API that requires named coverage classes for a conclusion. If any
required interval is degraded/uncovered, the result is `unknown` or carries the
declared reduced confidence. Callers cannot bypass this check by reading a
boolean “no finding.”

## Hugging Face Test Increment

Implement `HF-EVID-001` across the local incident path:

- force loss before, during, and after the `HF-LOCAL`/`HF-NET` denial;
- prove the physical denial remains active when evidence delivery is lost;
- prohibit a complete incident-history claim for that interval;
- disconnect Mithril Control, fill/replay the WAL, and deduplicate;
- restart the node with live fixture tasks and pinned enforcement;
- corrupt one segment and isolate it without inventing continuity; and
- prove no missing incident observation becomes “benign.”

## Code-Backed Tests

- WAL framing/checksum/rotation/crash/replay/corruption/full/retention tests;
- ring loss, ABI rejection, userspace overflow, mTLS disconnect, duplicate,
  reorder, gap, and clock-skew tests;
- coverage interval non-overlap and state-transition property tests;
- enforcement-without-observation and observation-without-enforcement tests;
- negative-conclusion prerequisite tests;
- restart with compatible/incompatible pinned generations;
- lost label epoch/counter with live tasks;
- partial policy swap and response-map reconciliation;
- central acknowledgement rollback and replay;
- diagnostics secret-redaction tests; and
- `HF-EVID-001` integration plus performance/disk budgets.

## Live Probe

Run Probes A and B under every applicable fault in Probe G. Retain the complete
coverage and recovery timeline.

## Checkpoint

Run the common repository gates, WAL and coverage property/fault tests, pinned
state reconciliation, incident denial under evidence loss, and the full
applicable Probe G matrix. Rebuild the accepted local stream from retained
records and compare its identity/effect digest.

## Acceptance

- every accepted node observation is locally durable before acknowledgement;
- retries do not duplicate normalized effects;
- every loss/failure creates a bounded coverage transition;
- pinned enforcement continuity is distinguishable from evidence continuity;
- central outage replays without identity/sequence reset;
- spool exhaustion follows the approved fail behavior;
- corruption is detected and isolated;
- restart reconciles programs/maps/profiles/identity/live tasks before new
  policy work;
- negative conclusions are unavailable without required healthy coverage;
- incident denials remain physically effective during injected evidence loss;
  and
- CPU/memory/disk/replay performance meets budget.

## Explicit Stop Point

Stop after node evidence and coverage truth pass. Do not implement multi-source
correlation before the user approves the Phase 7 central storage, replay,
authorization, and graph boundaries.

## Phase Result

State: Not started.

Record storage selection, schemas, failure policy, fault matrix, coverage
timelines, recovery artifacts, incident results, performance, and final state.
