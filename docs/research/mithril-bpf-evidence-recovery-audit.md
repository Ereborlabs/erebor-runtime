# Mithril BPF Evidence And Recovery Audit

## Purpose

This audit defines the evidence and recovery constraints for the next Mithril
implementation slice. It examines the production Interceptor programs, their
Rust lifecycle owner, the current node observation path, and the local Cilium
and Tetragon source trees. It does not change an enforcement claim.

The audit used the current source in these locations:

- [`bpf/erebor-interceptor/programs`](../../bpf/erebor-interceptor/programs)
- [`erebor-interceptor`](../../crates/erebor-interceptor/src)
- [`erebor-interceptor-abi`](../../crates/erebor-interceptor-abi/src)
- [`mithril-node`](../../crates/mithril-node/src)
- [`mithril-e2e`](../../crates/mithril-e2e/src)
- the local Cilium `pkg/bpf` and `pkg/monitor/agent` source
- the local Tetragon `pkg/observer`, `pkg/sensors`, `pkg/program`, and
  `pkg/bench` source

The focused Rust and bundled-BPF baseline passed before this document was
written. The command was:

```text
cargo test -p erebor-interceptor-abi -p erebor-interceptor --lib
```

## Current BPF Safety Properties

The production object has required LSM, tracepoint, fentry, fexit, task
iterator, cgroup-egress, and classifier programs. `KernelHostOwner` validates
the required set before it loads the object. It pins each required map and
link below one configured pin root.

The current effect path fixes the physical decision before it reserves a ring
record. A ring reservation failure increments a loss counter. It does not
change an allow or deny result. This property must remain true when durable
evidence is added.

Authoritative task, policy, object, socket, relationship, and lifecycle maps
do not use LRU eviction. The canonical mount cache is an LRU map, but it is a
recomputable cache and not an authority source. This separation prevents an
eviction from silently removing authority state.

Task allocation copies the parent state before the child can make a protected
effect. Exit processing uses tombstones and requests reconciliation when it
cannot complete a release. Missing authoritative state keeps the existing
fail-closed decision behavior.

## Current Lifecycle And Recovery Properties

`KernelHostOwner` has one exclusive lease for its pin root. Initial load uses
fresh directories. Recovery opens the exact retained maps, loads the current
object against those maps, checks program tags and map identities, reopens the
retained links, and rejects unexpected retained LSM links.

`verify_live_manifest` reopens each pinned map and link. It compares the live
map, link, and program identities with the startup manifest. This method is
the correct owner for continuous Interceptor integrity checks. A new health
loop must call it. A second pin scanner or lifecycle owner is not necessary.

Normal identity-mode shutdown leaves the pinned enforcement state in place.
The policy owner already recovers immutable generations, the active pointer,
pending activation, task and socket references, mount-view state, and durable
generation allocation. It retires a generation only after its represented
references are gone. The exception owner already has an append-only local WAL
and restores exact use receipts. It conservatively exhausts an uncertain
active exception.

These owners are the recovery foundation. General evidence recovery must not
replace them or infer state from a PID, process name, path, or cache entry.

## Evidence Gaps In The Current Source

The BPF health map currently contains `attempted`, `emitted`, `lost`, and
`unresolved` counters. The event does not contain a source epoch, CPU source,
or source sequence. The source cannot yet prove exact continuity after a
reader restart or CPU-local loss.

The node reader decodes ring records into a bounded in-memory queue. It gives
each record a userspace cursor. It does not persist the record, a source
cursor, or a coverage transition. A full userspace queue discards its oldest
record. A node restart discards the queue.

The ring reader stops the node if it returns an error. A stalled reader is
visible only when later ring reservation failures change the loss counter.
There is no reader-liveness interval, durable gap record, or controlled probe
that opens a new healthy interval.

The control stream has no evidence batch, durable intake, contiguous
acknowledgement, or replay message. The node cannot distinguish a durable
control acknowledgement from network delivery.

The current health record does not represent `suppressed`, `requested`, or
classifier-miss counts. It cannot validate this source equation:

```text
attempted = suppressed + requested
requested = emitted + lost
```

The current source also lacks durable coverage intervals and deterministic
local finding-input windows. Consequently, it cannot support a negative
claim across ring loss, reader loss, WAL failure, upload outage, or restart.

## Lessons From Tetragon

Tetragon keeps perf and ring readers separate from its bounded event queue. It
counts kernel-buffer loss, reader errors, queue receipt, and queue loss as
different conditions. Its benchmark summary reports received records, lost
records, and errors. Mithril must preserve this separation so one aggregate
counter cannot hide the failed stage.

Tetragon gives maps explicit owners and users. It checks compatibility when a
map is shared and maintains reference counts for sensor lifecycle. Mithril
already has a stricter security owner in `KernelHostOwner`. The useful lesson
is to keep ownership explicit and fail a mismatch. Mithril must not weaken an
exact generation check to obtain broad map reuse.

Metrics alone are not sufficient for Mithril. A lost count must close a
durable coverage interval. Later recovery must open a new interval; it must
not edit the old interval into a healthy result.

## Lessons From Cilium

Cilium forwards a perf loss event with the CPU identifier and loss count to
monitor consumers. This makes data loss part of the event stream instead of
only a process metric. Mithril must also persist loss with its exact source
and interval.

Cilium checks pinned-map compatibility and orders replacement so that new
programs attach before old pins are replaced. This prevents a transient
invalid data path. Mithril must retain its stricter recovery rule: reuse only
an exact compatible authority generation, and reject a mismatch.

Cilium and Tetragon provide strong operational observability patterns. They do
not provide Mithril's negative-claim rule. Mithril must treat every unknown
reader, queue, WAL, link, map, and source state as a coverage gap.

## Implementation Constraints

The implementation must preserve these constraints:

1. The BPF decision remains final before evidence reservation or delivery.
2. Each kernel source has an epoch and an ordered sequence. Per-CPU counters
   remain exact and use `suppressed` and classifier-miss counters explicitly.
3. One canonical envelope owns the evidence identifier, task and object
   coordinates, policy coordinates, result stage, proof quality, coverage
   interval, and bounded typed payload.
4. The envelope never contains a secret or raw administrative argument.
5. The node persists an integrity-checked ordered WAL before it makes a record
   available for upload. It truncates only below a durable contiguous
   acknowledgement.
6. Ring, reader, queue, map, WAL, upload, link, lease, and epoch failures close
   a coverage interval. No gapped interval can support a negative claim.
7. Recovery uses exact pinned identities, durable generation records, active
   pointers, task and native identities, object and socket state, mount
   topology, pending exceptions, and response floors.
8. A controlled readback and probe open a new healthy interval. Recovery does
   not rewrite an earlier gap.
9. Local finding-input windows are order independent. Duplicate, late,
   reordered, and contradictory records produce deterministic revisions.
10. The existing mTLS control stream carries evidence batches and durable
    acknowledgements. A parallel transport or runtime is not added.

## Required Verification Consequences

Automated tests must cover canonical bytes and identifiers, sequence gaps,
counter equations, each coverage transition, WAL rotation and retention,
torn and corrupt records, acknowledgement and replay, duplicate delivery,
upload outage, node restart, generation retirement, object and socket reuse,
and stale pin, link, and map state.

Physical tests must prove that local denial stays correct during ring loss,
reader loss, WAL failure, node restart, and control outage. They must prove
that recovery keeps live restrictions and consumption state, rejects stale
authority, and resumes evidence in a new healthy interval only after readback
and a controlled probe.

The physical record must measure the configured queue, ring, WAL, batch,
latency, and recovery bounds. Generated result digests and other CI-owned
qualification artifacts must not be committed.

## Post-Implementation Re-Audit

The final re-audit used source commit `6686a23` on 2026-08-19. It read the
checked-in C and Rust implementation and inspected the compiled BPF object.

The production effect path has this order:

1. `begin_effect_observation` clears the complete scratch observation.
2. The policy path fixes the physical result.
3. `emit_effect_observation` updates the per-CPU health record and allocates a
   nonzero source sequence.
4. The helper copies the fixed result and exact CPU into the record.
5. The helper reserves and submits the ring record. A missing health record,
   exhausted sequence, missing scratch record, or failed reservation returns
   the unchanged physical result. Represented loss increments `lost`.

The checked-in path requests every represented effect. Therefore,
`suppressed` is zero, and the complete equations remain explicit:

```text
attempted = suppressed + requested
requested = emitted + lost
```

An unresolved or unsupported object increments both `unresolved` and
`classifier_miss_count`. Node validates the equations and each per-CPU source
sequence. A decoder error, counter regression, or first-sequence gap closes
coverage.

The re-audit also confirmed these lifecycle properties:

- `effect_observations` is the one 4 MiB ring buffer written by the BPF effect
  helpers and drained by the sole Node reader;
- `effect_observation_health` is the one-entry per-CPU array written by the
  BPF helpers and read by Node health and coverage accounting;
- `KernelHostOwner` owns both maps, the exclusive pin-root lease, required
  links, and startup manifest;
- recovery compares held lease identity, map IDs and layouts, link IDs,
  program IDs, and 8-byte program tags before it restores readiness; and
- a mismatch closes readiness and evidence claims. It does not create another
  loader, scanner, or authority owner.

The automated BPF checks inspect ABI layouts, the compiled object, BTF map
shapes, required programs, and instruction behavior. They do not search C or
Rust source text for implementation phrases. The final physical run confirmed
that fixed denies and benign allows remain correct during ring saturation and
after restart.
