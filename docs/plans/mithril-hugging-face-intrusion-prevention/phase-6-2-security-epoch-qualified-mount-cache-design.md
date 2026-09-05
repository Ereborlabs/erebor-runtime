# Phase 6.2 Security-Epoch-Qualified Mount Cache Design Proposal

Status: Implemented experiment with incomplete Kubernetes qualification. The named Git checkpoint
`487a32fcdd873f43b84c9a157fa0a8e9d3b5e793` preserves the complete tracked
working state before this experiment. This document does not change the signed
policy model or the exact-object contract.

Parent: [Phase 6.2 Control Policy And Evidence Convergence](./phase-6-2-control-policy-and-evidence-convergence.md)

Implementation review: [Phase 6.2 review guide](./phase-6-2-implementation-review.md)

## Problem

The kernel mount namespace has a raw event counter. Linux can advance this
counter during detached mount work even when the protected namespace has the
same visible mount topology after the work completes. Stock `runc` can perform
this work while it seals an executable for a later container exec.

The current BPF cache uses the raw namespace event in the state key and in
every mount-selection row key. One event-only transition therefore creates a
new cache generation even when all of these security facts remain unchanged:

- the protected mount namespace identity;
- the namespace-root unique mount identity;
- the task walk root;
- the security-view mutation epoch;
- the pending-mutation count; and
- the visible `mountinfo` snapshot.

The lightweight K3s-runtime reproduction observed this state:

```text
mount activity sequence: increased
raw namespace event:     1366 -> 1437
security-view epoch:     22 -> 22
pending mutations:       0
mountinfo digest:        unchanged
ready cache states:      2 -> 3
```

BPF published the third state after a complete build. The Rust oracle then
failed because it required equality of the complete ready-key set. This result
does not prove that policy or the protected topology changed. It proves that
the cache uses the wrong fact as its generation identity.

## Existing Classification

BPF already separates activity evidence from security-view invalidation.

`mount_global_activity_sequence` records observed mount API activity.
`mount_global_mutation_epoch` advances before an operation that can change a
represented namespace's visible topology or security attributes. The pending
counter blocks access while such a mutation is in progress. Unknown
attribution uses the global fail-closed mutation path.

The existing operation classification remains authoritative:

| Operation | Record activity | Advance a security-view epoch |
| --- | --- | --- |
| Create or configure a new detached filesystem context | Yes | No |
| `fsmount` that returns a detached mount FD | Yes | No |
| `open_tree` with `OPEN_TREE_CLONE` | Yes | No |
| `move_mount` that attaches or moves a mount | Yes | Yes |
| `FSCONFIG_CMD_RECONFIGURE` | Yes | Yes, or use the global fallback |
| `mount_setattr` on an attached mount | Yes | Yes |
| `mount`, `umount`, or `pivot_root` | Yes | Yes |
| Unknown target or possible propagation | Yes | Use the global fallback |

This classification is not a `runc` exception. It applies to every caller.

## Proposed Cache Identity

Use `mount_global_mutation_epoch` as the cache generation. BPF owns and
increments this monotonic number before a relevant mount mutation. The cache
key calls the captured value `security_view_epoch`. This number is not a
signed policy generation, a kernel namespace event, or a per-namespace
allocator.

The global scope is conservative. A relevant mutation in one represented
namespace makes old cache generations unreachable in all represented
namespaces. This behavior can cause an extra cache build. It cannot make an
old generation current. A per-namespace cache epoch requires complete target
and propagation attribution and is outside this experiment.

Use the raw namespace event only as a synchronous race fence.

```text
cache generation identity
  = mount namespace address
  + namespace-root unique mount ID
  + security-view epoch
  + task walk-root mount address
  + task walk-root dentry address

race fence
  = raw namespace event captured for one build or one path walk
```

Keep the existing private cache-key size. Put `security_view_epoch` in the
former raw namespace-event field. Replace the former topology-generation
field with a zero reserved field. This avoids a private pinned-map size change
during the experiment. The build and path-walk scratch state retain the raw
event.

## Build And Publication

The first mount-dependent effect at security epoch `S` performs these steps:

1. Read `S` and require zero pending mutations.
2. Read the namespace identity, namespace-root identity, task walk root, mount
   count, and raw namespace event `E`.
3. Look for `READY(namespace, S, walk root)`.
4. If no ready state exists, scan the complete live mount tree and insert
   candidate rows under `S`.
5. Read the raw namespace event again and require `E`.
6. Require the same security epoch `S` and zero pending mutations.
7. Publish the ready state after all candidate rows exist.
8. Resolve the original object and recheck the raw event, epoch, and pending
   state before BPF applies the policy result.

The ready state is the publication point. Candidate rows do not authorize an
effect without that state.

## Event-Only Reuse

Assume BPF built a ready cache at raw event `E1` and security epoch `S`.
Detached work then advances the raw event to `E2` without advancing `S`.

The next effect performs these steps:

1. Read `S` and require zero pending mutations.
2. Read `E2`.
3. Find the existing ready cache by `S`.
4. Require the current namespace mount count to equal the ready state's
   namespace mount count. A mismatch reports a classifier failure and denies
   the effect.
5. Use its immutable mount-selection rows.
6. Validate every selected mount's namespace, root dentry, and unique mount
   identity as the current walker consumes the row.
7. Recheck `E2`, `S`, and the pending counter before the decision.

If the raw event changes during the effect, BPF denies that effect. A later
effect can retry against the same epoch-qualified cache after the event is
stable. BPF does not publish another cache generation only because the raw
event changed before the effect started.

## Relevant Mutation

A relevant mutation advances the security epoch before the visible change.

```text
READY(S)
  -> relevant mutation begins
  -> pending > 0 and security epoch becomes S+1
  -> effects deny
  -> mutation ends
  -> pending becomes 0
  -> next effect builds READY(S+1)
  -> old READY(S) is not selected
```

The raw namespace event remains an additional race fence. It does not replace
the mutation hook or the fail-closed global fallback.

## Concurrency And Failure Rules

- A ready state must never publish before its complete row set.
- A cache hit requires the current security epoch and zero pending mutations.
- A cache hit requires the live namespace mount count recorded by the ready
  state. A mismatch denies instead of rebuilding under the same epoch.
- A path walk must deny if its raw namespace event changes while it runs.
- A build must deny if its raw namespace event, security epoch, or pending
  state changes before publication.
- A selected mount row must still match its namespace, root dentry, and unique
  mount ID when BPF consumes it.
- A relevant mutation makes the old epoch key unreachable before the changed
  topology can authorize an effect.
- A failed build can leave candidate rows, but no failed build can publish a
  ready state. A later lifecycle change must retire unreachable rows.
- Exact-object event validation remains unchanged in this experiment.

## Policy Separation

This design changes runtime cache qualification only.

- A signed policy generation changes only after an accepted signed policy
  change.
- Signed entry declarations and roles remain stable for the binding and policy
  generation.
- Canonical initial mount routes remain binding-scoped policy material.
- Detached mount activity does not reinstall policy rows.
- A relevant mount mutation changes runtime evidence, not signed policy.
- The retained seccomp server remains unlinked from the active OCI path.

## Implementation Surface

| File | Change |
| --- | --- |
| `bpf/erebor-interceptor/programs/identity_maps.h` | Keep the private key size, store the security-view epoch in the former raw-event field, and reserve the former topology-generation field. |
| `bpf/erebor-interceptor/programs/identity_path.bpf.h` | Key ready states and rows by security epoch. Keep the raw event in scratch state and in prepublication and predecision checks. |
| `crates/mithril-e2e/src/effect/runc.rs` | Require exact ready-key stability for detached activity and retain the protected-effect oracle. |
| `crates/mithril-e2e/harness/vm/two-node-convergence.sh` | Apply the same cache-stability rule and capture a final timeout snapshot. |

## Qualification

Run the tests in this order:

1. Compile the BPF object and run focused Rust tests.
2. Run the lightweight direct-runc case with the distribution runtime.
3. Run the lightweight case with the exact K3s-bundled runc and containerd.
4. Require detached activity to advance the activity sequence without
   advancing the security epoch or adding a ready cache key.
5. Require the concurrent protected read to produce a normal
   `PATH_TREE_POLICY_DENY` result with no `UNRESOLVED_OBJECT` result.
6. Run a separate attached-mutation case. Require a new security epoch and a
   new ready cache generation after reconciliation.
7. Run the paired Kubernetes case only after the lightweight cases pass.
8. Capture cache, epoch, event, process, and stop-marker visibility evidence if
   the Kubernetes reader does not finish.

The Kubernetes result is complete only when the six entry roles pass, the
concurrent reader finishes after the stop marker, the stable follow-up read
passes its denial oracle, and no unresolved object appears.

## Rejected Shortcuts

Do not add a ready state for a new raw event while its rows still use the old
event. The lookup would miss the rows.

Do not delete and replace the prior key. A concurrent reader can still use the
prior security epoch.

Do not trust an endpoint `mountinfo` digest as the synchronous kernel guard.
The digest is test evidence. It does not protect a BPF decision from a
concurrent mutation.

Do not ignore the raw namespace event. It remains the race detector for one
build and one path walk.

Do not weaken `exact_mount_events` as part of this cache experiment. Exact
object identity has a separate transition and ambiguity contract.

## Result Record

Not done.

The experiment uses the dirty working tree based on
`7f02b11ae570172bcb5903cd43efae7768f9302f`. The checkpoint stash remains
available as `487a32fcdd873f43b84c9a157fa0a8e9d3b5e793`.

The following checks passed:

```text
rtk cargo check -p erebor-interceptor -p mithril-e2e
rtk cargo test -p erebor-interceptor -p mithril-e2e --lib
110 passed; 2 ignored

rtk bash crates/mithril-e2e/harness/vm/test.sh

rtk bash .github/scripts/verify-rust-ci.sh
Format, workspace check, strict Clippy, and complete workspace tests passed.
```

The distribution-runc 1.3.4 probe passed its complete lifecycle. Its result is
`target/mithril-r138-entry-security-epoch-retained/runc-entry-role-runtime-probe.json`.
The result records the following facts:

- runtime topology was uninitialized at `createContainer`;
- BPF initialized the live topology;
- ordinary entry policy and canonical initial routes stayed unchanged after a
  mount mutation;
- 32 concurrent detached exec preparations did not change the security epoch
  or ready-key set;
- the concurrent and stable reads produced normal path-policy denials; and
- the fixture removed its pin root, lease, cgroup, and files.

The K3s-runc 1.4.2 probe passed the ordered cache assertions. It then failed in
the later node-owner restart path because its runtime cgroup no longer existed.
The retained output is `/var/tmp/mithril-r141/output` on VM
`mithril-runtime-qualification-3098320`. This result does not qualify the
complete direct-runc lifecycle on K3s.

The fresh-image Kubernetes run failed before the concurrent cache test. It
observed two of the five required independent additional-entry roles. Its
diagnostics are in `target/mithril-r143-kubernetes-security-epoch`. This result
does not qualify or reject security-epoch cache reuse in Kubernetes.

Explicit retirement of unreachable candidate and ready cache rows is not
implemented. The paired Kubernetes concurrent-read proof and the complete
phase acceptance matrix remain open.
