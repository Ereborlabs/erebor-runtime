# Phase 6.2 Held OCI Route Publication Design Proposal

Status: Approved for implementation on 2026-09-05. Implementation and
qualification are not recorded in this proposal yet.

Parent: [Phase 6.2 Control Policy And Evidence Convergence](./phase-6-2-control-policy-and-evidence-convergence.md)

Related cache design: [Independent runtime mount-cache generation](./phase-6-2-security-epoch-qualified-mount-cache-design.md)

Closure: [Phase 6.2 closure matrix](./phase-6-2-closure-matrix.md)

This proposal prevents a held OCI container from publishing canonical path
routes from its preliminary process view. The binding and signed policy become
active during `createRuntime`. Binding-scoped exact objects, canonical mount
routes, and entry rows wait for the authoritative OCI root view at
`createContainer`.

## Intended End State

A newly held Kubernetes container has an active `PreparedContainer` binding
before runc continues. It has no binding-scoped path authority until the
matching `createContainer` request supplies the OCI root handle. The node
publishes the authoritative OCI routes before it releases the container.

Routine process-view reconciliation remains available for a running container,
node restart, BPF state recovery, and container adoption. A routine
reconciliation cannot make a held `PreparedContainer` path-resolved.

## Current Defect

The second `createRuntime` hook publishes the held binding and calls the normal
exact-binding reconciliation path. The periodic node reconciliation can call
the same path before `createContainer`.

The current resolver uses the held task process view when that view does not
look like the host root. A pre-entry runc view can still contain a host-prefixed
container root. The node can therefore publish a route such as this route:

```text
run/k3s/containerd/.../rootfs/srv/team/blue/secrets
```

The matching OCI root view later produces this route:

```text
/srv/team/blue/secrets
```

Commit `bf8a724f` makes the OCI route replace the preliminary route. That
precedence correction is necessary, but it does not prevent the preliminary
route from becoming visible before the OCI request.

## Authority Decision

Use the existing binding lifecycle as the authority boundary.

| Binding condition | Accepted route source |
| --- | --- |
| Held initial task and `PreparedContainer` | Matching explicit OCI entry view only |
| Running container with no retained authoritative route | Current process-root view |
| Active binding with retained authoritative OCI rows | Retained authoritative rows |
| Retired binding | No route source |

`has_host_root` remains a validation fact. It is not sufficient authority for a
held `PreparedContainer` route.

## Runtime Flow

The first `createRuntime` hook stages immutable runtime facts
  -> `WorkloadBindingOwner` validates the Kubernetes and container identity
  -> the stage grants no binding or path authority

The second `createRuntime` hook prepares the container
  -> `WorkloadBindingOwner` verifies CRI `Created` state and the held task
  -> `WorkloadBindingOwner` publishes the binding as `PreparedContainer`
  -> `NativeSecurityStateOwner` publishes and reads back the BPF identity
  -> `NodePolicyGenerationOwner` sees that the target requires an OCI entry view
  -> routine reconciliation publishes no exact object for that binding
  -> routine reconciliation publishes no canonical mount route for that binding
  -> routine reconciliation does not mark that binding path-resolved
  -> the signed policy generation and the prepared binding stay active
  -> runc can continue to the `createContainer` hook

Periodic reconciliation runs before `createContainer`
  -> `WorkloadBindingOwner` reports the same OCI-view requirement
  -> `NodePolicyGenerationOwner` does not use `/proc/<pid>/root` for path authority
  -> no preliminary route becomes reachable

The matching `createContainer` hook supplies the OCI root handle
  -> `RuntimeAdmissionServer` validates the immutable staged facts
  -> `WorkloadBindingOwner` verifies the binding ID and held initial task
  -> `NodePolicyGenerationOwner` validates the explicit OCI view
  -> `NodePolicyGenerationOwner` resolves exact selectors through that view
  -> `NodePolicyGenerationOwner` compiles canonical mount routes from that view
  -> `NodePolicyGenerationOwner` publishes and reads back the complete rows
  -> `NodePolicyGenerationOwner` marks the binding path-resolved
  -> `WorkloadBindingOwner` marks the declared entries staged
  -> the hook returns allow
  -> runc can release the application entry

Routine reconciliation runs after the OCI publication
  -> `retained_binding_ids` contains the active resolved binding
  -> `NodePolicyGenerationOwner` keeps the authoritative OCI objects and routes
  -> the process view cannot replace them

The node starts after the container is already running
  -> no live OCI admission request exists
  -> `WorkloadBindingOwner` reports a running process target
  -> `NodePolicyGenerationOwner` can use the current container process-root view
  -> normal recovery and adoption remain available

The OCI request fails, expires, or differs from the held binding
  -> `NodePolicyGenerationOwner` publishes no path authority for the request
  -> `WorkloadBindingOwner` does not mark the declared entries staged
  -> the runtime admission response denies the container start
  -> the application process does not run

## Implementation Surface

| Owner and file | Required change |
| --- | --- |
| `WorkloadBindingOwner` in `crates/mithril-node/src/identity/binding.rs` | Report when an exact-object target is a held `PreparedContainer` that requires an OCI entry view. |
| `NodePolicyGenerationOwner` in `crates/mithril-node/src/policy.rs` | Skip process-view exact objects and mount routes for that target. Do not retain old path rows for a target that still waits for its OCI view. Continue to accept the matching explicit OCI view. |
| Direct-runc qualification in `crates/mithril-e2e/src/effect/runc.rs` | Run routine reconciliation before the OCI reconciliation. Require zero binding path rows before the OCI view, complete rows after the OCI view, stable later reconciliation, and the normal path denial. |
| VM harnesses in `crates/mithril-e2e/harness/vm` | Require the route-deferral result before the paired Kubernetes protected-start result can pass. |

This change does not add a BPF ABI field, policy field, runtime protocol field,
durable owner, hook, daemon, or cache generation.

## Acceptance

1. A focused binding test identifies a held `PreparedContainer` as requiring
   an OCI entry view.
2. The lightweight direct-runc case runs the production routine reconciliation
   before the OCI reconciliation.
3. The lightweight case finds no entry or canonical mount-root row for that
   binding before the OCI view.
4. The lightweight case finds the complete OCI entry and route rows after the
   OCI view.
5. A later routine reconciliation preserves the OCI rows exactly.
6. The recursive protected read returns `PATH_TREE_POLICY_DENY` and does not
   return `APPLICATION_DEFAULT_ALLOW` or `UNRESOLVED_OBJECT`.
7. The paired Kubernetes protected-start case records the same route-deferral
   invariant and denial result.
8. A running-container recovery test continues to use the process-root view.
9. The repository Rust CI procedure passes after the final source edit.

## Exclusions And Remaining Work

This proposal does not implement explicit garbage collection for unreachable
mount-cache rows. It does not close the later evidence-health or node-projection
stress checks in the complete two-node suite. Those items remain open in the
Phase 6.2 closure matrix.

## Result

Not done. The design is approved. Implementation and current-source
qualification remain required.
