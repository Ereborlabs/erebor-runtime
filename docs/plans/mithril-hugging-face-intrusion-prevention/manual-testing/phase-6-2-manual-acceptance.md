# How To Manually Accept Phase 6.2

Status: Not done. This procedure now targets the approved
`WorkloadProtectionPolicy` and `WorkloadProtectionException` resources. The
corrected resources are not implemented or physically tested. The earlier run
used the superseded flattened CRD and stopped when stock `runc` used bootstrap
operations that have no typed authority.

Phase: [Control Policy And Evidence Convergence](../phase-6-2-control-policy-and-evidence-convergence.md)

Setup: [`SINGLE-NODE`](./environment-setup.md), extended to two nodes with a
durable Control store and Kubernetes API access

## Outcome

Prove that the live `mithril-node` DaemonSet defines the eligible node set and
that the Kubernetes scheduler selects the exact node. Prove that Control sends
the exact policy only to that node and that the initial container process does
not run before local policy and cgroup-binding activation. Prove that one base
policy and one bounded file exception converge without giving Control ownership
of node activation or exception consumption. Prove that Phase 6 evidence
reaches the production Control transaction before the node truncates its WAL.

## Current Physical Result

The previous provisioned two-node Kubernetes fixture passed readiness, typed
RBAC review, CRD reconciliation, Pod mutation and bypass rejection, scheduler
selection, exact selected-node delivery, policy activation, runtime binding,
Control acknowledgement, and durable evidence intake. The procedure then
failed protected container start. Stock `runc` used an anonymous file write
and IPC access after binding. The BPF enforcement path denied both operations
because they have no typed authority. The application process did not start.

This result is a product blocker, not test noise. The validated architecture
forbids a broad `runc`, pipe, or socket exception. Completion requires approval
for a signed, typed, bounded runtime-bootstrap authority. The gate-failure,
restart, Pod UID reuse, selector-change, watch-compaction, network-partition,
and storage-outage cases remain `Not run`. Scenario cleanup removed the test
namespace and runtime classes.

## Automated Companion

```text
rtk bash packaging/mithril/helm/tests/verify.sh
rtk cargo test -p mithril-control --test kubernetes_policy_api
rtk cargo test -p mithril-control --test contract
rtk cargo test -p mithril-control --test control_policy_reconciliation
rtk cargo test -p mithril-control --lib --tests
rtk cargo test -p mithril-node --lib --tests
rtk cargo test -p mithril-node --test control_tls
rtk bash .github/scripts/verify-rust-ci.sh
```

Record the commands and results outside the repository. Automated
reconciliation and runtime-gate tests are not substitutes for this physical
run.

## Preflight

1. Run the automated companion against the source under test.
2. Record the Kubernetes, CRI-O or containerd, runc, OCI hook manager, and NRI
   hook-injector versions. For containerd, verify that NRI and the hook-injector
   are active. Verify that the runtime reads the configured hook directory.
3. On each selected host, provision one unique `mithril-node` configuration
   and mTLS identity at the chart host paths. Verify that Control has the exact
   certificate digest for each node. Do not reuse one node ID or private key.
4. Create the admission TLS Secret. Verify that its certificate authenticates
   `mithril-control.<namespace>.svc`. Set the chart CA bundle from the same CA.
5. Compare both generated CRDs with the installed CRDs:

   ```text
   rtk cargo run -p mithril-control --bin mithril-policy -- print-crd --kind policy --output /tmp/mithril-workload-protection-policy.json
   rtk cargo run -p mithril-control --bin mithril-policy -- print-crd --kind exception --output /tmp/mithril-workload-protection-exception.json
   kubectl diff -f /tmp/mithril-workload-protection-policy.json
   kubectl diff -f /tmp/mithril-workload-protection-exception.json
   ```

6. Verify the Control and node service-account boundaries:

   ```text
   kubectl auth can-i list workloadprotectionpolicies.mithril.erebor.dev --all-namespaces --as=system:serviceaccount:<namespace>:mithril-control
   kubectl auth can-i patch workloadprotectionpolicies.mithril.erebor.dev/status --all-namespaces --as=system:serviceaccount:<namespace>:mithril-control
   kubectl auth can-i update workloadprotectionpolicies.mithril.erebor.dev --all-namespaces --as=system:serviceaccount:<namespace>:mithril-control
   kubectl auth can-i list workloadprotectionexceptions.mithril.erebor.dev --all-namespaces --as=system:serviceaccount:<namespace>:mithril-control
   kubectl auth can-i patch workloadprotectionexceptions.mithril.erebor.dev/status --all-namespaces --as=system:serviceaccount:<namespace>:mithril-control
   kubectl auth can-i update workloadprotectionexceptions.mithril.erebor.dev --all-namespaces --as=system:serviceaccount:<namespace>:mithril-control
   kubectl auth can-i create workloadprotectionpolicies.mithril.erebor.dev --namespace=<test-namespace> --as=<policy-writer>
   kubectl auth can-i create workloadprotectionexceptions.mithril.erebor.dev --namespace=<test-namespace> --as=<policy-writer>
   kubectl auth can-i create workloadprotectionexceptions.mithril.erebor.dev --namespace=<test-namespace> --as=<exception-writer>
   kubectl auth can-i create workloadprotectionpolicies.mithril.erebor.dev --namespace=<test-namespace> --as=<exception-writer>
   kubectl auth can-i patch nodes --as=system:serviceaccount:<namespace>:mithril-control
   kubectl auth can-i get nodes --as=system:serviceaccount:<namespace>:mithril-node
   ```

   The list and status commands and the Node patch command must return `yes`.
   Both spec update commands and the node service-account command must return
   `no`. The policy writer can create only the base policy. The exception
   writer can create only the exception. Built-in
   RBAC grants Node patch as one resource permission. Retain the Node diffs to
   prove that Control changes only the Mithril label, annotations, and
   quarantine taint.
7. Render and install the chart with the exact DaemonSet selector, affinity,
   admission CA, immutable images, and provisioned Secrets and volume claim.
   Do not configure another node selector in Control.
8. Apply each test manifest with strict server validation:

   ```text
   kubectl apply --server-side --field-validation=Strict -f <policy-manifest>
   kubectl apply --server-side --field-validation=Strict -f <exception-manifest>
   ```

   The policy and exception specs do not contain a submitted digest or other
   authority annotation. A client or API server that silently prunes unknown
   input is unsupported.

## Procedure

1. Start with two Nodes that match the DaemonSet constraints. Record the
   cluster UID, Control store revision, Node UIDs, node identities, boot IDs,
   label epochs, and active candidate digests.
2. Verify each matching Node receives
   `mithril.erebor.dev/not-ready:NoSchedule` before it has the ready label.
   Verify the DaemonSet tolerates the taint and starts on both Nodes.
3. Verify each `mithril-node` loads and reads back its BPF state, opens the
   root-only runtime-admission socket, registers its downward Node name over
   mTLS, and reports complete readiness. Verify Control then adds
   `mithril.erebor.dev/ready=true` and removes only the quarantine taint. Start
   a second socket owner. Verify that it cannot replace the live node owner.
4. Stop one `mithril-node` or expire its Control session. Verify Control
   removes its ready label, restores its quarantine taint, and leaves the last
   active local generation intact. Restore the node and verify it must attest
   the current boot before it becomes ready again. In the test cluster, replace
   that Node with a Node that has the same name and a new UID. Verify that the
   old session cannot make the replacement ready. Re-enroll the exact new Node
   name and UID before continuing.
5. Change the DaemonSet selector or required affinity. Verify Control derives
   the new live constraint. Verify nodes outside it lose the Mithril readiness
   projection and nodes newly inside it start quarantined. Restore the intended
   two-node constraints.
6. Create one valid `WorkloadProtectionPolicy`. Record its UID, generation,
   bounded rollout status, internal policy source revision, and rollout snapshot.
   Verify status does not contain digests, signatures, receipts, or per-node
   inventory. Verify no node receives a workload target before a Pod is
   scheduled.
7. Create one Pod that does not match a policy. Verify admission does not add
   Mithril scheduling annotations or constraints and the runtime hook does not
   run for its containers.
8. Create one matching protected Pod with a digest-pinned image. Verify
   admission adds the live DaemonSet selector, required affinity, ready label,
   policy identity and source revision. Verify it does not add `spec.nodeName`.
   Record the scheduler binding event and prove the scheduler selected one of
   the two ready Nodes. Submit separate CREATE requests with either reserved
   Mithril annotation and with a required-affinity product above the bound.
   Verify that admission rejects each request.
9. Verify binding admission accepts the scheduler-selected current Node.
   Submit separate direct `nodeName`, quarantine-toleration, wrong-Node UID,
   stale-ready-label, and wrong-boot cases. Verify all bypass cases reject.
   Try to add protection to an unprotected scheduled Pod. Try to remove or
   replace the admitted policy or source annotation on the protected Pod.
   Try to add a matching ephemeral container that violates the admitted image
   pin. Verify that validating admission rejects each update.
10. After Kubernetes persists Pod UID and `spec.nodeName`, verify Control
    records the Pod, controller, ServiceAccount, container, pinned image,
    selected Node, node UID, node ID, boot ID, and label epoch. Verify only the
    selected node inventories and downloads the exact signed candidate.
11. Observe the stock OCI prestart hook for the protected container. Prove the
    initial PID remains the sole process in its cgroup while the node stages,
    reads back, probes, activates, and publishes the exact binding. Prove the
    application marker does not appear before activation. Verify the runtime
    releases the process only after active policy and cgroup-binding readback.
12. Create one `WorkloadProtectionException` for a named file grant, exact Pod
    UID, and matching container. Verify the request cannot exceed the grant
    duration or uses. Verify Control resolves the precompiled file cells and
    sends the exception candidate only to the selected node. Verify the active
    base generation does not change. Consume each permitted use and prove that
    the next use denies. Repeat with expiry, deletion, revocation, stale update,
    overlap, and object recreation. Verify no case refunds a consumed use or
    widens another rule family.
13. Stop the node admission service or withhold the exact candidate. Start a
    new protected container. Verify the OCI runtime terminates the hook at the
    configured outer deadline, reports container-start failure, and never runs
    the application marker. Restore the service and use a new container
    lifetime for the next attempt.
14. Restart the protected container. Verify it receives a new runtime binding
    and cannot reuse the terminated binding. Delete and recreate the Pod with
    the same name. Verify the new Pod UID creates a new target and the old
    authority cannot start it.
15. Create a second policy with an overlapping Pod selector. Verify that an
   ambiguously matched Pod rejects without changing the first policy's active
   node generations.
16. Disconnect the selected node. Update the policy and prove that Control
   reports a mixed rollout while the disconnected node keeps its last valid
   generation.
17. Reconnect the node. Deliver stale, replayed, wrong-target, invalid-signature,
   and current candidates. Prove that only the current valid candidate can
   advance rollout state.
18. Submit an invalid update, stop Control, stop the Kubernetes API, and force
   object deletion without a retirement acknowledgement. Prove that none of
   these actions remove the last valid node generation.
19. Restore Control and the API, force watch compaction and relist, then delete
   and recreate the policy CRD. Verify that deletion retires the last accepted
   generation even though Kubernetes does not increment it. Interrupt the
   watch so that Control misses one deletion event. Verify that a complete
   relist retires the missing durable source. Interrupt a paginated relist
   before it completes and verify that it retires no source. Verify UID,
   generation, retirement, and replacement behavior without historical-state
   reuse.
20. Upload a Phase 6 evidence window with duplicates, delay, reordering, a gap,
   and one conflicting duplicate. Stop storage before acknowledgement, restart
   Control, restore storage, and complete the upload.
21. Verify the node truncates only the durable contiguous range. Record the
   immutable accepted observations, source cursor, coverage state, and policy
   provenance that Phase 7 will consume.
22. Call the admission HTTPS `/healthz` endpoint and the authenticated
    `ControlHealth.Get` method. Record the queue, storage, watch, compile,
    rollout, target, node, evidence-cursor, and pending evidence counts. Verify
    that the reply has no policy, evidence, or secret payload.

## Required Oracles

| Case | Required result |
| --- | --- |
| Valid base policy | One accepted source and signed base-policy profile; exact selected targets only; bounded standard status |
| Invalid public field or compile | Rejected condition; no internal-only field reaches lowering; previous active generations stay active |
| Overlapping base policies | Ambiguous Pod admission rejects; no precedence or composed candidate; previous valid generation stays active |
| Valid exception | Only one named file grant for the exact Pod and container becomes active within its duration and use limits |
| Invalid or exhausted exception | Wrong reference, target, family, duration, uses, overlap, stale state, replay, or excess use denies without refund |
| Partial rollout | Per-node state and mixed generation are explicit; no global-active claim |
| Stale node message | Old boot, target, source, or candidate cannot advance current state |
| Policy deletion | Disappearance creates signed retirement; it does not directly erase a local generation |
| Exception removal | Expiry, exhaustion, deletion, or revocation creates an exact signed revocation and preserves consumption history |
| Control/API outage | Installed local policy continues; new Control-owned work is unavailable |
| Watch relist | Same source revision and target state reconstruct without duplicate authority |
| Complete relist deletion | A durable source that is absent from the complete snapshot enters signed retirement |
| Partial relist | No source retires from an incomplete snapshot |
| Evidence retry | Duplicate is idempotent; conflicting duplicate rejects |
| Storage failure | No durable acknowledgement and no node WAL truncation |
| Tenant/RBAC violation | Cross-tenant policy, evidence, acknowledgement, and status access reject |
| CRD status mutation | Status cannot select, sign, deliver, activate, approve, or consume policy or exception authority |
| Health query | Only an enrolled current-trust session succeeds; the reply contains bounded counts and booleans only |
| New eligible Node | It stays quarantined until its exact current-boot node session reports complete readiness |
| Replaced Node UID | A replacement Node cannot inherit a ready session through the same name |
| DaemonSet change | Control derives the changed selector and affinity; no second node-pool setting participates |
| Scheduler choice | Kubernetes selects one of two ready nodes; Mithril admission does not set `spec.nodeName` |
| Pod update | A scheduled Pod cannot add, remove, or replace its admitted Mithril protection identity |
| Ephemeral-container update | A protected Pod cannot add a matching container outside the admitted image-pin contract |
| Exact delivery | Only the persisted scheduler-selected node receives the Pod target and candidate |
| Protected start | The initial process remains held until exact policy and cgroup-binding activation |
| Gate failure | The runtime reports start failure at the bounded hook deadline and no application marker runs |
| Runtime lifetime | Container restart and Pod UID replacement create new authority and cannot reuse the old binding |

## Required Artifacts And Pass Rule

Retain the policy and exception source revisions, policy and exception
candidates, compiler and approval records, target snapshots, node activation readbacks,
acknowledgements, exception receipts, rollout inventory, restart and relist
history, evidence batches, durable commits, contiguous acknowledgements, WAL
before and after state, RBAC denials, and health metrics. Pass requires the
same canonical state after replay and restart, no stale or refunded authority,
no premature WAL truncation, and no Control write to node BPF state.

Record a `Not run`, `Pass`, or `Fail` result for each procedure step. A passed
automated suite cannot change an unrun physical step to `Pass`.

## Troubleshooting

- Kubernetes `resourceVersion` is a watch cursor. Do not compare it as a
  policy version.
- CRD status is a projection. Inspect the Control durable record and the node
  readback before accepting activation.
- If one node is unreachable, expect a mixed rollout. Do not repair the report
  by marking the policy globally active.
- If Control cannot create and sign a valid retirement candidate, the last
  valid node generation must remain active.
