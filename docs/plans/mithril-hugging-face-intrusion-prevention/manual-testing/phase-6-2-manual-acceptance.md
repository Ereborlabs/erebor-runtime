# How To Manually Accept Phase 6.2

Status: The Kubernetes scheduling and runtime-gate procedure is available.
This amended manual runbook has not been run.

Phase: [Control Policy And Evidence Convergence](../phase-6-2-control-policy-and-evidence-convergence.md)

Setup: [`SINGLE-NODE`](./environment-setup.md), extended to two nodes with a
durable Control store and Kubernetes API access

## Outcome

Prove that the live `mithril-node` DaemonSet defines the eligible node set and
that the Kubernetes scheduler selects the exact node. Prove that Control sends
the exact policy only to that node and that the initial container process does
not run before local policy and cgroup-binding activation. Prove that one CRD
revision converges without giving Control ownership of node activation. Prove
that Phase 6 evidence reaches the production Control transaction before the
node truncates its WAL.

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

Record the exact source commit and results. Automated reconciliation and
runtime-gate tests are not substitutes for this physical run.

## Preflight

1. Run the automated companion from the exact source commit under test.
2. Record the Kubernetes, CRI-O or containerd, runc, OCI hook manager, and NRI
   hook-injector versions. For containerd, verify that NRI and the hook-injector
   are active. Verify that the runtime reads the configured hook directory.
3. On each selected host, provision one unique `mithril-node` configuration
   and mTLS identity at the chart host paths. Verify that Control has the exact
   certificate digest for each node. Do not reuse one node ID or private key.
4. Create the admission TLS Secret. Verify that its certificate authenticates
   `mithril-control.<namespace>.svc`. Set the chart CA bundle from the same CA.
5. Compare the generated CRD with the installed CRD:

   ```text
   rtk cargo run -p mithril-control --bin mithril-policy -- print-crd --output /tmp/mithril-workload-protection-profile.json
   kubectl diff -f /tmp/mithril-workload-protection-profile.json
   ```

6. Verify the Control and node service-account boundaries:

   ```text
   kubectl auth can-i list workloadprotectionprofiles.mithril.erebor.dev --all-namespaces --as=system:serviceaccount:<namespace>:mithril-control
   kubectl auth can-i patch workloadprotectionprofiles.mithril.erebor.dev/status --all-namespaces --as=system:serviceaccount:<namespace>:mithril-control
   kubectl auth can-i update workloadprotectionprofiles.mithril.erebor.dev --all-namespaces --as=system:serviceaccount:<namespace>:mithril-control
   kubectl auth can-i patch nodes --as=system:serviceaccount:<namespace>:mithril-control
   kubectl auth can-i get nodes --as=system:serviceaccount:<namespace>:mithril-node
   ```

   The first two commands and the Node patch command must return `yes`. The
   policy update and node service-account commands must return `no`. Built-in
   RBAC grants Node patch as one resource permission. Retain the Node diffs to
   prove that Control changes only the Mithril label, annotations, and
   quarantine taint.
7. Render and install the chart with the exact DaemonSet selector, affinity,
   admission CA, immutable images, and provisioned Secrets and volume claim.
   Do not configure another node selector in Control.
8. Apply each test manifest with strict server validation:

   ```text
   kubectl apply --server-side --field-validation=Strict -f <profile-manifest>
   ```

   The manifest must include the canonical submitted-spec digest annotation.
   A client or API server that silently prunes unknown input is unsupported.

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
   `mithril.erebor.dev/ready=true` and removes only the quarantine taint.
4. Stop one `mithril-node` or expire its Control session. Verify Control
   removes its ready label, restores its quarantine taint, and leaves the last
   active local generation intact. Restore the node and verify it must attest
   the current boot before it becomes ready again.
5. Change the DaemonSet selector or required affinity. Verify Control derives
   the new live constraint. Verify nodes outside it lose the Mithril readiness
   projection and nodes newly inside it start quarantined. Restore the intended
   two-node constraints.
6. Create one valid `WorkloadProtectionProfile`. Record its UID, generation,
   canonical spec digest, compiled candidate digest, rollout snapshot, and
   status conditions. Verify no node receives a workload target before a Pod
   is scheduled.
7. Create one Pod that does not match a profile. Verify admission does not add
   Mithril scheduling annotations or constraints and the runtime hook does not
   run for its containers.
8. Create one matching protected Pod with a digest-pinned image. Verify
   admission adds the live DaemonSet selector, required affinity, ready label,
   profile ID, and source revision. Verify it does not add `spec.nodeName`.
   Record the scheduler binding event and prove the scheduler selected one of
   the two ready Nodes.
9. Verify binding admission accepts the scheduler-selected current Node.
   Submit separate direct `nodeName`, quarantine-toleration, wrong-Node UID,
   stale-ready-label, and wrong-boot cases. Verify all bypass cases reject.
10. After Kubernetes persists Pod UID and `spec.nodeName`, verify Control
    records the Pod, controller, ServiceAccount, container, pinned image,
    selected Node, node UID, node ID, boot ID, and label epoch. Verify only the
    selected node inventories and downloads the exact signed candidate.
11. Observe the stock OCI prestart hook for the protected container. Prove the
    initial PID remains the sole process in its cgroup while the node stages,
    reads back, probes, activates, and publishes the exact binding. Prove the
    application marker does not appear before activation. Verify the runtime
    releases the process only after active policy and cgroup-binding readback.
12. Stop the node admission service or withhold the exact candidate. Start a
    new protected container. Verify the OCI runtime terminates the hook at the
    configured outer deadline, reports container-start failure, and never runs
    the application marker. Restore the service and use a new container
    lifetime for the next attempt.
13. Restart the protected container. Verify it receives a new runtime binding
    and cannot reuse the terminated binding. Delete and recreate the Pod with
    the same name. Verify the new Pod UID creates a new target and the old
    authority cannot start it.
14. Create a second CRD with the same profile ID and another with an overlapping
   workload selector. Verify that both conflicts reject without changing the
   first profile's active node generations.
15. Disconnect the selected node. Update the profile and prove that Control
   reports a mixed rollout while the disconnected node keeps its last valid
   generation.
16. Reconnect the node. Deliver stale, replayed, wrong-target, invalid-signature,
   and current candidates. Prove that only the current valid candidate can
   advance rollout state.
17. Submit an invalid update, stop Control, stop the Kubernetes API, and remove
   the CRD finalizer. Prove that none of these actions remove the last valid
   node generation.
18. Restore Control and the API, force watch compaction and relist, then delete
   and recreate the CRD. Verify UID, generation, retirement, and replacement
   behavior without stale-state reuse.
19. Upload a Phase 6 evidence window with duplicates, delay, reordering, a gap,
   and one conflicting duplicate. Stop storage before acknowledgement, restart
   Control, restore storage, and complete the upload.
20. Verify the node truncates only the durable contiguous range. Record the
   immutable accepted observations, source cursor, coverage state, and policy
   provenance that Phase 7 will consume.
21. Call the admission HTTPS `/healthz` endpoint and the authenticated
    `ControlHealth.Get` method. Record the queue, storage, watch, compile,
    rollout, target, node, evidence-cursor, and pending evidence counts. Verify
    that the reply has no policy, evidence, or secret payload.

## Required Oracles

| Case | Required result |
| --- | --- |
| Valid CRD | One canonical source revision and candidate; exact selected targets only |
| Invalid CRD or compile | Rejected condition; previous active generations stay active |
| Duplicate or overlapping CRD | Conflict condition; no precedence or composed candidate; previous valid generation stays active |
| Partial rollout | Per-node state and mixed generation are explicit; no global-active claim |
| Stale node message | Old boot, target, source, or candidate cannot advance current state |
| CRD deletion | Signed retirement or replacement uses normal activation; disappearance alone removes nothing |
| Control/API outage | Installed local policy continues; new Control-owned work is unavailable |
| Watch relist | Same source revision and target state reconstruct without duplicate authority |
| Evidence retry | Duplicate is idempotent; conflicting duplicate rejects |
| Storage failure | No durable acknowledgement and no node WAL truncation |
| Tenant/RBAC violation | Cross-tenant policy, evidence, acknowledgement, and status access reject |
| CRD status mutation | Status cannot select, sign, deliver, or activate policy |
| Health query | Only an enrolled current-trust session succeeds; the reply contains bounded counts and booleans only |
| New eligible Node | It stays quarantined until its exact current-boot node session reports complete readiness |
| DaemonSet change | Control derives the changed selector and affinity; no second node-pool setting participates |
| Scheduler choice | Kubernetes selects one of two ready nodes; Mithril admission does not set `spec.nodeName` |
| Exact delivery | Only the persisted scheduler-selected node receives the Pod target and candidate |
| Protected start | The initial process remains held until exact policy and cgroup-binding activation |
| Gate failure | The runtime reports start failure at the bounded hook deadline and no application marker runs |
| Runtime lifetime | Container restart and Pod UID replacement create new authority and cannot reuse the old binding |

## Required Artifacts And Pass Rule

Retain the CRD revisions, source and candidate digests, compiler and approval
records, target snapshots, node activation readbacks, acknowledgements,
rollout inventory, restart/relist history, evidence batches, durable commits,
contiguous acknowledgements, WAL before/after state, RBAC denials, and health
metrics. Pass requires the same canonical state after replay and restart, no
stale authority, no premature WAL truncation, and no Control write to node BPF
state.

Record a `Not run`, `Pass`, or `Fail` result for each procedure step. A passed
automated suite cannot change an unrun physical step to `Pass`.

## Troubleshooting

- Kubernetes `resourceVersion` is a watch cursor. Do not compare it as a
  policy version.
- CRD status is a projection. Inspect the Control durable record and the node
  readback before accepting activation.
- If one node is unreachable, expect a mixed rollout. Do not repair the report
  by marking the policy globally active.
- If the CRD disappears without a valid retirement candidate, the last valid
  node generation must remain active.
