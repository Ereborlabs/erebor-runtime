# How To Manually Accept Phase 6.2

Status: Implementation available. Focused automated acceptance passed on
2026-08-22. The final repository gate is pending. This manual runbook has not
been run.

Phase: [Control Policy And Evidence Convergence](../phase-6-2-control-policy-and-evidence-convergence.md)

Setup: [`SINGLE-NODE`](./environment-setup.md), extended to two nodes with a
durable Control store and Kubernetes API access

## Outcome

Prove that one CRD revision converges through Control to the exact selected
nodes without giving Control ownership of node activation. Prove that Phase 6
evidence reaches the production Control transaction before the node truncates
its WAL.

## Automated Companion

```text
rtk cargo test -p mithril-control --test kubernetes_policy_api
rtk cargo test -p mithril-control --test contract
rtk cargo test -p mithril-control --test control_policy_reconciliation
rtk cargo test -p mithril-control --lib --tests
rtk cargo test -p mithril-node --lib --tests
rtk cargo test -p mithril-node --test control_tls
rtk bash .github/scripts/verify-rust-ci.sh
```

The focused contract, reconciliation, and Kubernetes API command passed 14
tests at source commit `f26d622`. The deterministic two-node reconciliation
test is not a substitute for this physical run.

## Preflight

1. Run the automated companion from the exact source commit under test.
2. Compare the generated CRD with the installed CRD:

   ```text
   rtk cargo run -p mithril-control --bin mithril-policy -- print-crd --output /tmp/mithril-workload-protection-profile.json
   kubectl diff -f /tmp/mithril-workload-protection-profile.json
   ```

3. Verify that the Control service account can read policy and target facts,
   and that it cannot write policy spec:

   ```text
   kubectl auth can-i list workloadprotectionprofiles.mithril.erebor.dev --as=system:serviceaccount:<namespace>:mithril-control -n <namespace>
   kubectl auth can-i patch workloadprotectionprofiles.mithril.erebor.dev/status --as=system:serviceaccount:<namespace>:mithril-control -n <namespace>
   kubectl auth can-i update workloadprotectionprofiles.mithril.erebor.dev --as=system:serviceaccount:<namespace>:mithril-control -n <namespace>
   ```

   The first two commands must return `yes`. The last command must return
   `no`.
4. Apply each test manifest with strict server validation:

   ```text
   kubectl apply --server-side --field-validation=Strict -f <profile-manifest>
   ```

   The manifest must include the canonical submitted-spec digest annotation.
   A client or API server that silently prunes unknown input is unsupported.

## Procedure

1. Record the cluster UID, Control store revision, two node identities and boot
   and label epochs, and the current active candidate digest on each node.
2. Create one valid `WorkloadProtectionProfile`. Record its UID, generation,
   canonical spec digest, compiled candidate digest, rollout snapshot, and
   status conditions.
3. Create a second CRD with the same profile ID and another with an overlapping
   workload selector. Verify that both conflicts reject without changing the
   first profile's active node generations.
4. Verify each selected node receives the signed candidate, stages and reads
   it back, runs the controlled probes, changes one active pointer, and returns
   an acknowledgement bound to its current boot and candidate.
5. Disconnect one node. Update the profile and prove that Control reports a
   mixed rollout while the disconnected node keeps its last valid generation.
6. Reconnect the node. Deliver stale, replayed, wrong-target, invalid-signature,
   and current candidates. Prove that only the current valid candidate can
   advance rollout state.
7. Submit an invalid update, stop Control, stop the Kubernetes API, and remove
   the CRD finalizer. Prove that none of these actions remove the last valid
   node generation.
8. Restore Control and the API, force watch compaction and relist, then delete
   and recreate the CRD. Verify UID, generation, retirement, and replacement
   behavior without stale-state reuse.
9. Upload a Phase 6 evidence window with duplicates, delay, reordering, a gap,
   and one conflicting duplicate. Stop storage before acknowledgement, restart
   Control, restore storage, and complete the upload.
10. Verify the node truncates only the durable contiguous range. Record the
   immutable accepted observations, source cursor, coverage state, and policy
   provenance that Phase 7 will consume.
11. Call the authenticated `ControlHealth.Get` method. Record the queue,
    storage, watch, compile, rollout, target, node, evidence-cursor, and pending
    evidence counts. Verify that the reply has no policy, evidence, or secret
    payload.

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
