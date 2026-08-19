# Live Two-Node Lifecycle Probe

Status: The Phase 5 network-route portion is verified. The complete lifecycle
probe remains required for later applicable phases.

## Purpose

Prove the product works across the real boundaries that unit tests and event
replay cannot establish:

- supported Linux kernel and BPF verifier;
- BPF LSM and cgroup/packet decision points;
- Rust/libbpf program/map/link lifecycle;
- containerd or CRI-O create/start ordering;
- first-process task/profile binding;
- two independently observed node-local task trees;
- Kubernetes audit, object UID, controller, scheduler, and CRI joins;
- local and remote physical containment; and
- restart, loss, replacement, and watch-window behavior.

Kind-on-one-host, mocked audit, and synthetic event replay are useful CI layers.
They do not replace the final two-node proof because they cannot independently
prove node boot identity, host ownership, remote root binding, or node-local
actuation.

## Verified Phase 5 Network Portion

The Phase 5 companion creates two disposable VMs with different boot
identities and installs K3s `v1.35.5+k3s1`. It waits for exactly two Ready
nodes and pins one peer Pod to each node. A Rust peer server runs inside each
Pod network namespace. The opposite host sends to the remote Pod IP through
the Flannel CNI route.

Both directions delivered the allowed TCP and UDP payloads. The denied port
had no peer receipt. The complete 13-row network fixture matrix passed on each
source node. The harness removed the namespace, K3s installations, and its two
VMs after the result.

This result closes only the Phase 5 network-route requirement. It does not
claim Kubernetes audit joins, remote task-root binding, distributed lineage,
Control coordination, cross-node response authorization, Pod-origin
enforcement, another CNI, or an arbitrary service mesh. Those requirements
remain with their owning later phases or a future claim-expansion result.

## Required Testbed

Record exact versions and immutable image digests for:

- two Linux nodes or VMs with independent boot IDs;
- one advertised full-support kernel configuration;
- cgroup v2;
- BTF and every selected BPF LSM/helper/map/program capability;
- containerd and, on a separate matrix run, CRI-O if both are advertised;
- a Kubernetes version supported by the phase;
- enabled Kubernetes audit with a source that preserves audit IDs;
- the `mithril-node` image and one DaemonSet Pod on each node;
- Mithril Control and its schema/content/profile generations;
- the Hugging Face fixture images and manifest digest; and
- provider simulators or dedicated sandbox tenants required by the phase.

The test cluster contains no production credentials, accounts, repositories,
data, routes, or endpoints.

## Preflight

Before each run:

1. prove the two node boot IDs differ;
2. collect the Mithril capability report and active LSM list from each node;
3. prove one active sensor pin-root owner per node;
4. prove no Tetragon, KubeArmor, Falco kernel driver, or second Runtime loader
   overlaps the selected hooks;
5. record BPF program, link, map, ABI, policy, and label-epoch generations;
6. record Kubernetes audit/object-watch/CRI and provider-source coverage;
7. hash the protected fixture deployment;
8. prove the fixture token, Secrets, cloud identities, repositories, mesh, and
   connector routes are isolated test assets; and
9. start a run-specific evidence namespace and idempotency domain.

Any failed preflight is a classified capability or coverage failure. The probe
must not continue and later claim a full-tier pass.

## Probe A: Legitimate Unchanged Workload

1. Start the unchanged long-running worker and legitimate controller.
2. Run overlapping logical jobs in the same interpreter.
3. Run approved child-process and no-child job paths.
4. Let the legitimate controller read its mounted projected token and perform
   its signed API sequence.
5. Complete approved conversion file and network effects.
6. Assert no false process/effect/authority finding.
7. Compare the protected deployment digest with preflight.
8. Record performance and coverage.

Required result: `HF-BASE-001` passes without a Defender-specific job event,
job-per-Pod architecture, removed credential, RBAC change, or network blackout.

## Probe B: First Local Prohibited Effect

1. Invoke the safe post-compromise driver in the existing worker interpreter.
2. Attempt the phase-selected prohibited file/credential effect.
3. If that effect is deliberately allowed for the profile variant, attempt the
   prohibited executable, device/security, or network effect.
4. Record the exact task/process/execution/profile/object/destination and kernel
   decision.
5. Probe whether bytes, image installation, connection, packet, privilege, or
   device state changed.
6. Assert every forbidden later fixture action was not invoked.

Required result after Phase 5: the first selected prohibited effect is
`prevented`, not merely followed by a killed process.

## Probe C: Same-Process Authority Ambiguity

1. Use the legitimate controller's existing process, token, client, and TLS
   connection.
2. Perform one approved API operation.
3. Perform one isolated out-of-profile operation that the test RBAC allows.
4. Assert the kernel/network evidence does not invent an API verb.
5. Assert Kubernetes audit produces the semantic finding with actual result.
6. Trigger the approved process/socket or cgroup response.
7. Verify the physical fence and preserve the fact that the API effect may
   already have completed.

Required result: honest `detected_after_effect` followed by the exact verified
or explicitly partial containment result.

## Probe D: Cross-Node Expansion

1. In a run variant where the source API write is deliberately allowed,
   process A on node 1 creates an isolated test owner object.
2. Let the controller create a child Pod on node 2.
3. Capture audit ID, object UIDs/resourceVersions, owner references, binding,
   full container ID, and node 2 root task/process.
4. Query the distributed lineage and retain every causal edge/evidence ID.
5. Assert no cross-node native parent edge exists.
6. Delete and recreate an object under the same name and prove its UID creates
   a distinct branch.
7. Remove one bridge source in a separate run and assert a named open branch.

Required result after Phase 8: `HF-XNODE-001` proves the direct path only when
every authoritative bridge exists.

## Probe E: Distributed Containment

1. Freeze the current lineage version into a simulated response plan.
2. Review every target, causal edge, physical action, blast radius,
   authorization, and postcondition.
3. Authorize the exact fixture-scoped plan.
4. Fence the node 1 seed and its known sockets.
5. Re-resolve and contain node 2's exact native member.
6. Constrain the exact owning controller with UID/resource-version
   preconditions.
7. During `watch_until`, cause one controller replacement or late branch.
8. Require a new plan version and authorization for that branch.
9. Verify every node, controller, provider, and coverage postcondition.

Required result after Phase 9: the response is `verified` only if no required
open branch or replacement remains. An injected offline node or missing source
must force `partial` or `unknown`.

## Probe F: Provider Expansion And Recovery

For each Phase 10 adapter:

1. create one run-scoped provider identity/resource;
2. perform the safe representative action;
3. ingest the authoritative audit event with immutable identifiers;
4. prove the native/provider causal edge at its declared strength;
5. simulate the exact and any wider fallback response;
6. authorize only the isolated test target;
7. invoke the connector;
8. verify provider-specific postconditions; and
9. prove direct TLS flow alone never identified the operation.

GitHub token revocation and installation suspension, mesh key deletion and
device deletion, and exact cloud identity versus role-wide session revocation
must remain separate probes.

## Probe G: Fault, Restart, And Upgrade

Repeat the applicable path while injecting:

- ring-buffer loss;
- userspace queue overflow;
- local spool full/corruption;
- central mTLS outage;
- node collector restart;
- control restart;
- node reboot;
- policy generation swap and rollback;
- stale root-admission acknowledgement;
- Kubernetes audit and watch loss;
- connector delay/replay;
- controller replacement;
- mixed node capability/generation; and
- upgrade failure between program/map generations.

Required result: enforcement, observation, coverage, and response states remain
distinct. No gap is silently represented as a benign interval or verified
response.

## Required Artifacts

Each probe run retains:

```text
run manifest and immutable fixture digests
node kernel/capability/boot reports
BPF verifier, program, link, map, ABI, generation and pin-root inventory
protected deployment before/after digest
raw node/Kubernetes/flow/provider source envelopes and hashes
coverage intervals and loss/fault records
native graph export
distributed lineage versions
finding versions
response simulation, authorization, executions and postconditions
performance report
final conformance result
```

Secrets and response bodies are never retained merely to make a test easier.
Fixtures use opaque fingerprints and provider-native IDs.

## Phase Reporting

Every applicable phase result records:

- testbed versions and node boot IDs;
- exact fixture/test IDs run;
- supported and missing capability classes;
- legitimate control result;
- adversarial decision and physical postcondition;
- graph/correlation result;
- injected fault and resulting coverage state;
- performance against budget;
- artifact location and digest; and
- `Done`, `Not done`, or `Blocked`.

If the host or cluster cannot satisfy the phase's live prerequisites, report
the exact failure and mark the phase blocked. Do not substitute replay or unit
tests and call the live proof complete.
