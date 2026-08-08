# How To Set Up A Mithril Manual Acceptance Environment

Status: Proposed shared setup contract. Version-specific values and
Mithril-owned commands must be filled from Phase 0 and the implementing phase.

This guide creates the isolated Linux/Kubernetes/provider test environment used
by every phase manual runbook. It never uses production workloads, credentials,
accounts, repositories, routes, or provider resources.

## 1. Choose The Environment Profile

| Profile | Used by | Required shape |
| --- | --- | --- |
| `KERNEL-LAB` | Phase 0 | disposable Linux VM or host for verifier, hook, race, and saturation prototypes |
| `SINGLE-NODE` | Phases 1-7 | one qualified Linux Kubernetes node plus isolated Mithril Control and evidence storage |
| `TWO-NODE` | Phases 8-11 | two independently booted Linux nodes, Kubernetes control plane, audit/object history, and node-local actuation |
| `PROVIDER-SANDBOX` | Phase 10 | `TWO-NODE` plus dedicated AWS/Google/GitHub/mesh/connector/artifact simulators or sandbox tenants |
| `OPTIONAL-SURFACE` | Phase 12 | owning prerequisite profile plus the separately approved optional component |

A local kind cluster may run deterministic integration tests, but it cannot
satisfy the `TWO-NODE` proof because both workers share one kernel and boot
identity.

## 2. Isolate The Lab

- Use disposable nodes or VMs dedicated to the run.
- Place the cluster and provider simulators on test-only networks.
- Use synthetic marker data with no production value.
- Create run-scoped Kubernetes namespaces, ServiceAccounts, RBAC, Secrets,
  repositories, provider principals, mesh keys, connector identities, and
  artifact buckets.
- Deny routes to production control planes and metadata endpoints. Provide
  explicit mock/sandbox destinations for the API, IMDS, repository, mesh, and
  provider cases.
- Give every resource the run ID and an expiry label. Record the exact cleanup
  targets before testing.

Do not continue if a test principal can reach production data or authority.

## 3. Record Host And Kernel Facts

Run these read-only probes on every node and retain their complete output:

```bash
uname -a
cat /sys/kernel/security/lsm
stat -fc %T /sys/fs/cgroup
test -r /sys/kernel/btf/vmlinux
bpftool feature probe kernel
```

Record CPU model and microcode, memory/NUMA topology, architecture, kernel
release/build/config digest, boot arguments, active LSM order, BTF digest,
cgroup-v2 mount, lockdown state, and the exact helper/program/map/storage
probe results required by the candidate capability profile.

The operator must not infer support from the kernel release. A missing command
or inaccessible probe is recorded as a setup failure until the owning phase
supplies an approved equivalent.

## 4. Record Runtime And Kubernetes Facts

Collect and retain:

```bash
kubectl version --output=yaml
kubectl get nodes -o wide
kubectl get nodes -o yaml
crictl info
```

Also record the containerd or CRI-O version, OCI/NRI/runtime-hook
configuration, CNI and packet-hook order, Kubernetes audit configuration,
object-history source, scheduler binding source, admission configuration,
and full node-to-runtime capability mapping.

For `TWO-NODE`, verify that the selected workers have different boot IDs and
that the scheduler can place one fixture Pod on each node.

## 5. Build And Identify The Candidate

Before implementation, the exact command is intentionally unavailable:

```text
IMPLEMENTATION COMMAND REQUIRED: build mithril-node, mithril-control,
erebor-interceptor BPF objects, mithril-e2e, images, and Helm artifacts from
one source revision and emit their immutable digests.
```

The implementing phase must record:

- source revision and dirty-state digest;
- Rust binaries and BPF object digests;
- Rust/C ABI and schema revision;
- node and Control image digests;
- Helm/package digest;
- policy, trust, fixture, and protected-workload digests; and
- SBOM/provenance where the phase requires them.

Never test a mutable image tag without resolving and retaining its digest.

## 6. Install The Shared Interceptor, Node, And Control

Use only the package produced by the approved phase. The final setup command
must be added by Phase 1 and updated by Phase 11:

```text
IMPLEMENTATION COMMAND REQUIRED: install one mithril-node container per node,
one exclusive Interceptor pin-root owner, and mithril-control with mTLS.
```

Verify before continuing:

1. exactly one process owns the Interceptor pin root on each node;
2. no Tetragon, KubeArmor, Falco driver, stale Mithril installation, or Runtime
   loader overlaps the selected links/maps/hooks;
3. node and Control authenticate each other with run-scoped identities;
4. program, link, map, pin, ABI, policy, boot, and label epochs read back;
5. every required source reports a fresh coverage epoch; and
6. readiness states which capabilities are full, reduced, observe-only, or
   unsupported.

## 7. Install The Unchanged Hugging Face Fixture

Install the safe fixture described by the adversarial acceptance contract:

- long-running concurrent conversion worker;
- native-child and no-child job paths;
- legitimate controller with narrow token/API behavior;
- projected test token and synthetic Secrets;
- allowed conversion file/network paths;
- isolated API/IMDS, repository, provider, mesh, connector, message, and
  artifact targets needed by the approved phase; and
- safe in-process post-compromise driver.

Before enabling observe or protect mode, calculate and retain the protected
deployment digest covering image, manifests, Pod/controller objects, RBAC,
credential inventory without secret bytes, network configuration, concurrency,
and process topology. Every later run compares that digest.

## 8. Create The Run Manifest

Each run manifest records at least:

```text
run_id
phase and deliverable IDs
source and candidate artifact digests
node IDs and boot IDs
kernel/BTF/LSM/cgroup/runtime/Kubernetes/CNI manifest digests
Interceptor program/link/map/pin/ABI generations
Control/node trust and policy generations
protected deployment digest
fixture IDs and activation conditions
provider sandbox identities without secrets
faults to inject
performance threshold-set identity
artifact output location
operator identity and start time
```

Create a new run ID after node reboot, candidate rebuild, policy/trust change,
or fixture change. Do not splice results from different manifests.

## 9. Establish Baseline And Negative Controls

Before an adversarial row:

1. run the unchanged worker and legitimate controller;
2. confirm their allowed file, network, token, and API operations;
3. record latency, throughput, CPU, memory, event loss, and WAL backlog;
4. run one isolated known deny and prove its physical negative oracle; and
5. remove one required source in a separate run and confirm the claim narrows.

A test environment that cannot pass its legitimate control is invalid even if
every hostile action fails.

## 10. Collect Evidence Without Secrets

Retain the artifacts required by the live two-node probe:

- run and platform manifests;
- BPF verifier, program, link, map, pin, ABI, and generation inventories;
- protected deployment before/after digests;
- raw node/Kubernetes/flow/provider envelopes and their hashes;
- source coverage/loss/fault intervals;
- syscall return values and object/packet/provider physical probes;
- graph, finding, policy, response, and postcondition revisions;
- performance/capacity records; and
- final case/result bundle and digest.

Do not retain tokens, Secret values, TLS bodies, or hostile payloads merely to
make verification convenient. Use opaque sentinels, fingerprints, immutable
test object IDs, and provider-native result IDs.

## 11. Stop Conditions

Stop the run and record `Blocked` when:

- production authority or an unapproved route is reachable;
- two supposed nodes share one kernel/boot identity for a two-node claim;
- a required hook/helper/source is unavailable;
- more than one loader or pin-root owner is active;
- the protected deployment digest changed unexpectedly;
- capability, policy, trust, ABI, or fixture generations disagree;
- coverage is already gapped before the test stimulus; or
- the harness cannot provide the physical oracle named by the case.

Do not “continue for information” and later report the same run as qualified.

## 12. Reset And Cleanup

Reset only the run-scoped targets recorded in the manifest. Preserve the
sealed result bundle first. Cleanup must remove test namespaces, provider
resources, credentials, keys, repositories, buckets, devices, routes, pinned
test objects, and local WAL data without touching shared or production state.

The implementing packaging phase must provide exact idempotent cleanup and
post-cleanup inventory commands. Until those commands exist, cleanup remains a
manual inventory task and the environment must be disposable.

## Troubleshooting

| Symptom | Required response |
| --- | --- |
| BPF LSM absent from active LSM order | mark affected prevention unsupported; do not substitute ptrace |
| BTF/CO-RE or verifier failure | retain verifier log and candidate digest; return to Phase 0 |
| second pin-root owner | stop; remove the exact stale/test owner before a new run |
| Kubernetes audit gap | local tests may continue, but semantic/cross-node results are ineligible |
| Control unavailable | installed local policy may continue; new trust/policy/graph/response work is unavailable |
| WAL/ring/source loss | preserve physical decision result and close the affected evidence interval |
| legitimate control fails | invalidate the environment or policy; hostile denials do not pass |
| provider sandbox cannot expose required IDs/readback | record the exact weaker proof or unsupported actuator |

## Related

- [Manual acceptance index](./README.md)
- [Hugging Face adversarial acceptance](../hugging-face-adversarial-acceptance.md)
- [Live two-node lifecycle probe](../live-two-node-lifecycle-probe.md)
