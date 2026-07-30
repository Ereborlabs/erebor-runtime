# Hugging Face Adversarial Acceptance

Status: Normative standing acceptance contract for every phase in this plan.

This contract turns the public `HF-008` through `HF-021` sequence into
repeatable product tests. It does not embed the original exploit strings,
production credentials, external destinations, or destructive provider
actions.

## Proof Objective

The suite must answer, for each run:

```text
what exact subject acted?
what exact physical effect was attempted?
which signed rule and kernel/provider decision point decided it?
did the effect complete?
what later causal branches exist?
what source coverage supports the answer?
what physical postcondition proves prevention or containment?
```

Every adversarial scenario has a legitimate control using the same deployment
shape. A test is invalid if it passes only after removing credentials, changing
RBAC, splitting jobs into Pods/processes, changing the application harness, or
blocking every network destination.

## Safe Reference Testbed

The fixture lives under the proposed
`crates/mithril-e2e/fixtures/hugging-face/` tree and must be implementable in
two modes:

1. deterministic CI/replay with synthetic but schema-valid authoritative
   records; and
2. a live isolated two-node Kubernetes cluster with supported kernels and
   container runtimes.

The live fixture contains:

- one long-running conversion worker Pod that accepts many concurrent logical
  jobs in the same interpreter;
- optional child-process work so native subtrees can be tested without
  pretending every job creates one;
- one legitimate controller role that reads its mounted projected token and
  performs a narrow expected Kubernetes API sequence;
- the original-style mounted projected token, test environment credentials,
  RBAC, API/IMDS-representative routes, and network paths;
- synthetic Secrets, repositories, provider accounts, mesh devices, and
  connector identities containing no production authority;
- a second node on which an isolated test controller can create an exact
  child workload;
- Kubernetes audit plus object history, scheduler binding, CRI/container-start,
  node sensor, flow, and provider-event sources;
- an authenticated test clock/sequence controller for loss, reorder, delay,
  replay, and restart injection; and
- a safe post-compromise driver invoked inside the existing interpreter.

The post-compromise driver directly attempts the effect sequence that hostile
in-process code would attempt. It does not need to weaponize HDF5 or Jinja to
prove the Mithril boundary. A separate application-owned regression fixture may
verify HDF5/Jinja fixes, but it is not a baseline Mithril gate.

## Unchanged Deployment Invariant

The baseline fixture is hashed before the first observe run:

```text
container image digest
Pod/controller manifest digests
ServiceAccount and RBAC object UIDs/resourceVersions
mounted credential inventory without secret bytes
network/CNI configuration digest
job concurrency and process-topology configuration
```

Every baseline prevention run compares those values. Mithril-owned
DaemonSet/control/audit configuration is allowed to change; the protected
application deployment is not. Optional H/R variants use a different fixture
ID and can never satisfy the unchanged-deployment gate.

## Required Result Vocabulary

Tests assert one of these exact meanings:

| Result | Required evidence |
| --- | --- |
| `prevented` | authoritative pre-effect hook returned denial and a physical probe proves the effect did not occur |
| `observed_allowed` | effect completed under the current signed profile and evidence records that result |
| `observed_denied` | another authority denied the operation and its result is retained |
| `detected_after_effect` | authoritative audit proves a semantic deviation that already completed or may have completed |
| `contained_verified` | all requested physical restrictions and watch-window postconditions succeeded under healthy coverage |
| `partial` | at least one requested restriction succeeded but a branch, authority, scope, or postcondition remains unresolved |
| `failed` | no intended restriction achieved its physical postcondition |
| `unknown` | coverage or evidence cannot establish completion or containment |

`SIGKILL` delivery, ring-buffer receipt, a BPF map update, an API `2xx`, or a
finding severity cannot by itself produce `prevented` or
`contained_verified`.

## Per-Test Record

Every test case committed to `mithril-e2e` declares:

```text
test_id
incident_event_ids[]
fixture_version
protected_deployment_digest
required_platform_tier
required_sources_and_coverage[]
signed_profile_digest
initial_native_subject
adversarial_action
legitimate_control_action
expected_decision_point
expected_result
forbidden_later_effects[]
required_evidence_fields[]
required_physical_postconditions[]
expected_degraded_result_by_missing_source[]
```

The test runner rejects a result if the required coverage interval, profile
generation, platform capability, or protected-deployment digest is missing.

## Incident Stage Matrix

| Published stage | Safe fixture action | Mithril decision/evidence point | Required postcondition |
| --- | --- | --- | --- |
| `HF-008` hostile revision | submit an inert fixture revision carrying an immutable test digest | ingest existing platform revision identity when available; otherwise create no invented revision-to-process edge | revision remains contextual unless authenticated scheduling/platform evidence binds it |
| `HF-009` environment disclosure | same interpreter reads a designated protected environment/proc object and a normal conversion file | BPF LSM file/mmap decision under the exact process role | prohibited bytes are not returned; ordinary conversion read succeeds |
| `HF-010` in-process execution | invoke the safe driver inside the existing Python process with no fork/exec | record no fabricated exec edge; evaluate its first external effect | graph retains the same process/execution identity until a real native transition |
| `HF-011` projected token | expected controller and unexpected worker/helper both access the same mounted test token | task-role plus kernel file-object decision; already-in-memory case moves to later effect | expected role succeeds; prohibited role receives `EACCES`; no claim that old in-memory bytes were revoked |
| `HF-012` API/IMDS probe | direct Python TCP/UDP attempts to all fixture API/metadata addresses, plus legitimate controller API use | BPF LSM/cgroup connect/send decision; server audit for allowed same-process traffic | prohibited connection never establishes or sends; legitimate connection works; unexpected server operation is classified from audit |
| node/CSI authority pivot | test principal attempts high-risk token, Secret, exec, and workload operations | Kubernetes audit and effective authority inventory | exact verb/resource/result retained; no admission-prevention claim for reads |
| privileged workload creation | isolated test controller creates a privileged/host-mount-equivalent harmless fixture object | audit ID → object UID → controller/owner → Pod UID → binding → remote root | denied server write never persists, or allowed write is labeled completed and every resulting branch is correlated |
| broad Secret access | authorized test principal reads a synthetic Secret | API audit is the semantic boundary | result is `detected_after_effect` unless RBAC denied it; admission is never credited |
| `HF-013` dead-drop | use a mock repository API over TLS with a provider audit event | flow proves communication; repository audit proves operation/resource/result | no clone/push semantic claim from packets; exact revision can be quarantined only from immutable provider identity |
| `HF-014`–`HF-016` mesh/connector | create a test enrollment and connector forwarding event with exact IDs | mesh and connector audit plus typed request-forwarding edge | exact key/device/route is disabled when authorized; shared broker widening is disclosed |
| `HF-017` cloud use | use a dedicated test access-key/role session against a mock or sandbox account | CloudTrail-compatible exact event/access-key/session identity | source is fenced; exact or role-wide revocation postcondition matches provider semantics |
| `HF-018` source control | mint/use a dedicated GitHub-compatible installation token for a test repository | provider audit distinguishes token mint, clone, push, workflow, and result | exact known token revocation or installation suspension is verified separately |
| `HF-019` remote loader | load a harmless immutable test artifact through a fixture service | local exec/mmap/code-source effect plus request/message/artifact digest joins | unapproved load is denied; allowed branch is correlated only by exact request/message/digest |
| `HF-020`–`HF-021` continuation | emit late branches and controller replacement during containment watch | lineage versioning, response coordinator, connector/node postconditions | closure requires no required open branch and healthy coverage through `watch_until` |

## Core Scenario Catalog

### `HF-BASE-001`: unchanged concurrent worker remains functional

- Run at least two overlapping logical jobs in one interpreter and at least one
  job path with a child process.
- Require no Mithril job event, wrapper, sidecar, or manifest change.
- Assert no fabricated work-item identity and no unexpected process/effect
  finding for approved behavior.
- Assert the signed legitimate controller can read its token and execute its
  approved API sequence.
- Record throughput and latency against the Phase 0 budget.

### `HF-LOCAL-001`: in-process protected-file denial

- Invoke the safe driver inside the existing interpreter.
- Attempt one protected environment/proc read and one projected-token read that
  the worker role does not need.
- Require the BPF LSM hook to return `EACCES`.
- Verify the sentinel bytes were not returned and no later socket/API stage ran.
- In a separate negative-control variant, place a test credential in the
  interpreter's environment before Mithril attaches or before a permitted
  fork. Reading it through `os.environ` performs no new file effect; the test
  must mark file prevention ineligible and require the later prohibited
  socket/API effect to be denied or detected. It must never claim the file hook
  revoked bytes already in memory.
- Require task cookie, process lineage, execution, role, file-object key,
  profile generation, errno, and evidence sequence.
- Run the allowed conversion-file and legitimate-controller-token controls.

### `HF-LOCAL-002`: unexpected child and immutable executable identity

- Attempt `python → sh`, `python → curl`, and a path-matching but
  content-replaced executable.
- Require denial before image installation and absence of a resulting
  `ExecutionInstance`.
- Exercise `execve`, `execveat`, script/interpreter resolution, `memfd`/
  `fexecve`, overlay copy-up, bind mount, hard link, and deleted-open cases.
- Prove an approved executable edge succeeds and receives its resulting role.

### `HF-LOCAL-003`: in-process device, privilege, and kernel escape

- From the existing interpreter, attempt unapproved device open/ioctl,
  capability/credential transition, ptrace/process-memory access, namespace,
  mount, BPF, perf, keyring, and module operations.
- Require a pre-effect denial for every advertised full-tier class.
- A missing hook or unproved path must downgrade the node; it cannot be omitted
  from the result.

### `HF-NET-001`: process-role API/IMDS denial

- Attempt TCP and UDP from Python without creating a child process.
- Cover IPv4, IPv6, hard-coded IP, changed DNS, public/private API endpoints,
  node-local proxies, and secondary-interface inventory.
- Require no prohibited connection establishment or packet delivery.
- Require approved conversion traffic and controller API traffic to remain
  functional.

### `HF-NET-002`: descriptor and established-flow containment

- Exercise inherited sockets, `SCM_RIGHTS`, connected writes, `sendmsg`,
  unconnected UDP, `sendfile`, `splice`, `io_uring`, raw/packet sockets,
  TUN/TAP, AF_XDP, and BPF redirection as applicable.
- Prove use-time role checks where current-task context exists.
- Prove a socket-cookie or cgroup packet fence stops an already established
  flow.
- State sharing/blast radius when one socket is used by multiple processes.

### `HF-SEM-001`: same-process semantic ambiguity

- Let the legitimate controller use its existing process, token, destination,
  and TLS connection.
- Send one approved API operation and one out-of-profile operation to the test
  API.
- Require the kernel/network layer to label both as allowed channel activity,
  not decode a verb.
- Require Kubernetes/provider audit to produce the semantic deviation with
  exact request identity and actual result.
- Require the response result to say `detected_after_effect` if the server
  allowed it.

### `HF-ID-001`: hostile native identity matrix

- Cover thread creation, fork without exec, fork then exec, exec without fork,
  non-leader-thread exec/de-threading, double fork, orphan, bootstrap, fork
  bomb, task depth overflow, PID/TID reuse, loader restart, label-epoch rebuild,
  node reboot, and cgroup reuse.
- Assert child policy exists before the child's first protected effect.
- Assert stable task/process cookies survive valid coordinate transitions and
  never merge reused subjects.
- Missing ancestry produces a coverage gap and makes exact-subtree response
  ineligible.

### `HF-EVID-001`: loss and durability truth

- Force ring-buffer reservation loss, userspace queue overflow, local WAL
  outage/full/corruption, mTLS disconnect, duplicate/reordered replay, clock
  skew, policy swap, node restart, and control-plane outage.
- Require bounded coverage intervals and no false negative conclusion.
- Prove pinned local denial can remain active during
  `enforcing_without_observation`.
- Prove recovery never duplicates durable observations or silently resets the
  label epoch/sequence.

### `HF-CORR-001`: credential and authority pivot

- Deliver file, socket, Kubernetes audit, and cloud audit observations in every
  relevant order, including five-minute-late evidence.
- Assert deterministic `HF-DW-001` identity and a new immutable finding version
  for late stronger evidence.
- Distinguish same task, same process/different thread, descendant process,
  socket lineage, exact workload, and Pod-only contextual joins.
- Two concurrent Pods using the same ServiceAccount must not receive a direct
  edge from the name alone.

### `HF-XNODE-001`: exact two-node Kubernetes propagation

- Prove the complete path:

```text
process A/node 1
  → socket/request
  → Kubernetes audit ID
  → exact object UID
  → controller/owner-reference UID
  → exact Pod UID
  → scheduler binding
  → node 2/full container ID
  → independently observed root process B
```

- Retain every evidence ID, join field, proof class, coverage interval, and
  missing proof.
- Remove each bridge observation one at a time; require a named open branch,
  not a shortcut.
- Cover Deployment, DaemonSet, Job, and custom-controller fan-out, retry,
  deletion/recreation under the same name, and label-matching Pod adoption.
- Reject every cross-node `parent_process` edge.

### `HF-RESP-001`: exact local containment

- Insert the exact process lineage into the response-root generation.
- Require fresh file, exec, socket, device, and security probes from every
  existing thread and descendant to fail.
- Create a child after restriction; prove it inherits the restricted ancestry
  before running.
- Verify pidfd coordinates independently before stop/kill.
- Verify socket-cookie fence and broader cgroup egress/freeze as distinct
  scopes.
- Reject stale boot, epoch, task cookie, process lineage, PID/TID, Pod,
  container, cgroup, profile, or expiry coordinates.

### `HF-RESP-002`: distributed containment and reconciliation

- Freeze one exact lineage version into a response plan.
- Fence the seed immediately, revalidate and contain each remote native member,
  revoke an exact propagation capability when available, and constrain the
  owning controller with UID/resource-version preconditions.
- Create a replacement/late branch during `watch_until`; require a new
  independently authorized plan version.
- Exercise offline node, outside-authority target, incomplete socket history,
  broader-than-approved scope, and lost coverage.
- Require the final state to match the physical postconditions:
  `verified`, `partial`, `failed`, or `unknown`.

### `HF-PROV-001`: provider operation and recovery semantics

- Mesh: distinguish auth-key deletion from already-enrolled device deletion.
- AWS: distinguish exact access/session evidence from role-wide
  revoke-before-cutoff blast radius.
- Connector: require source and destination request IDs for a direct forwarding
  edge; a shared principal plus time remains contextual.
- GitHub: distinguish known installation-token revocation from wider
  installation suspension; inspect later commits, branches, workflows,
  releases, packages, and image digests.
- Artifact/queue: require immutable digest or message ID/partition offset;
  mutable names and time remain contextual.
- Direct TLS evidence must never identify an operation without provider audit.

## Coverage And Negative-Control Matrix

Each core scenario is rerun with one prerequisite removed:

| Removed prerequisite | Required result |
| --- | --- |
| BPF LSM or required hook/helper | node becomes `enforce-reduced`, `observe`, or `unsupported`; no equivalent prevention claim |
| root-admission acknowledgement gate | startup interval is uncovered; strict-from-first-exec is false |
| task label or complete bounded ancestry | protected effect fails closed where configured; exact-subtree response is ineligible |
| ring/userspace evidence path | enforcement may continue, but result is `enforcing_without_observation` |
| Kubernetes audit | API semantics and request-to-object edge are unknown |
| object UID/history | names and labels remain contextual |
| scheduler binding | remote node target is open/unknown |
| CRI/container-root binding | Pod cannot become a response-eligible native process |
| provider audit | flow proves communication only |
| exact credential/request/message/artifact identity | provider/cross-node join remains contextual |
| response postcondition source | response cannot be `verified` |

## Performance Gate

Phase 0 records absolute budgets; every later live run reports:

- fork/exec rate and p50/p95/p99 latency;
- allowed and denied file-effect latency;
- TCP/UDP connection rate and latency;
- CPU and memory per `mithril-node`;
- ring-buffer reservation loss and userspace backlog;
- local spool disk and replay rate;
- profile-generation swap time;
- first-process admission delay;
- incident finding latency from source receipt;
- local fence activation time;
- distributed graph expansion and response completion time; and
- overhead in `runtime-observe`, `mithril-observe`, and
  `mithril-protect` modes.

A performance pass never compensates for missing enforcement, attribution,
coverage, or postcondition proof.

## Release Claim Ladder

| Completed through | Allowed claim |
| --- | --- |
| Phase 3 | observes and simulates the published post-compromise effect classes on declared platforms |
| Phase 5 | prevents covered local post-compromise effects and network expansion on declared full-tier nodes |
| Phase 8 | correlates exact Kubernetes expansion across nodes with visible gaps |
| Phase 9 | physically contains proven local/distributed Kubernetes branches with typed results |
| Phase 10 | correlates and recovers declared provider branches with provider-specific semantics |
| Phase 11 | passes the full unchanged-deployment incident prevention and containment conformance matrix |

No earlier phase may use the Phase 11 product claim.
