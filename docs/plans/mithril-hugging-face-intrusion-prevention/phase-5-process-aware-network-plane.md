# Phase 5: Process-Aware Network Plane

Status: Proposed; depends on Phase 4 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 5 runbook](./manual-testing/phase-5-manual-acceptance.md)  
Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Enforce current-actor and socket-provenance policy for local channels, network
destinations, DNS, rewritten flows, established traffic, and response fences.

## Scope And Design Coverage

Chapters 18-19 and 30-31; Appendices A.13.4 and A.14.

## Deliverables

### D5.1 — Socket and flow lifetime identity

Label created, accepted, paired, inherited, passed, preconnected, reused, and
destroyed sockets before first governed use. Preserve creator generation,
current actor, socket/network namespace, destination/flow generation, and
response references independently of fd/process lifetime.

### D5.2 — Actor-stage network decisions

Enforce socket creation/control, bind/listen/accept, TCP connect/send, UDP
connected/unconnected send, receive where qualified, inherited/passed socket
use, and local IPv4/IPv6/Unix relationships. Unsupported raw/packet/TUN/AF_XDP,
RDMA/vsock/netlink/SCTP/MPTCP or async paths are denied or explicitly scoped.

### D5.3 — Final-destination and packet floor

Install actor-authorized socket/flow state and enforce the final post-rewrite
destination at the qualified cgroup/TC/XDP/packet boundary without requiring a
fictional packet-stage current task. Cover NAT, CNI, mesh, redirects, literal
IP, IPv4/IPv6, route changes, and final packet absence.

### D5.4 — Established/shared-flow response

Fence or destroy future packets on established flows. When multiple lineages
share a socket, disclose and authorize the whole socket/flow/cgroup blast
radius; never claim per-lineage attribution for queued bytes or retransmits.

### D5.5 — DNS policy and encrypted-protocol limits

Implement the selected DNS mode with bounded UDP/TCP parsing, exact/suffix
qname/type/answer/CNAME/size/rate/cardinality rules, resolver destination floor,
and malformed/fragmented/encrypted handling. Keep IP/destination enforcement
independent. Record that direct TLS cannot reveal provider verbs or bearer
intent.

### D5.6 — HF network prevention increment

Prove API/IMDS/C2/alternate-resolver/tunnel attempts are denied at the claimed
connect/send/packet stage, while the allowed result service and legitimate
controller path remain functional. Same-endpoint/same-credential TLS cases
receive the honest allowed/contextual result for later Control correlation.

## Checkpoint

Every advertised socket/message/final-flow/DNS path proves its exact physical
result under actor, namespace, rewrite, passed-socket, and established-flow
variants without claiming TLS semantics.

## Required Tests And Fixtures

- `FILE-DELEGATED-EGRESS-001`, `HF-004-RESULT-001`,
  `HF-011-READ-RESULT-001`, `HF-NET-001`, and `IPC-LOCAL-INET-008`.
- `NET-ACCEPT-PASS-001`, `NET-DNS-EXFIL-001`, `NET-NS-PASS-001`,
  `NET-RECV-001`, `NET-REWRITE-001`, `NET-SHARED-RESPONSE-002`,
  `NET-SOCKCTL-001`, and `NET-SOCKET-LIFE-001`.
- Shared-socket response controls and the network portions of the live
  two-node lifecycle probe.

## Acceptance

- Current actor and retained socket authority intersect on every supported use.
- Final rewritten destinations cannot bypass the actor-stage decision.
- Denied new and established-flow effects have the stated syscall or packet
  oracle.
- DNS parser failure never bypasses the destination/IP floor.
- Encrypted semantic ambiguity is reported rather than invented.

## Excluded

TLS termination, arbitrary L7 parsing, provider audit correlation, and
distributed response authorization.

## Phase Result

```text
State: Not done.
Validated architecture revision/digest: not recorded.
Completed deliverable IDs: none.
Files and durable owners changed: none.
Upstream-adoption dossier IDs used: none.
Fixture cases and exact physical results: not run.
Commands and exact source state covered: none; this is a plan-only rewrite.
Platform/kernel/runtime manifests: none.
Performance/capacity results: none.
Unsupported/degraded paths: not yet measured.
Remaining work in this phase: all deliverables.
Next phase not authorized: yes.
```
