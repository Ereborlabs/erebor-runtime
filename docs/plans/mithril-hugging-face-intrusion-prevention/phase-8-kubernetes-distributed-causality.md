# Phase 8: Kubernetes Distributed Causality

Status: Proposed; depends on Phase 7 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

## Purpose

Join authenticated Kubernetes/runtime facts to node evidence, represent
cross-node causality without fake process ancestry, and close the attacker-
created privileged workload branch required for the full HF claim.

## Design Coverage

Chapters 7-8, 23, 25, and 30-31; Appendices A.9-A.10 and A.15.3.

## Deliverables

### D8.1 — Kubernetes source adapters and coverage

Ingest authenticated audit, object history/watch, scheduler binding, admission,
runtime/CRI, and node-binding facts with source-specific IDs, actors, resource
UID/resourceVersion, request/result, timestamps, gaps, and proof quality. Do not
invent probe/lifecycle purpose missing from stock CRI.

### D8.2 — Kubernetes graph contracts

Implement registered edges for API request to object revision, controller/
owner reference, scheduler binding, Pod/container/cgroup/runtime root, and node
observation. Preserve fan-out, retries, replacement controllers, deletion,
name reuse, late events, and contradictions as explicit branches.

### D8.3 — Cross-node causal package

Complete the cross-node HF package from a credential/API action on node A to a
workload root/effect on node B. Shared ServiceAccount or timing remains
shared-principal/context unless exact request/object/binding identifiers close
the join.

### D8.4 — Unmatched-workload and privileged-root floor

Implement the architecture-approved Kubernetes validating-admission and node
hard-floor contracts for privileged mode, host namespaces, dangerous
capabilities, hostPath/devices, unsafe security settings, and unresolved roots.
Normal OCI setup remains runtime-owned. Exceptions are signed, exact,
expiring, bounded-use, physically consumed, and separately audited.

### D8.5 — Root-purpose truth matrix

Qualify initial containers, init/native sidecars, probes, lifecycle, ordinary
and approved admin exec, `crictl exec`, ephemeral containers, moved/unmatched
tasks, and direct runtime roots with identical commands. Kubernetes audit
identifies API actors where available but never retroactively grants a task
role.

### D8.6 — HF multi-node proof

Prove the node-A-to-node-B privileged Pod/fan-out branch is rejected at an
advertised admission/node floor or reported with the exact weaker result. A
denial must have API/runtime/physical workload-absence or restricted-root
oracle, not only an audit event.

## Required Tests And Fixtures

`XNODE-PRIVILEGED-POD-001`, `NODE-FLOOR-EXCEPTION-002`, relevant
`ENTRY-*`, `EDGE-K8S-SHARED-002`, `EDGE-MESSAGE-CONSUMER-006`, Kubernetes
fan-out/reuse/contradiction variants, and the live two-node lifecycle probe.

## Acceptance

- Cross-node edges use authoritative object/request/binding facts, never
  process parentage or time alone.
- Stock CRI ambiguity remains conservative under identical commands.
- Privileged/unmatched branches receive a physical rejection/restriction or an
  explicit unsupported result.
- Controller replacement and object/name/IP reuse cannot hide or retarget a
  branch.
- Legitimate controllers and ordinary workload scheduling still work.

## Excluded

Provider-specific audit semantics and response actuation.

## Phase Result

State: Not done.  
Completed deliverables: none.  
Verification: not run; this is a plan rewrite.  
Next phase: not authorized.
