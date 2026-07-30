# Phase 11: Production Installation And Final Conformance

Status: Not started.

Master plan: [Mithril Hugging Face Intrusion Prevention](./README.md)

## Purpose

Prove Mithril is simple to install and operate, secure against protected
workloads, upgradeable without hidden gaps, scalable, independently releasable,
and able to pass the complete unchanged-deployment Hugging Face prevention and
containment suite.

## Depends On

Phases 0 through 10 must be `Done` for every capability advertised by the
release. Reduced tiers may omit named provider/effect classes only when product
status and release claims say so explicitly.

## Phase Scope

### One-Install Operations

Finalize one Helm release and optional host-package path:

```text
one mithril-node DaemonSet
  → one Pod/container/process per protected Linux node

optional Mithril Control deployment
  → ordinary service workloads, not privileged node gatherers
```

Installation performs:

- capability discovery and truthful tier assignment;
- trust bootstrap and certificate rotation;
- least-privilege ServiceAccount/RBAC;
- exact host mount/capability inventory;
- audit/object/provider source configuration and coverage validation;
- default observe mode;
- signed profile simulation/activation;
- diagnostics and uninstall planning; and
- no mandatory operator, relay, sidecar, admission webhook, CNI, or upstream
  security product.

If strict-from-first-exec protect mode is enabled, the runtime integration and
matching acknowledgement gate are installed and verified as one transaction.

### Build, Supply Chain, And Self-Protection

- reproducible Rust/BPF builds;
- signed images, artifacts, profiles, and detection content;
- SBOM and exact source/toolchain/object provenance;
- dependency/license policy;
- multi-architecture output;
- protected update channel;
- BPF pin root, local socket, credentials, binary, configuration, spool, and
  diagnostics permissions;
- seccomp/mount/capability/namespace restrictions for `mithril-node` consistent
  with its required host authority; and
- attempts by unprivileged and privileged fixture workloads to tamper with
  Mithril links, maps, bpffs, local APIs, credentials, files, or update state.

The node agent is privileged security infrastructure. The plan does not claim a
workload-level control contains a hostile host root with equivalent authority.

### Atomic Upgrade, Rollback, And Uninstall

Upgrade must:

1. verify ABI/program/map/profile compatibility;
2. stage and probe a complete new generation;
3. preserve prior enforcement while observation/control components change;
4. atomically transfer the one-owner lease where needed;
5. maintain or explicitly break coverage intervals;
6. roll back on failed verifier/probe/health checks; and
7. prove no duplicate overlapping event stream.

Mixed fleet versions expose capabilities/generations. Uninstall requires an
authorized audited workflow that removes links/maps/hooks/credentials and
declares evidence-retention behavior; stopping the Pod must not leave unknown
enforcement state.

### Scale And Reliability

Test the approved fleet envelope for:

- node count and simultaneous reconnect;
- process/effect/socket rate;
- Kubernetes audit/controller fan-out;
- graph size/depth/lateness;
- incident storm and response concurrency;
- provider delay/rate limiting;
- local spool and central storage pressure;
- certificate/profile/content rotation; and
- node/control/provider regional outage.

Budgets and shedding behavior retain coverage truth.

### Runtime/Mithril Shared Sensor

Prove:

- Runtime-only installation uses only observation programs for Runtime-owned
  agent cgroups;
- Mithril-only installation has one active node owner;
- co-resident Runtime subscribes to `mithril-node` and no second loader/event
  stream exists;
- Runtime cannot request node-wide evidence, policy-map writes, packet fences,
  task kill/freeze, or provider response;
- Mithril identity/policy/findings do not become Runtime Session objects; and
- shared ABI/host changes run both products' conformance suites.

Any production Runtime integration is implemented through a separately
approved child scope grounded in the current owners:

```text
crates/erebor-runtime-core/src/config/session/interception.rs
crates/erebor-runtime-session/src/os/linux/process_guard.rs
crates/erebor-runtime-session/src/os/linux/process_guard/
crates/erebor-runtime-e2e/
```

That child scope must state whether ptrace remains a named compatibility
backend, how Session admission selects `runtime-observe`, how agent cgroups are
authenticated to the shared host owner, and how loss reaches Runtime evidence.
It cannot delete or reinterpret the current backend merely to complete Mithril.

### Repository And Release Shape

Prepare the history-preserving migration from `erebor-runtime` to the `erebor`
monorepo with independent Runtime and Mithril artifacts, package namespaces,
release provenance, CI, documentation links, and downstream compatibility.

Executing the repository rename requires its own explicit user approval. The
security release gate may be proved in the current repository first; renaming
cannot be used to delay or weaken it.

### Full Incident Conformance

Run every scenario in
[Hugging Face Adversarial Acceptance](./hugging-face-adversarial-acceptance.md)
on every advertised full-tier kernel/runtime/CNI class:

- unchanged deployment baseline;
- local identity/effect prevention;
- process-aware network prevention;
- same-process semantic ambiguity;
- evidence loss/recovery;
- Kubernetes distributed causality;
- local/distributed response;
- provider correlation/recovery;
- late branch/reconciler replacement;
- platform capability degradation; and
- performance.

Also replay all 68 acceptance requirements from the incident research and
record a requirement-to-test/result matrix.

## Code-Backed Tests

- Helm render/schema/upgrade/rollback/uninstall and one-Pod/one-container
  topology tests;
- least-privilege RBAC/host permission and negative authorization tests;
- signature/SBOM/provenance/reproducibility tests;
- node-agent self-protection and compromised-workload tampering tests;
- fresh install, central outage, node reboot, partial upgrade, incompatible
  ABI, failed verifier, mixed generation, and rollback tests;
- one-owner handoff and duplicate-stream detection;
- Runtime-only/Mithril-only/co-resident authority tests;
- fleet load, soak, loss, provider-rate, and response-storm tests;
- full live two-node probe suite;
- full incident scenario catalog and 68-point traceability matrix; and
- documented reduced/observe/unsupported platform behavior.

## Live Probe

Run Probes A through G after the final relevant edit and package build. Repeat
on every advertised full-tier platform class and a representative reduced,
observe-only, and unsupported node.

## Checkpoint

Run the final repository CI procedure, reproducible build and supply-chain
checks, install/upgrade/rollback/uninstall and self-protection suites, fleet
load/soak tests, Runtime/Mithril co-residency tests, Probes A–G, and the
68-point incident traceability matrix from the final source/package state.

## Acceptance

- a fresh supported cluster reaches truthful observe coverage through one
  install;
- one privileged node gatherer is present per node;
- strict mode protects the first user process or reports the startup interval
  uncovered;
- default observe, signed protect activation, status, diagnostics, and
  response simulation are operationally coherent;
- upgrade never creates an unreported enforcement/observation gap;
- failed upgrade rolls back or reports the precise uncovered state;
- compromised fixture workloads cannot modify Mithril authority/state through
  their available namespaces/cgroups/interfaces;
- Runtime and Mithril remain independently installable and co-resident through
  one owner;
- every full-tier incident scenario passes its physical postconditions;
- every legitimate control remains functional;
- every same-process/provider limitation is stated without a false prevention
  claim;
- every distributed branch/response result is coverage-backed;
- scale and performance meet the approved release budgets;
- the 68-point research acceptance matrix has no unexplained missing row; and
- uninstall and evidence retention are authorized, audited, and predictable.

## Explicit Stop Point

Stop and present the complete release dossier. Do not call the product
production-ready until the user approves the advertised support matrix,
incident conformance, operational risks, provider actions, and release claim.

The optional Phase 12 is not a prerequisite for launch.

## Phase Result

State: Not started.

Record release/version/artifact digests, installation manifests, support
matrix, supply-chain evidence, full test and live-probe results, performance/
scale, residual risks, 68-point traceability, and final state.
