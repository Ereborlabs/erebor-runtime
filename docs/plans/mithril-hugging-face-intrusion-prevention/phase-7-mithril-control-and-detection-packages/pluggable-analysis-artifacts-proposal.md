# Pluggable Analysis Artifacts Proposal

Provide local packages for detection, discovery, correlation, and policy
suggestions. Each package contains complete, reusable computations with typed
inputs and outputs. Users install a file or folder through Araphor. They do
not operate a separate processing platform.

Status: **Proposal recorded. Implementation: Not done.** Research date:
2026-10-09. The user approved this separate record. The later
[7.5 child phases](phase-7-5-graphs-findings-and-notifications/README.md#approved-extension-and-child-phases)
record the approved SDK and execution direction. This proposal retains the
earlier alternatives; it does not override those child plans.

Parent: [Control, discovery, and detection plan](README.md).
Current contracts: [Engine design](engine-design.md).
This proposal does not replace those contracts or start implementation.

## Intended end state

One Araphor installation validates, installs, runs, inspects, tests, updates,
and rolls back analysis packages. A package can consume several datasets and
prior state. It can return several datasets and next state. Other packages
can consume its named outputs through the same interface.

Each computation contains its complete filter, group, join, window, or
algorithm. Do not repeat calculations in manifest fields. Define its inputs,
parameters, outputs, and documentation once. Use that definition for validation,
CLI help, console forms, and agent descriptions.

Results must remain correct when accepted input is added, corrected, or removed.
AnalysisStore remains the durable data owner. Existing owners validate findings,
policy proposals, notifications, approvals, publication, and physical effects.
Package installation does not require a broker, external database, compiler,
or separate environment managed by the operator. Package authors can use build
tools. Araphor must reject a package with unsupported dependencies.

## Proposed flow

```text
User submits a local package file or folder
  -> Araphor validates identity, interfaces, dependencies, parameters, and limits
  -> Araphor runs package fixtures through the production evaluator
  -> Araphor retains one exact installed revision and its test result
  -> Araphor activates the revision when its input and runtime requirements pass
  -> Araphor reports Active, WaitingForInput, or Failed with the exact reason

Accepted input or a declared context revision changes
  -> the responsible data owner selects authorized input revisions and prior state
  -> the evaluator runs the affected computations within their resource limits
  -> DiscoveryOwner or GraphAndFindingOwner validates the applicable output
  -> AnalysisStore commits outputs, next state, references, progress, and quota
  -> NotificationRouter processes the committed qualified finding revision

Input validation, evaluation, cancellation, or a resource limit fails
  -> Araphor records the failure and its coverage limit
  -> AnalysisStore does not commit partial outputs as a completed result
  -> a retry uses the same recorded input and installed revision
  -> an identical committed retry returns its original receipt
  -> a changed retry is rejected

User submits an update or requests rollback
  -> Araphor validates the selected package and state format
  -> Araphor tests state conversion or reconstructs state from retained input
  -> Araphor changes the active revision only after validation succeeds
  -> failure preserves the previous active revision
```

The package runtime must define activation and failure transitions before this
flow becomes an implementation plan. A missing required input must remain
visible. Installed does not imply Active.

## Computation and state contract

A computation receives named typed datasets, exact input revisions, parameters,
authorized scope, recorded time inputs, coverage, and prior state. It returns
named typed datasets, next state, and exact evidence references. State must use
a declared versioned format. Hidden interpreter or process state cannot be the
only recovery source.

Define the complete result for a selected input first. An implementation can
recompute that result or maintain it through changes. An incremental
implementation must match recomputation on the same inputs. Custom algorithms
need a valid update or rebuild method; a scalar function interface is not enough.

For example, a model produces a finding for three distinct destinations. Input
contains A, B, and C. A correction removes C. The current result must then remove
that finding. AnalysisStore retains the historical finding and its references.
This correction does not reverse a response action.

Reuse intermediate results where this preserves authorization and meaning.
Compile or prepare reusable work outside repeated evaluation where supported.
Use bounded batches and shared indexes where suitable. These are design goals,
not measured performance results.

Example discovery flow:

```text
Accepted access records + prior profile
  -> observed resources
  -> recursive directory generalization
  -> profile and policy candidates
```

Each step is a named computation with inspectable output. This dependency graph
does not prove an incident's causal relationships. GraphAndFindingOwner still
requires qualified identity, lifetime, and effect evidence for a causal edge.

## Product references and engine candidates

The following products support the proposal's design. They are not dependencies
selected for installation.

| Reference | Behavior to evaluate or use as a design example | Limit |
| --- | --- | --- |
| [Velociraptor artifacts](https://docs.velociraptor.app/docs/vql/artifacts/) | Named files, parameters, result tables, reusable artifact calls, and folder or ZIP loading. | [New VQL capabilities](https://docs.velociraptor.app/docs/vql/extending_vql/) can require external tools or extensions. Artifact loading does not establish atomic state recovery. |
| [Apache Hamilton](https://hamilton.apache.org/) | Small typed functions form a dependency graph. Parameters identify dependencies; the body contains the calculation. | It does not supply a security boundary or continuous incremental execution. |
| [Pathway](https://pathway.com/developers/user-guide/introduction/concepts/) | Python defines table computations that a Rust engine maintains through input additions and removals. | Its [license](https://github.com/pathwaycom/pathway/blob/main/LICENSE.txt) has production and service restrictions relevant to distribution. |
| [DBSP](https://docs.rs/dbsp/latest/dbsp/) | Embedded Rust computation over changing datasets. Feldera uses this engine. | Package authoring and owner integration remain required. Check the selected library features and [platform fault tolerance terms](https://docs.feldera.com/pipelines/fault-tolerance-overview/). |
| [Differential Dataflow](https://docs.rs/differential-dataflow/0.25.1/differential_dataflow/) | Embedded collection transformations, additions, removals, and iterative computation. | It requires a package interface, recovery integration, and authoring tools. |
| [Tenzir](https://tenzir.com/docs/explanations/packages/) | Complete pipelines, reusable operators, parameters, security functions, and package tests. | Its [executor contract](https://tenzir.com/docs/explanations/executor/) does not establish recovery for every operator and custom algorithm. |
| [DataFusion](https://docs.rs/datafusion/latest/datafusion/) | Embedded Rust and Arrow execution with custom functions and operators. | Query evaluation alone does not maintain detector results through corrections. |
| [osquery extensions](https://osquery.readthedocs.io/en/latest/deployment/extensions/) | Local packs and monitored extension processes. | The extension contract targets endpoint queries and tables. |
| [Arrow UDF](https://github.com/arrow-udf/arrow-udf) and [Extism](https://extism.org/docs/concepts/runtime-apis/) | Typed batch functions or portable executable plugins with host functions. | They do not supply the complete stateful detector contract. Resource and cancellation controls need qualification. |
| [PRQL](https://prql-lang.org/book/) and [Ibis](https://ibis-project.org/why) | Complete, reusable relational computations. | They do not supply a general algorithm runtime or installed detector lifecycle. |

Also use [Falco's plugin boundaries](https://falco.org/docs/concepts/plugins/architecture/),
[Tracee's detector interfaces](https://aquasecurity.github.io/tracee/dev/docs/detectors/),
[Wazuh's production-engine tests](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html),
[Sigma's correlation semantics](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html),
[Elastic's detection tools](https://github.com/elastic/detection-rules), and
[YARA-L's composite detections](https://docs.cloud.google.com/chronicle/docs/yara-l/composite-detection-rules)
as focused examples. Their rule formats do not define a complete general
learning and state interface.

Python authoring does not require all computation to execute in Python.
Pathway executes native table operations in Rust. Actual Python functions have
separate execution and dependency costs. Its [function contract](https://pathway.com/developers/user-guide/data-transformation/user-defined-functions/)
also retains nondeterministic results so a removal retracts the original value.

Compare **Tenzir with an embedded incremental engine based on DBSP or
Differential Dataflow**. These are separate candidates. DBSP and Differential
are separate libraries, not two names for one engine. This proposal does not
require all three to run together. DuckDB storage does not decide this choice.

## Required algorithm cases and owners

| Case | Required behavior |
| --- | --- |
| Discovery Engine | Merge prior and current resource sets. Preserve [recursive path collapse](../../../../discovery-engine/src/common/pathAggregator.go) and versioned inventory inputs for policy construction. |
| Security Analytics | Preserve statistics, unordered inclusive time correlation, set intersections, and custom vector or index algorithms. |
| Hugging Face incident | Join several qualified evidence datasets across exact subjects and nodes. Missing application, Kubernetes, or provider evidence remains explicit. |

Local source paths: `discovery-engine/src/common/pathAggregator.go`,
`discovery-engine/src/networkpolicy/networkPolicy.go`, and
`security-analytics/src/main/java/org/opensearch/securityanalytics/correlation/JoinEngine.java`.
Use the [primary incident timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline)
for incident cases. No runtime can produce telemetry that the deployed sources
did not record.

QueryOwner keeps query admission, authorization, bounded extraction, and
cancellation. DiscoveryOwner validates profiles and policy candidates.
GraphAndFindingOwner validates graph and finding candidates. AnalysisStore
owns durable outputs, references, progress, and recovery. NotificationRouter
and Control keep their existing authorities. Packages cannot publish policy,
execute response, or write directly to the durable store.

The [native graph row storage TODOs](phase-7-5-graphs-findings-and-notifications/README.md#native-graph-storage-improvement-todos)
remain separate work. This proposal does not replace or complete them.

## Qualification TODOs and decision boundary

- [ ] Select the authoring interface and one executable algorithm interface.
  Validate complete computations, reusable outputs, and agent-readable schemas.
- [ ] Compare candidate implementations with the same algorithm fixtures.
  Check additions, removals, corrections, late input, duplicate input, and missing
  identity. Check exact semantics, not only similar output shapes.
- [ ] Prove cancellation, resource limits, crash recovery, exact retries,
  atomic state/result commits, package updates, and rollback.
- [ ] Define the evidence and coverage contract for custom algorithms.
  Qualify cross-node joins independently of time or similarity.
- [ ] Propose a performance workload and limits for explicit user approval
  before a benchmark. Installation size, setup cost, memory, and latency remain
  unqualified.
- [ ] Record the chosen engine, deployment, license terms, and required changes
  to the parent design before implementation approval.

Use small modules and functions. Share encoders and validation. Use Rust or
platform tests through production owners. Do not add long shell test programs.
Work in the supplied primary checkout. Do not create worktrees.

The research established design references and candidate interfaces. It did
not establish an engine winner, a complete package implementation, or full
physical reproduction of the Hugging Face incident.
