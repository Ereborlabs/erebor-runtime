# Research And Demand

This record separates source facts, operator reports, and proposed design
choices. Research date: 2026-09-20. Public reports are demand signals, not a
representative survey or proof that one product cannot meet a need.

## Discovery Engine source study

The local clone is at `discovery-engine/` in the primary checkout. The inspected
revision is `0b5b73425c5aec89b803e737b188b2a331d0e218`, dated 2023-09-12.
The links below pin that revision. The study covers the main system-policy
route, network aggregation, recommendation, persistence publication, and the
discovered-policy controller. It is not a complete security audit.

```text
System logs arrive from a file, relay, or feed
  -> population code cleans and groups logs by cluster and Pod
  -> live Kubernetes metadata supplies labels and container context
  -> system-policy filter keeps configured operations and results
  -> workload/process/file sets merge old and new resources
  -> path aggregation reduces resource sets
  -> conversion produces allow-policy YAML
  -> optional DiscoveredPolicy creation starts with Inactive status
  -> operator activation lets a controller create or update the target policy

Network logs arrive
  -> source and destination conversion resolves labels and network details
  -> grouping combines matching endpoint selectors
  -> aggregation can reduce selectors, ports, and destination representations
  -> format conversion produces the selected network policy family
```

### What is useful

| Source | What the implementation contributes | Araphor use |
| --- | --- | --- |
| [System population](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/systempolicy/systemPolicy.go) | `PopulateSystemPoliciesFromSystemLogs` separates source ingestion, grouping, generation, and conversion. `GenFileSetForAllPodsInCluster` retains sets across runs. | Keep deterministic stages and incremental facts. Make their inputs and revisions explicit. |
| [Network processing](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/networkpolicy/networkPolicy.go) | `DiscoverNetworkPolicy` groups ingress and egress rules. `aggregateSrcByLabel` checks all matching Pods at level 2; level 3 omits that guard. | Show selector membership and unobserved members before any generalization. Pin the inventory snapshot. |
| [Path tree and tests](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/common/pathAggregator_test.go) | Small deterministic tests describe exact paths, directory merging, and sort behavior. | Keep exact golden input/output tests for every transform. Add negative permissions, not only compact output. |
| [Recommendation worker](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/recommendpolicy/recommendPolicy.go) | Curated hardening templates complement learned activity. | Keep declared guardrails separate from observed activity. Pin and review template versions. |
| [Discovered policy creation](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/cluster/dspHandler.go) | `CreateDsp` sets `PolicyStatus` to `Inactive`. The design has a review boundary. | Preserve explicit review. Do not describe upstream as automatically enforcing every observed operation. |

### Where Araphor needs stronger contracts

1. **Aggregation can enlarge authority.** In
   [pathAggregator.go](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/common/pathAggregator.go),
   `Threshold` is 3. More than three child nodes can become a directory. `/tmp`
   has special directory treatment. System-policy conversion emits recursive
   directory rules. Four observed files must not silently authorize a fifth
   file or a future subtree. Araphor records this as a permission-increasing
   transform, not a harmless display compression.
2. **Attempts are not requirements.**
   [FilterSystemLogsByConfig](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/systempolicy/helperFunctions.go)
   admits `Passed`, `Permission denied`, and `Operation now in progress`.
   The traced workload/process/file-set route accumulates these resources,
   and `buildSystemPolicy` defaults to `Allow`. A denied attempt can therefore
   contribute to an allow proposal. That is not evidence of automatic
   enforcement. Araphor must preserve result class through generation and
   require a separate owner decision for a denied operation.
3. **Mutable names are weak cohort keys.** The inspected system path uses live
   Pod metadata and sets keyed by cluster, namespace, container, source,
   labels, and set type. The
   [system log type](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/types/logData.go)
   lacks the source epoch, boot identity, sequence, and image digest required
   here. Araphor must not merge two lifetimes because their names match.
4. **Streaming needs recovery and backpressure.**
   [Consumer publication](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/libs/consumer.go)
   sends to bounded subscriber channels while holding a shared lock. A slow
   subscriber can block publication. The
   [discovery API](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/protobuf/v1/discovery/discovery.proto)
   streams YAML and labels without a durable resume cursor, proposal revision,
   or coverage contract. Araphor uses committed revisions and bounded reads.
5. **Created does not mean enforced.** The
   [controller](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/pkg/discoveredpolicy/controllers/policy_deployment.go)
   reports `Activated` after Kubernetes create or patch. That operation does
   not itself prove a node has installed the policy. Araphor exposes source
   acceptance and exact target acknowledgements separately.
6. **Dependency age is a maintenance input, not a vulnerability finding.**
   [go.mod](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/go.mod)
   declares Go 1.20 and replaces the Cilium requirement with 1.10.14. The
   inspected integration and API assumptions need fresh qualification. Do not
   copy its dependency graph into the Rust service.

No root license file was found in the inspected clone. Runtime license-check
code is not a source license. Before copying or deriving code, resolve the
applicable license and record the revision, files, notices, and reuse class.
This plan proposes independent implementations of the stated contracts; it
does not authorize source copying.

### Storage and count semantics

The pinned [SQLite handler](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/libs/sqliteHandler.go)
stores process/file sets, policies, logs, and summaries. Its log update path
increments `total`; its connections select `_journal=OFF`. The inspected
[summary publisher](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/observability/publisher.go)
moves an in-memory batch, combines counts, reduces paths, and optionally saves
or publishes the result. These mechanisms explain compact summaries; they do
not establish replay-safe counting or complete observation. Do not copy their
journal setting or use a shortened display path as an exact permission key.

Araphor needs an explicit database transaction for count updates and input
progress. A retry must not add the same accepted record again. Keep the exact
resource, outcome, and source lifetime below any display group.

## Kubewarden adm-controller source study

The second local clone is `adm-controller/`, remote
`https://github.com/kubewarden/adm-controller`. Inspected revision:
`2e0f9ef5f1e0437b017879755ec6636aecb2eba5`, dated 2026-09-14. Unlike the
Discovery Engine snapshot, this is a recently updated monorepo. It includes
the Go controller/audit scanner and Rust policy server, evaluator, fetcher,
and `kwctl`. The root license is Apache-2.0; review file and dependency
provenance before any source reuse. The clone was read, not run or changed.

```text
Kubernetes sends an admission request
  -> policy server selects the configured policy and context permissions
  -> shared evaluator executes the policy
  -> response handler applies monitor/protect and mutation constraints
  -> admission response returns to Kubernetes

Audit scanner examines an existing object
  -> scanner selects eligible policies and records skips/errors
  -> scanner builds a synthetic CREATE request
  -> audit endpoint returns the underlying evaluation result
  -> scanner writes a report, not a runtime enforcement claim

Operator uses recorded host interactions with kwctl
  -> shared evaluator requests context
  -> replay checks the requested interaction against the recorded exchange
  -> matching recorded response or error is returned
  -> an unexpected or exhausted exchange fails replay
```

| Source inspected | Useful mechanism | Araphor decision |
| --- | --- | --- |
| [Response handler](https://github.com/kubewarden/adm-controller/blob/2e0f9ef5f1e0437b017879755ec6636aecb2eba5/crates/policy-evaluator/src/admission_response_handler.rs) | Monitor mode returns allow and removes mutation patches. Protect mode checks mutation permission. | Preserve the computed decision separately from the action actually applied. Preview must have no publication effect. |
| [API service](https://github.com/kubewarden/adm-controller/blob/2e0f9ef5f1e0437b017879755ec6636aecb2eba5/crates/policy-server/src/api/service.rs) | Audit uses the underlying evaluation response; live validation applies the response handler. | Carry execution mode and proof kind in every preview. Do not infer simulated deny from a live allow flag. |
| [Synthetic request](https://github.com/kubewarden/adm-controller/blob/2e0f9ef5f1e0437b017879755ec6636aecb2eba5/internal/audit-scanner/scanner/admission_request.go) and [policy selection](https://github.com/kubewarden/adm-controller/blob/2e0f9ef5f1e0437b017879755ec6636aecb2eba5/internal/audit-scanner/policies/client.go) | Background audit constructs CREATE requests; selection filters unsupported cases and tracks skips/errors. | A scan of present configuration is not historical request replay. Show synthetic, skipped, unsupported, and error counts. |
| [Callback replay](https://github.com/kubewarden/adm-controller/blob/2e0f9ef5f1e0437b017879755ec6636aecb2eba5/crates/kwctl/src/callback_handler/proxy.rs) | Records successful and failed context exchanges. Replay checks request equality and sequence. | Retain resolver inputs/results, including failures. Offline replay cannot query today's cluster as a hidden substitute. |
| [Evaluation context](https://github.com/kubewarden/adm-controller/blob/2e0f9ef5f1e0437b017879755ec6636aecb2eba5/crates/policy-evaluator/src/evaluation_context.rs) | Explicit Kubernetes-resource and host-capability permissions constrain context access. | Optional analyzers get bounded read capabilities, not broad cluster credentials. Default to no host callbacks. |
| [Evaluation environment](https://github.com/kubewarden/adm-controller/blob/2e0f9ef5f1e0437b017879755ec6636aecb2eba5/crates/policy-server/src/evaluation/evaluation_environment.rs) | Reuses precompiled modules and creates an evaluation environment per call. Epoch timeout behavior depends on global configuration. | Bound initialization and evaluation separately. A configured per-job timeout is insufficient unless the runtime actually enforces it. |
| [Policy downloader](https://github.com/kubewarden/adm-controller/blob/2e0f9ef5f1e0437b017879755ec6636aecb2eba5/crates/policy-server/src/policy_downloader.rs) | When verification is configured, verifies signatures and then checks downloaded local bytes against the verified manifest. | Bind model/template bytes to the reviewed artifact digest. Do not validate a tag and later load unrelated bytes. |

The useful architecture lesson is one evaluator shared by production and local
tools, with explicit context and result contracts. Araphor already has a native
compiler and simulator. Extend those owners instead of adding Kubewarden as a
runtime policy authority.

Wasm is a possible later format for third-party discovery transforms or
checks. It is not required for the first engine and is not itself a learning
method. Consider it only when there is a real independently supplied analyzer.
Such an analyzer would need a digest, settings schema, capability manifest,
input/output bounds, enforced initialization/execution limits, and replay
fixtures. Its output would remain an untrusted suggestion. Do not introduce
a plugin marketplace or allow arbitrary Wasm callbacks as part of this plan.

## Demand evidence

| ID | Evidence and limit | Design response | Acceptance measure |
| --- | --- | --- | --- |
| D1 | [January 2026 network-policy discussion](https://www.reddit.com/r/kubernetes/comments/1q9ulxg/how_do_you_monitoranalysetroubleshoot_your/) asks which policy blocked traffic and how to inspect several policies together. Self-reported experience. | Explain the applicable policy set and the exact changed decision. | Operator finds the rule and affected target without reading several raw files. |
| D2 | [March 2026 runtime-security discussion](https://www.reddit.com/r/kubernetes/comments/1s29dq9/do_people_actually_use_deep_runtime_security_in/) describes substantial tuning and different noise in CI and production. Anecdotal, with possible participant bias. | Separate workload revision, lifecycle, and environment; group repeated evidence without hiding it. | Fewer reviewed items, with no lost seeded attack group. |
| D3 | [December 2023 policy discussion](https://www.reddit.com/r/kubernetes/comments/18gkfik) raises team coordination and difficulty predicting policy effects. | Bind requirements to an owner and provide pre-publication impact and conflict review. | Stale source and cross-team changes cannot publish without review. |
| D4 | [Monzo's engineering account](https://monzo.com/blog/we-built-network-isolation-for-1-500-services) describes testing, ownership, rollback, and generated-policy problems at service scale. Historical first-party experience, not a current market survey. | Test before enforcement; keep source ownership explicit; review rollback effects too. | A rollout and rollback both preserve required cases on the tested scope. |
| D5 | [Falco rules issue 291](https://github.com/falcosecurity/rules/issues/291) reports a false positive associated with a systemd behavior change. An issue report is not an independently reproduced defect. | Treat software updates as profile changes; retain platform/version context. | Update drift appears as a review item, not an unexplained new attack score. |
| D6 | [September 2026 AI-runtime discussion](https://www.reddit.com/r/AskNetsec/comments/1wbdd9b/anyone_else_struggling_with_false_positives_from/) asks for application-specific learning after noisy alerts. Low-strength recent anecdote. | Evaluate local assistance against exact grouping and context, not generic anomaly claims. | Measured review-time gain on held-out workloads, with attack recall and abstentions reported. |

These reports support a problem hypothesis. They do not establish willingness
to pay, market size, or demand for a particular ML algorithm. Do not use vote
counts as prevalence estimates. No user interviews were conducted for this
planning change.

### Why discovery does not remove all noise

The reviewed complaints do not establish that the reporters installed AccuKnox
Discovery Engine. Falco rule alerts, Tetragon observations, and discovered
allow-policy proposals are different outputs. The existence of one discovery
project does not show that another project's alert pipeline uses it.

| Evidence | What is still missing | Design implication, not a claim of proven demand |
| --- | --- | --- |
| [March 2026 Falco report](https://www.reddit.com/r/kubernetes/comments/1ry2ygm/how_are_you_actually_using_falco_in_production/) describes about 6,000 daily alerts and Ceph traffic matching mining-port rules. A reply describes legitimate ConfigMap access. These are unverified operator reports. | A broad detector can match legitimate behavior. Removing duplicate rows does not correct the rule's meaning. | Show source rule, exact action, known application context, and the reason for each match. Never infer a provider operation or threat from a port alone. |
| [July 2026 runtime-tool discussion](https://www.reddit.com/r/devops/comments/1v3aave/currently_on_falco_for_runtime_security_anyone/) includes routine controller API calls and concern about blocking legitimate workloads. | A proposed exception needs scope, impact, ownership, and tests. | Keep notification grouping separate from permission changes. Preview both valid work and forbidden cases. |
| [Falco exception documentation](https://falco.org/docs/concepts/rules/exceptions/) describes explicit field tuples for expected behavior. | Context-specific exceptions already exist; a new engine must make them easier to review and maintain, not claim to invent them. | Bind each reviewed decision to exact scope and revision. Show when an application update invalidates it. |
| [NeuVector modes](https://open-docs.neuvector.com/policy/modes/) separate learning from monitoring and protection. | A learned baseline records the learning interval, not every rare restart, recovery, or scheduled path. | Use a lifecycle test matrix. Neither elapsed time nor a quiet period proves completeness. |
| [NeuVector issue 2663](https://github.com/neuvector/neuvector/issues/2663) reports visible sessions absent from learned rules and an application failure in Protect mode. Not reproduced here. | Operators need to see the difference between received, included, excluded, and unresolved input. | Expose every denominator and exclusion reason before review. Do not turn a filtered view into a complete-profile claim. |
| [Kubescape node-agent release notes](https://github.com/kubescape/node-agent/releases) describe fixes for oversized profile splitting, duplicate report times, and bounded report retries. These are maintainer reports, not tests performed here. | Aggregation can fail through size, retry, and lifecycle behavior, not only poor classification. | Test split bounds, duplicate delivery, late input, and restart. Display loss and partial profiles instead of presenting a smaller result as success. |

The resulting hypothesis is that much of the remaining work is context and
review work, not a missing neural network. Frequent behavior can be unwanted;
rare behavior can be required. Learning during an intrusion can preserve the
intrusion. A compact rule can also permit unseen actions. None of these
distinctions follows from event frequency alone.

Measure four separate quantities: accepted observations, exact behavior atoms,
review items, and notifications. Lower notification volume is not evidence of
fewer false positives. Measure incorrect classifications and operator time on
labeled tasks; also count missed forbidden cases and harmful approvals.

Before a broad release, observe at least five operators across platform,
application, and security roles using the fixture. Use their real recent
policy-change tasks where permission permits. Record current review time,
needed context, false assumptions, and rejected proposals. Revisit the design
if fewer than three can identify a recurring task this engine improves. This
small study is a product gate, not a statistically representative survey.

## Other projects and new techniques

| Reference | Lesson | Boundary for Araphor |
| --- | --- | --- |
| [Inspektor Gadget advisors](https://inspektor-gadget.io/docs/latest/gadgets/) | Focused collection can produce seccomp and network suggestions. | Reuse the idea of a declared recording task, not another collector. A syscall set does not express object-level authority. |
| [Security Profiles Operator v1 migration](https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/doc/migration-guide-v1.md) | Recording and profile APIs have continued to evolve since the clone's date. | Pin target API versions. Seccomp/AppArmor output is a separate adapter with separate semantics and tests. |
| [Kubescape Bill of Behavior](https://kubescape.io/docs/operator/bill-of-behavior/) | Behavior can be a portable, reviewable declaration built from a tested application. | Explore image-bound behavior artifacts. Signing authenticates origin, not completeness or safety. |
| [Kubescape quickstart](https://kubescape.io/docs/operator/bill-of-behavior/quickstart/) | The inspected workflow names an `sbob-rc3` release candidate and experimental features. | Do not call the inspected behavior-signing workflow a stable universal standard. |
| [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html) | Observed activity can seed policy review, but some actions and data events are absent; denied events are included in analysis. | Display source limitations and distinguish seen activity from required grants. No automatic conversion of logs into authority. |
| [Kubernetes NetworkPolicy semantics](https://kubernetes.io/docs/concepts/services-networking/network-policies/) | Applicable allow rules combine; source egress and destination ingress both matter. | Reject exports that silently discard a deny or depend on an uninspected surrounding policy set. |
| [Cedar validation](https://docs.cedarpolicy.com/policies/validation.html) | Schema checking catches invalid policy shapes and type use. | Reuse typed validation principles. Do not substitute Cedar for the existing native compiler. |
| [fastText classification](https://fasttext.cc/docs/en/supervised-tutorial.html) | Compact local supervised classification is a practical baseline. | Compare a linear classifier before adding a transformer runtime. Its score is not attack probability. |
| [SetFit](https://huggingface.co/docs/setfit/index) | Few-shot sentence classification can use local embedding models. | Test short reviewed descriptions only. Published text benchmarks do not establish security effectiveness. |
| [River drift methods](https://riverml.xyz/latest/api/overview/) | A distribution-change detector can flag when a baseline has changed. | A change alarm does not identify malicious intent and must not trigger automatic retraining or enforcement. |
| [ONNX Runtime CPU execution](https://onnxruntime.ai/docs/execution-providers/) and [thread controls](https://onnxruntime.ai/docs/performance/tune-performance/threading.html) | Optional models can execute locally with explicit resource controls. | Add only after a measured model win. Pin runtime, artifact, operators, threads, memory, and model license. |
| [OpenTelemetry GenAI attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/) | Agent and tool context can aid grouping when a source supplies it. Some conventions are still in development. | Pin a schema. Trace text is context, not verified actor purpose or permission. Do not collect prompt bodies by default. |
| [AutoCedar research](https://arxiv.org/abs/2607.03656) | Verifier-guided synthesis separates proposed policy from checked intent. July 2026 research, not proof of production readiness. | Explore constrained candidate generation only after the native deterministic verifier exists. No model may change the approved requirement to make a check pass. |

KubeArmor, Tetragon, Cilium/Hubble, Falco, NeuVector, and OpenShell remain
relevant enforcement, observation, or review references. Their specific
capabilities and the incident sources are recorded in the
[console research](../araphor-console/research-and-design-inputs.md).
The case for Araphor is the combined review and proof workflow. It is not the
claim that these projects have no enforcement or no policy learning.

### Storage and aggregation comparison

| Project or method | Inspected mechanism | Decision for Araphor |
| --- | --- | --- |
| [Kubescape storage](https://github.com/kubescape/storage) | SQLite holds metadata; filesystem payloads hold larger resources. List operations can omit payloads. | Use an embedded query database with separate immutable evidence artifacts. Do not put full event history in the Control state image. |
| [Security Profiles Operator](https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/installation-usage.md) | Recording, profile, and binding resources have separate contracts. | Keep observation scope, derived profile, and applied policy separate. Profile output is not activation evidence. |
| [Tetragon aggregator at the local revision](https://github.com/cilium/tetragon/blob/dbb59576f9ce504c044f8d9a0cd7a0f91c71ae2c/pkg/aggregator/aggregator.go) | In this inspected file, `handleEvent` has only a default branch that forwards events. The cache/window structure alone does not prove effective aggregation. | Inspect the executable path, not only an API option named aggregation. This finding is limited to the pinned revision and file. |
| [Cilium monitor aggregation](https://docs.cilium.io/en/latest/operations/performance/tuning/) | The inspected development documentation describes connection/flag and periodic emission controls. | Source records need sampling and reduction metadata. Emitted observations are not packet counts or proven physical-effect counts. |
| [SQLite WAL](https://www.sqlite.org/wal.html) | Concurrent readers share one writer; WAL requires a same-host filesystem. Long reads can delay checkpoints. The WAL-reset fix is in 3.51.3 and documented backports. | Transactional baseline for the storage experiment. Bound readers and WAL growth; reject network-filesystem deployment. |
| [DuckDB workload guidance](https://duckdb.org/docs/current/guides/performance/how_to_tune_workloads) | Designed for analytical workloads, not many small concurrent requests. | First-class candidate for batched events, context joins, and investigation queries. Measure the actual mixed workload before selecting it or SQLite. |
| [ClickHouse incremental views](https://clickhouse.com/docs/concepts/features/materialized-views/incremental-materialized-view) | An insert transforms an input block. Changes to joined reference tables do not update previous results automatically. | Consider later for measured fleet-scale analytics. It does not remove input deduplication, revision, or replay requirements. |

No inspected project establishes Araphor's capacity. The embedded choice must
pass the declared input, query, restart, and concurrent-policy tests. A future
multi-writer Control service would need a separate ownership and recovery
design, not only a different SQL driver.

### Local algorithms and typed AI

The useful comparison is between methods, not brands. Prefer exact keys,
ordered set differences, typed rules, and fixed test-selection rules. These
methods require no training and can produce byte-identical replay artifacts.

| Method reference | Useful experiment | Limit |
| --- | --- | --- |
| [Drain log parsing](https://github.com/logpai/logparser/blob/main/logparser/Drain/README.md) | Template grouping when a future source supplies unstructured diagnostic text. | Current evidence is typed. Template variables must not replace object identity or become wildcard permissions. No parser is needed for the first native path. |
| [ADWIN](https://riverml.xyz/latest/api/drift/ADWIN/) | Compare bounded distribution-change detection with exact revision/set changes. | A change is not an attack. Input order and parameters must be pinned; false alarms need a separate evaluation. |
| [GLiClass](https://github.com/Knowledgator/GLiClass) and [its paper](https://arxiv.org/abs/2508.07662) | Local label-conditioned text classification; compare with supervised SetFit when reviewed descriptions add useful context. | General text results are not security results. Neither method establishes required behavior. |
| [TypeSafe Jev quickstart](https://docs.typesafe.ai/introduction/quickstart) and [confidence contract](https://docs.typesafe.ai/confidence) | Fixed typed questions and explicit score semantics are useful interface ideas. | The inspected integration uses a hosted endpoint; no local deployment package was verified. Distribution concentration is not probability of correctness. |
| [Simple Jev](https://github.com/featherless-ai/simple-jev) | A local fixed-choice logit scorer is an alternative to generating prose and parsing JSON. | It is not the Jev architecture. Resolve code/model licenses and qualify the runtime before reuse. |
| [Simple Jev scoring source](https://raw.githubusercontent.com/featherless-ai/simple-jev/main/common/response_scoring.py) | Validates label sets and finite logits, then applies softmax. | Its scores are uncalibrated. Araphor must retain score kind and calibration status rather than display the maximum as certainty. |
| [Laya typed-decisions model card](https://huggingface.co/convaiinnovations/laya-typed-decisions) | A local 421M-parameter encoder supplies another typed-decision experiment. | The card reports calibration limitations. FP16 weights alone are about 842 MB, above this plan's production artifact and worker limits. Evaluate offline only unless a smaller artifact passes all gates. |
| [Calibration research](https://proceedings.mlr.press/v70/guo17a.html) | Fit calibration on validation data and inspect held-out reliability. | Calibration on one distribution does not prove safety or survive arbitrary drift. |

Use deterministic grouping as the baseline in every experiment. Compare a
structured linear model, one compact semantic classifier, and at most one
tool-using model on the same frozen tasks. A hosted typed classifier is now
eligible under an approved disclosure policy; local availability is no longer
a product constraint. A fixed-choice method alone does not investigate a case.
Do not deploy all candidates.
The detailed input, replay, abstention, and adoption contracts are in
[local-intelligence.md](local-intelligence.md).

## Incident-derived requirements

Use the console research's primary Hugging Face timeline and technical report,
not its illustrative graph, as incident sources. Do not claim this engine
would have stopped the incident merely because it could produce a policy.

- A credential read during a compromised training window remains an observed
  action. Frequency and success cannot make it a required read.
- Distinguish ordinary workload activity from additional runtime entries.
  Similar commands do not prove that an entry is a probe or an administrator.
- A permitted TLS connection cannot show which remote repository or provider
  operation occurred. Missing provider evidence remains missing.
- A dependency, model artifact, tool description, or retrieved document can
  contain attacker-controlled content. Such content cannot instruct the
  classifier, authorize a test, or alter a proposal's scope.
- Already-open resources and already-issued credentials need explicit test
  cases. A new policy is not evidence that old access has been removed.

The investigation fixture must test at least three alternatives: compromised
entry, declared maintenance, and changed application behavior. Join entry,
credential-access result, policy state, and release context only where the
source proves the join. Ask for provider audit evidence before alleging remote
token use or data access. The result must identify missing facts and a useful
next check, not only group credential-read events. This is an incident-inspired
fixture, not a reconstruction or proof of prevention of the real incident.

### Hugging Face's defender, not only the attacker

[Hugging Face reports](https://huggingface.co/blog/agent-intrusion-technical-timeline#how-we-intercepted-and-analyzed-the-attack)
that its security-agent stack correlated the signals but failed to raise the
criticality and trigger on-call. For investigation, it deployed quantized
GLM-5.2 on its own infrastructure after other models refused parts of the
analysis. It used the model to decode payloads and build trace-analysis views.

This account supports two requirements, not a claim that a local model alone
prevented the incident: qualify a self-hosted defender for hostile-evidence
analysis, and test the complete escalation-to-response workflow. Model location
does not establish authority or ensure a correct conclusion.

Araphor therefore uses shared evidence and owner records for the local agent
and console. Assessments enter the API directly; qualified action results return
to the same subject/finding view. Deterministic routing floors, acknowledgement
deadlines, and verified response cannot depend on a successful model verdict.
Refusal, low suggested priority, or agent loss must leave those obligations
visible. Keep this in the existing owners, not a separate agent case system.

## Agent investigation research

The earlier design limited AI to operational labels. That does not meet the
revised requirement. The following sources support context retrieval, security
assessment, and recommendation as separate functions. Product documentation
describes capabilities; vendor reports and papers do not prove Araphor results.

| Source | Finding | Implementation consequence |
| --- | --- | --- |
| [Elastic's internal triage report, August 2026](https://www.elastic.co/security-labs/blog/alert-triage-agentic-soc-self-correcting-agents) | The team reports better agreement with analyst closure decisions after adding rule-specific guides, entity context, and prior case reasons. Predictable lookups remain queries. This is a vendor's internal result, not independent security accuracy. | Supply exact rule/runbook context and scoped reviewed history. Measure assistance against tasks, not summary fluency. Keep investigation in the existing client; do not infer an optimal topology from this report. |
| [Elastic Attack Discovery](https://www.elastic.co/docs/solutions/security/ai/attack-discovery) | Correlated alerts support attack hypotheses and investigation, rather than only duplicate removal. | Return hypotheses with evidence and competing explanations. Retain the distinction between an assessment and a proved causal finding. |
| [HolmesGPT runbooks](https://holmesgpt.dev/0.23.0/reference/runbooks/) | Runbooks direct iterative tool-based investigation and retain completed or skipped checks. | Provide versioned method/runbook context and a check ledger. Missing mandatory checks remain visible; a fluent final answer cannot mark them complete. |
| [HolmesGPT tool loop](https://raw.githubusercontent.com/HolmesGPT/holmesgpt/master/holmes/core/tool_calling_llm.py) and [tool implementation](https://raw.githubusercontent.com/HolmesGPT/holmesgpt/master/holmes/core/tools.py) | The inspected source has step limits, cancellation, and explicit approval handling. Some transformations can return original data on failure. Inspection covers these paths, not a full security audit; master was viewed on 2026-09-20. | Let existing clients own their loop. Fail closed on Araphor export filtering. Do not expose generic shell tools or copy permissive defaults. Pin a source revision before any code reuse. |
| [Microsoft Guided Response research](https://arxiv.org/abs/2407.09017) | Separates historical-context retrieval, triage, and containment recommendations. Its GUIDE data uses analyst triage labels, including benign positives. | Separate predicate match from security disposition and suggested response. A correct rule match can be benign; analyst feedback is useful but fallible and scope-dependent. |
| [Microsoft triage-agent documentation](https://learn.microsoft.com/en-us/defender-xdr/phishing-triage-agent) | Exposes verdict, rationale, evidence, activity, and feedback. Some workflows can close alerts. | Keep traceable assessment and reviewed feedback. Do not adopt automatic closure for the initial Araphor delivery. |
| [Agentic alert-investigation research](https://arxiv.org/abs/2604.25846) | Studies staged investigation using predefined queries and agent-selected evidence retrieval. Its task-specific results do not establish general runtime-security accuracy. | Compare a context-only model with the same model using bounded methods. Query execution stays deterministic and independently testable. |
| [Context engineering guidance](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents) | Treats context as a limited resource and supports targeted retrieval instead of loading all available material. | Use compact context packets, exact references, progressive reads, and explicit omissions. Do not add vector search before showing a retrieval failure. |
| [Sigma correlation specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html) | Defines explicit count and temporal correlation semantics with grouping and windows. | Version predicates and order/coverage assumptions. Provide versioned SQL recipes; do not claim Sigma compatibility or causality from temporal correlation. |
| [MCP tool specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) and [security guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) | Structured tool contracts support machine clients; tool metadata does not replace authorization. Token audience and confused-deputy risks remain. | Use a thin adapter to the authenticated HTTP API. Check principal, scope, disclosure, and limits on the server for every call. No bearer-token passthrough to a model provider. |
| [AgentDojo](https://arxiv.org/abs/2406.13352) | Evaluates useful agent tasks alongside adversarial instructions in tool-returned data. | Test both investigation utility and indirect prompt injection. A schema check or an instruction to ignore malicious text is not a sufficient defense. |

The design inference is specific: give the agent enough relevant, qualified
context to distinguish hypotheses, then let it choose bounded reads. Return
classification, rationale, counterevidence, and typed next steps. Keep identity,
method execution, evidence references, authorization, and change validation
outside the model. Do not treat a model verdict or repeated analyst decision
as an automatic allow-list entry.

### Recheck: simpler tools, measured context, and protection

| Primary source | Experiment or documented behavior | Decision and limit |
| --- | --- | --- |
| [Vercel: removing specialized tools](https://vercel.com/blog/we-removed-80-percent-of-our-agents-tools) | Its internal data agent improved after replacing specialized wrappers with access to documented data. The comparison used five queries. Although the prose describes one bash tool, the shown configuration exposes ExecuteCommand and ExecuteSQL. | Test fewer read wrappers and better schema/context. This small vendor experiment does not prove one SQL tool is universally best, and its shell access is not Araphor's security model. |
| [Elastic: specialized versus general agents](https://www.elastic.co/security-labs/blog/agentic-soc-token-budget-architecture) | Reports lower token use with inline methodology. Fleet totals cover 36,822 conversations, but the tighter comparison used four matched alerts, one run per architecture. Route costs combine agent medians; the unified-agent sample was five runs. | Counterevidence to “fewer agents/tools always wins.” Test an inline checklist with the same client before building orchestration. Do not present the fleet total as a controlled trial of that size. |
| [Elastic: reducing repeated model calls](https://www.elastic.co/security-labs/blog/ai-agent-optimization-production-scale) | Reports 14–19 calls reduced to 7–9 for the studied alert class after concrete stopping checks. It identifies repeated enrichment/schema queries and overly broad retrieval as waste. | Supply required fields and exact context once; query only missing facts. Measure completion, omissions, errors, and run variance, not merely tool count. A stopping rule must allow an Unknown result. |
| [Anthropic: effective tools](https://www.anthropic.com/engineering/writing-tools-for-agents) | Recommends task-oriented tools, useful response content, and evaluation rather than wrapping every API operation. | One investigation query can coexist with separate policy and response tools. Distinct effects and authority justify separate contracts. |
| [osquery result logging](https://osquery.readthedocs.io/en/stable/deployment/logging/) | Distinguishes full snapshots from added/removed differences across scheduled query results. Reconstructing current state from differences needs history. | Do not pretend arbitrary aggregate SQL is an append-only event stream. Follow durable record revisions; run ordinary SQL for current state and analysis. No per-client scheduled-query cache. |
| [DuckDB untrusted-SQL guidance](https://duckdb.org/docs/current/operations_manual/securing_duckdb/overview) | Treats untrusted SQL as untrusted code; engine settings are not an OS security boundary. | Qualify an isolated query worker with authorized input only. SELECT-only parsing and final-output redaction are insufficient. Include isolation cost in store selection. |

These reports justify an experiment, not a guaranteed improvement. Compare
specialized read wrappers, documented SQL, and SQL plus exact context/runbooks
using identical evidence, model, grants, and repeated held-out tasks. Keep
specialized effectful tools where approval, target identity, or postconditions
differ. Simplicity means less duplicate machinery, not fewer product capabilities.

[Hugging Face's timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline)
describes local file disclosure, in-process execution, credential pivots, and
replacement workloads. Query access would help investigation but could not
prevent these effects. The
[OpenAI technical report](https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf)
adds cross-evaluation sharing and indirect external paths. Do not force the
accounts into one inferred process lineage or treat a tool name as provenance.

The implementation consequence comes from the existing master acceptance:
local pre-effect policy first; exact cross-owner evidence; separately authorized
containment; provider-specific recovery; and checked postconditions with a
healthy watch. The
[owner mapping](engine-design.md#protection-boundary-and-master-plan-integration)
keeps those requirements and their unavailable dependencies explicit. It does
not claim Araphor has already prevented or reproduced the incident.

### Storage implication for investigation

[DuckDB concurrency](https://duckdb.org/docs/current/connect/concurrency)
supports concurrent work within one writer process. That matches the present
single-owner Control shape; a distributed writer service is not required.
[Its transaction contract](https://duckdb.org/docs/current/sql/statements/transactions)
means durability is not, by itself, a reason to reject it. The open question is
the mixed workload: exact deduplication, micro-batches, point lookups, context
joins, and paged review during ingestion.

[DuckDB indexing](https://duckdb.org/docs/current/guides/performance/indexing)
does not make every SQLite indexing assumption portable. Its
[non-determinism guidance](https://duckdb.org/docs/current/operations_manual/non-deterministic_behavior)
also requires explicit ordering and care with parallel floating-point results.
Benchmark query plans and memory as well as OLAP throughput. Select one store
before durable implementation; keep immutable evidence and approved policy
outside the derived database. No second DB or generic driver framework is
needed to run a one-time comparison.

## Ideas selected beyond the reference projects

1. **Test-guided discovery:** identify the next lifecycle test that resolves an
   important ambiguity, instead of waiting indefinitely for more traffic.
2. **Permission expansion receipt:** show which unseen resources a proposed
   wildcard, directory, selector, or destination group would permit.
3. **Revision comparison:** separate changes caused by a new image or config
   from changes within the same revision. Do not silently merge both baselines.
4. **Agent-ready investigation:** provide scoped context, deterministic methods,
   security assessments, and typed suggestions. Local or hosted models can
   assist under explicit disclosure controls, without acquiring authority.
5. **Portable evidence bundle:** retain the exact inputs needed to reproduce
   a review. A later signed distribution format is optional.

Each idea has a measurable experiment in [local-intelligence.md](local-intelligence.md)
or [verification.md](verification.md). None requires a new general-purpose
agent service or a new enforcement boundary.
