# Agent Investigation, Classification, And Test Selection

This design gives agents bounded SQL reads, relevant context,
evidence-backed classification, and typed next steps. Local and hosted models
are both eligible. The path remains unchanged to preserve existing links.
It does not ask a model to determine which operations are authorized. The
deterministic engine remains useful when no model is installed.

## Problems to solve

| Task | Useful output | Forbidden interpretation |
| --- | --- | --- |
| Investigate a detection | Supporting evidence, counterevidence, competing explanations, and missing facts | A matching pattern proves an attack or causal chain. |
| Classify activity | Expected activity, misconfiguration, suspicious activity, likely malicious activity, or insufficient evidence; separate impact and activity facets | A suggested benign label closes an incident or creates an exception. |
| Compare two application revisions | New and changed behavior, with possible explanations | A code update authorizes every new action. |
| Prioritize review | Items with high impact, uncertain context, or guardrail conflicts first | Low-ranked items may be silently approved or removed. |
| Identify missing tests | A case likely to resolve an important unknown | A generated test is authorized to run in production. |
| Explain a rule | Evidence references and a plain explanation of its transform | Fluent explanation is proof that a policy is correct. |

The external agent selects its model under an approved tenant/export purpose. Local execution
avoids mandatory external transfer, but does not guarantee privacy or quality.
Hosted execution can provide better reasoning if the measured benefit and
disclosure policy permit it. No provider or fallback is enabled implicitly.
The product contract is useful evidence-backed assistance, not local inference.

## Compare methods in increasing cost order

| Method | Proposed use | Adoption gate |
| --- | --- | --- |
| Exact grouping, ordered set differences, and fixed typed rules | Required baseline: operation, resource kind, declared lifecycle, cohort, result, guardrail conflict | Always available. No model required. |
| Deterministic test selection | Cover missing facts with approved tests, ordered by impact and cost with stable ID tie-breaking | Required baseline. No model may omit a mandatory case. |
| Feature hashing plus regularized linear classifier | Local operational categories and review ranking from reviewed labels | Must beat the deterministic baseline on held-out workloads and operator time. |
| Small tree model | Alternative when interactions between typed features matter | Compare with the linear model. Do not deploy both without a measured benefit. |
| Local compact text classifier: GLiClass or SetFit | Short, redacted owner descriptions and package metadata; label-conditioned classification or reviewed few-shot labels | Compare one candidate with structured features. Do not assume text is needed when typed facts already answer the question. |
| EWMA or ADWIN change detector | Additional signal for comparable source-normalized feature sequences | Must beat explicit revision and set changes. Missing coverage disables rate comparison. A change is not an attack. |
| Local fixed-choice scorer: small encoder or restricted next-token logits | Typed category suggestions without free-text generation; Simple Jev and Laya are experimental references | Run offline against the same tasks. Closed output does not ensure correctness, calibration, or portable deterministic inference. |
| Existing tool-using agent, local/self-hosted/hosted | Investigate hypotheses, request missing context, assess behavior, and propose typed next steps | Compare context-only and tool-assisted tasks. Enforce disclosure, per-call authorization, budgets, citation checks, and review. |

[fastText](https://fasttext.cc/docs/en/supervised-tutorial.html),
[SetFit](https://huggingface.co/docs/setfit/index), and
[River](https://riverml.xyz/latest/api/overview/) are method references, not
selected production dependencies. The first experiment should use an isolated
offline training tool. A runtime dependency is selected only after the
experiment succeeds. Do not introduce Python into the Rust service to run a
benchmark that might reject the model.

If the selected model is a small linear model, a reviewed bounded feature
schema and weight artifact can be sufficient for Rust inference. Do not build
a general ML runtime for it. If a compact encoder wins, evaluate a pinned CPU
runtime such as ONNX Runtime. Include its native code, supported operators,
threads, and model deserialization in the security and license review.

### Determinism contract

The core uses no model: exact identity checks, counts, partitions, ordered set
differences, native validation, guardrails, and test selection. Pin canonical
encoding, integer overflow behavior, feature order, and tie-breaking. Replays
with permuted arrival and different batch boundaries must return the same
core content digests. No online learning or random clustering enters this path.

Deterministic text templates explain why a row exists: source rule, exact
operation, revision difference, missing lifecycle case, or guardrail conflict.
Show the supporting fields. Template grouping such as Drain is unnecessary
for already typed evidence. Approximate text or vector similarity must not
merge exact permissions, decide attribution, or suppress required review.

A frozen model can be repeatable on a pinned runtime without being correct.
Temperature zero also does not prove bit-identical output across hardware,
tokenizers, quantization, and runtime versions. Retain the actual annotation
and its input/model/runtime digests. Replay of policy and evidence does not
rerun inference. Model reruns are a separate comparison with stated tolerance;
they cannot change sealed facts, proposal digests, approval, or queue eligibility.

### Classification contract

Classify a scoped investigation, not each event. The taxonomy has independent
facets: activity category, security disposition, likely cause, affected asset,
impact, and recommended urgency. Security disposition is Expected,
Misconfiguration, Suspicious, LikelyMalicious, or InsufficientEvidence. An alert
can also have TruePositive, BenignPositive, FalsePositive, or Undetermined
relative to its exact detector intent. A rule can correctly match harmless
activity; that is different from a broken predicate. Labels do not authorize
behavior. Preserve source severity; a suggested priority cannot hide mandatory
review or an existing high-risk finding.

Each assessment states a short conclusion, alternative hypotheses, supporting
and contradicting evidence, missing facts, and the next discriminating check.
Separate Suggested from HumanConfirmed. A policy approval is neither a benign
label nor training truth. Abstain when required facts are absent; do not force
a binary verdict. An agent may still recommend how to obtain those facts.

Each request binds tenant, cohort, snapshot, context/feature digest, taxonomy,
label order, prompt/tool schema, and available model/runtime/tokenizer versions.
Pin local artifact digests. Record opaque hosted versions as unknown where the
provider does not expose them; do not invent a weight digest. Bound text and
token counts; reject overflow rather than silently truncating required facts.
Treat all descriptions and resource strings as untrusted data. For logit-based
scoring, validate that label token mappings are distinct and supported by the
pinned tokenizer. Do not rely on free-form JSON generation for fixed choices.

Each response uses the ClassificationAssessment schema: supplied context IDs,
allowed labels, cited claims, alternatives, missing facts, and typed suggestions.
If a score is present, require a finite value, `score_kind`, calibration status,
and calibration-set/version where applicable. Require an abstention reason
when evidence is insufficient. Reject unknown fields and fabricated references.
Raw softmax concentration is not probability of correctness. Calibrated output
is still not probability that granting permission is safe. The
[method research](research-and-demand.md#local-algorithms-and-typed-ai) records
the distinction and local candidates; Jev is not the architecture requirement.

Retain validated assessment reports by tenant, input revisions, and content
digest. Repeated unchanged evidence needs no new model request. Control does not
own a provider session, model cache, paid-call retry, or agent-run state machine.
Server query receipts prove what Araphor returned; client-reported calls, costs,
and model identity remain unverified unless a qualified source supplies them.

### One defender workflow

The supported local defender uses an existing agent runtime and a model on the
operator's own infrastructure. “External client” means outside Control's process,
not outside the deployment or an export/import workflow. Local model execution
must be qualified explicitly; running a CLI locally while it calls a hosted
model is not local inference.

Console and defender share subject/finding revisions, query receipts, assessments,
approvals, and action results. The agent submits reports directly through the API.
Its private chat is neither the case record nor a required input for recovery.
One query interface simplifies investigation, not the enforcement boundary.

```text
Agent receives a workload or finding question
  -> query returns exact subject, policy, coverage, rule guide, and reviewed context
  -> runbook states required checks, alternatives, useful SQL, and stop criteria
  -> agent queries only missing facts or follows relevant revision records
  -> query returns evidence, counterevidence, scope, limits, and receipt
  -> agent submits an AssessmentReport through submit_assessment
  -> validator checks schema, references, revisions, and unsupported claims
  -> console immediately shows the same report and linked suggestions
  -> operator reviews the same policy or response revision
  -> action results and open branches return to that subject/finding view

Access changes or a query fails
  -> query returns denial, expiry, limit, or unavailable state
  -> required check remains incomplete
  -> the agent can report uncertainty without fabricating a verdict
  -> replay uses retained results and does not require model execution

Agent proposes enforcement or containment
  -> the owning policy or response tool validates an immutable proposal
  -> independent approval or exact existing preauthorization controls execution
  -> the execution owner revalidates the target before effects
  -> query/follow exposes activation, postconditions, and unresolved branches
```

Implement two versioned runbooks: credential access and deployment behavior
change. Include the columns needed for common checks directly in each runbook.
Fetch known subject/rule context in one query; do not require repeated schema
discovery or fetching facts already present. Stop after the named checks with
a supported result or explicit uncertainty. A stopping checklist cannot convert
missing evidence into a benign verdict.

An approved runbook is bounded context, not executable authority. SQL examples
use admitted read-only syntax; policy/response suggestions use typed schemas.
No arbitrary shell, URL fetch, or production test execution. Compare the fixed
recipes with agent-written SQL; do not restrict investigation to four RPCs.

Use field/exact retrieval first. Add semantic retrieval only for a measured
failure on approved text. Similarity can rank context, not establish identity
or merge permissions. A separate vector database is not required.

### Disclosure for external agents

A separately authorized tenant administrator configures `DisclosurePolicyV1`:
tenant, recipient, purpose, permitted data classes, redaction, retention, and
expiry. The service principal binds that policy. Model/provider choices must
fit the approved recipient's agreement; no silent local-to-hosted fallback.

Control applies row/field authorization and redaction before SQL evaluation
and before tool serialization. Exclude credentials, environment values, and
private file contents. Paths may contain secrets. Use stable scoped pseudonyms
only where joins remain valid; never reuse them across tenants. Record omissions
and their effect on conclusions. Filtering failure sends no original payload.

The external client owns provider credentials, network destinations, token
budgets, and model cancellation. Araphor cannot enforce that client's onward
use or prove provider deletion after export. State that limit instead of
claiming server-side provider control. Araphor enforces its own read/export
grants, request/concurrency/byte limits, expiry, and revocation on later reads.

Treat logs, filenames, context documents, and model reports as untrusted.
Test injection that asks for secret retrieval, foreign scope, false benign
verdicts, fabricated citations, or unauthorized actuation. Schema validity
does not prove a claim; human review and labeled evaluation remain required.

Qualify one local agent/model configuration as part of the first assisted
delivery. Record the agent runtime/version, MCP schema, model artifact/runtime,
endpoint location, resource needs, and disclosure profile in the existing
qualification manifest. Deny all network egress except Araphor and the approved
in-network inference endpoint during the local qualification. Provision model
artifacts before the test; do not rely on a hidden hosted fallback.

Test lawful analysis of hostile evidence, including encoded fixture payloads,
malicious instructions, and misleading benign context. Static decoding can
produce an assessment attachment with the original evidence digest, transform
description/version, output digest, and bounded text. Keep it ClientDerived
until a qualified replay verifies the transform; it is not a new sensor event.
Never execute a recovered payload or load an untrusted model in Control.
Existing agent analysis tools, if used, run only in an isolated analyst workspace
without production credentials. Dynamic analysis needs separate authorization.

Model refusal is an explicit FailedCheck, not a benign verdict or a reason to
disable safeguards. Keep the evidence available to an authorized human or
another approved configuration. Deterministic criticality and escalation do
not wait for the model. No choice of model guarantees successful defense.

The first product does not add a model gateway or hosted inference service.
A future managed classifier must demonstrate a task/cost benefit and obtain
separate approval for transport, credentials, budgets, isolation, and retention.
This is not a prerequisite for using local or hosted agents now.

## Input and labels

The feature record is derived from a sealed snapshot. It includes:

- operation family and exact operation;
- source result class and coverage/attribution quality;
- declared entry class, when the source provides one;
- resource kind, mount class, and bounded path-shape features;
- platform, image/configuration revision change, and container kind;
- counts capped per source and run, plus number of distinct runs;
- lifecycle evidence and explicit test identity;
- existing guardrail conflict and permission-expansion flags.

An optional path-shape feature can indicate a UUID-like component or a known
temporary directory. It must not replace the raw resource binding or create
a wildcard grant. Do not use raw secrets, file contents, environment values,
full argv, prompt bodies, request payloads, or arbitrary tool descriptions as
default features. A path can itself contain a secret; redact before optional
text inference. Redaction can reduce usefulness and must be recorded.

Activity labels include startup dependency, steady-state
dependency, cache/temp activity, network dependency, maintenance-related,
test-related, and unresolved. Labels can overlap. A category does not identify
an authorized actor role. In particular, `maintenance-related` does not grant
an administrative role or prove a kubelet purpose.

Keep these labels separate from requirement labels: required, forbidden,
unresolved. A human can confirm the first without approving the second.
Rejected proposals are not automatically malicious examples. Accepted
proposals are not proof of benign activity.

## Optional training and evaluation lifecycle

```text
Authorized owner labels a behavior group
  -> Control records label, scope, reviewer, revision, and evidence references
  -> training export applies the tenant's data and retention policy
  -> offline trainer fits a candidate on the approved training partition
  -> evaluator tests a frozen held-out partition and adversarial cases
  -> model review records accuracy, abstention, cost, and known limits
  -> operator explicitly promotes the model artifact for that tenant/scope

External model assesses a sealed context packet
  -> bounded export excludes unsupported and sensitive fields
  -> classifier returns a schema-limited annotation
  -> output validator rejects bad references, sizes, and numeric values
  -> console separates suggested disposition, hypotheses, and next steps
  -> no policy, evidence, role, or guardrail field changes

Data shifts or the model exceeds its limit
  -> report records drift, timeout, failure, or out-of-distribution status
  -> classifier abstains or is disabled for the affected scope
  -> deterministic review continues
  -> retraining requires a new dataset and explicit model promotion
```

Use tenant-local labeled data by default. Cross-tenant training requires
explicit data permission and an evaluation for leakage. Do not train from
private raw events merely because a model is local. Deletion and retention
rules must cover exported examples, features, checkpoints, and model artifacts;
record when deletion requires retraining rather than asserting erasure from
weights. Use scoped reviewed history as context before adding training. Reuse
only decisions available before the investigation cutoff; keep rejected and
contradictory reviews visible. Do not automatically turn a closure reason into
a global rule or an approved runbook instruction. Training is not a prerequisite
for the context-and-tool workflow; implement it only for a measured classifier
need. Do not build training merely because reviewed labels exist.

Partition by workload family, release, and time, not random event rows. Events
from one trace or replica group cannot occur in both training and test sets.
Include a cold-start workload and an unseen application version. Keep attack
examples and policy guardrail tests outside the training stream. Limit repeated
examples so one noisy or compromised workload cannot dominate the model.

Report class support, per-class precision/recall, macro averages, confusion
matrix, coverage of non-abstained predictions, and calibration on the stated
validation set. A displayed score names its meaning and model version. Do not
display it as the probability that an action is safe.

Also report Brier score, calibration error and reliability bins, risk versus
abstention coverage, and support by workload family. Freeze calibration and
thresholds before held-out evaluation. Report confidence intervals and mark
rare classes inconclusive rather than hiding them in a high aggregate score.
Test changed class frequencies, label-order changes, unrelated labels, empty
descriptions, missing evidence, and prompt-like resource names. A confident
answer on absent evidence is an error, not a reason to relax abstention.

Choose abstention thresholds on a validation partition, then freeze them before
the held-out test. Abstain for missing required features, unseen schema, an
unsupported cohort, close competing classes, or detected distribution shift.
Do not claim calibration or conformal guarantees continue under arbitrary
production drift.

## Review selection and feedback

The deterministic queue orders guardrail conflicts and privilege increases
before ordinary repeated observations. Model ranking can order items within
an eligible group, but cannot hide a conflict or change mandatory review.

For active learning, request a small daily label budget. Prefer uncertain and
representative examples, with a cap per cohort. Include some random examples
to reveal selection bias. Batch exact duplicates, not semantically similar
permissions. The reviewer can split a group and see the original members.

Feedback records the reason: wrong grouping, wrong class, missing context,
incorrect requirement, or incorrect policy transform. These are different
defects. Do not train all of them into one accepted/rejected label.

## Test selection algorithm

Start with a finite catalog of reviewed test cases and their required inputs,
expected result fields, lifecycle coverage, and resource costs. Reuse the
existing lightweight/physical qualification pairing. The planner does not
invent test execution permissions.

For each unresolved proposal item:

1. Identify the missing fact: lifecycle use, exact binding, operation result,
   target support, or permission expansion.
2. Find catalog tests that can produce that fact for this target family.
3. Exclude tests whose scope, secrets, effects, or platform are not approved.
4. Rank by number and impact of unresolved items covered, then lower cost.
5. Return the chosen test and the remaining unanswered questions.

Use a fixed lexicographic order: mandatory safety/lifecycle class, number of
unresolved facts covered, lower declared cost, then stable fixture ID. When
selecting several tests, remove covered facts after each choice. Record each
choice and remaining set. This is a bounded greedy selection, not a claim of
globally optimal set cover. It needs no learned planner.

A later ranking model can learn which approved test was useful. Compare it
with this deterministic coverage-per-cost ranking. Do not add reinforcement
learning with production actions. An unlisted test remains a human-readable
request until its fixture and execution contract are reviewed.

Example: a workload has startup and steady-state evidence but no graceful
shutdown evidence. A proposed removal of write access to a state file is
unresolved. Recommend the existing shutdown fixture, not additional hours of
steady-state observation. A passing fixture supports this case and revision;
it does not prove every shutdown path is safe.

## Artifact and runtime security

- Bind model bytes, feature schema, label schema, training manifest digest,
  validation report, runtime version, license, and promotion decision.
- For local inference, load only approved artifacts. No runtime downloads, remote custom
  code, arbitrary pickle loading, custom executable model operators, or
  automatic package installation.
- Bound model bytes, input rows, input text, tensor shapes, CPU, threads, memory,
  and execution time. Reject malformed and non-finite scores.
- If local native model parsing/inference is introduced, run it in an unprivileged,
  resource-limited local worker with no network and no production credentials.
  This worker is optional computation, not another durable policy service.
- Use a bounded request/result interface. Worker termination must not terminate
  Control or delay policy reconciliation. Restart has a retry budget.
- Store explanation references and final annotations. Do not store hidden
  chain-of-thought or portray generated prose as independent evidence.
- Treat all model outputs as untrusted. A candidate may reference only the
  supplied tenant-scoped rows and allowed label fields.
- Keep a kill switch and the prior approved model. Model rollback does not
  roll back or modify a workload policy.

## Experiments and stop rules

| Experiment | Baseline | Proposed pass gate |
| --- | --- | --- |
| Operational classification | Fixed typed rules plus exact grouping | At least 95% precision on non-abstained labels and at least 50% non-abstained coverage in the frozen pilot corpus; report recall, class support, and each workload family's results. |
| Security assessment | Deterministic method results plus analyst context | Report benign/malicious confusions, severity-weighted errors, abstention, and supported versus unsupported claims. No seeded malicious case may be downgraded to Expected in the pilot. A small zero-error sample is not a safety guarantee. |
| Agent investigation | Raw rows, context-only, documented SQL, then SQL plus exact context/runbook | Measure retrieval recall, citation validity and support, counterevidence, next checks, completion, calls, bytes, tokens, cost, latency, and variance. Keep model and tasks fixed. |
| Review workload | Deterministic queue on the same tasks | At least 30% lower median task time in the pilot, with no additional incorrect approvals and all seeded high-risk groups still shown. Report sample size and per-task outcomes. |
| New revision explanation | Exact set and result differences | Reviewers identify the actual changed dependency more often or faster; an unsupported explanation counts as an error. |
| Test selection | Declared missing-case order | Fewer approved test runs to resolve the same case set, without skipping any required or forbidden case. |
| Runtime and disclosure | No-model engine | Enforce query CPU/byte/scope limits; no unapproved export or actuation; no primary intake/rollout regression. Client cost limits are evaluator controls, not a Control guarantee. |

These numbers are proposed pilot gates, not measured performance or statistical
security guarantees. Phase 1 fixes the corpus and review protocol before model
selection. If a gate fails, ship the deterministic function and retain the
experiment report. A model is not a release requirement.

Run bounded comparisons after the deterministic baseline:

1. Fit one regularized linear model on typed features. Test a small tree only
   if a recorded feature interaction explains a material linear-model error.
2. If approved text exists, test one semantic classifier: GLiClass for the
   label-conditioned case or SetFit when reviewed few-shot training is the
   actual requirement. Hold the input task and evaluation split fixed.
3. Test one approved external agent with context-only and query-tool modes.
   It can be local, self-hosted, or hosted. Use synthetic/public permitted data
   for a hosted experiment unless a separate data disclosure is approved.
   A fixed-choice Jev-like method is useful for a finite classification task,
   but cannot replace investigation, counterevidence, or suggestion validation.

The isolated compact-classifier experiment may use up to 8 GiB RAM, four CPU threads,
1,024 input tokens, and 60 seconds per request, with no network after artifact
provisioning. These limits do not replace the production limits of 128 MiB
model bytes, 512 MiB worker memory, and the batch deadline. A candidate that
only fits the offline tier is not eligible for deployment. If distillation or
quantization is tested, treat its output as a new model and rerun all gates.
Teacher labels are proposed labels, not ground truth or policy requirements.
These compact-worker limits do not restrict a separately approved self-hosted
or hosted investigation endpoint; its request and cost limits still apply.

Select one self-hosted client/model configuration for local-defense qualification;
add a second client for protocol compatibility. Hosted quality comparison is
optional and uses its own approved disclosure profile. A cheap typed classifier is optional, not another required tier.
Prefer the simpler candidate when the
operator benefit is indistinguishable. Store rejected-candidate measurements
in the evaluator result, not additional planning or gap-review documents.


### Experiment for simple tools and complete protection

Run the same held-out tasks with (a) the former specialized read-method wrappers,
(b) one query over documented raw views, and (c) one query plus the exact context
view and inline runbook. The wrappers are evaluator adapters, not production
APIs. Keep evidence, export permissions, model, and safety validators equal.
Repeat each task at least five times and report per-task errors and variance.

Then test the permitted draft, policy-publication, and response workflows as
separate tasks. A fast investigation that cannot request a valid protection
change does not pass the product workflow. Neither does a tool that bypasses
approval. Response tests require the master plan's qualified owner or must
report Unsupported; synthetic owner records do not prove live containment.
Use the same subject/finding and resulting operation IDs in the client trace,
console, and owner records. Test agent replacement mid-investigation, dropped
mutation replies, a missed human acknowledgement, and a late branch. Success
requires a traceable handoff and actual postconditions, not separately passing
an agent demo and a console demo.

Adopt the simpler read interface only if mandatory evidence retrieval and all
seeded security decisions are preserved, with no additional unsafe approvals.
Measure setup steps and maintenance as well as tool count. If general SQL
repeatedly misses a required check, improve the exact context/recipe first;
add a specialized tool only when the measured failure needs a distinct contract.

## Broader exploration, with boundaries

The initial assistant can translate an owner's statement into draft typed
requirements, explain a policy counterexample, and retrieve reviewed cases.
It must cite records, preserve ambiguity, and use the existing deterministic
validators. It cannot rewrite an approved requirement to make a policy pass.

Sequence models or graph models may help when independent events cannot
explain a review problem. First demonstrate that exact lineage and bounded
sequence features fail on a real labeled case. Reuse the graph owner's output;
do not add a second causal graph or train on timing as if it were causality.

Do not select a vendor from an example name. The requirement is deterministic
core behavior with measured agent assistance. Model and runtime
choice remains an experiment decision, not the product definition.
