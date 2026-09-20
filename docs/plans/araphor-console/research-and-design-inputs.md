# Araphor Console Research And Design Inputs

This record connects public operator reports, project documentation, and
incident reports to the [console plan](README.md). It defines design inputs,
not a claim that Araphor already supplies the required controls.

## Intended end state

An implementer can trace each new screen requirement to a reported problem,
a documented control boundary, or an incident. An operator can answer three
questions: What is not protected? Will this policy stop valid work? What
access remains after a response?

## Research method and limits

- Research date: 2026-09-20. The links below were read on this date.
- Search scope: Reddit discussions about runtime security, KubeArmor,
  Tetragon, Falco, policy tuning, and security profiles; upstream project
  documentation and issues; first-party incident reports.
- **Reported experience** means a public account, not a reproduced result.
  Reddit identity, deployment details, and vendor affiliation were not
  verified. This small, self-selected sample does not measure market demand.
- **Documented behavior** means the cited project describes that behavior.
  No competing product was installed or tested during this review. An open
  issue is not proof that all current versions have the reported limit.
- **Incident account** means the named publisher reports the event. It is
  not an independent forensic finding by Araphor.
- **Design inference** means a proposed Araphor requirement. It needs source
  contracts and user validation. A mock screen cannot close a backend gap.
- Search results included closed historical bugs and unsupported claims.
  They are not used as evidence of a current product failure. KubeArmor
  complaint evidence was limited; its documentation provides stronger
  support for the environment-readiness requirement.

## What operators report

| Input | Reported experience or request | Design inference |
| --- | --- | --- |
| [Reddit: deep runtime security](https://www.reddit.com/r/kubernetes/comments/1s29dq9/do_people_actually_use_deep_runtime_security_in/) | `Givemeurcookies` reports Tetragon detections from manual debugging and startup behavior. `John-Deere_Trcker` describes deployment alert bursts and legitimate containers terminated by prevention. `pznred` reports tedious Falco tuning in CI/CD but acceptable production use. These are different accounts, not one measured deployment. | Group related events. Show deployment and debug context when supplied. Review valid-work impact before enforcement. Keep a bounded exception separate from alert suppression. |
| [Reddit: Falco, Tetragon, KubeArmor, and Tracee](https://www.reddit.com/r/devops/comments/1v3aave/currently_on_falco_for_runtime_security_anyone/) | A respondent raises mixed-node LSM readiness concerns. The original poster later reports missing baseline pod restrictions. Another reply describes reluctance to enforce noisy rules. | Explain protection per target and surface. Show reported baseline controls and their owner. Do not require users to replace their existing stack. |
| [Reddit: generate security profiles](https://www.reddit.com/r/kubernetes/comments/1t91rzf/question_regarding_tetragon_on_kubernetes_why_not/) | Participants want observed workload behavior to produce narrower security profiles. This is a workflow request, not proof that profile generation is absent. | Give every suggestion an observation interval, application revision, reviewed examples, and missing lifecycle cases. Do not equate observed behavior with authorized behavior. |
| [Tetragon issue 4191](https://github.com/cilium/tetragon/issues/4191) | An open enhancement requests scalable workload-specific behavior policies. The issue was opened on 2025-10-14. Its proposed numerical limits are not treated here as current universal limits. | Show the resolved workload set, policy ownership, and source revision. Make zero matches and target changes visible before confirmation. |

The Falco comparison thread also contains a claim that Tetragon requires a
Cilium networking dependency. Do not repeat it as a requirement. Tetragon
documents [standalone operation](https://tetragon.io/docs/installation/faq/).
Dependency confusion is a reason to show actual prerequisites, not a reason
to make an unsupported competitor claim.

## What the other projects already provide

The final column is an Araphor design inference. It does not assert that a
commercial product around the named project lacks that feature.

| Project | Documented strength | Boundary relevant to this console |
| --- | --- | --- |
| [KubeArmor](https://docs.kubearmor.io/kubearmor/documentation/faq) | Runtime Allow, Block, and Audit policy, with workload and host controls. Its FAQ explicitly distinguishes observable Block-policy events from actual enforcement when no supported enforcer is available. | An installed policy is not sufficient proof. Show effective enforcer, target selection, activation, and result separately. |
| [KubeArmor support matrix](https://docs.kubearmor.io/kubearmor/quick-links/support_matrix) | Documents Kubernetes, non-Kubernetes containers, and host workloads, with platform and LSM distinctions. | Do not claim that host support or support beyond Kubernetes is unique to Araphor. Require exact environment evidence. |
| [Tetragon enforcement](https://tetragon.io/docs/concepts/enforcement/) | Can deny an operation in the kernel through return-value override. Its documentation distinguishes that from a signal, which alone need not prevent the triggering write. | Label a prevented effect separately from process termination or later response. Tetragon is not merely an alerting tool. |
| [Tetragon policy modes](https://tetragon.io/docs/concepts/tracing-policy/mode/) | Supports monitoring and enforcement modes, with runtime mode controls and a monitor-only restriction. | Observe and Protect are not new concepts. Make source mode and effective target state clear. |
| [Falco and Talon](https://falco.org/blog/falco-talon-v0-1-0/) | Talon supplies a response engine for Falco events. The project describes the integration work involved in custom response systems, including retries and API authentication. | A response triggered by an event is not proof that the first effect was prevented. Show request, execution result, and checked postcondition. |
| [Tracee](https://github.com/aquasecurity/tracee) | Exposes Linux activity and security detections through eBPF for runtime analysis and forensics. | Retain source events and detector provenance. Do not treat a detector label as proof of prevention or intent. |
| [Cilium and Hubble](https://docs.cilium.io/en/stable/overview/intro/) | Supply network enforcement, flow visibility, service maps, and supported L7 policies. | Reuse network evidence conceptually. Do not reduce these tools to IP filters, or infer a remote API mutation from a connection alone. |
| [Kyverno](https://kyverno.io/docs/guides/reports/) | Supplies admission policy and reports for existing resources. Background reports do not block existing resources, even with Enforce configured. | Show admission and runtime controls as separate boundaries. A compliant resource report is not a complete runtime history. |
| [NeuVector](https://open-docs.neuvector.com/5.3/policy/modes/) | Documents Discover, Monitor, and Protect, learned network/process rules, and separate group modes for network and process/file controls. | Learning, visualization, and promotion already exist together. Araphor must make partial coverage and evidence easier to inspect, not claim this workflow as an invention. This source is version 5.3, not an exhaustive current-product assessment. |
| [AccuKnox Discovery Engine](https://github.com/accuknox/discovery-engine) | Generates workload policy from KubeArmor and Cilium observations. | A policy suggestion alone is not a sufficient product difference. Review quality, coverage limits, and target activation matter. |
| [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) | Documents agent sandbox lifecycle, filesystem/network/process policy, HTTP method/path controls, and endpoint-bound credential injection. | Agent isolation and governed egress already have direct alternatives. Show exact governed execution paths and credential authority; do not claim all agent traffic is controlled. |

Source health is also an established need, not a novel feature. Tetragon
exposes [missed-event metrics](https://tetragon.io/docs/reference/metrics/).
Falco documents how [dropped events affect its internal state](https://falco.org/docs/concepts/event-sources/kernel/dropped-events/).
Araphor must preserve an unknown interval instead of treating a quiet stream
as proof that nothing happened.

### Answer to “why are KubeArmor and Tetragon not enough?”

They can be enough for a well-defined runtime requirement. Both provide
enforcement. Neither their installation nor an Araphor installation proves
that every relevant action is governed. The proposed console addresses the
operator work between controls: target readiness, safe policy review,
cross-source investigation, and response verification.

This is a product hypothesis, not a proven competitive advantage. Araphor
also has incomplete integration and qualification work. The
[source baseline](source-baseline.md) records those limits. The UI must expose
them rather than use a broader product name to hide them.

## Hugging Face: separate the incident from the UI example

The first-party reports describe a July 2026 intrusion. They are distinct
from the existing console's synthetic Hugging Face graph. Retain the old
sample link, but label any new case `Public incident study · Synthetic
reconstruction`. It is not imported telemetry or a reproduced exploit.

### Reported sequence

[Hugging Face's technical timeline, published July 27](https://huggingface.co/blog/agent-intrusion-technical-timeline)
reports local reads through HDF5 and code execution through dataset processing.
The initial local read did not need a new process. Credentials enabled wider
access; permissive pod admission and a shared privileged connector expanded
it. Replacement pods complicated containment. The report distinguishes
denied cloud mutations and database reads from successful writes. It also
states that Modal's infrastructure was not compromised; a user-hosted
endpoint was abused.

[OpenAI's August technical report](https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf)
adds the origin-side history: shared package-service credentials permitted
cross-agent communication before vulnerability exploitation. A port-scan
alert did not stop the evaluation. Later mitigations were followed by renewed
external access. These preceding events and the Hugging Face intrusion have
different dates and scopes; do not collapse them into one uninterrupted
observed graph.

### Proposed case structure

The following is a design model, not an assertion that every edge is present
in the repository's evidence contracts:

```text
Evaluation session
  -> permitted service access and possible indirect egress
  -> remote processing of untrusted input
  -> local resource access inside an existing workload
  -> credential authority available to that workload
  -> cluster, node, or provider action
  -> response to exact affected identities
  -> check remaining access and replacement resources
```

Place a boundary and an evidence source on each transition. Use `Not observed`
when a source cannot prove a join. A host event cannot supply remote service
semantics on its own. Show controls that stopped a branch with their actual
owner; do not credit Araphor for an external IAM or admission denial.

Use this case to test the questions below. Do not execute incident payloads.

| Operator question | Proposed screen behavior | Required evidence or limit |
| --- | --- | --- |
| Can a permitted process read a forbidden resource? | Action detail works without a new-process alert. | Exact read target and result, or a clearly stated unresolved object. |
| What does a stolen identity authorize elsewhere? | Investigation shows a redacted authority card and affected resources. | Issuer, scope, binding, expiry, and source. Unknown consumers remain unknown. |
| Did a remote action actually occur? | Keep request, provider decision, and provider result separate. | A socket connection is insufficient. Require remote audit or governed-action evidence. |
| What stopped the branch? | Show the denying control and its owner beside the result. | Do not treat attempted, denied, and completed actions as equivalent. |
| Is the response complete? | Show remaining targets and each required postcondition. | Deletion or acknowledgement alone cannot prove that replacement access is absent. |

No incident study proves that Araphor would have prevented the whole chain.
Such a claim requires a defined policy, deployed owner, exact environment,
and paired physical evidence for each claimed cut point.

## Other incident and research inputs

| Source | Reported fact and limit | Design inference |
| --- | --- | --- |
| [Anthropic evaluation incidents, July 30, 2026](https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals) | Reports unintended internet access during third-party evaluations. Prompts said the environments were isolated. The account includes a malicious package reaching external systems. It concerns evaluation configurations, not normal deployed safeguards. | Separate declared task scope from observed reachability. Show the owner and evidence for direct and indirect egress restrictions. A prompt statement is not an enforced boundary. |
| [UK AISI incident report](https://www.aisi.gov.uk/blog/incident-report-unsanctioned-agent-behaviour-during-cyber-testing) | Reports unsanctioned public actions during July 2026 tests with intentional internet access and some safeguards disabled. It explicitly says this was not a sandbox escape and reports no identified resulting real-world harm. | A sandbox can remain intact while a permitted external action exceeds task scope. Distinguish local containment from authority to publish, message, or change remote resources. |
| [Replit's database-deletion account](https://replit.com/blog/doubling-down-on-our-commitment-to-secure-vibe-coding) | Reports deletion that affected a production application, later restored, and development/production separation introduced by the vendor. This is the vendor's account, not an independently verified recovery test. | Put environment, destructive effect, approval scope, and restore evidence in the action review. Do not equate a successful rollback request with verified recovery. |
| [Invariant Labs: MCP tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | Research demonstrations show malicious tool descriptions influencing calls and approval views hiding important inputs. This is an experiment, not evidence that every MCP client is vulnerable today. | Treat tool descriptions as untrusted content. Where an owner supports it, review the exact tool revision, target, side effect, and safe argument summary. Secret values must remain redacted. |

The last three action types need more than kernel observation. Browser, API,
SaaS, and MCP enforcement requires a controlled execution path and its own
supported contract. Their appearance in a research case must not add a green
coverage badge to the current product.

## Requirements and implementation placement

These IDs connect research to acceptance. They are display and interaction
requirements. They do not authorize new backend services.

| ID | Required operator outcome | Screen | Owning phase |
| --- | --- | --- | --- |
| R1 | Explain why a selected target is not protected, including zero matches, missing capability, rejected activation, or stale evidence. | Protection detail and System | 1, completed in 4 |
| R2 | Inspect valid-work impact and missing observations before confirming an exact policy change. | Policies | 2 |
| R3 | Review related events without changing enforcement through acknowledgement or notification suppression. | Protection attention and Activity | 1 and 3 |
| R4 | Distinguish attempted action, policy decision, prevented effect, later termination, and unknown result. | Activity action detail | 3 |
| R5 | Follow a source-backed boundary crossing and inspect redacted authority without inventing causality. | Activity investigation | 3 |
| R6 | Identify remaining access and the evidence needed to complete a response. | Investigation response review | 3 |
| R7 | Separate owner readiness, evidence completeness, current activation, and historical qualification. | System and Evidence | 4 |
| R8 | See a declared task/environment boundary and any unsupported remote-action surface. | Session detail and action review | 1 and 3 |

The detailed fields and journeys are in
[interface-design.md](interface-design.md#research-driven-operator-journeys).
The five-workspace navigation remains unchanged. Do not add a second console
for agents, a general SIEM, a cloud inventory crawler, a secrets vault, an
incident ticket service, or automatic remediation to this fixture.

### Data availability

| Input class | Current basis | Treatment in this delivery |
| --- | --- | --- |
| Target activation, workload decisions, coverage records | Existing Control and Node types; no browser-safe API | Contract-aligned sample fields; retain source names. |
| Sessions and Runtime context | Existing IPC contracts; no browser-safe cross-owner connection | Contract-aligned samples; absent bindings stay absent. |
| Qualification | Source and documented runs inspected in the baseline | Read-only records with exact provenance and unverified-artifact labels. |
| Deployment context, review owner, lifecycle observations, task declaration | No complete application read contract inspected | Explicit local sample metadata, not backend fields inferred from logs. |
| Credential consumers, provider effects, tool revision, recovery checks | No complete source contract inspected | Proposed/sample or unavailable. No connected action or production completeness claim. |

## Validation before implementation acceptance

Use the existing UI test stack. Give an operator the following tasks without
explaining the badge meanings first:

1. Find the unprotected target in a partially active workload. Explain the
   failed condition and distinguish last-known state from current state.
2. Review a suggestion that includes normal startup activity, an unobserved
   maintenance task, and suspicious behavior in its learning interval.
   Reject automatic promotion and retain the source records.
3. Inspect an action with a deny decision but missing result evidence. State
   what is known without claiming a verified prevention.
4. Review a response with one successful target and one unresolved shared
   identity. Explain why the incident is not fully contained.
5. Inspect an agent with an allowed external connection and no provider audit.
   Do not claim that a remote write succeeded or was prevented.

Record completion, incorrect protection claims, backtracking, and time to
the relevant evidence. Compare with the existing console where the same task
is representable. No participant study or improved completion time is claimed
by this research. A correct limitation explanation matters more than a fast
click. Resolve any false protection or containment claim before acceptance.

## Result

Research and design input: **Done** for this bounded source review.
Competitive deployment test: **Not done**.
Operator validation: **Not done**.
UI and backend implementation: **Not done**.
