# Use Erebor Evidence In Security Review

This guide provides short copy an agent vendor can adapt for a customer
security questionnaire, AI governance review, or NIST AI RMF-aligned RFP
appendix.

Use it with the [Sample Runtime Evidence Packet](runtime-evidence-packet.md)
and [Governed OpenClaw Evidence Trace](evidence-trace.fixture.md).

## Claim Boundary

Do not write:

- "Erebor makes us FedRAMP compliant."
- "Erebor makes us CMMC compliant."
- "Erebor makes us GDPR compliant."
- "Erebor makes us HIPAA compliant."
- "Erebor makes us NIST compliant."

Use this narrower claim:

> Erebor produces runtime evidence for selected AI-agent controls by enforcing
> policy at the execution boundary and retaining a reviewable trace of allowed,
> denied, mediated, and residual-risk actions.

## Enterprise Security Questionnaire Copy

Question:

> How do you govern autonomous or semi-autonomous agent actions?

Answer:

> We run selected AI-agent workflows through Erebor Runtime, which enforces
> policy at the browser/process execution boundary and records a session-level
> evidence trace. For governed sessions, the trace shows the agent purpose,
> actor, resources exposed, actions attempted, policy decisions, denied
> authority transitions, residual risks, and retained evidence artifacts.

Question:

> What evidence can you provide to show agent control?

Answer:

> We can provide a runtime evidence packet for governed sessions. The packet
> includes an Agent Mandate Report, Runtime Evidence Packet, Policy Decision
> Ledger, Exception/Block Report, and optional NIST AI RMF mapping annex for
> selected controls. The packet is generated from real audit records, not only
> from policy documentation.

Question:

> What is outside the scope of this evidence?

Answer:

> Erebor evidence is scoped to the governed execution path and selected
> controls. It does not by itself certify FedRAMP, CMMC, GDPR, HIPAA, or NIST
> compliance, and it does not replace legal review, customer approval, semantic
> data classification, or broader host/network controls.

## AI Governance Review Copy

Review summary:

> The governed session documents the agent's intended purpose, allowed
> resources, observed actions, policy decisions, denied authority transitions,
> and residual risks. Erebor is used as an execution-boundary control so the
> evidence comes from the runtime path where the agent acts.

Reviewer ask:

> Please review whether this packet is sufficient for the named agent workflow,
> or whether approval still requires semantic data classification, stronger
> sandboxing, human-in-the-loop approval, additional retention controls, or a
> narrower mandate.

Residual-risk statement:

> The sample OpenClaw trace proves governed action/resource provenance for the
> enrolled browser/process path. It does not claim whole-host containment or
> semantic PII classification.

## NIST AI RMF-Aligned RFP Appendix Copy

Use this wording only when the RFP asks for AI risk-management evidence or
NIST AI RMF alignment. Do not present it as certification.

Appendix summary:

> For selected AI-agent workflows, we use Erebor Runtime to generate runtime
> evidence aligned to AI risk-management review needs. Erebor records the
> session purpose, actor, governed resources, policy decisions, allowed actions,
> denied authority transitions, retained artifacts, and residual risks. This
> evidence can support reviewer assessment across Govern, Map, Measure, and
> Manage activities for the specific governed workflow.

Selected mapping language:

> Govern: the packet documents the agent mandate, policy package, actor, and
> stop conditions.
>
> Map: the packet identifies the governed resources, surfaces, data-bearing or
> authority-bearing transitions, and residual risks.
>
> Measure: the packet records observed actions, allow/deny decisions, policy
> rules, and artifact hashes from real runtime audit records.
>
> Manage: the packet shows how Erebor blocked or mediated a risky authority
> transition and what follow-up risks remain.

Reviewer caveat:

> This appendix is runtime evidence for selected controls and selected
> execution paths. It is not a standalone compliance certification.

## Follow-Up Request To Reviewer

Use this after sending the packet:

```text
Would this runtime evidence help you approve, reject, or scope the named agent
workflow? If not, which missing evidence field, control, or reviewer would
still block approval?
```
