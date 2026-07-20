# Sample Runtime Evidence Packet

This sample packet shows how an agent vendor could attach Erebor output to a
customer security review, AI governance review, or RFP appendix.

Source run: [Governed OpenClaw Evidence Trace](evidence-trace.fixture.md)

Demo title:

> From Agent Action To Reviewable Evidence

## Scope And Non-Claims

This packet is a technical evidence sample for one governed OpenClaw run. It
shows action/resource provenance, policy decisions, an enforced authority
transition block, and retained artifacts from the governed execution path.

It does not claim FedRAMP, CMMC, GDPR, HIPAA, or NIST compliance. It does not
claim whole-host containment, semantic PII classification, or legal approval.
It is evidence a reviewer can inspect for selected controls.

## 1. Agent Mandate Report

Reviewer question:

> What was the agent authorized to do?

Sample answer:

- Agent: OpenClaw support agent.
- Purpose: investigate a local OAuth callback reproduction.
- Allowed resources: the governed browser target, the OAuth lab repro page, and
  the governed session process tree.
- Sensitive transition: OAuth callback handoff from GitHub back to the local
  callback URL.
- Runtime boundary: Erebor-controlled execution path for browser CDP and
  session process actions.
- Stop condition: block the OAuth callback handoff unless explicitly allowed by
  policy or operator approval.

Evidence attachment:

- [evidence-trace.fixture.md](evidence-trace.fixture.md), "Session Purpose And
  Actor"
- [session-config.json](session-config.json)
- [prompt.txt](prompt.txt)

## 2. Runtime Evidence Packet

Reviewer question:

> What did the agent actually do?

Sample answer:

The run produced a shared session audit covering browser CDP and
terminal/process actions under one session id. The evidence trace records the
governed resources exposed, the allowed action timeline, denied authority
transitions, policy rules, residual risks, and artifact hashes.

Evidence attachment:

- [evidence-trace.fixture.md](evidence-trace.fixture.md)
- [fixtures/evidence-trace-audit.jsonl](fixtures/evidence-trace-audit.jsonl)

## 3. Policy Decision Ledger

Reviewer question:

> Which policy decisions were made, and why?

Sample answer:

The run includes allowed browser/process actions and one denied network request
for the OAuth callback handoff. The policy rule records that the OAuth callback
must not reach the local callback without operator approval.

Evidence attachment:

- [policy.json](policy.json)
- [evidence-trace.fixture.md](evidence-trace.fixture.md), "Policy Package And
  Rule Evidence"

## 4. Exception And Block Report

Reviewer question:

> What did Erebor stop, hold, or mediate?

Sample answer:

Erebor mediated Chrome launch into a governed CDP endpoint and denied the OAuth
callback network request before the local callback completed. The trace reports
summary counts for allowed, denied, held, and mediated actions.

Evidence attachment:

- [evidence-trace.fixture.md](evidence-trace.fixture.md), "Denied, Held, Or
  Mediated Authority Transitions"

## 5. Optional NIST AI RMF Mapping Annex

Use this annex as control-evidence support only. Do not call it NIST
certification or NIST compliance.

Selected mapping:

- Govern: session purpose, actor, policy package, and stop condition are
  documented.
- Map: governed resources, surfaces, authority transition, and residual risks
  are identified.
- Measure: allowed and denied actions are recorded with policy decisions and
  artifact hashes.
- Manage: the OAuth callback handoff is denied and residual risks are retained
  for reviewer follow-up.

Evidence attachment:

- [evidence-trace.fixture.md](evidence-trace.fixture.md), "Controls And
  Non-Claims"
- [evidence-trace.fixture.md](evidence-trace.fixture.md), "Residual Risk"
- [evidence-trace.fixture.md](evidence-trace.fixture.md), "Artifact Integrity"

## Reviewer Packet Checklist

Attach these files together for the sample review:

- [evidence-trace.fixture.md](evidence-trace.fixture.md)
- [fixtures/evidence-trace-audit.jsonl](fixtures/evidence-trace-audit.jsonl)
- [policy.json](policy.json)
- [session-config.json](session-config.json)
- [prompt.txt](prompt.txt)

The buyer-facing question for this packet is narrow:

> Would this runtime evidence help you answer a customer security review, AI
> governance review, or RFP question about how the agent is controlled?
