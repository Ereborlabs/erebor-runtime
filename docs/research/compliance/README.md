# Erebor Compliance Framework Wedge Research

Created: 2026-06-25

This folder turns the Complyance framework list into an Erebor product-research
map. The question is not "can Erebor make a company compliant?" It cannot. The
question is sharper:

Can Erebor make AI-agent workflows easier to approve, audit, and operate by
creating framework-relevant evidence from real governed runs?

Complyance's framework page is useful because it shows the GRC pattern:
centralize frameworks, cross-map controls, collect evidence, and reduce manual
work. Erebor's wedge is different: capture and enforce what an AI agent actually
did while operating through controlled execution paths: browsers, terminals,
processes, SaaS apps, APIs, MCP/tool calls, network actions, desktop automation,
internal systems, and customer-data access.

Source:
https://www.complyance.com/frameworks

Overall view:
[Erebor Compliance Framework Wedge Overview](wedge-overview.md)

Current ICP validation track:
[Runtime Evidence For Agent Vendors](../icp-validation-agent-vendors.md)

## Best Wedges

The strongest wedges are where an AI agent can take real actions and the
approver needs evidence, not just policy language.

1. **AI governance:** AIUC-1, ISO/IEC 42001, NIST AI RMF.
   These are closest to Erebor's native thesis: define what the agent is allowed
   to do, enforce it outside the model, and produce evidence.

2. **Security assurance:** SOC 2, ISO/IEC 27001, NIST CSF 2.0, CIS Controls v8.
   These are broad buyer-recognized trust frameworks. Erebor can become the
   "agent runtime evidence" appendix for access, audit, change, incident, and
   monitoring controls.

3. **Privacy and regulated data:** GDPR, HIPAA, ISO/IEC 27701, ISO/IEC 27018,
   HITRUST, HICP.
   These are not always buyer budgets, but they create approval pressure when
   agents touch personal data, PHI, or customer data.

4. **Federal, defense, cloud, and critical infrastructure:** FedRAMP, CMMC,
   NIST SP 800-171, NIST SP 800-53, DCC, NIS2, DORA.
   These are high-friction environments where independent runtime evidence and
   controls can matter, but sales cycles are heavier.

5. **Operational governance:** NIST SP 800-61, ISO 22301, ISO/IEC 20000,
   ISO 9001, COSO, COBIT, C2M2.
   These are useful as secondary mapping stories, not the first wedge.

## Product Direction

The concrete product idea is a framework-mapped agent evidence packet:

- what the agent was authorized to do
- what data, systems, tools, browser sessions, SaaS apps, and commands it used
- what policy applied
- what was allowed, denied, escalated, or approved
- who owned/supervised the run
- what changed
- what evidence is retained for audit, incident response, or review

That can become a repeatable "governed agent workflow" package for enterprise
agent vendors and regulated teams.

## Recommended Wedge To Test

Do not start by selling "compliance automation" as a broad category. That puts
Erebor against mature GRC platforms and makes the story too generic.

Start with this narrower claim:

> Erebor turns real AI-agent runs into reviewer-ready control evidence.

The buyer to test first is still not a generic DPO. The better initial targets
are:

- agent vendors trying to sell computer-using or tool-using agents into
  enterprises
- regulated enterprise teams trying to deploy agents that can run commands,
  use tools, call APIs, browse, or touch SaaS/customer-data access

The approver may be DPO, legal, GRC, security, product security, internal audit,
or risk. The buyer is more likely the team whose agent rollout or enterprise
deal is slowed by those reviewers.

## Demoable Report Packages

The compliance wedge becomes credible if Erebor can generate concrete packets
from a real run:

- **Agent Mandate Report:** what the agent was allowed to do, who owned it, what
  systems/data/actions were in scope, and who could stop it.
- **Runtime Evidence Packet:** full action trail across commands, tools,
  browser, SaaS, API, MCP/tool, desktop, internal-system, approvals, denials,
  and policy decisions.
- **Framework Mapping Annex:** maps a governed run to selected controls in SOC
  2, ISO 27001, NIST AI RMF, ISO 42001, GDPR, HIPAA, DORA, or FedRAMP.
- **Exception And Block Report:** what Erebor stopped, escalated, or allowed
  with approval, including rationale and follow-up.
- **Incident Reconstruction Packet:** what the agent did before, during, and
  after an incident or risky workflow.

That is a better wedge than claiming Erebor "does compliance." It gives buyers
something they can hand to reviewers.

## Framework Notes

- [AIUC-1](frameworks/aiuc-1.md)
- [ISO/IEC 42001](frameworks/iso-42001.md)
- [NIST AI RMF](frameworks/nist-ai-rmf.md)
- [SOC 2](frameworks/soc-2.md)
- [ISO/IEC 27001](frameworks/iso-27001.md)
- [NIST CSF 2.0](frameworks/nist-csf-2.md)
- [CIS Controls v8](frameworks/cis-v8.md)
- [PCI DSS](frameworks/pci-dss.md)
- [HIPAA](frameworks/hipaa.md)
- [HITRUST](frameworks/hitrust.md)
- [HICP](frameworks/hicp.md)
- [GDPR](frameworks/gdpr.md)
- [ISO/IEC 27701](frameworks/iso-27701.md)
- [ISO/IEC 27018](frameworks/iso-27018.md)
- [FedRAMP](frameworks/fedramp.md)
- [CMMC](frameworks/cmmc.md)
- [NIST SP 800-171](frameworks/nist-sp-800-171.md)
- [NIST SP 800-53](frameworks/nist-sp-800-53.md)
- [DCC](frameworks/dcc.md)
- [CIS AWS Foundations](frameworks/cis-aws-foundations.md)
- [NIS2](frameworks/nis2.md)
- [DORA](frameworks/dora.md)
- [SOX](frameworks/sox.md)
- [TISAX](frameworks/tisax.md)
- [SOC 1](frameworks/soc-1.md)
- [NIST SP 800-61](frameworks/nist-sp-800-61.md)
- [ISO 22301](frameworks/iso-22301.md)
- [ISO/IEC 20000](frameworks/iso-20000.md)
- [ISO 9001](frameworks/iso-9001.md)
- [COSO](frameworks/coso.md)
- [COBIT](frameworks/cobit.md)
- [C2M2](frameworks/c2m2.md)
- [ISO/IEC 27017](frameworks/iso-27017.md)
