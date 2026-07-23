# Erebor Compliance Framework Wedge Overview

Date: 2026-06-25

## Bottom Line

Erebor's compliance wedge is real, but it is not "compliance automation" in the
generic GRC sense.

The strongest claim is:

> Erebor turns real AI-agent runs into reviewer-ready control evidence for
> selected controls, when those runs are routed through Erebor-controlled
> execution paths.

That wedge applies across browser, terminal/process, SaaS, API, MCP/tool,
network, desktop automation, and internal-system governance. Those surfaces are
valid product direction. They only become overpromises when the docs imply
Erebor controls actions outside its execution path, replaces auditors or legal
judgment, or produces certification by itself.

## Product Boundary

Valid claims:

- Erebor governs AI-agent actions across controlled execution paths.
- Erebor enforces policy outside the model when it controls execution.
- Erebor records action provenance, identity, approvals, denials, exceptions,
  policy versions, systems touched, data touched, and retained artifacts.
- Erebor generates framework-mapped evidence annexes for selected controls.
- Erebor helps regulated teams and agent vendors get risky workflows through
  security, privacy, GRC, internal audit, customer assurance, and legal review.

Invalid or risky claims:

- Erebor certifies ISO, SOC, FedRAMP, PCI, HIPAA, HITRUST, TISAX, CMMC, or SOX
  compliance.
- Erebor replaces CPAs, auditors, 3PAOs, QSAs, C3PAOs, assessors, legal
  counsel, DPOs, management, incident commanders, or control owners.
- Erebor determines framework scope, materiality, lawful basis, reportability,
  CUI/PHI/PII classification, control effectiveness, deficiency severity, or
  risk acceptance.
- Erebor controls actions that do not run through Erebor.
- Erebor is a full GRC, SIEM, DLP, CSPM, ITSM, vulnerability-management,
  identity-governance, data-discovery, or records-retention platform.

## Best Wedges To Lead With

1. **AI governance:** NIST AI RMF, ISO/IEC 42001, AIUC-1.
   These map directly to the native thesis: define what an agent may do, govern
   it outside the model, and retain evidence.

2. **Enterprise trust and audit:** SOC 2, SOC 1, SOX, PCI DSS.
   These connect to buyer trust, customer assurance, financial systems, payment
   systems, and audit evidence.

3. **Security assurance:** NIST CSF 2.0, NIST SP 800-53, NIST SP 800-171,
   NIST SP 800-61.
   These are strong mappings for access control, audit, change, incident
   reconstruction, federal assurance, and CUI workflows.

4. **Privacy and healthcare:** GDPR, HIPAA, HICP, HITRUST, ISO/IEC 27701,
   ISO/IEC 27018.
   These matter when agents touch personal data, PHI, customer data, exports,
   deletion, access review, or incident workflows.

5. **Regulated-market access:** DORA, NIS2, CMMC, FedRAMP, TISAX, DCC.
   These are credible in heavily regulated sales motions, but need careful
   scope language and longer buyer education.

6. **Supporting governance stories:** CIS Controls, CIS AWS Foundations, COBIT,
   COSO, ISO/IEC 20000, ISO 22301, ISO 9001, C2M2, ISO/IEC 27017.
   These are useful as supporting mappings, not usually the first wedge.

## Framework Scorecard

Scores are product-direction wedge strength, not implementation completeness.

| Framework | Wedge | Product-direction verdict |
| --- | ---: | --- |
| NIST AI RMF | 4.5/5 | Best native wedge for AI-agent boundaries, task scope, monitoring, and risk management evidence. |
| ISO/IEC 42001 | 4/5 | Strong AI management-system evidence annex for governed agent operation and oversight. |
| AIUC-1 | 4/5 | Strong AI-agent control catalog story for unauthorized actions, unsafe tool use, logging, and runtime evidence. |
| SOC 2 | 4/5 | Strong enterprise-trust wedge for controls affected by governed agent actions. |
| SOC 1 | 4/5 | Strong for financially relevant agent actions in ERP, billing, payroll, reporting, databases, scripts, and finance SaaS. |
| SOX | 4/5 | Strong ICFR evidence wedge for ERP, finance SaaS, reporting pipelines, scripts, privileged admin, and close workflows. |
| PCI DSS | 4/5 | Strong narrow wedge when agents can affect CDE systems, payment pages, scripts, CHD/SAD handling, or payment SaaS admin. |
| NIST CSF 2.0 | 4/5 | Strong security-assurance wedge across Govern, Identify, Protect, Detect, Respond, and Recover. |
| NIST SP 800-53 | 4/5 | Strong high-assurance mapping for federal, FedRAMP, and enterprise security review. |
| NIST SP 800-171 | 4/5 | Strong CUI evidence wedge around access, audit, change, incident, and export workflows. |
| NIST SP 800-61 | 4/5 | Strong incident-response wedge for reconstructing agent actions before, during, and after incidents. |
| GDPR | 4/5 | Strong when agents access, export, modify, delete, or otherwise act on personal data. |
| HICP | 4/5 | Strong healthcare cybersecurity guidance wedge for agent oversight, access management, data protection, and IR. |
| TISAX | 4/5 | Strong automotive-supplier wedge for confidential information, prototype data, supplier portals, exports, and SaaS workflows. |
| NIS2 | 3.5/5 | Strong EU critical/important-entity wedge for governed admin actions, incidents, and risk-management evidence. |
| ISO/IEC 27701 | 3.5/5 | Strong privacy-management evidence annex for governed personal-data workflows. |
| HIPAA | 3/5 | Good healthcare evidence story for audit controls, activity review, incidents, and BA assurances. |
| HITRUST | 3/5 | Useful healthcare and enterprise assurance story, especially with AI/security assurance products. |
| DORA | 3/5 | Strong financial-sector ICT evidence story, especially for incidents, resilience exercises, and critical functions. |
| FedRAMP | 3/5 | Good high-assurance cloud-service evidence annex, not an authorization path by itself. |
| CMMC | 3/5 | Credible defense-industrial-base wedge for FCI/CUI workflows and assessment evidence. |
| DCC | 3/5 | Valid UK defense supplier evidence story for governed agent workflows around defense data and systems. |
| ISO/IEC 27001 | 3/5 | Solid ISMS evidence appendix for controlled agent workflows affecting access, change, logging, and incidents. |
| ISO/IEC 27017 | 3/5 | Valid cloud-security evidence story for governed cloud-provider and cloud-customer actions. |
| ISO/IEC 27018 | 3/5 | Good public-cloud PII processor evidence story for governed access, exports, deletes, and admin actions. |
| CIS AWS Foundations | 3/5 | Strong when agents administer AWS through console, CLI, SDK, or IaC routed through Erebor. |
| CIS Controls v8/v8.1 | 3/5 | Useful security-hygiene mapping for access control, audit logs, configuration, and incident evidence. |
| COBIT | 3/5 | Useful IT-governance evidence story for policy, oversight, change, accountability, and exceptions. |
| COSO | 3/5 | Useful internal-control framing for evidence, traceability, approvals, monitoring, finance, and GenAI risk. |
| ISO/IEC 20000 | 3/5 | Valid service-management evidence story for governed requests, changes, incidents, and SaaS admin. |
| ISO 9001 | 2.5/5 | Secondary quality-management evidence story for support, release, complaint, change, and service workflows. |
| ISO 22301 | 2/5 | Secondary continuity evidence story for recovery exercises and continuity-relevant agent actions. |
| C2M2 | 2/5 | Cyber-maturity appendix for critical infrastructure and security operations; weak as a first wedge. |

## Product Packages To Build

The wedge becomes credible when Erebor generates concrete artifacts from real
governed runs:

- **Agent Mandate Report:** owner, purpose, permitted systems, permitted data,
  allowed actions, stop conditions, approval routes, and policy versions.
- **Runtime Evidence Packet:** identities, timestamps, browser/API/tool/SaaS/
  terminal/desktop actions, parameters, targets, decisions, outputs, hashes, and
  retained artifacts.
- **Policy Decision Ledger:** every allow, deny, escalation, approval,
  exception, fallback, and policy version involved in a run.
- **Exception and Block Report:** what Erebor stopped or escalated, why, who
  approved, and what follow-up happened.
- **Incident Reconstruction Packet:** timeline of agent actions before, during,
  and after an incident or risky workflow.
- **Framework Mapping Annex:** selected evidence mapped to SOC 2, NIST AI RMF,
  ISO/IEC 42001, NIST CSF, PCI DSS, HIPAA, GDPR, SOX, or other buyer-relevant
  controls.
- **Out-of-Path Gap Statement:** explicit list of systems, actions, users,
  agents, or data paths Erebor did not control.

## Minimum Evidence Fields

- run id and session id
- agent identity and human owner
- user mandate, ticket, request, or workflow objective
- system, data, tool, API, browser, command, SaaS, desktop, or internal-system
  target
- action attempted
- policy id and policy version
- decision: allowed, denied, escalated, approved, failed, or out-of-scope
- approver identity and rationale, when applicable
- result and side effect
- timestamps and duration
- retained artifacts and hashes
- risk labels and framework mappings
- out-of-path caveat, if applicable

## Honest Product Copy

Good:

> Govern AI-agent actions across controlled execution paths and turn every run
> into reviewable control evidence.

Good:

> Erebor provides an AI-agent runtime evidence annex for selected SOC 2, ISO/IEC
> 42001, NIST AI RMF, PCI DSS, SOX, HIPAA, GDPR, and NIST controls.

Good:

> Erebor cannot make a company compliant. It can make governed agent workflows
> inspectable, enforceable, and easier to approve.

Risky:

> Erebor automates SOC 2, ISO 27001, HIPAA, GDPR, PCI, FedRAMP, or SOX
> compliance.

Risky:

> Erebor proves all agent activity is compliant.

Safer:

> Erebor controls agent actions routed through Erebor-controlled execution
> paths, including browser, terminal/process, SaaS, API, MCP/tool, network,
> desktop, and internal-system workflows.

## Final Positioning

Erebor's wedge is the missing runtime layer between AI agents and the systems
they act on. Compliance frameworks expose the buyer pain: reviewers need to know
who authorized the agent, what it was allowed to do, what it actually did, what
was blocked, what changed, and what evidence is retained.

That wedge remains valid across SaaS, APIs, MCP tools, terminals, browsers,
desktops, networks, and internal systems as long as the claim stays anchored to
Erebor-controlled execution paths.
