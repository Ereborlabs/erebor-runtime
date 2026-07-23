# AI Adoption Slowdown: How Much Is Erebor-Shaped?

Created: 2026-06-22

This note summarizes current surveys, analyst reports, and research on why AI adoption is slow inside companies, enterprises, and SMEs, with a specific question in mind:

How much of the slowdown is caused by the lack of something like Erebor: an independent runtime/control layer that can observe, mediate, block, and evidence what an AI agent did when it operated a computer, ran commands, used tools, browsed, or touched SaaS/customer-data access?

## Short Answer

There is strong evidence that AI adoption is no longer mainly blocked by model availability. The bigger bottleneck is moving from pilots and individual use into governed, production workflows.

But the evidence does not support saying "lack of Erebor causes X% of all AI adoption slowdown." The better answer is segmented:

- For general AI/copilot/chatbot adoption, Erebor-shaped gaps are one blocker among several. Data quality, workflow integration, ROI, skills, infrastructure, and organizational change are also major blockers.
- For agentic AI with real action authority, the Erebor-shaped gap appears to be one of the central blockers: governance, runtime control, auditability, identity, safety, security, and evidence.
- For regulated workflows, it is even sharper. Legal/privacy/security reviewers need to know what the agent is allowed to do, what data it may touch, who supervises it, and what evidence proves it stayed inside the approved boundary.
- For SMEs, the evidence is thinner. Their slowdown is often cost, skills, integration, and complexity first. But if an SME is deploying agents near customer data, payments, healthcare, finance, security, or regulated systems, the same governance gap appears.

My best honest estimate:

- General enterprise AI adoption: roughly 15-30% of adoption friction is Erebor-shaped.
- Agentic AI / computer-using agents / autonomous workflows: roughly 40-70% of the production-readiness friction is Erebor-shaped.
- Regulated or customer-data workflows: often the gating blocker, not the only blocker.
- SMEs: lower as a broad category, but high for regulated SMEs or vendors selling agent products into enterprise.

This should be treated as a discovery hypothesis, not a proven market number.

## What "Erebor-Shaped" Means

This research counts a blocker as Erebor-shaped if it relates to:

- lack of visibility into agent actions
- weak audit trails or inability to prove what happened
- lack of runtime mediation, approval, blocking, or rollback
- unclear agent identity, ownership, permissions, or lifecycle
- inability to show legal/privacy/security what the agent touched
- reliance on prompts or policy documents instead of enforceable controls
- shadow AI/agent sprawl where IT cannot see or govern use
- lack of evidence needed to approve a pilot or production workflow

This does not include all AI adoption blockers. It does not include model quality, generic ROI uncertainty, poor data quality, lack of AI skills, unclear strategy, or workflow redesign unless the blocker specifically relates to control, evidence, security, privacy, or governance of agent action.

## Key Evidence

### 1. AI use is high, but scaling remains limited

McKinsey's 2025 State of AI survey says 88% of respondents report regular AI use in at least one business function, up from 78% the prior year. But nearly two-thirds have not begun scaling AI across the enterprise, and only about one-third say they have begun scaling AI programs. For agents specifically, 23% report scaling an agentic AI system somewhere in the enterprise, while another 39% are experimenting. In any individual function, no more than 10% report scaling agents.

Why this matters for Erebor:

The gap is not "nobody is trying AI." The gap is moving from access/experimentation to scaled operational deployment. That is where action governance, runtime evidence, approvals, and workflow integration start to matter.

Source:
https://www.mckinsey.com/capabilities/quantumblack/our-insights/the-state-of-ai

### 2. Smaller companies are behind larger enterprises in scaling

McKinsey also reports that larger companies are more likely to be scaling AI. Nearly half of respondents from companies with more than $5B in revenue have reached the scaling phase, compared with 29% of those with less than $100M in revenue.

Why this matters for SMEs:

For smaller companies, the broad adoption slowdown is probably not only governance. It is also resources, integration, skills, data, and infrastructure. Erebor's SME story needs to be narrow: make governed agent deployment easier without requiring a large security/platform team.

Source:
https://www.mckinsey.com/capabilities/quantumblack/our-insights/the-state-of-ai

### 3. Privacy/data governance is expanding because of AI, but mature AI governance is rare

Cisco's 2026 Data and Privacy Benchmark Study surveyed more than 5,200 IT, technology, and security professionals with privacy responsibilities. Cisco says AI ambition is outpacing readiness. Key findings include:

- 90% report privacy programs expanded due to AI.
- 93% plan to allocate more resources to privacy and data governance over the next two years.
- 23% still lack a dedicated AI governance committee.
- Only 12% describe existing AI governance committees as mature and proactive.

Why this matters for Erebor:

This is direct support for the "approver gap." AI is forcing privacy/governance programs to expand, but the maturity needed for production AI is missing. Erebor should not be framed as "compliance paperwork"; the stronger story is that control and evidence can unlock safe approval.

Source:
https://www.cisco.com/c/en/us/about/trust-center/data-privacy-benchmark-study.html

### 4. CIOs/CTOs say governance is not keeping up with AI agents

An IBM-reported global survey of 2,000 CIOs and CTOs, summarized by ITPro, found:

- Two-thirds are accountable for AI systems they do not fully control.
- Only 11% feel completely prepared for large-scale AI agent deployment.
- 77% say AI adoption is outpacing current governance capabilities.
- Nearly six in ten cite security and compliance as top barriers to scaling AI agents.
- Organizations relying on manual governance have higher incident risk as adoption scales; organizations embedding controls directly into AI systems report 25% fewer incidents.
- Organizations that build control into AI systems reportedly deploy 16 times as many AI agents as those relying on manual governance.

Why this matters for Erebor:

This is one of the strongest data points for the product thesis. It says the bottleneck is not only policy; it is embedded control and visibility in the systems where agents operate.

Source:
https://www.itpro.com/technology/artificial-intelligence/cios-and-ctos-are-making-high-stakes-decisions-with-incomplete-information-ibm-survey-reveals

### 5. Agent governance is lagging agent deployment

Deloitte's State of AI in the Enterprise findings, reported by multiple outlets, say:

- 23% of businesses currently use AI agents at least moderately.
- 74% expect to use AI agents at least moderately within two years.
- Only about 21% say they have robust safety and oversight mechanisms for agents.
- 73% report concern about AI security and data privacy risks.

Why this matters for Erebor:

This is close to the Erebor wedge: agent adoption is expected to accelerate faster than oversight. If agents run tools, commands, browsers, or SaaS workflows, policy-only governance will not be enough.

Sources:
https://www.techradar.com/pro/a-live-operational-risk-why-ai-agents-are-outrunning-your-security
https://timesofindia.indiatimes.com/technology/tech-news/deloitte-ai-institute-chief-on-ai-oversight-governing-ai-agents-is-tougher-because/articleshow/127574981.cms

### 6. Governance failures are already causing rollbacks

Gartner reporting, summarized by TechRadar and ITPro, warns that as many as 40% of enterprises may roll back or decommission autonomous AI agents by 2027 because governance gaps are discovered after incidents. Gartner's point is that organizations often treat agent governance as binary: fully locked down or fully trusted. That either slows delivery and drives shadow development, or gives agents too much access.

Why this matters for Erebor:

This is the exact "approval/operation" problem. The right control is not blanket allow or blanket block. It is proportional mediation based on autonomy, access, and risk.

Sources:
https://www.techradar.com/pro/lack-of-ai-governance-could-force-40-percent-of-enterprises-to-roll-back-autonomous-ai-agents-by-2027
https://www.itpro.com/technology/artificial-intelligence/one-size-fits-all-agent-governance-sets-enterprises-up-to-fail

### 7. Production agents are already being shut down for governance reasons

Sinch survey reporting says 62% of companies have AI customer communications agents live in production, but 74% have rolled back or shut down at least one AI communication agent on governance grounds. Another ITPro summary says reported issues included data exposure, hallucinations, and lack of auditability; companies are prioritizing trust, security, and compliance investment over AI model development.

Why this matters for Erebor:

This is a post-pilot signal. The issue is not "will people try agents?" They already do. The issue is whether organizations can operate them safely enough to keep them in production.

Sources:
https://www.techradar.com/pro/the-most-advanced-organizations-arent-failing-less-theyre-seeing-failures-sooner-many-firms-are-already-having-to-roll-back-ai-customer-service-tools
https://www.itpro.com/technology/artificial-intelligence/ai-agents-arent-cutting-it-in-customer-service

### 8. Many organizations use AI without embedded governance

Trustmarque reporting says 93% of organizations use AI in some capacity, but only 7% have fully embedded governance frameworks, 8% have integrated AI governance into the software development lifecycle, and only 4% say their data and infrastructure environments are fully prepared to support AI at scale. It also reports weak ownership and limited monitoring.

Why this matters for Erebor:

This supports the story that organizations have AI usage but not operational AI governance. However, it is broader than Erebor: it includes model governance, data governance, SDLC, bias, interpretability, infrastructure, and management ownership.

Source:
https://www.itpro.com/technology/artificial-intelligence/organizations-face-ticking-timebomb-over-ai-governance

### 9. Industrial agentic AI research finds a verification gap

A 2026 arXiv interview study of 16 practitioners across 12 companies found most companies were at low maturity levels for agentic AI in software workflows. Its primary finding was a capability-deployment verification gap: several companies had higher-level experimental agentic capabilities but could not integrate them into production because adequate output verification mechanisms were absent, leaving human-in-the-loop as the only trusted verification mechanism. Reported barriers included non-determinism, data confidentiality concerns, context limitations, and underperformance in proprietary environments.

Why this matters for Erebor:

This is highly relevant. It says industrial teams may have the capability, but cannot trust deployment without verification. Erebor should not claim to solve all verification, but the runtime trace/control layer is one missing component.

Source:
https://arxiv.org/abs/2605.14675

### 10. Agent vendors disclose little safety/evaluation information

The 2025 AI Agent Index studied 30 state-of-the-art AI agents and found that the ecosystem is complex, fast-moving, and inconsistently documented. The authors observed that most developers share little information about safety, evaluations, and societal impacts.

Why this matters for Erebor:

If vendors do not provide credible safety/evaluation evidence, enterprise buyers and approvers will need independent operational evidence. This supports the "not just another wrapper" story: companies need a trustable run record and enforcement boundary.

Source:
https://arxiv.org/abs/2602.17753

### 11. Web/computer agents remain vulnerable to prompt injection

The WASP benchmark for web agents tested realistic prompt-injection attacks against web navigation agents. Agents began executing adversarial instructions between 16% and 86% of the time, although successful end-to-end attacker goal completion was lower, between 0% and 17%.

Why this matters for Erebor:

This supports the claim that prompt instructions alone are not a reliable control boundary for computer-using agents. The stronger need is independent mediation and action-level controls.

Source:
https://arxiv.org/abs/2504.18575

## What The Evidence Says About "How Much"

### General AI adoption

For basic AI adoption, the slowdown is not mostly Erebor-shaped. McKinsey and other reports point to workflow redesign, data quality, skills, ROI, leadership, infrastructure, and operating model as broad constraints. Erebor-like controls matter, but they are one part of a bigger execution problem.

Estimate: 15-30% of general AI slowdown is related to governance/control/evidence gaps.

### Enterprise agentic AI

For agents with real authority, the evidence gets much stronger. Multiple surveys and reports point to insufficient governance, security, privacy, identity, monitoring, and operational control as major reasons agents stay in pilots, get rolled back, or fail to scale.

Estimate: 40-70% of agentic AI production-readiness friction is Erebor-shaped.

### Regulated workflows

For finance, healthcare, security, customer data, legal/privacy-sensitive workflows, or SaaS authority, the blocker may often be binary: no approval without evidence and control. In those cases, Erebor-shaped capabilities can be gating, even if not the only work needed.

Estimate: often a gating condition for pilots and production, especially when the agent can act rather than only advise.

### SMEs

For SMEs broadly, the evidence is weaker and more mixed. Smaller companies are behind in scaling, but their blockers often include cost, skills, lack of data infrastructure, and integration complexity. Erebor is more relevant to:

- regulated SMEs
- SMEs handling sensitive customer data
- agent vendors selling to enterprises
- mid-market companies that want agents but lack enterprise-grade platform/security teams

Estimate: not the primary broad SME adoption blocker, but potentially high-value where sensitive workflows or enterprise sales are involved.

## What This Means For Erebor

The best-supported thesis is not:

"Companies are slow to adopt AI because they lack Erebor."

The stronger thesis is:

"Companies are adopting AI, but agentic AI gets stuck when it needs authority. The missing layer is operational trust: what the agent is allowed to do, what it actually did, what it was blocked from doing, and who can approve or stop it."

That points to a sharper buyer story:

- AI platform/security teams want to deploy agents safely.
- Agent vendors want enterprise buyers to approve pilots faster.
- Legal/privacy/GRC teams are approvers, not usually buyers.
- The pain becomes strongest when agents move from answering to acting.

## Interview Implications

For DPO/legal/security approvers, ask:

- Have you seen an agent workflow get blocked or limited because of access, data, or accountability?
- What would you need to see before approving a limited pilot?
- What evidence from a real run would matter?
- When is audit enough, and when does control need to happen during the run?
- Who brings these workflows to you?

For likely buyers/champions, ask:

- Have you tried to deploy or sell an agent that got stuck in review?
- Who blocked it?
- What did they ask for?
- What workaround did you use?
- Would independent runtime evidence or mediation have changed the decision?

## Bottom Line

There is enough external evidence to justify the Erebor discovery thesis, especially for agentic AI and regulated workflows. The research does not prove the company yet. It does suggest the wedge is real enough to test aggressively:

agentic workflows are moving faster than enterprise governance, and organizations need operational controls and evidence before they can let agents act with real authority.

## Sources

- McKinsey, "The state of AI in 2025: Agents, innovation, and transformation": https://www.mckinsey.com/capabilities/quantumblack/our-insights/the-state-of-ai
- Cisco, "2026 Data and Privacy Benchmark Study": https://www.cisco.com/c/en/us/about/trust-center/data-privacy-benchmark-study.html
- ITPro, IBM CIO/CTO AI agents governance survey summary: https://www.itpro.com/technology/artificial-intelligence/cios-and-ctos-are-making-high-stakes-decisions-with-incomplete-information-ibm-survey-reveals
- TechRadar, Deloitte AI agent governance coverage: https://www.techradar.com/pro/a-live-operational-risk-why-ai-agents-are-outrunning-your-security
- Times of India, Deloitte State of AI in the Enterprise summary: https://timesofindia.indiatimes.com/technology/tech-news/deloitte-ai-institute-chief-on-ai-oversight-governing-ai-agents-is-tougher-because/articleshow/127574981.cms
- TechRadar, Gartner agent governance rollback summary: https://www.techradar.com/pro/lack-of-ai-governance-could-force-40-percent-of-enterprises-to-roll-back-autonomous-ai-agents-by-2027
- ITPro, Gartner proportional governance summary: https://www.itpro.com/technology/artificial-intelligence/one-size-fits-all-agent-governance-sets-enterprises-up-to-fail
- TechRadar, Sinch AI communication agents rollback summary: https://www.techradar.com/pro/the-most-advanced-organizations-arent-failing-less-theyre-seeing-failures-sooner-many-firms-are-already-having-to-roll-back-ai-customer-service-tools
- ITPro, Sinch AI customer service agent governance summary: https://www.itpro.com/technology/artificial-intelligence/ai-agents-arent-cutting-it-in-customer-service
- ITPro, Trustmarque AI governance report summary: https://www.itpro.com/technology/artificial-intelligence/organizations-face-ticking-timebomb-over-ai-governance
- Apostolou, Bosch, Holmström Olsson, "Agentic AI in Industry: Adoption Level and Deployment Barriers": https://arxiv.org/abs/2605.14675
- Staufer et al., "The 2025 AI Agent Index": https://arxiv.org/abs/2602.17753
- Evtimov et al., "WASP: Benchmarking Web Agent Security Against Prompt Injection Attacks": https://arxiv.org/abs/2504.18575
