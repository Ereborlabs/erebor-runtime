# Gabriela Roulin Interview Guide

Use this guide for the 15-minute interview with Gabriela. Start with an example
from her work. Follow that example through the review, the evidence she needed,
and what happened when she raised a concern.

Profile supplied by Navid: Legal Counsel and DPO; privacy and compliance;
life sciences, technology, and financial services; EU-qualified lawyer.
[LinkedIn profile](https://www.linkedin.com/in/gabriela-roulin/).
Confirm her current work during the call. Do not assume a current employer,
jurisdiction, budget, or authority to stop deployment.

Gabriela agreed to discuss what evidence would help her review agent actions.
Start there. Briefly explain how the product has changed, then let her describe
her experience.

## What to learn

Try to understand what she needs to know, how she gets that information today,
and what is still difficult to check. Find out who handles her concerns and
whether better evidence would change a real decision.

The person who reviews an AI tool, the person who operates it, and the person
who buys security software can be different people. Find out how those roles
work in her experience. Her interest in the subject does not mean she plans to
buy a product.

## The 15 minute script

Use the six main questions as a route through the conversation. Do not read
every follow-up. If she answers a later question early, continue from there.
Stay with one useful example rather than asking for a new case at each step.

### Minute 0 to 1 opening

> Thanks for making the time, Gabriela. When I contacted you, I was building
> Erebor to help control what AI agents can do and keep a record of their
> actions. That work has grown into a broader security product, now called
> Araphor. The aim is to restrict what agents and other software can do, and
> help teams check what actually happened.

> You mentioned that evidence for reviewing agent actions is a real gap. I'd
> like to understand what that looks like in your work. Please keep examples
> anonymous. Is it okay if I take notes?

If she asks what the product does, give the short explanation below. Otherwise,
start with her experience before giving more product detail.

### Minute 1 to 4 one real case

**1. Have you recently reviewed an AI tool that could access company or
customer data, or take actions for someone? Could you walk me through it?**

If useful: "What was it supposed to do, and what were you asked to review?"

If she has no direct example, say: "A similar review of software or a vendor
would also be useful." Note whether the example involved an agent, another AI
tool, or ordinary software.

**2. What did the team show you to help with that review?**

If useful: "What was useful, and what did you still need to ask them?"

Find out what she actually received: a description of the tool, contract
terms, test results, activity records, or an explanation from an engineer.
If something was missing, ask: "How did you get that information?" If the
material was sufficient, ask what made it useful.

### Minute 4 to 7 checking what the tool did

Use this transition if the review focused on plans or vendor documents:

> That helps me understand the initial review. I'm also interested in what
> you can check once the tool starts doing work.

**3. How would you check whether it only accessed the data and took the
actions it was allowed to?**

If the tool was tested or used, ask what she could check in that case. Let her
answer before offering an example. If an example would help, say:

> Suppose an agent may read one approved folder and draft a summary. It tries
> to read a file containing passwords outside that folder. The security tool
> says it blocked the attempt. What would you want to see to trust that result?

Then ask: "What would you still need to know?"

Keep the example hypothetical. Listen for what the agent was allowed to do,
what it tried, whether it succeeded, and where the record came from. Ask about
one missing detail rather than reading a list of possible requirements.

For Navid: a denied read does not prove that no other data left the system.
File and network records can also leave the affected personal data unclear.
If she needs that detail, ask where she would expect to get it.

### Minute 7 to 9 privacy of the activity records

> Those records could help with a review, but they could also contain
> sensitive information themselves.

**4. What would you be comfortable recording, and what would you want left
out?**

If useful: "Who should be able to see those records, and how long should they
be kept?"

Follow her answer. She may focus on personal identifiers, message contents,
passwords, employee activity, or deletion requests. Ask what her team would do
when an investigation needs information they would otherwise remove.

### Minute 9 to 12 when recording is insufficient

> We've talked about checking what happened. I'd also like to understand when
> you need to prevent something from happening.

**5. In the example you described, would reviewing the activity afterwards
have been enough?**

If useful: "Which actions, if any, would need approval or a technical block
before they happen?"

Ask how that works today. Does a person approve the action? Does a system
block it? Can someone stop the tool or remove its access? Also ask whether
the organization accepts the risk or changes contract terms instead.

If she says "stop the agent," ask what remains to be checked after it stops.
Stopping the tool does not remove access from every other system. It also
cannot take back data that was already sent.

### Minute 12 to 14 what happens after a concern

**6. When you raise a concern like that, what happens next?**

If useful: "Who has to fix it, and who decides whether the tool can still be
used?"

Then connect her answer to practical value: "If you had the records and
controls we discussed, what would become easier?"

Listen for a faster review, a safer trial, less investigation work, or no
meaningful change. If existing tools already meet the need, ask which ones
and what they provide. Ask about budget only if she identifies a real need
for another tool: "Which team would normally pay for that?"

### Minute 14 to 15 close

Reflect one concrete point back to her:

> Let me check that I understood: in [workflow], you need [evidence] to make
> [decision], and [person or team] would handle the concern. Have I got that
> right?

Choose one next step that fits the conversation:

> Would you be open to looking at a one-page example of these records later
> and telling me what is useful or missing?

Or:

> Who would you suggest I speak with to understand how the security or IT
> team handles this in practice?

Stop at 15 minutes unless she offers more time. Do not request a demo, a pilot,
and an introduction together.

## Short product explanation

Use this only if she asks for more detail:

> Think of an agent that is allowed to read certain files but must not read
> passwords or send data to an unapproved destination. I'm building ways to
> enforce those limits and keep records of what it tried, what was blocked,
> and what actually happened. The broader product also covers other software
> and helps security teams investigate related activity. Changes to the rules
> and actions taken in response need their own authorization. I'm trying to
> understand what would help you assess a system like that.

Present this as what you are building. If she asks what works today, describe
only demonstrated results and state their limits. Investigation, policy
publication, response, and provider integration still have incomplete work in
the linked plans. Do not promise that Araphor can see all data inside encrypted
traffic, control every SaaS action, prove compliance, or recover disclosed data.

## Optional follow up questions

Use these instead of a main follow-up, or after she offers more time.

**Evidence sent to an external AI service**

> If a team wanted an external AI service to analyze security evidence, what
> would you need to know before they sent the records to it?

Then ask what information they could send, who would receive it, and whether
keeping the analysis inside the company would change her answer.

**AI conclusions and observed facts**

> If an AI summary says the problem has been stopped, what would you want to
> check before relying on that conclusion?

Ask who makes the final assessment and how they see what is still uncertain.
An AI explanation does not prove that an action was blocked or that a response
worked.

**Other security incidents**

> Would you need different information if the same action came from an
> attacker using a stolen account?

Find out whether the same problem occurs outside agent reviews. Interest in
agent controls does not establish a need for broader software protection.

**Sector differences**

> Does what you need to see change between life sciences, technology, and
> financial services? Could you give an example from your experience?

Let her select the sector and explain the difference. Do not assume that one
regulation or review process applies to all her work.

**Contracts and technical evidence**

> In that vendor review, which questions could you resolve through documents
> or contract terms, and which needed evidence from the running system?

Ask what would remain unresolved even with a strong technical record. This
tests where a security product can help within a wider legal review.

**A control failure or evidence gap**

> If the security tool is still blocking actions but some activity records are
> missing, what would you need to do next?

If relevant, also ask what happens when the tool cannot block actions. Keep
that situation separate from missing activity records.

## Sample activity record for a later review

Offer this after she explains what matters to her. Use made-up data. Ask what
she would remove as well as what she would add.

| Field | Content to test |
| --- | --- |
| What was allowed | The task, permitted systems and data, restrictions, responsible person, and review period. |
| Who acted | The software or agent session and the account it used. Show how the action was linked to it. |
| What it tried | The action, its target, the time, and where the record came from. Include sensitive content only where justified. |
| Which rule applied | The rule version, its decision, and whether it was active for that software. |
| What happened | Whether the action succeeded or was blocked. Permission to act does not prove the action completed. |
| What is missing | Gaps in the records, the period covered, and details the system could not see. |
| What happened next | Who reviewed it, what they approved, what was done, and what access or uncertainty remains. |
| How the records are handled | Who can read or receive them, where they are stored, and how retention, preservation, and deletion are handled. |

Ask: "What would this help you decide? What would you still need to ask
engineering or security?"

## Notes to complete after the call

Keep the interview notes separate from this guide. Mark what she experienced
herself, what she heard from others, and what she would want in an imagined
case. Keep Navid's interpretation separate from her answers.

- Current role and review responsibilities:
- Task or incident, without identifying details:
- Decision required and actual result:
- Evidence available and source:
- Missing evidence and the work needed to obtain it:
- Limits on what is recorded, who can see it, where it can go, and retention:
- Actions that need approval or a block before they happen:
- Who reviews, who decides, who operates the tool, and who pays:
- Existing tools and procedures that already work:
- What better evidence would change:
- What Araphor would not solve:
- Agreed next step and person responsible:

A real example is useful when she can explain what was missing, what problem
that caused, and who had to deal with it. General interest or a feature list
does not establish demand. Keep answers that challenge the product idea,
including cases where existing tools and procedures already work.

## Lessons from the earlier interviews

Use these notes to prepare. Let Gabriela answer before sharing another
interviewee's view.

| Source | What they said | What to explore with Gabriela |
| --- | --- | --- |
| [Amy](../interviews/amy-wittmann.md#amy-on-use-case-and-governance-before-controls) | First explain what the agent may do, what data it needs, and who is responsible. | What does she need to understand before reviewing the technical controls? |
| [Alex](../interviews/alexandre-andrietta.md#full-response-from-alex) | A success message is insufficient. Show blocked attempts and a way to stop the agent or remove its access. | What would help her check that the controls work? |
| [George](../interviews/george-joe-farhat-2026-06-25.md#original-interview-notes-grammar-fixed) | Testing found a vendor agent reading passwords. He wanted effective restrictions and evidence of what happened. | How would she find out what data a tool accessed? |
| [Kayne](../interviews/kayne-2026-06-24.md#summary) | Privacy and GRC may advise or ask for contract changes without deciding whether the tool is used. | Who acts on her concerns and makes the final decision? |
| [Tony](../interviews/tony-yip.md#polished-structured-call-notes) | IT receives privacy advice and deploys the tool. The response to a product failure also matters. | Who operates the tool, and what happens if its controls fail? |
| [Ross](../interviews/ross-stapleton-gray.md#polished-structured-call-notes) | Knowing what happened is only part of the problem. Teams also need authority to act and a fast response. | Does she see the same problem with compromised accounts or ordinary software? |

These are separate interview accounts. Test where Gabriela agrees or differs.
Do not present them as a market consensus.

## Product references

- [Current discovery and evidence scope](../../plans/mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/README.md).
- [Evidence and authority contracts](../../plans/mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/engine-design.md).
- [Review and client access contracts](../../plans/mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/console-and-api.md).
- [Prevention and response boundary](../../plans/mithril-hugging-face-intrusion-prevention/README.md#goal-and-release-boundary).
- [Araphor product naming and console scope](../../plans/araphor-console/README.md).
- [Earlier interview guide](../icp-interview-guide.md).
