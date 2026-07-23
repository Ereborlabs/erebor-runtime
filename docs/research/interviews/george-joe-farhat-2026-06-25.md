# George Joe Farhat Interview Findings

Date: 2026-06-25

Profile: George Joe Farhat  
LinkedIn: https://www.linkedin.com/in/gjfarhat/

Profile context: Legal Counsel | Data Privacy & Compliance | Commercial Contracts | AI Governance | Legal Tech | Risk Management

Interview type: legal/privacy/compliance practitioner interview

## Summary

George's interview is a strong counterweight to the simplest version of Kayne's
claim. Kayne warned that legal/GRC/DPO may often advise, document risk, or push
responsibility through contracts rather than truly block deployment. George's
answer suggests the reality depends heavily on company context and DPO strength.

In some environments, especially larger companies and government-adjacent
organizations, DPO/legal can force escalation, DPIA review, and actual stoppage.
George explicitly said the missing tooling is an actual blockade: a way to
restrict the agent no matter what.

This is a strong Erebor signal.

The biggest learning is that the DPO/legal review starts with practical
questions, not generic AI policy:

- who is behind the system or LLM
- where the data is processed
- why the agent needs to process that data or act that way
- whether government/export-license constraints apply
- whether there is a breach or potential breach
- whether the agent is doing more than the team said it would do

George's examples also validate that runtime behavior matters. A vendor agent
was found reading people's passwords during testing, and the issue was flagged
through forensic work. That means review cannot rely only on vendor statements
or policy documents. Reviewers need evidence from actual runs and the ability
to stop or restrict behavior.

## What This Means For Erebor

### 1. The strongest phrase is "actual blockade"

George said the current tooling gap is a tool that can restrict the agent no
matter what. He specifically framed the missing piece as actual blockade.

This strengthens Erebor's positioning as more than audit:

- not just logs
- not just governance documents
- not just policy prompts
- actual runtime enforcement outside the agent

That is very close to Erebor's core thesis.

### 2. DPO/legal can sometimes be buyers, not only approvers

This does not fully overturn the buyer hypothesis, but it adds nuance.

George said DPOs sometimes have no budget, especially in startups. But in his
previous company, the DPO did have budget, and he said if the price fit the
budget, DPOs would buy this.

So the buyer map should be:

- startups: DPO/legal probably not buyer
- larger companies: DPO/legal may influence or own budget
- government-adjacent companies: legal/privacy/security pressure is stronger
- agent vendors: still strong buyer path if customers require evidence/control

### 3. Government-adjacent companies may care about who is behind the model

George immediately brought up who is behind the LLM and export-license issues.
That is a new angle compared with Amy/Alex.

Erebor may need to support an evidence packet that includes:

- agent provider
- model/provider identity
- data processing location
- integrated LLM or tool chain
- whether data leaves the customer's environment
- vendor/subprocessor information
- action trace

This matters for government, defense, public sector, and regulated buyers.

### 4. The 3 Ws are a useful DPO/legal shortcut

George's review frame was: Who, Where, and Why.

- Who is behind it?
- Where is the data being processed?
- Why is it processing that data or acting that way?

This is simpler and more memorable than saying "governance model." It also
maps well to a demo report.

### 5. Audit trail alone is not enough

When asked when audit is enough versus runtime control, George answered: both
are needed.

That is important because it supports Erebor's combined product shape:

- runtime control/blockade
- audit trail
- forensic evidence
- compliance documentation
- reviewer packet

### 6. Hallucination and overreach are rejection triggers

George said he would reject or ask for more evidence if the agent does more
than what was requested, or if hallucinations create risk.

For Erebor, this suggests policies should not only protect data, but also catch
scope drift:

- action outside the approved mandate
- tool/API use beyond the approved workflow
- unexpected data access
- unsupported external action
- suspicious or hallucinated rationale

### 7. The API question matters

George's example question, "Can I plug it into my API, and if I can, what kind
of thing can it do?" points to API/tool authority as a major risk surface.

The product story should continue to include commands, tools, APIs, browser,
and SaaS access. Browser/OAuth is only the visible demo surface.

## Comparison With Earlier Interviews

### Compared With Amy

Amy emphasized starting with intended use and responsibility before architecture
or controls. George adds sharper practical questions: Who, Where, and Why,
including model/vendor identity and data processing location.

### Compared With Alex

Alex emphasized structured execution logs, blocked attempts, kill switch,
limited pilot, and reversible versus irreversible actions. George agrees with
the need for both evidence and control, and uses stronger language: actual
blockade.

### Compared With Kayne

Kayne warned that legal/GRC/DPO often may not block and may shift risk through
contracts. George suggests this varies by organization. A strict DPO can stop
or escalate the workflow, and larger/government-adjacent companies may have
budget and stronger blocking power.

The right discovery question remains:

Are workflows actually blocked, delayed, narrowed, approved with conditions, or
deployed anyway?

George gives evidence that in some organizations they are escalated, subjected
to DPIA, and sometimes stopped.

## Product Requirements Suggested By George

- Actual runtime blockade, not only logging
- Audit trail for real runs
- Forensic evidence support
- Compliance evidence packet
- Model/provider identity in the evidence packet
- Data processing location
- Who/Where/Why summary for DPO/legal review
- Detection of actions beyond the approved mandate
- Evidence of API/tool authority and what the agent can do through it
- DPIA-support report
- Escalation evidence for managers, DPOs, security, or risk committees

## Demo Changes Suggested

The demo should include a concrete DPO/legal review packet with:

1. Who is behind the agent/model/tool chain.
2. Where the data is processed.
3. Why the agent needs the data and action authority.
4. What systems, APIs, browser sessions, commands, or SaaS tools it can touch.
5. One allowed action.
6. One out-of-scope action that gets blocked.
7. A forensic/audit trail showing the attempted action.
8. A compliance/DPIA-style summary.
9. A clear statement that the blockade is outside the agent.

## Original Interview Notes, Grammar Fixed

### How Review Starts

**Question:** If an internal team or vendor brought you an AI-agent workflow,
how would the review usually start?

**George:** The first questions are where the data is being processed, what kind
of LLM is integrated into the workflow, and who is behind it. The "who" is
important because our company might work with government, and export licensing
can matter.

A recent example was a vendor that brought an agent which was reading people's
or users' passwords. Once they did testing, a colleague flagged it.

### What They Need To Explain

**Question:** What do they need to explain before you can even route or review
it?

**George:** Data breaches or potential breaches, and the three Ws: Who, Where,
and Why.

### What Happens When Concerns Are Raised

**Question:** When you raise concerns about an AI-agent workflow, what usually
happens in practice?

**George:** There is resistance, because business and legal want different
things. It is escalated and raised to the appropriate manager. Sometimes they
listen and sometimes they do not. It really depends on the DPO. If the DPO is
strict, it is stopped. Sometimes they create a DPIA report, and based on that
they decide.

### What Agent Builders Do After A Concern

**Question:** Once you raise the concern, what would the agent builders do?

**George:** They usually cooperate. The topic is new, and we are all learning
together.

### Limited Pilot Bar

**Question:** What would you need before being comfortable with a limited pilot?

**George:** Again, the three Ws, but mostly Why. Why is it doing that? Why is it
processing that data? Why is it doing it this way?

### Evidence From A Real Run

**Question:** What evidence from a real agent run would actually help you
evaluate it?

**George:** Audit trail, forensic studies, compliance documents, and any
testimonies. For example, regarding the agent that was reading people's
passwords, it was found through forensic studies.

### Audit Trail Versus Runtime Control

**Question:** When is an audit trail enough, and when would you need control
during the run itself?

**George:** Both are needed.

### Fast Rejection Signals

**Question:** What would make you reject the workflow quickly, or ask the team
to come back with more evidence?

**George:** If they realize the agent does more than what they asked it to do,
or if there are hallucinations.

Another question is: can I plug it into my API, and if I can, what kind of
things can it do?

### Current AI Governance Tooling Gap

**Question:** What is the current tooling gap in AI governance?

**George:** A tool to restrict the agent, no matter what. Actual blockade is
missing. Big companies and government need this: actual blockade.

### DPO Budget

**Question:** Do DPOs have the budget?

**George:** Sometimes no, sometimes yes. If it is a startup, no. But his
previous company did have the budget, and if the price was within the budget,
DPOs would buy this.

### End Of Call

At the end, George asked about Erebor. I explained it briefly. He said it was
interesting. He was going on vacation, but said that once he returns he is going
to message me to see a demo. He also said he might know companies that want or
need this.

## Follow-Up To Consider

Do not immediately send a long recap. Since George already asked to see Erebor
after vacation, the best next step is to wait for his return or send a short,
non-pushy note after an appropriate interval.

Possible follow-up later:

```text
Hi George,

Thank you again for the conversation. I really appreciated the practical view,
especially around actual blockade and the Who / Where / Why questions.

When you are back from vacation, I would be happy to show you a short demo and
get your candid reaction.

Best,
Navid
```

