# Alexandre Andrietta Written Findings

Date: 2026-06-25

Profile: Alexandre Andrietta  
LinkedIn: https://www.linkedin.com/in/ACoAAAGD0XIB3ml8vU3ryOx1K_NnMoDV1-pFWCg

Interview type: written DPO/privacy practitioner feedback

## Summary

Alex's response is one of the clearest privacy-practitioner signals so far.
The useful learning is not simply "privacy wants logs." The bar is more
specific:

- the agent workflow has to be scoped before review
- risk increases with sensitive data and autonomy
- high-risk workflows trigger DPIA-style review
- approval is conditional and usually starts as a limited pilot
- privacy cares about legal basis, purpose, minimization, and traceability
- security owns infrastructure/access-control review, but privacy needs to know
  whether the agent's data use is proportionate and explainable
- a generic success log is useless
- blocked attempts and error cases are valuable evidence
- audit logs are only enough for low-risk, reversible, test-environment actions
- sensitive or irreversible actions need control during execution
- no kill switch means no pilot approval

This strengthens the Erebor thesis: the product should not be framed as just an
audit log. It should be framed as a governed runtime that makes a limited pilot
reviewable by defining scope, enforcing action boundaries, recording the full
step-by-step run, showing blocked attempts, and giving a clear stop/revoke/undo
story.

## What This Means For Erebor

### 1. The pilot demo should start with the mandate

Alex's intake flow starts with what the agent does, what data it touches, and
what actions it can take. That means the demo should not start with the control
mechanism alone.

The demo should first show a small approved mandate:

- allowed systems
- allowed data
- allowed actions
- prohibited actions
- approval-required actions
- pilot timebox
- human supervisor
- stop/revoke plan

Then the runtime evidence should prove whether the agent stayed inside that
mandate.

### 2. Erebor needs to show both allowed and blocked behavior

Alex specifically said blocked attempts are useful. That is important.

The demo should include:

- a normal allowed action
- a risky action that requires approval
- an out-of-scope attempt that is blocked
- the resulting evidence trace

The blocked attempt is not a failure in the demo. It is the proof that the
control layer works.

### 3. Logs must be structured and tamper-resistant

Alex rejected generic "task completed successfully" logs and also called out
logs the agent can edit or delete.

Erebor should emphasize:

- structured execution log
- command/tool/browser/SaaS action details
- data touched
- policy decision
- approval/denial result
- actor identity
- timestamp
- immutable or tamper-evident storage

This should feed the audit crate and sink design: file, ClickHouse, Datadog, or
other sinks should receive the same filtered-but-trustworthy event stream.

### 4. Reversible vs irreversible actions are a policy boundary

Alex gave a practical rule:

- audit trail can be enough for low-risk and reversible actions
- execution-time control is needed for sensitive or irreversible actions

This maps cleanly to Erebor policy levels:

- allow and log
- allow with review/audit
- require approval before execution
- block
- stop/revoke session

High-risk examples Alex named:

- sensitive data
- children's data
- deleting records
- sending data externally
- changing access permissions
- moving money

These are good default high-risk examples for demos and policy docs.

### 5. Kill switch and rollback matter

Alex said without a way to stop the agent, revoke access, and undo actions, he
would not sign off on even a small pilot.

Erebor should show:

- stop current run
- revoke or cut off access
- preserve evidence after stop
- record what already happened
- support rollback/undo instructions where possible

Even if Erebor cannot undo every external side effect, the demo should show a
clear containment story.

### 6. The buyer pain may show up before privacy as an engineering/privacy gap

Alex's answer to question 7 is very useful. In staging/UAT, the pain is often
the gap between engineering saying "ready" and DPO/GRC saying "not adequate."

That supports this buyer hypothesis:

The buyer may be the team trying to ship or sell the agent, but the product
needs to satisfy privacy/security/GRC reviewers who define the minimum bar.

Erebor can be positioned as the artifact that reduces that gap.

## Product Requirements Suggested By Alex

- Agent mandate/spec before runtime
- Data scope and system scope
- Read/write/autonomous action classification
- Pilot mode with restricted scope and time limit
- Structured execution log
- Data-access trace by person/data category where possible
- Blocked-attempt logging
- Human approval before critical actions
- Kill switch / stop run
- Access revoke story
- Rollback or containment story
- Tamper-resistant logs outside the agent's control
- Reviewer-ready evidence export

## Demo Changes Suggested

The next demo should not only show OAuth mediation. It should show a complete
privacy-reviewable pilot:

1. Define the agent mandate.
2. Start a limited run.
3. Let the agent perform one allowed action.
4. Let the agent attempt one out-of-scope action.
5. Show Erebor blocking or requiring approval.
6. Show a structured evidence trace with allowed, blocked, and approval events.
7. Show stop/revoke or kill-switch behavior.
8. Export a reviewer packet.

The strongest line from Alex for the demo:

> A generic "task completed successfully" log is useless to me - I need the
> step-by-step, including cases where it tried something and got blocked by a
> rule.

## Full Response From Alex

> Hi Navid,
>
> Happy to share my view from practice!
>
> Here you go, straight and to the point.
>
> 1. How would approval usually work?
> It goes through a formal intake: the team or vendor explains what the agent does, what data it touches, and what actions it takes (read-only vs. write/act autonomously). From there I classify the risk - the more sensitive the data and the more autonomy it has, the higher the level of review. High risk triggers a DPIA. In parallel, security reviews access controls and logging, and legal locks down the legal basis and the vendor contract (DPA). Final approval goes in a chain: business owner > security > privacy > risk committee for sensitive cases. It's almost always conditional: a limited pilot first, with restricted scope and a time limit, before production.
>
> 2. What would your part of that review focus on?
> Three things: (1) legal basis and purpose - is the use covered by a valid legal basis, and is it staying within the original purpose the data was collected for; (2) minimization - does the agent actually need that volume/type of data, or can scope be narrowed (masking, tokenizing, least-privilege access); (3) data subject rights and traceability - can I later explain and prove what the agent did with a specific person's data if they request access, correction, or deletion. Technical security and infrastructure I leave to the security team; my lens is proportionality and justifiability from a privacy standpoint.
>
> 3. What would you need to understand before being comfortable with a limited pilot?
> Exact scope: which systems it touches, what data it reads/writes, and whether it's a real environment or a test environment with synthetic/masked data - I always prefer masked data first if possible. Who's watching the agent while it runs: real-time human supervision or only after-the-fact review. And a rollback plan - how I stop the agent, revoke its access, and undo any action it already took. Without that, I won't sign off on even a "small" pilot.
>
> 4. What evidence from a real agent run would actually help you evaluate it?
> A complete, structured execution log: what the agent decided to do, why (reasoning or triggering prompt if visible), what data it accessed, and the concrete action taken in each system. A generic "task completed successfully" log is useless to me - I need the step-by-step, including cases where it tried something and got blocked by a rule. That tells me whether controls actually work in practice, not just on paper. Seeing an error case or an out-of-scope attempt is especially valuable.
>
> 5. When is an audit trail enough, and when would you need control during the run itself?
> An audit trail is enough when risk is low and reversible: non-sensitive data, an action with no harm if undone later, or an isolated test environment. When the agent touches sensitive data, children's data, or performs an irreversible action - deleting a record, sending data externally, changing access permissions, moving money - I need control at the moment of execution: human approval before the critical action, or a technical checkpoint that blocks it otherwise. An audit log after the fact doesn't undo data that already went to the wrong third party.
>
> 6. What would make you reject it quickly, or ask the team to come back with more evidence?
> If the team can't clearly explain what the agent does and why it needs that access - that alone signals nobody mapped the risk. No logging at all, or a log the agent itself can edit/delete. Overly broad access requested "just to make sure it works," without case-by-case justification. And no kill switch - no clear way to stop the agent mid-run - means I won't approve even the pilot. I don't need a perfect solution, but I need to see the team thought about what can go wrong, not just what's supposed to go right.
>
> 7. Who usually feels this pain before it reaches privacy, legal, security, or GRC?
> It depends on the stage. In production, the first to feel it is customer support, getting a direct complaint about an anomaly, or it lands straight on legal via a formal notice - at that point it's already an external problem. In staging/UAT, the fight is internal: it's usually GRC or the DPO who feel it, because the solution isn't adequate yet and engineering almost always thinks it is. That gap in perception - "it's ready as far as I'm concerned" vs. "this doesn't meet the minimum privacy bar" - is where the pain actually shows up before it formally reaches privacy or security.
>
> Hope this is useful for the pilot design.
>
> Happy to dig deeper into any of these if it helps.
>
> Warm Regards,
>
> Alex

## Reply To Send

Hi Alex,

Thank you. This is genuinely helpful, and I really appreciate you taking the
time to write such a practical answer.

This gives me a lot to work with for the pilot design.

If you are open to it, once I have a cleaner version, I may send you a short
summary or demo and get your candid reaction.

Really appreciate this, especially coming from a cold message.

Warm regards,
Navid
