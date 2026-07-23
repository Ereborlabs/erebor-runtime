# Ross Stapleton-Gray Interview Findings

Date: 2026-07-08

Profile: Ross Stapleton-Gray, Ph.D., CISSP, CIPM  
LinkedIn: https://www.linkedin.com/in/ross-stapleton-gray/

Profile context: Infosec, GRC, and Privacy Leader; Security and Privacy Lead at
Braintrust

Interview type: live security/privacy/GRC interview with AI observability,
evals, and agent-governance context

## Summary

Ross's call is one of the strongest signals so far that Erebor is not just a
DPO/legal curiosity. He said clearly that there is a need for agent governance,
and that an organization like Braintrust could be a customer for this kind of
platform. His framing was that Braintrust is in AI observability and evals,
closer to QA for AI systems, but not in governance.

That distinction matters a lot:

- Braintrust helps teams observe, evaluate, and improve AI behavior.
- Erebor can own the runtime governance layer around what agents are allowed to
  do.
- The overlap is evidence and traces.
- The gap is authority, control, escalation, and stopping behavior fast enough.

Ross also connected the problem to identity and authority. He has been hearing
about this at events: once agents move from answering questions to taking
actions, the hard questions become who or what gave the agent authority, what
authority it has, and how that authority was obtained. He mentioned Okta working
on identity in this area.

His strongest operational point was speed. In an agent world, incidents can move
much faster than human-driven workflows. He referenced the Zenity AI Summit and
the idea that agentic systems may change bug bounty and incident response
because five minutes in an agent workflow can be a very long time. Small
exposures can become serious incidents quickly if nobody flags or stops the
behavior early.

He also gave a security incident context from Braintrust: a privileged user
account was compromised, a database dump was not secured, and LLM keys were
exposed. The incident was not AI-caused, but it sharpened the need for systems
that flag exposed keys, escalate quickly, and involve humans when the risk
crosses a threshold.

## What This Means For Erebor

### 1. The observability versus governance distinction is real

Ross did not treat Braintrust and Erebor as the same category. His response
supports the current positioning:

> Braintrust is observability/evals/QA for AI. Erebor is governance around agent
> authority and action.

This is important because Braintrust is not a weak or irrelevant comparison. It
is a sophisticated adjacent product. If Braintrust still leaves room for a
runtime governance layer, that makes the Erebor wedge more credible.

### 2. Authority and identity are central

Ross went quickly to identity and authority:

- where the agent gets authority
- what authority it has
- how that authority is delegated
- what happens when the agent starts taking actions

This aligns with Erebor's thesis that browser/OAuth is only the first visible
surface. The real product is about governing delegated authority across
commands, tools, browsers, SaaS, APIs, and computer-use surfaces.

Erebor should be able to answer:

- Which identity was the agent acting under?
- Which authority did the agent inherit or request?
- Which action did it take with that authority?
- Was the action inside the approved boundary?
- Who or what approved, blocked, or escalated it?

### 3. "Agent goes off the trail" is strong product language

Ross said he would want the system to flag when the agent goes off the trail.
That is a useful phrase.

It captures the product better than abstract "AI governance":

- define the trail
- watch the agent's actions
- flag deviation
- escalate to a human
- stop or contain the behavior quickly

This maps directly to Erebor's mandate/enforcement/evidence model.

### 4. Human in the loop still matters, but timing matters

Ross was not dismissive of human-in-the-loop. From his perspective, humans are
needed when risk appears. But his comments also show why human review has to be
timely and backed by technical enforcement.

In an agent workflow, waiting too long can turn a small exposure into a serious
incident. Erebor should not frame human-in-the-loop as a vague checkbox. It
should frame it as:

- human approval before sensitive actions
- human escalation when the agent leaves the trail
- fast pause/stop/containment
- evidence that lets the human make a decision quickly

### 5. Key exposure and secret leakage are natural early policies

Ross's Braintrust incident context suggests a concrete early policy family:
detecting and escalating exposed keys, credentials, database dumps, or other
secrets during agent workflows.

This is especially relevant for coding agents and setup agents:

- agents reading files
- agents installing SDKs
- agents editing instrumentation
- agents running commands
- agents accidentally exposing tokens
- agents pushing or sending sensitive files

Erebor can make this concrete in demos: if an agent encounters an API key,
database dump, OAuth token, or other secret, the runtime flags, blocks, or
escalates.

### 6. Corporate IT and risk are stronger buyer signals

Ross's buyer map pointed to compliance, corporate IT, IT management, and risk
departments in large organizations.

He said compliance would feel the pain. He also said IT management would feel
the pain because they are told to do integrations. For larger organizations, he
mentioned risk departments as likely buyers.

That reinforces the current buyer correction:

- DPO/legal/security are not the only path.
- Agent vendors are one buyer path.
- Internal AI platform and corporate IT are another.
- Compliance/risk may own the organizational governance need.

Ross's version is especially strong for:

- companies deploying AI tools internally
- corporate IT teams asked to integrate agents
- risk/compliance functions responsible for organizational controls
- observability/eval companies that need a governance layer for their own AI
  usage or customer trust

### 7. "Recreating corporate network" is a useful analogy

When Erebor was explained as a sandbox that governs agent actions, Ross said it
sounds like recreating the corporate network, and that this is necessary.

This is a good analogy, if used carefully.

The point is not that Erebor literally replaces the corporate network. The point
is that agentic systems need a new control plane around delegated action, similar
to how corporate networks, identity, and security controls became necessary once
employees and software had broad access.

Possible language:

> Agents need their own corporate-network-style control layer: identity,
> authority, policy, monitoring, escalation, and containment around actions.

## Comparison With Earlier Interviews

### Compared With Amy

Amy emphasized the approved agent mandate before controls. Ross adds the
identity/authority layer: once an agent has authority, the reviewer needs to know
where it came from, what it can do, and how deviation is flagged.

Together:

- Amy: what is the approved mandate?
- Ross: how is authority attached to the agent, and how do we catch deviation?

### Compared With Alex

Alex emphasized structured logs, blocked attempts, kill switch, and control
during sensitive or irreversible actions. Ross agrees with the need for
flagging and human escalation, but adds urgency: agent timelines are much faster
than human incident timelines.

Together:

- Alex: logs and controls must be useful to a reviewer.
- Ross: controls must operate quickly enough to stop fast-moving agent damage.

### Compared With George

George used the phrase "actual blockade." Ross's "off the trail" framing is
similar but more operational. George wants the system to restrict the agent no
matter what. Ross wants the system to flag and escalate when the agent deviates,
especially before a small exposure becomes a critical incident.

Together:

- George: actual blockade.
- Ross: fast off-trail detection and escalation.

### Compared With Kayne

Kayne warned that GRC/legal/privacy may not always block or buy. Ross gives a
stronger buyer signal from the compliance, IT management, and risk side. He also
said Braintrust itself could be a customer of this kind of platform.

This does not fully reverse Kayne's warning, but it makes the segmentation
clearer:

- some GRC teams may avoid owning the problem
- some compliance/risk/IT teams will feel the integration and governance pain
- companies closer to AI infrastructure may understand the gap earlier

### Compared With Tony

Tony pointed to IT and compliance because IT deploys the systems. Ross
reinforces that point more strongly. He specifically named corporate IT, IT
management, compliance, and risk departments.

Together:

- Tony: legal/privacy concerns flow to IT.
- Ross: corporate IT and risk/compliance may be the buyer or operator for
  organizational agent governance.

## Product Requirements Suggested By Ross

- Agent identity and authority tracking
- Delegated-authority evidence: how the agent got access and what it can do
- Off-trail detection
- Fast escalation to a human
- Human approval for risky actions
- Runtime flagging when agents behave unexpectedly
- Stop/pause/containment before small exposures become major incidents
- Secret/key/token exposure detection
- Evidence that helps security/privacy understand whether the agent acted
  faithfully
- Ability to anticipate or constrain action changes
- Governance layer that complements AI observability/evals
- Corporate IT / compliance / risk-facing deployment story

## Demo Changes Suggested

The demo should include a scenario that shows both observability and governance:

1. Define the agent's allowed trail: what systems, commands, browser actions, or
   SaaS actions are allowed.
2. Let the agent perform an allowed action.
3. Let the agent encounter or attempt something risky, such as reading an API
   key, touching a database dump, opening an OAuth-protected resource, or
   running a command outside the mandate.
4. Show Erebor flagging that the agent went off the trail.
5. Escalate to a human with enough context to decide.
6. Block, pause, or contain the action.
7. Preserve an evidence trace for compliance, IT, risk, and security review.

This demo should not be framed as "better observability than Braintrust." It
should be framed as:

> Observability tells you what happened. Erebor helps decide what is allowed,
> what must be stopped, and when a human has to step in.

## Buyer And Discovery Notes

Ross pointed toward:

- compliance leaders
- corporate IT
- IT management
- risk departments in large organizations
- organizations integrating agentic systems
- AI observability/eval companies that need governance for their own workflows
- buyers responsible for organizational governance, not only model quality

Strong follow-up targets:

- IT leaders responsible for AI tool rollout
- enterprise risk leaders working on AI adoption
- compliance leaders with AI governance responsibility
- security leaders at AI infrastructure companies
- AI platform owners inside companies deploying agents internally
- agent vendors that need a governance story for customer trust

## Polished Structured Call Notes

### What Changes When AI Systems Take Actions

**Question:** From a security and privacy perspective, what changes when an AI
system moves from answering questions to taking actions with tools, commands,
browsers, or SaaS access?

**Ross:** He has attended a number of events where this topic came up,
especially around identity. Once agents get to the point of taking actions, the
question becomes what authority the agent has and how the agent got that
authority.

Even when an AI system is only answering questions, there can still be authority
questions depending on what access it has and what data it can retrieve.

He mentioned Okta working on identity in this area: what authority the agent
has, and how the agent got it.

Ross said he is new in his organization, but he needs tools like this there.

He said there is absolutely a need for agent governance. Braintrust would be a
customer of this kind of platform. Braintrust is in the observability of AI, but
not in governance. He described Braintrust as sort of a QA tool.

### What Security Or Privacy Needs Beyond Traces

**Question:** If a team can show traces of an agent run, including prompts, tool
calls, outputs, and eval scores, what would security or privacy still need
before letting that agent touch real systems?

**Ross:** The question is whether the agent performs faithfully, and whether
you can anticipate the change of actions.

He said he would want the system to flag when the agent goes off the trail.
From his perspective, human-in-the-loop is needed. Having that kind of single
pane of glass is required.

He described a security incident they had where LLM keys were exposed. Anything
that can flag those kinds of issues and escalate to a human would be useful.

He referenced the Zenity AI Summit and said this kind of problem is killing bug
bounty because, in an agent world, things happen much faster than in a human
world. Flagging and stopping these issues early is important. Five minutes in
an agent world is ages.

He said that often, a lot of things go rogue. Small exposures can become
critical incidents.

He is concerned that if agents take more direct actions, they may disclose
information from third parties.

The incident he mentioned was not AI-related. It happened because a privileged
user account was taken over, and there was a database dump that was not secure.
LLM tokens were stolen as part of the incident.

### Who Feels The Pain

**Question:** If I wanted to find the people who already feel this pain, who
should I talk to next?

**Ross:** In the compliance world, that would be the buyer. Compliance would
feel the pain, like him.

IT management would also feel the pain because they are told to do these
integrations.

He specifically said IT manager.

Tools like this would be used by corporate IT. It is much more organizational
governance.

He also mentioned that in big organizations, they would have a risk department,
and the risk department would be the buyer.

### Erebor Explanation

At this point, Erebor was explained as a sandbox that governs agent actions.

Ross said this sounds like recreating the corporate network. He said it is
necessary, but he is still trying to explain to customers why things have
changed and why this is required.
