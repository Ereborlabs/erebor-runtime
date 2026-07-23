# Tony Yip Call Findings

Date: 2026-06-26

Profile: Tony Yip  
LinkedIn: https://www.linkedin.com/in/tonyyip8675309/

Interview type: live call with AI privacy counsel / DPO / global compliance lead

## Summary

Tony's call was conversational. The biggest signal was not that he has deep
agent deployment experience. He was clear that most of the startups he works
with are building AI-enabled software or shadow-AI-related products, not fully
agentic systems. Only one startup he works with is building something closer to
an agent, around accounts receivable.

That said, the call was still useful because Tony reacted like a privacy/product
counsel who will see this category as it enters real companies. He expects
companies to start testing agents soon, and his first instinct was exactly the
risk Erebor is trying to govern: agents can go off-script, ignore instructions,
or take actions the business did not expect.

When Erebor was initially explained, Tony thought it might be a governance agent
itself. After clarification that Erebor is not the agent, but a sandbox/runtime
around agents, he recognized it as a solution to the problem he had just
described.

The useful learning:

- Tony has limited direct agent-review experience, so this should not be treated
  as a mature enterprise-agent procurement datapoint.
- Privacy/legal review starts with the vendor, guardrails, data access, vendor
  location, vendor identity, and basic privacy/security questions.
- Tony's concerns flow to IT, because IT is usually the group deploying the
  system.
- If business tries to route around legal/privacy, IT is expected to check with
  him first.
- A legal/privacy "no" may not be absolute; the business may accept the risk,
  though Tony has not personally seen that play out in this exact context.
- For buyer discovery, Tony pointed to IT and compliance as closer to the
  deployment decision than privacy/legal alone.
- The minimum evidence he named was an audit trail: what happened, what the
  agent did, and how to understand or reverse a wrong action.
- Documentation matters. He expects proof, security assurances, and a clear
  failure-response story.
- Conservative companies are more likely to care early than companies that are
  already "all in" on AI.
- If IT or compliance is convinced, they can buy or push the purchase.

## What This Means For Erebor

### 1. The explanation needs to be crisp

Tony initially mapped Erebor to "a governance agent." That is a warning.

The simple explanation should be:

> Erebor is not an agent. It is the governed runtime around agents. When an agent
> browses, runs commands, uses tools, or touches systems with real access, Erebor
> enforces policy and records what happened.

This needs to appear early in calls, demos, and outreach. Otherwise privacy and
legal people may assume Erebor is another AI system that itself needs review,
instead of the control layer around the agent.

### 2. The "agent goes rogue" story lands

Before Tony fully understood Erebor, he independently raised the problem of an
agent going off-script or not following instructions. That is a good signal.

It suggests the demo should not only talk about abstract governance. It should
show the failure mode:

- the agent is given a task
- it tries to do something outside the expected boundary
- Erebor blocks, mediates, or records the action
- the reviewer can see what happened

The market language can be plain:

> What happens when the agent does not follow the instruction?

That is more concrete than "AI governance."

### 3. IT and compliance are likely closer to the buying path

Tony did not describe legal/privacy as the solo buyer. He described legal/privacy
as an assessor whose advice flows to IT, because IT deploys the tool.

That fits the current hypothesis:

- DPO/legal/privacy are reviewers and approvers
- IT/compliance/security are closer to deployment and budget
- the business may still accept risk, but IT needs to know what it is deploying

Erebor should keep interviewing DPO/legal people, but the buyer discovery should
continue moving toward IT, compliance, security, AI platform owners, and agent
vendors selling into those groups.

### 4. Audit trail is necessary but not the whole product

Tony's bare minimum was an audit trail, especially to understand what happened
and reverse a wrong action.

That supports the evidence-trace part of Erebor. But Alex and George both pushed
harder on control during execution. Tony's call should not pull Erebor back into
"just logs."

The better synthesis:

- Tony validates that reviewers need a record of what happened.
- Alex validates that generic logs are not enough.
- George validates that actual blockade matters.

So the product story should stay:

> enforce in the moment, preserve the trace after the fact.

### 5. Documentation and incident response are part of trust

Tony specifically called out proof, security assurances, and failure response.
That matters for pilots.

Erebor should have a small "review packet" for a pilot:

- what Erebor is and is not
- what surfaces are governed
- what policies are enforced
- what evidence is recorded
- where logs are stored
- what the agent cannot modify
- how to stop a run
- what happens during a failure
- response-time commitments for pilot support

Even if this is not a full enterprise SLA yet, the pilot needs a credible answer
to: "What happens if this fails?"

### 6. Conservative companies may be better early targets

Tony split companies into two rough groups:

- companies all-in on AI, using it everywhere
- more conservative companies that are worried

His clients are closer to the second group. That suggests the early wedge may be
where AI adoption is desired but blocked or slowed by trust concerns.

This is different from selling to teams that do not care about governance, and
different from selling to companies that have already accepted the risk.

## Product Requirements Suggested By Tony

- Clear explanation that Erebor is not an agent
- Governed runtime/sandbox framing
- Agent action audit trail
- Ability to reconstruct what happened
- Evidence useful for reversing or containing a wrong action
- Vendor/security assurance documentation
- Failure-response story
- Pilot support expectations or lightweight SLA
- IT/compliance-facing review packet
- Demo that shows an agent going beyond instructions and Erebor handling it

## Buyer And Discovery Notes

Tony points toward these roles:

- IT leaders who deploy AI systems
- compliance leaders who evaluate deployment risk
- privacy/legal counsel who influence approval
- conservative companies that want AI but worry about control
- startups building AI products that need to satisfy enterprise review

He did not have an immediate design-pilot referral, but said he would keep
Erebor in mind.

## Demo Changes Suggested

The demo should make the distinction very visible:

1. The agent is not Erebor.
2. The agent has a task.
3. The agent tries something risky or outside instructions.
4. Erebor mediates or blocks the action.
5. Erebor leaves a trace showing what happened.
6. The reviewer can understand whether the action can be reversed or contained.

This is the part Tony seemed to understand quickly once the framing was clear.

## Polished Structured Call Notes

The call with Tony was conversational.

Tony does not have a lot of direct agent experience yet. He works with startups
that are building AI-enabled or shadow-AI-related software, but mostly not
agents. The startups he sees also do not always have much enterprise
experience. One startup he is working with is building something closer to an AI
agent for accounts receivable.

Tony thinks companies will start using and testing agents soon.

Before I started asking my questions, Tony asked what I was building. I explained
Erebor, but at first he thought I was building a kind of governance agent. From
there, he started talking about agents themselves: which kinds might be useful,
and what can go wrong. He raised the risk that an agent might go rogue, fail to
follow instructions, or do harmful things. He gave examples of agents going off
track and said I should be prepared for that objection.

When I clarified that I am not building an agent, but a sandbox/runtime around
agents to govern them, he said that means I am building a solution to the
problem he had just described.

I asked him what he does when an agent or AI system comes to him for assessment.
He said he reviews the agent, the vendor, the guardrails, where the vendor is,
who the vendor is, what data the system accesses, and the basic privacy/security
controls around it. After that, he sends his opinion or concerns to the IT
people inside the company, because they are the ones who would deploy the
system.

I asked what happens when he sees a concern, and whether that blocks the agent.
He said IT listens to his advice. If the business tries to go around him and ask
IT directly for deployment, IT would usually check with him first.

He also said that once he says no, or raises a concern, the business may still be
able to accept the risk and deploy anyway. He has not seen that happen in this
exact context, but he sees it as possible.

I asked who I should talk to if I want to get closer to the deployment decision.
He said IT and compliance.

I asked what the bare minimum would be from a sandbox like Erebor. He said audit
trail. The reason is that if something goes wrong, the company needs to know what
happened and what the agent did, so they can understand the issue and reverse or
contain the wrong action where possible.

He also said there are two types of companies. Some are all-in on AI and use it
for everything. Others are more conservative and worried. His clients are closer
to the conservative group.

Tony said that if I can convince a company's IT or compliance team, then they can
buy.

He also said the documentation needs to be in order. A company would ask for
proof and security assurances.

He gave failure response as an example. If Erebor fails, what happens? What is
the response? I need to have an answer for that. I need to be able to say, for
example, that I will acknowledge the issue within a certain time, start
investigating within a certain time, and so on. In other words, I need some kind
of support or SLA answer, at least for pilots.

I asked if he knows anyone who might be interested in being a design pilot. He
said no, because he has not worked much in the agent industry yet, but he would
keep me in mind.

## Raw Notes

```text
Call with Tony

The call with Tony was conversational.

He does not have a lot of agent experience. He is working with startups who are
building AI shadow / AI-enabled software, but not agents.

These startups do not have enterprise experience. Only one startup he is working
with is doing some kind of AI agent for accounts receivable.

He thinks companies will start using/testing agents really soon.

Before I started questions, he asked about what I am doing, and I explained
Erebor, but he thought I am building a kind of governance agent itself. So he
started talking about agents and which ones would be useful. He mentioned the
issue that the agent might go rogue, not follow instructions, and start making
examples of agents going rogue and the horrible things they did, so I have to be
prepared for that. When I mentioned I am not building an agent, but a
sandbox/runtime for agents that can govern them, he said: so you are building a
solution to a problem I just mentioned.

I then asked him what he does once an agent comes to him for assessment.
He reviews the agent, vendor, guardrails, where the vendor is, who the vendor is,
what data it accesses, the guardrails, and this kind of basic stuff. Then he
sends his opinion/concerns about it to the IT people in the company. They are
the ones going to deploy the agent.

I asked him what happens when he sees a concern. Does it block the agent?
He said IT listens to his advice, and if the business goes around him and asks IT
for deployment, IT will check with him first.

He also said that once he says no or raises a concern, the business might be able
to accept the risk of deployment, so they would do that, but he has not seen that
in action.

Who should I talk to closer to the deployment decision?
IT and compliance department.

What is the bare minimum he would need from such sandbox?
Audit trail, in order to realize what happened and reverse the wrong action.
Audit trail is important. We need to know what it did.

He also said there are two types of companies: all-in on AI, where they use it
for everything; and another kind of company that is more conservative. These are
his clients. These guys are worried.

He said if I can convince a company IT or compliance team, then they buy.

He also said my documentation should be in order:
They would ask: show me the proof.
Security assurances.

For example, how do I respond in case of failure? I need to have an answer to
the question. I need to have an SLA. For example, I would acknowledge within this
amount of time, start investigation within this amount of time, and so on.

Does he know anyone who might be interested in being a design pilot?
No, because he has not worked a lot in agent industries, but he keeps me in mind.
```
