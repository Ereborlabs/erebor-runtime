# Amy Wittmann Written Findings

Date: 2026-06-25

Profile: Amy Wittmann  
LinkedIn: not captured in the pasted thread

Profile context: Attorney / data protection / AI governance / digital law

Interview type: written legal/privacy/AI-governance practitioner feedback

## Summary

Amy's thread was the first conversation that clearly shifted the framing away
from "show controls first" and toward "define the agent mandate first."

Her core point was that a legal/privacy reviewer would not start with runtime
controls, architecture, or liability. They would start one step earlier:

- intended use case
- operating boundaries
- data categories
- approval and supervision authority
- responsibility allocation

Only after those are clear would she move to deployment architecture, technical
controls, and allocation of legal responsibility under frameworks like GDPR and
the EU AI Act.

This is one of the most important product lessons so far: Erebor's runtime
controls only become legible to legal/privacy if they map back to an approved
mandate.

## What This Means For Erebor

### 1. Start the demo with the agent mandate

The demo should not begin with OAuth mediation, CDP, logs, or policy machinery.
It should begin with the approved workflow:

- what the agent is supposed to do
- what data it can touch
- what systems it can use
- what actions it can take
- what actions require approval
- who supervises it
- who can stop it
- who is accountable if it exceeds the mandate

Then Erebor can show that the runtime enforces and evidences that mandate.

### 2. Governance should be a product feature, not only a compliance exercise

Amy explicitly warned against thinking about governance purely as compliance.
She said well-designed governance can become a product feature and competitive
advantage, especially for enterprise customers in regulated industries.

This supports the current hypothesis-buyer path:

- agent vendors selling into enterprises
- regulated enterprise teams deploying agents
- buyers who need evidence and control before letting agents touch real systems

### 3. Independent controls outside the agent matter

Amy found the idea of policy enforcement outside the agent interesting. She
said relying only on prompts is unlikely to be sufficient for enterprise
deployments.

That validates Erebor's core technical stance:

- prompts are not a control boundary
- the enforcement layer should sit outside the agent
- auditability and responsibility allocation need to be evidenced
- autonomy increases the importance of independent controls

### 4. Deployment model changes the legal analysis

Amy's first reply highlighted SaaS, self-hosted, and white-label deployments,
plus contractual responsibility allocation.

For Erebor this means the evidence packet should identify:

- deployment model
- who operates the runtime
- who controls policies
- where data is processed
- what the vendor/customer responsibility split is
- what is self-hosted versus third-party controlled

This later connects directly to George's "Who / Where / Why" frame.

### 5. Role allocation is central

Amy mentioned AI governance frameworks, role allocation matrices, and
responsibility models. This matters because Erebor should not only show what
the agent did. It should also show who had authority over each stage:

- who approved the workflow
- who defined the boundary
- who approved a risky action
- who could stop the run
- who owns residual risk

### 6. The strongest buyer language is not "DPO approval"

Amy is a strong validator, but her answers also show why DPO/legal may not be
the buyer. She frames what a reviewer would need to see. The buyer is still
likely the team or vendor trying to get the workflow approved, sold, or deployed.

## Comparison With Later Interviews

### Compared With Alex

Amy gave the upstream legal/governance frame: mandate before controls. Alex made
the evidence requirements concrete: structured execution logs, blocked attempts,
kill switch, limited pilot, and control during sensitive or irreversible actions.

Together:

- Amy says what must be defined before review.
- Alex says what evidence/control makes the review credible.

### Compared With George

Amy's mandate frame is broader. George's version is sharper and more practical:
Who, Where, and Why. George also adds the phrase "actual blockade," which turns
Amy's independent control-layer idea into a clearer product requirement.

Together:

- Amy: define authority, boundaries, and accountability.
- George: prove Who / Where / Why, and provide actual blockade.

### Compared With Kayne

Kayne warned that legal/GRC/DPO may not always be real blockers or buyers. Amy
does not contradict that. She shows what a serious reviewer would want to see if
the organization actually has a review path.

The current discovery goal remains:

Are agent workflows blocked, delayed, narrowed, approved with conditions, or
deployed anyway?

Amy helps define what "approved with conditions" should require.

## Product Requirements Suggested By Amy

- Agent mandate record
- Intended use-case description
- Data category mapping
- Operating boundary definition
- Approval/supervision/stop authority
- Responsibility allocation matrix
- Deployment-model disclosure: SaaS, self-hosted, on-premises, white-label
- Runtime controls tied back to the approved mandate
- Evidence that policy enforcement is outside the agent
- Governance-layer and execution-layer separation
- Review packet for legal/privacy/AI-governance stakeholders

## Demo Changes Suggested

The demo should show:

1. A clear intended use case.
2. The approved operating boundary.
3. Who can approve, supervise, and stop the agent.
4. A governed run inside that boundary.
5. A risky action mediated by Erebor.
6. An out-of-boundary action blocked by Erebor.
7. Evidence connecting the runtime trace back to the mandate.
8. A clear separation between the execution layer and governance layer.

## Full Conversation Text, Lightly Cleaned

### Initial Outreach

**Navid:** Hi Amy, I'm Navid, building Erebor. I'm interviewing legal/privacy
leaders about how AI-agent access gets reviewed when customer data or SaaS
authority is involved. I know your time is valuable; would you be open to 15
minutes of candid feedback?

**Amy:** Hi Navid, I have no time the next weeks - I am travelling on business -
feel free to send me your questions. Best regards, Amy.

### Written Questions

**Navid:** Hi Amy,

Thank you, I really appreciate that, especially while you're traveling.

I'm building Erebor around governing AI agents when they do real work on a
computer: running commands, using tools, browsing, and interacting with systems
that carry real access. I'm trying to learn what a legal/privacy reviewer would
actually need to see before being comfortable with those workflows.

If you're open to it, I'd really value your take on a few short questions:

1. When an AI agent may touch personal data or SaaS authority, who usually needs
   to sign off?
2. What evidence would you want from a real agent run before you'd consider that
   workflow acceptable?
3. Is auditability after the fact enough, or do you also need the ability to
   mediate or stop certain actions in the moment?
4. Where do current AI-agent tools feel weakest from a data protection or
   AI-governance perspective?
5. If something like this were brought to you for review, what would make you
   take it seriously versus dismiss it quickly?

Even brief thoughts or bullets would be genuinely helpful. No rush at all, and
thank you again for being open to this.

Best regards,  
Navid

### Amy On Deployment Models And Responsibility

**Amy:** Thank you for your thoughtful questions. They raise some very
interesting legal and technical issues, particularly around AI deployment
models, cloud architecture and the allocation of operational responsibility.

At a high level, there is no single answer, as much depends on whether a
solution is provided as SaaS, self-hosted software or as a white-label
deployment, and on how responsibilities are allocated contractually between the
parties involved.

Out of curiosity, may I ask what prompted your interest in these particular
topics? Are you currently working on a specific AI project or researching
white-label architectures?

### Navid's Context

**Navid:** Hi Amy,

Thank you. This is really helpful. The distinction between deployment models is
exactly the kind of nuance I was hoping to understand better.

What prompted this is mostly practical experience. I use coding agents every
day, and I kept running into the same uncomfortable pattern: instructions given
to the agent are not really a control boundary. The agent may misunderstand,
forget, or work around a restriction while trying to complete a task.

That led me to start building Erebor, an open-source, self-hostable runtime for
governing AI agents when they operate on a real computer, running commands,
using tools, browsing, or interacting with systems that carry real access. The
idea is that some controls should exist outside the agent itself, so actions can
be observed, mediated, blocked when necessary, and reviewed afterward.

It is still early, so I'm trying to learn from people who understand data
protection, AI governance, and responsibility allocation before I make too many
assumptions.

Your point about the deployment model changing the analysis makes a lot of
sense. If you were reviewing something like this, would you typically start with
the technical control model, the deployment architecture, or simply who is
responsible when something goes wrong?

Best regards,  
Navid

### Amy On Use Case And Governance Before Controls

**Amy:** Thank you, Navid. I appreciate the additional context, and I think
you're asking exactly the right questions.

Based on what you've described, I would probably start neither with the
technical control model nor with the question of liability. I would start one
step earlier: the intended use case and the governance model.

From a legal perspective, those two elements drive almost everything that
follows. Before looking at architecture or controls, I would typically want to
understand:

- What is the agent actually authorised to do?
- What categories of data may it access or process?
- Who defines its objectives and operating boundaries?
- Who has the authority to approve, supervise or stop its actions?
- Who bears responsibility if the agent exceeds its mandate or causes harm?

Only once those questions are answered would I move on to the deployment
architecture (SaaS, self-hosted, on-premises, etc.), the technical control model
and finally the allocation of legal responsibilities under frameworks such as
the GDPR and the EU AI Act.

One point I find particularly interesting in your description is the idea that
policy enforcement should exist outside the agent itself. In my view, relying
solely on prompts as a governance mechanism is unlikely to be sufficient for
enterprise deployments. Independent control layers, auditability and clearly
defined responsibility allocation are becoming increasingly important,
particularly as agents are entrusted with higher levels of autonomy.

In fact, I have been working extensively on AI governance frameworks, role
allocation matrices and responsibility models for enterprise AI deployments,
and one recurring theme is that many organisations start by asking, "What can
the agent do?" whereas the more useful legal question is often, "Who is
accountable for each stage of the decision-making process, and what controls
exist to evidence that accountability?"

It is a fascinating area, and I suspect the legal and governance architecture
will become just as important as the underlying AI capabilities over the next
few years.

I would be interested to see how Erebor evolves.

### Navid's Reply

**Navid:** Hi Amy,

Thank you. This is honestly very helpful, and I really appreciate you taking the
time to write such a thoughtful answer to a cold message.

You gave me a better way to think about the problem. I was too quickly jumping
into the runtime/control layer, and your answer helped me see what needs to be
clearer before that.

I'm going to sit with this and use it to sharpen both the product and the demo.
If you're open to it, I may send you a cleaner version once I've worked this in.
I'd be curious whether it matches how you'd think about the governance side.

And if anything else comes to mind later from your own work in this area, I'd
be very glad to hear it.

Thank you again,  
Navid

### Amy On Governance As Product Feature

**Amy:** Thank you, Navid. I appreciate your kind words.

From my perspective, that's actually one of the most interesting aspects of AI
governance. People often jump directly to technical controls or runtime
restrictions, but in my experience the more fundamental questions are: What is
the intended use case? Who defines the operating boundaries? Who has authority
over the agent? And how is responsibility allocated and evidenced?

Those foundational decisions tend to drive the legal analysis rather than the
other way around.

I'd certainly be happy to take a look at a future version from that perspective.
One suggestion I would make is to avoid thinking about governance purely as a
compliance exercise. Well-designed governance can become a product feature and
a competitive advantage, especially for enterprise customers in regulated
industries.

If and when you have a more mature architecture or demo, feel free to share it.
I would be interested to see how you've approached the separation between the
execution layer and the governance layer.

Best of luck with the project in the meantime.

## Follow-Up To Consider

Amy explicitly invited a future architecture/demo once it is more mature. The
best follow-up should be short and not a recap of her own advice.

Possible future note:

```text
Hi Amy,

I hope your travels went well. I have a cleaner version of the Erebor demo now,
and I tried to make the agent mandate and governance layer clearer before
showing the runtime controls.

If you are still open to it, I would be grateful to send a short summary or show
you the demo and get your candid reaction.

Best regards,
Navid
```

