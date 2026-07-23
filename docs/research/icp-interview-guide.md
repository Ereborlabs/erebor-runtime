# Hypothesis ICP Interview Guide

Use this guide for likely buyers, champions, and people closer to deployment pain.

Hypothesis: the buyer is not usually DPO/legal. The buyer or champion is the
team trying to deploy, buy, or sell agents that can do real work. DPO, legal,
security, and GRC may be approvers, validators, reviewers, or pressure sources,
but they often do not own the budget, deployment path, or enforcement boundary.

Important correction: this was not learned only from Kayne. Before the Kayne
call, we had already moved away from "DPO is the buyer" toward "DPO/legal are
approvers or validators." Kayne sharpened the next point: even as approvers,
they may not be able or willing to block agent workflows directly. In many
organizations, they may advise, document risk, ask questions, push contractual
responsibility, or define review expectations, while the actual deployment and
economic pressure sits with the team selling, buying, or shipping the agent.

So the interview goal is not simply "what would a DPO approve?" The goal is to
find who feels real pressure to make agent deployment trusted enough to happen,
and what role DPO/legal/security/GRC play in that decision.

Important counterexample: some companies do have real gates. For example,
Claude cowork being banned at Just Eat Takeaway means the market is not only
"companies deploy anyway." Some organizations already restrict or ban agentic
tools when they cannot evaluate the risk.

The better segmentation is:

- Some companies deploy anyway and shift risk later.
- Some companies ban or tightly restrict agentic tools.
- Some vendors lose or slow enterprise adoption because their buyer is in the
  second group.

Erebor is most likely urgent for the second and third cases: teams inside
restricted organizations, and vendors trying to sell into restricted
organizations.

## Learning From Kayne

Kayne's call sharpened the market map, not the product feature list.

The key learning is that GRC, legal, privacy, and DPO teams may not be the
buyer, and in many organizations they may not even be a clean blocking gate.
They may advise, document risk, push responsibility into contracts, or try not
to be the team that says no. That means we should not build the whole company
story around "legal will block agents."

At the same time, Kayne's view is not the whole market. Some companies really
do ban or restrict agentic tools. The useful segmentation is:

- companies that deploy anyway and accept or transfer risk
- companies that ban or restrict agents until there is a control story
- vendors selling agents into companies that ban or restrict them

This changes the buyer question. The strongest buyer may be the person or
company that needs agent deployment to be trusted by someone else:

- an agent vendor trying to pass enterprise security review
- an agent-company founder, CTO, product leader, field CTO, solutions leader,
  or enterprise/revenue owner who loses time or deals when buyers do not trust
  the agent

Internal AI platform, security, product security, DPO, legal, GRC, and
AI-governance people are still useful interview targets. They help explain the
buyer objections. But they are not the current hypothesis buyer.

For interviews, do not ask only "what would a DPO approve?" Ask whether agent
tools are actually banned, restricted, delayed, or pushed into contracts, and
who loses when that happens.

## Learning From Amy

Amy's feedback sharpened the buyer hypothesis. The approval blocker is not only "show me logs" or "show me controls." Before approvers look at architecture, they want the use case and governance model to be clear:

- what the agent is authorized to do
- what data and systems it may touch
- who defines its objectives and boundaries
- who can supervise or stop it
- who is accountable if it exceeds its mandate

For buyer interviews, this means we should look for people who already own this messy translation from "we want agents" to "this is an approved, governed workflow." Erebor should be tested as a way to make that mandate enforceable and evidenced, not merely as logging.

## Target Profiles

- Founders or product leaders selling agent products into enterprises
- CTOs, CPOs, field CTOs, solutions leaders, and enterprise/revenue leaders at agent vendors
- Secondary learning targets: AI platform owners, security/product-security,
  DPO/legal/GRC, and internal teams whose agent projects got stuck in review

## LinkedIn Search Mode

Use `linkedin_playwright_collect.py --search-set hypothesis-buyers` or:

```bash
./run.sh collect-hypothesis-buyers outreach-prospects-hypothesis-buyers.csv http://127.0.0.1:9222
```

This search mode is for the current buyer hypothesis, with two lanes:

- agent vendors selling AI agents into enterprise
- European or regulated enterprise teams trying to deploy agentic workflows
  under a real review bar

Good agent-vendor profiles are founders, CEOs, CTOs, CPOs, product leaders,
field CTOs, solutions leaders, and enterprise/revenue leaders.

Good regulated-enterprise profiles are AI-platform owners, enterprise-AI
leaders, product-security/AppSec leaders, security architects, responsible-AI
owners, and AI-governance/risk leaders only when their work is tied to real
agent deployment.

Weak profiles are DPOs with no deployment ownership, generic compliance/GRC
reviewers, IC AI engineers, generic consultants, advisors, students,
recruiters, and broad AI commentators.

## Opening

Thanks for taking the time. I am building Erebor around governing AI agents when they operate a computer: running commands, using tools, browsing, and interacting with systems that carry real access.

The thing I am trying to understand is practical: when a team wants to deploy or
sell agents into a real organization, do those workflows get allowed, restricted,
or banned, who owns that decision, and what evidence or controls would actually
change the conversation?

## Core Questions For Enterprise AI / Platform / Security Teams

1. Are teams in your organization already trying to use agents that can take actions, not just answer questions?

2. What kinds of actions are people asking agents to perform: command execution, code changes, browser work, SaaS admin actions, customer support, data operations, internal tools, or something else?

3. For those workflows, who defines what the agent is allowed to do and what it must not do?

4. Where does deployment get slowed down or blocked today?

5. Have any agentic tools been banned, restricted, or limited to toy data in your organization?

6. Who has to say yes before an agent can touch real systems or customer data?

7. Who has authority to supervise, pause, or stop the agent once it is running?

8. What is the current workaround when approval is not there: manual review, restricted accounts, read-only access, shadow usage, custom scripts, internal policy, or just no deployment?

9. What evidence would you need from a real agent run to trust that it stayed within its mandate?

10. Which matters more for approval: visibility after the fact, real-time control, least-privilege access, human approval gates, or accountability records?

11. If an agent runs a command, opens a browser, or uses a tool it should not use, what should happen in the ideal system?

12. Who would own the budget for solving this: AI platform, security, product security, infrastructure, GRC, the business unit, or the agent team?

13. If Erebor only solved one painful workflow first, which workflow would be most valuable?

## Questions For Agent Vendors Selling To Enterprises

1. When you sell agents into enterprises, where do deals slow down: security review, legal/privacy review, procurement, technical evaluation, or buyer uncertainty?

2. What questions do enterprise buyers ask that are hardest to answer today?

3. Have deals or pilots stalled because the customer was uncomfortable with agent autonomy, data access, command execution, browsing, or SaaS permissions?

4. Have customers told you they ban, restrict, or cannot approve tools like Claude, ChatGPT, Copilot, browser agents, or desktop agents?

5. What evidence would help your buyer get internal approval faster?

6. Do customers ask who defines the agent's operating boundaries and who is accountable if the agent crosses them?

7. Would a governed runtime / control layer be valuable as part of your product, as a deployment option, or as evidence during sales?

8. Do customers ask for self-hosted, private cloud, on-prem, audit logs, policy controls, or admin approval flows?

9. Who on the customer side becomes the blocker or champion after the initial buyer is interested?

10. What would make this worth paying for instead of building your own control layer?

## Questions For Teams With Blocked Agent Projects

1. What agent workflow did you want to deploy?

2. Who wanted it, and what business result were they trying to get?

3. What stopped or slowed it down?

4. Was the objection technical, security, legal, privacy, operational, or ownership/accountability?

5. Was there a clear owner for the agent's mandate, boundaries, supervision, and accountability?

6. What did you try as a workaround?

7. If you could show a reviewer one artifact from a real agent run, what would need to be in it?

8. Would a limited governed pilot have helped, or was the workflow fundamentally too risky?

## Signals To Listen For

Strong buyer signal:

- They have a named agent workflow already blocked or delayed.
- They have a named company or buyer segment where agentic tools are banned,
  restricted, or limited to synthetic/toy data.
- They can name the approving team and the deployment owner.
- They have tried workarounds: restricted accounts, manual approvals, sandboxing, logging, custom proxies, internal review boards.
- They say current tools do not give enough runtime control or evidence.
- They have budget or ownership for AI platform, security controls, vendor enablement, or governance infrastructure.
- They are responsible for turning an agent's intended use case into approved operating boundaries.
- They care about independent enforcement outside the agent, not only prompt instructions.
- They ask whether Erebor can support commands, tools, browsers, SaaS actions, and self-hosted deployment.
- For vendors: they can connect the problem to delayed pilots, security review
  friction, enterprise deployment requirements, or lost revenue.

Weak signal:

- They only have curiosity about agents, not active deployment pressure.
- They talk about generic AI governance but no specific workflow.
- They think the problem is solved by training, policy, or model choice.
- They cannot identify who owns approval or operation.
- For vendors: they have never seen buyer restrictions affect deals,
  deployment, security review, or customer commitments.

## Best Closing Questions

1. If this problem became urgent tomorrow, who would own fixing it?

2. Who else should I talk to who has actually tried to deploy or sell agents into this kind of approval process?

3. Is there one real workflow where a governed runtime could make a pilot possible sooner?
