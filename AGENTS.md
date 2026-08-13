# Erebor Runtime Agent Instructions

This file applies to the repository root. A deeper `AGENTS.md` overrides it.
Do not edit external source trees such as `openclaw/`, `playwright/`, or
`cdp-rs/` unless the task explicitly includes them.

## Read First

1. Read [.agents/README.md](.agents/README.md). It is the map for every local
   instruction, plan family, and documentation family.
2. Read the guide that matches the work before editing: `engineering.md` for
   code, `planning.md` for plans, `browser-cdp.md` for browser/CDP work, and
   `verification.md` before claiming a result.
3. Read the relevant current plan and its supporting documents. Use
   [docs/README.md](docs/README.md) and
   [docs/plans/README.md](docs/plans/README.md) as the document and plan
   indexes; do not rely on a remembered or stale path.

## Product Shape

This workspace contains related products, integrations, and shared components.

- **Erebor Runtime** is the universal action-governance platform for agents and
  tools. Browser/CDP is one proof surface; the model must extend to terminal,
  filesystem, APIs, SaaS tools, desktop automation, MCP, and internal systems.
- **Erebor Interceptor** is a shared Linux kernel component family. It is not a
  daemon or policy authority.
- **Mithril** is the Linux/Kubernetes prevention, evidence, causality, and
  verified-response product. It uses the shared Interceptor without replacing
  Erebor Runtime.
- **Integrations and adoption surfaces** use Erebor Runtime. They do not become
  the enforcement boundary.

The exact crate and runtime ownership model is in
[.agents/engineering.md](.agents/engineering.md). Keep it there so this root
guide does not duplicate implementation rules.

An SDK or integration can improve adoption, but it is not enforcement. An
action is governed only when it uses an Erebor-controlled execution path.

## Product And Plan Discovery

This repository contains multiple products, integrations, and shared
components. Derive the task-specific product boundary, owner, scope, and
status from the current documentation and plans; do not assume all work belongs
to one product.

Start with the documentation indexes, then use `rg --files docs docs/plans` to
find the relevant material. Read the applicable parent document, master plan,
nested plan, phase, result, acceptance record, and linked design before acting.
When records differ, preserve the difference and do not claim more than the
narrowest proven result.

Do not put plan titles, phase numbers, implementation status, or a product
catalogue in agent instructions. Plans change independently; the instructions
must remain a stable method for finding and reading them.

## Scope And Authority

- The explicit user request and its active plan are the implementation scope.
  Do not move to another phase, change architecture, or add adjacent work
  without approval.
- Plans guide implementation, but the current user request takes precedence.
  Reconcile recovered or historical plans with the checked-out source before
  treating them as current.
- Simplification is valid only when the remaining owner still preserves
  authorization, attribution, lifecycle, recovery, evidence, and physical
  effect guarantees.
- For a documented implementation phase, update its status with the work done,
  verification evidence, and an explicit `Done`, `Not done`, or `Blocked`
  result before handoff.
- Keep phase names inside their planning documentation. Do not put them in a
  commit message, handoff, status output, code comment, log, or other outward
  work unless the user explicitly asks.

## Documents And Comments

- Treat every plan and document as user-owned source material. Preserve its
  structure and content unless the user explicitly asks to replace or rewrite
  that exact file. Add narrowly scoped material instead of condensing a
  document wholesale.
- Every plan and documentation change—README, guide, design, research note,
  example, runbook, plan, phase, or status—and every code comment written or
  changed by an agent must use **ASD-STE100**. Keep the text direct, precise,
  and necessary.
- Write documents for engineers who must make, review, operate, or verify the
  work. State concrete behavior, owners, inputs, outputs, limits, commands,
  examples, and proof where they help the reader act. Do not write management
  reports, generic strategy prose, boilerplate bullets, or filler. Prefer a
  short direct explanation or example over an abstract summary.
