# Agent Instruction Map

This directory keeps detailed agent guidance out of the root `AGENTS.md` while
making the rules easy to reference.

## Files

- [engineering.md](engineering.md): coding standards, crate boundaries, CLI
  rules, error/logging style, and commit behavior.
- [planning.md](planning.md): phase-plan style, current-code grounding,
  verification claims, and follow-up tracking.
- [browser-cdp.md](browser-cdp.md): browser governance, CDP proxy rules,
  browser state authority, Playwright/browser-use validation, and future
  process/endpoint governance.
- [verification.md](verification.md): required checks, real example acceptance,
  and how to handle host-specific browser failures.

## Canonical Plans

Use these plans as source material when work touches their area:

- [docs/development-plan.md](../docs/development-plan.md)
- [docs/governed-browser-and-terminal-plan.md](../docs/governed-browser-and-terminal-plan.md)
- [docs/browser-state-authority-plan.md](../docs/browser-state-authority-plan.md)
- [docs/plans/browser-governance/browser-level-cdp/README.md](../docs/plans/browser-governance/browser-level-cdp/README.md)
- [examples/playwright-cdp-demo/README.md](../examples/playwright-cdp-demo/README.md)

If a plan and the current user instruction conflict, follow the current user
instruction and update the plan only when the user asks for that.
