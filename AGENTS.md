# Erebor Runtime Agent Instructions

This file is the entry point for agents working in this repository. It applies
to the whole repo unless a deeper `AGENTS.md` overrides it. External source
trees such as `openclaw/`, `playwright/`, and `cdp-rs/` may have their own
instructions and should not be edited unless the task explicitly asks for it.

## Start Here

Read these files before making non-trivial changes:

- [.agents/README.md](.agents/README.md) for the instruction map.
- [.agents/engineering.md](.agents/engineering.md) for Rust, CLI, errors,
  logging, tests, and commit behavior.
- [.agents/browser-cdp.md](.agents/browser-cdp.md) before touching CDP,
  browser ownership, Playwright/browser-use validation, or browser state.
- [.agents/verification.md](.agents/verification.md) before claiming a phase or
  example works.

Project plans are authoritative. If a request is tied to a milestone, stage, or
step, implement that scope and do not jump ahead without explicit approval.
Current planning documents live under [docs/](docs/) and
[docs/plans/](docs/plans/).

## Product Direction

Erebor Runtime is a universal action-governance runtime for agents and tools.
CDP/browser governance is the first proof surface, not the whole product.
Architecture should remain extensible to terminals, APIs, SaaS tools, desktop
automation, MCP, internal systems, and agent runtimes such as OpenClaw, Codex,
Claude Code-like tools, and custom clients.

SDKs and integrations improve adoption, but they are not the enforcement
boundary. The enforcement boundary is the Erebor-controlled execution path.

## Non-Negotiables

- Do not commit. The user commits. Always provide a short commit message at the
  end of code-changing work.
- No cosmetic churn. Keep changes scoped to the requested phase or bug.
- No dead code, unused wiring, or placeholder skeletons that do not serve the
  current phase.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` must
  be clean.
- Use `thiserror` for error types and `snafu::Location` or similar context where
  the crate pattern expects enriched errors.
- Use `tracing` for runtime logging.
- Prefer existing crate boundaries and local patterns over inventing new
  abstractions.
- CLI code is wiring only: parse arguments, translate them into crate-level
  requests, call the owning crate, and print/return results. Business logic,
  audit/session/policy/runtime orchestration, feature JSON/text rendering, file
  artifact handling, and e2e harnesses must live in the appropriate domain or
  e2e crates, not `erebor-runtime-cli`.
- Use `cdp-protocol` for CDP commands and events wherever the crate supports
  the shape. Manual JSON handling is only acceptable for unavoidable wire
  envelopes, generic forwarding, or crate gaps.
- The Playwright CDP demo acceptance criterion is that the example works against
  an Erebor-owned browser through the governed endpoint.

## Working Style

Use `rg` for search. Use `apply_patch` for manual edits. Treat user changes as
owned by the user and do not revert them. If local verification is blocked by
the host environment, report the exact command and error, then keep the code
path diagnosable.
