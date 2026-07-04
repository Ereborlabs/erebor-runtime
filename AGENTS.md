# Erebor Runtime Agent Instructions

This file is the entry point for agents working in this repository. It applies
to the whole repo unless a deeper `AGENTS.md` overrides it. External source
trees such as `openclaw/`, `playwright/`, and `cdp-rs/` may have their own
instructions and should not be edited unless the task explicitly asks for it.

## Start Here

Read these files before making non-trivial changes:

- [.agents/README.md](.agents/README.md) for the instruction map.
- [.agents/engineering.md](.agents/engineering.md) for Rust, CLI, SNAFU
  errors, logging, tests, and commit behavior.
- [.agents/planning.md](.agents/planning.md) before creating or rewriting
  project plans.
- [.agents/browser-cdp.md](.agents/browser-cdp.md) before touching CDP,
  browser ownership, Playwright/browser-use validation, or browser state.
- [.agents/verification.md](.agents/verification.md) before claiming a phase or
  example works.

Project plans are authoritative. If a request is tied to a milestone, stage, or
step, implement that scope and do not jump ahead without explicit approval.
Current planning documents live under [docs/](docs/) and
[docs/plans/](docs/plans/).
When creating or rewriting plans, follow the phase-plan style in
[.agents/planning.md](.agents/planning.md).

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
- Do not make architecture decisions on the user's behalf. Provide honest
  analysis, tradeoffs, and recommendations when useful; the user decides the
  architecture.
- When implementing a documented phase, update the relevant plan/status
  document before final handoff with a detailed current-status note, explicit
  verification results, and a clear `Done`, `Not done`, or `Blocked` state.
- No dead code, unused wiring, or placeholder skeletons that do not serve the
  current phase.
- Strong file-size rule: code files should stay under 300 lines. Treat this as
  almost non-negotiable; if a file must exceed it temporarily, document why and
  split it before adding more behavior.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` must
  be clean.
- Use crate-local SNAFU error modules: returned Rust errors belong in each
  crate's `src/error.rs` or a thin `src/error.rs` plus `src/error/*.rs`
  submodules, with `snafu::Location` context, `erebor_runtime_error::ErrorExt`
  mappings, and a local `Result<T>` alias where the crate has one primary
  error.
- Use repository telemetry wrappers for runtime logging. Direct `tracing`
  usage should stay inside telemetry setup/internals or narrow CLI logging
  setup.
- Prefer existing crate boundaries and local patterns over inventing new
  abstractions.
- CLI code is wiring only: parse arguments, translate them into crate-level
  requests, call the owning crate, and print/return results. Business logic,
  audit/session/policy/runtime orchestration, feature JSON/text rendering, file
  artifact handling, and e2e harnesses must live in the appropriate domain or
  e2e crates, not `erebor-runtime-cli`.
- Prefer upstream crates and mature protocol/domain libraries over hand-rolled
  implementations wherever they reasonably fit the problem and crate boundary.
  For CDP, use `cdp-protocol` for commands and events wherever the crate
  supports the shape. Manual JSON handling is only acceptable for unavoidable
  wire envelopes, generic forwarding, or crate gaps.
- The Playwright CDP demo acceptance criterion is that the example works against
  an Erebor-owned browser through the governed endpoint.

## Error And Logging Style

- Prefer `snafu::Snafu` for crate-owned error enums. `thiserror` is allowed only
  for narrow test helpers or temporary external glue that a current approved
  phase explicitly keeps and documents.
- Every crate that returns domain errors owns those errors in `error.rs`. If
  that file would exceed 300 lines, make `error.rs` a module root and split the
  variants by responsibility under `src/error/`.
- Error variants should carry structured context fields, `source` errors, and
  `snafu::Location`; avoid untyped string-only errors at public boundaries
  unless they are wrapped in a typed variant.
- Each public/domain error should implement `erebor_runtime_error::ErrorExt`
  with stable status/category and retry-hint mappings. Policy denials, invalid
  user input, and infrastructure failures must not collapse into one generic
  error class.
- Log errors once at the owning boundary with structured fields. Lower layers
  should return enriched errors instead of logging and rethrowing.
- Use `error!(err; "...")`/`warn!(err; "...")` style telemetry wrappers at
  runtime boundaries, with structured fields for operational context.
- `println!`/`eprintln!` are for CLI user output only. Runtime diagnostics use
  structured tracing.

## Working Style

Use `rg` for search. Use `apply_patch` for manual edits. Treat user changes as
owned by the user and do not revert them. If local verification is blocked by
the host environment, report the exact command and error, then keep the code
path diagnosable.
