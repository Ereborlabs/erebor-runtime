# Engineering Rules

## Scope Discipline

- Follow the active plan, milestone, stage, or step exactly.
- Ask before moving to a different phase or changing architecture direction.
- When creating or rewriting plans, follow `planning.md` and use the repository
  phase-plan style.
- Do not add placeholders just to make a folder look complete.
- Do not leave unused variables, dead code, test-only wiring in production code,
  or functions that are not plugged into the current behavior.
- Keep file organization intentional: related structs can share a file; errors
  belong in each crate's `error.rs` or a thin `error.rs` module root with
  focused `error/*.rs` submodules; avoid dumping everything into `lib.rs`.

## Runtime Architecture

- Runtime orchestration abstractions belong in `erebor-runtime-core`.
- Each governance runtime implements its own runtime type in its own crate.
- The CLI starts configured runtimes from a launch plan. It should not own
  runtime-specific implementation details.
- `erebor start` starts all configured governance layers. Do not add one command
  per governance layer as the default user path.
- `dev` commands are convenience entry points, but they should still flow
  through the same runtime launch shape where possible.

## Rust Quality

- Prefer the repository's existing crate patterns and APIs.
- Use `snafu::Snafu` for crate-owned error enums. `thiserror` is allowed only
  for narrow test helpers or temporary external glue when an approved phase says
  so.
- Include enriched context with `snafu::Location` and structured context fields.
- Keep a crate-local `Result<T>` alias when a crate has one primary error type.
- Map public/domain errors to `erebor_runtime_error::ErrorExt` status/category
  and retry-hint implementations.
- Use repository telemetry wrappers for runtime logs. Direct `tracing` usage
  should stay inside telemetry setup/internals or narrow CLI logging setup.
  Avoid `println!` except CLI user output.
- Log errors once at the owning boundary with structured fields; lower layers
  return enriched errors instead of logging and rethrowing.
- Keep public APIs small and useful for the current phase.
- Avoid manual string parsing when a structured parser or protocol crate exists.
- Keep comments sparse and useful.

## CLI Rules

- Use restrictive Clap behavior.
- Unknown, ambiguous, conflicting, or incomplete commands should fail tests.
- Command names should be clear and short. The runtime start command is
  `start`.

## Commit Behavior

- Never run `git commit` unless the user explicitly asks and approves.
- Always provide a concise commit message at the end of code-changing work.
- Do not include stage numbers in commit messages unless the user asks for that.
- Do not revert user changes. If unrelated files are dirty, ignore them.

## Baseline Commands

Use these before claiming code is clean:

```sh
cargo fmt
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Run narrower tests first while iterating, then run the workspace checks when the
change is ready.
