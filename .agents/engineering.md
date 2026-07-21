# Engineering Rules

## Scope Discipline

- Follow the active plan, milestone, stage, or step exactly.
- Ask before moving to a different phase or changing architecture direction.
- When creating or rewriting plans, follow `planning.md` and use the repository
  phase-plan style.
- Do not add placeholders just to make a folder look complete.
- Do not leave unused variables, dead code, test-only wiring in production code,
  or functions that are not plugged into the current behavior.
- Every implementation phase needs real code-backed tests for the behavior it
  changes. Put tests beside the crate owner when the behavior is crate-local;
  put fixtures and tests in `erebor-runtime-e2e` when the proof crosses crates,
  process boundaries, the CLI binary, browser/CDP, session mediation, or other
  lifecycle boundaries. Shell probes and manual runs support the evidence but
  do not replace committed Rust tests.
- Keep file organization intentional: related structs can share a file; errors
  belong in each crate's `error.rs` or a thin `error.rs` module root with
  focused `error/*.rs` submodules when that improves readability; avoid
  dumping everything into `lib.rs`.
- Treat the 300-line guideline as a readability smell detector, not an
  absolute law. Prefer files around or under 300 lines when ownership remains
  clear, but do not split cohesive owners, command families, or scenario tests
  into tiny fragments just to satisfy a count. If a larger file is clearer,
  document why and keep unrelated behavior out of it. A readable 700-line file
  with a clear responsibility is preferable to several loosely organized
  200-line files that fragment the logic and make it harder to follow.
- Keep sibling domain concepts in the same module family. If browser,
  terminal, and filesystem are all surfaces, they belong under the surface
  owner; if Docker and Linux-host are runners, they belong under the runner
  owner. Avoid one-off top-level files for a sibling concept unless the file is
  itself the family root.
- Prefer ownership-oriented organization over clusters of unrelated free
  functions. Loose production free functions are prohibited by default. When
  several operations repeatedly need the same state, config, paths, policy,
  engine, sink, clock, IO handle, or runtime handle, introduce a small owner
  struct and make those operations methods on that owner.
- Pure helper functions are allowed only when they are truly stateless, private,
  local to the owner that uses them, and make that owner easier to read. If a
  helper needs repeated context, mutates lifecycle state, coordinates IO, owns
  path/clock/copy decisions, or crosses a policy/protocol boundary, it should
  become an owner method or move behind an existing domain trait.
- Do not treat line count as the only cleanup signal. A short file with
  orphaned functions can still be harder to follow than a larger cohesive
  owner. During ownership cleanup, audit loose functions explicitly and move
  them onto an owner when doing so improves readability, call flow, or
  lifecycle ownership.
- Validation belongs to the validated type or to a named validator owner. Avoid
  stray `validate_*` functions unless they are private framework hooks wrapped
  by an owner.
- Real defaults belong in `Default` impls or derives. Avoid `default_*` helper
  functions unless a serde or protocol hook requires that spelling; such hooks
  should be private and delegate to the owning `Default`.
- Avoid decorative builder-style `with_*` APIs. Use a constructor for complete
  values, and use explicit mutating owner methods such as `add_*` or `set_*`
  for accumulated options. Do not add clones or moves merely to support fluent
  chaining.
- Put traits at real seams: runtime/platform seams, policy or sink contracts,
  protocol boundaries, and test doubles. Do not add traits only to hide a large
  module split or to make a local helper look abstract.
- Avoid extra ownership churn while reorganizing. Pass references where the
  callee only reads, move values when ownership naturally transfers, and use
  `Arc`/clone only for actual shared async or lifetime boundaries.
- Keep module roots thin. Prefer `module.rs` plus `module/*.rs` for large
  domains, with the root declaring modules and re-exporting the public surface
  intentionally.
- Put owner tests beside the owner where practical. A small test prelude may
  centralize imports, but scenario tests should not drift into a generic bucket
  when an obvious owner module exists.
- Keep plans and phase files grounded in the current source tree. When a split
  moves a concept into a family directory, update the phase text to use the new
  path and remove stale one-off module names from future instructions.
- Prefer the least complex architecture that preserves the complete correctness
  and enforcement contract. Never call a change a simplification when it only
  moves complexity into another owner or collapses distinct authorization,
  protocol, lifecycle, recovery, evidence, or physical-effect boundaries.
- If external codebases are used for taste or organization research, translate
  the lesson into local engineering rules. Do not name or copy external repo
  style instructions into phase plans unless the user explicitly requests the
  citation.

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
- Prefer mature, well-maintained crates for standard domain primitives such as
  hashing, crypto, parsing, codecs, protocol types, URL handling, and time.
  Hand-rolled implementations are allowed only when a phase explicitly
  documents why an upstream crate is unsuitable.
- Prefer mature Rust bindings for system/domain tools over stringly command
  wrappers. A command runner is acceptable when the executable interface is the
  actual product boundary, but crate-owned runtime behavior should normally use
  a library binding with an owner trait seam for tests.
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

For Rust changes, use the shared CI procedure before claiming code is clean:

```sh
bash .github/scripts/verify-rust-ci.sh
```

Run narrower tests first while iterating. Run the shared procedure only after
the final relevant edit; a result from an earlier working-tree state does not
cover later source, test, manifest, workflow, or verification-script changes.
