# Engineering Rules

## Scope And Completion

- The user request and approved phase are the complete authorization. Do not
  add compatibility paths, abstractions, protocol/data-model changes, or
  adjacent cleanup without approval.
- Do not leave placeholders, unused production wiring, dead code, or APIs that
  do not serve the approved behavior.
- Each implementation phase needs real code-backed tests. Put crate-local proof
  beside its owner. Use `erebor-runtime-e2e` when the proof crosses crates, the
  CLI, processes, browser/CDP, mediation, or another lifecycle boundary. Manual
  probes support, but do not replace, committed tests.
- Keep plans and phase results aligned with current paths and behavior. Remove
  obsolete instructions when a move changes ownership.

## Implementation Review Workflow

- Use the `ponytail` skill for implementation work. Apply its simplification
  ladder after understanding the complete flow. Do not simplify input
  validation, error handling, security, accessibility, or an explicit user
  requirement.
- After an implementation is complete, use the
  `implementation-review-guide` skill to create or update a source-grounded
  review guide. The guide must explain the actual owners, reading route, data
  flow, lifecycle, tests, and applicable BPF or ABI boundaries. It must not
  present planned behavior as implemented behavior.

## Code Shape And Ownership

- Put domain behavior on the struct that owns its state, or behind a narrow
  trait at a real platform, runtime, protocol, policy, sink, or test-double
  seam. Loose production free functions are prohibited by default.
- A helper may be private, stateless, and local to one owner. If it needs
  configuration, paths, policy, runtime handles, sinks, clocks, I/O,
  validation state, or lifecycle state, make it an owner method or an owner
  collaborator.
- Keep related structs together when they share one responsibility. Keep
  sibling concepts in one module family: surfaces under a surface owner,
  runners under a runner owner, and session plans under a session owner. Do not
  create a one-off top-level sibling file unless it is the family root.
- Keep module roots thin. For a large domain, use a module root that declares
  focused submodules and intentionally re-exports the public surface. Do not
  use `lib.rs` as a dumping ground.
- Treat 300 lines as a readability signal, not a limit. Keep a larger cohesive
  owner when splitting it would hide its flow. A short file with orphaned
  functions is not simpler; move those functions onto their real owner.
- Keep validation on the validated type or a named validator. Do not leave
  stray `validate_*` functions, except for a private framework hook wrapped by
  an owner.
- Put real defaults in `Default`. A serialization or protocol `default_*` hook
  must be private and delegate to that owner’s `Default`.
- Use a constructor for a complete value. Use `add_*` or `set_*` for state that
  accumulates. Do not add decorative `with_*` builders or clone only to enable
  fluent chaining.
- Add traits only at a real seam. Do not add a trait with one implementation to
  hide a module split or make a local helper appear abstract.
- Borrow for read-only work and move at natural ownership boundaries. Use
  `Arc` or cloning only for a real shared async or lifetime requirement.
- Put tests beside the owner they prove. A shared test prelude may centralize
  imports, but it must not turn owner-specific scenarios into a generic bucket.
- Keep comments sparse and necessary. Every added or changed code comment uses
  **ASD-STE100**.

## Workspace Ownership

- `erebor-runtime-*` crates implement the general Erebor Runtime platform.
  Keep daemon, client, session, policy, audit, and surface behavior at their
  documented owners. The CLI remains a wiring boundary, not a second owner.
- `erebor-interceptor-abi` owns portable surface requests/results and exact
  Rust/C BPF map and event layouts. It is shared by Runtime adapters, Mithril,
  fixtures, and generated C; it does not own kernel lifecycle or policy.
- `erebor-interceptor` owns Linux preflight; BPF object load and attach; links,
  maps, pins, and the exclusive pin-root lease; capability readback; and scoped
  local subscriptions. It is the only loader and does not own policy semantics,
  actor state, evidence semantics, detection, or response.
- `mithril-node` embeds the Interceptor for Mithril mode. It owns node-local
  identity, signed policy activation, effect result handling, local evidence,
  and local response. `mithril-control` owns policy compilation/signing,
  secure node control, graph/finding work, approvals, and approved connectors.
  `mithril-e2e` owns fixtures, qualification, and release proof.
- A Runtime deployment can embed the shared Interceptor only after it obtains
  the same exclusive lease. It must use an authenticated, scoped client when
  Mithril owns the loader. Never start a Runtime loader and a Mithril loader at
  the same time.
- Do not move Mithril-specific identity, signed-policy, evidence, detection, or
  response ownership into the generic Interceptor. Do not create a second
  policy engine, kernel reader, or privileged node daemon.

## Architecture And Dependencies

- Identify the product boundary, durable owner, shared component, and
  exclusivity rule from the applicable plan before changing code. Do not infer
  ownership from a directory or crate name.
- Prefer the simplest architecture that preserves authorization, attribution,
  lifecycle, recovery, evidence, and physical-effect guarantees. A rename,
  code move, or second owner is not simplification.
- Reuse local patterns and mature crates or Rust bindings. Do not hand-roll a
  parser, protocol model, codec, cryptographic primitive, time utility, or
  system wrapper when an appropriate dependency fits the crate boundary.
- A command runner is appropriate only when the executable interface is the
  product boundary. Otherwise prefer a mature binding and a narrow owner seam
  for tests.
- When external code informs the work, translate the lesson into local rules.
  Do not copy another project’s style guide into a plan without approval.

## Runtime And CLI

- Runtime orchestration belongs in `erebor-runtime-core`; each governance
  runtime owns its runtime type in its crate.
- The CLI only parses, translates a request, invokes the owning crate, and
  renders user output. It does not own policy, audit/session/runtime
  orchestration, artifact handling, feature rendering, or e2e harnesses.
- `erebor start` starts configured governance layers. Keep `dev` commands on
  the same launch model where practical.
- Use restrictive Clap behavior. Tests must reject unknown, ambiguous,
  conflicting, and incomplete commands.

## Errors And Logging

- Use `snafu::Snafu` for crate-owned errors. Allow `thiserror` only for narrow
  test helpers or temporary external glue that an approved phase documents.
- A crate with returned domain errors owns them in `src/error.rs`, or in focused
  `src/error/` modules. Error variants carry structured context, a source when
  applicable, and `snafu::Location`; avoid string-only public errors.
- Keep a crate-local `Result<T>` alias when a crate has one primary error type.
  Map public/domain errors through `erebor_runtime_error::ErrorExt` with stable
  status, category, and retry hints. Never collapse policy denial, invalid
  input, and infrastructure failure into one error class.
- `erebor-telemetry` owns the repository telemetry wrappers and shared stderr
  initialization. Direct `tracing` is limited to telemetry internals,
  attributes, and narrow CLI setup.
- Service stderr uses the current human-readable `tracing-subscriber` format:
  timestamp, level, Rust target, static message, and optional `key=value`
  fields. Do not add a custom renderer. Use the Rust target for product and
  component filters.
- Use `ERROR` when the process cannot continue safely or fail-closed rollback
  fails. Use `WARN` for recoverable degradation. Use `INFO` for low-frequency
  lifecycle changes and expected security decisions. Use `DEBUG` for one
  request, retry, reconciliation step, or bounded batch. Use `TRACE` for
  high-frequency protocol and kernel detail.
- Log once at the boundary that selects exit, retry, rejection, quarantine, or
  reduced readiness. Lower layers return enriched errors. Put changing values
  in structured fields, for example `error!(err; "...", node_id = %node_id)`.
- Do not log policy, exception, evidence, audit, file, command, environment,
  credential, request-body, response-body, or complete Kubernetes metadata
  payloads. Use bounded identifiers, states, reasons, and counts.
- Use `println!` and `eprintln!` only for CLI user output or one logging
  initialization failure before a subscriber exists. Keep service logs out of
  command stdout.

## Change Control And Handoff

- Preserve unrelated user changes. Run `git commit` only when the user
  explicitly requests it. Stage only the requested scope and use a concise
  repository-style message. Otherwise, the user commits.
- For Rust changes, run the final shared CI procedure in
  [verification.md](verification.md) after the last relevant edit.
- At handoff, state what changed, verification evidence, any exact blocker,
  and the commit or a concise commit message. Do not include a phase name in
  any outward output unless the user explicitly asks.
