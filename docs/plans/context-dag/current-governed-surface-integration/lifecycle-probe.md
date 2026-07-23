# Current-Surface Context Integration Lifecycle Probe

Status: Planned. Required after every implementation phase after Phase 0.

## Purpose

Prove that the session-owned context integration works across the real runtime
lifecycle, not just through crate-local serialization tests. The probe combines
the deterministic CDP mini-upstream fixture with a Linux-host session guard when
the host permits it.

## Required Evidence

For a test-owned session, the probe must demonstrate:

```text
session registry creates context repository
  -> root bootstrap commit exists before surface work
  -> governed CDP command / paused Fetch / filesystem decision appends one blob
  -> ContextPin reaches durable audit JSONL
  -> permitted effect occurs only after durable audit
  -> reopened repository validates every recorded ContextPin
```

The probe also needs a negative case for each active boundary:

```text
CDP command audit failure     -> no upstream command
paused Fetch audit failure    -> Fetch.failRequest, not continueRequest
filesystem audit failure      -> guard returns denial before the file effect
```

## Planned Execution

1. Run the focused e2e fixture against the repository's process-local mini CDP
   upstream:

   ```sh
   cargo test -p erebor-runtime-e2e --test context_current_surface_integration --all-features
   ```

2. Run a Linux-host `erebor session run` fixture with the current ptrace guard,
   filesystem interception enabled, and a short controlled command. The test
   fixture must receive its configuration and workspace from a temporary
   directory and record the generated session id, registry directory, audit
   path, and context repository path.

3. If a local Chrome executable can run under the host's sandbox, run the
   existing browser-CDP lifecycle/real-Chrome fixture through the prepared
   session path. Confirm the test used the Erebor-governed endpoint, not a raw
   DevTools URL.

4. Reopen the completed session through `SessionRegistry`, read JSONL through
   `read_audit_records`, and call `ContextRepository::validate_pin(...)` for
   every pinned record. Then run `SessionReviewSource::render_describe(...)` to
   confirm the user-facing review projection remains valid.

## Host Limitations

- A sandbox that blocks the Linux ptrace guard cannot prove the filesystem
  effect boundary. Report the exact `erebor session run` command and guard error
  rather than treating a router fixture as equivalent.
- A Chrome sandbox failure proves neither a CDP integration failure nor a
  browser success. Report Chrome stderr, including a `crashpad` or
  `setsockopt: Operation not permitted` error when present.
- The deterministic mini-upstream fixture is mandatory even when Chrome is
  available; it is the stable proof for forwarding and blocking assertions.

## Reporting

Every implementation-phase result must report:

- focused e2e result and fixture name;
- context repository and audit record validation result after restart;
- whether the Linux guard effect probe ran, plus its exact result or block;
- whether the real-Chrome supplementary probe ran, plus its exact result or
  block; and
- the commands used for formatter, tests, and Clippy.
