# Phase 1: Inventory And Migration Contract

Status: Done. Planning and inventory phase only.

## Purpose

Inventory every place where the Linux interception backend looked terminal-owned
and define the migration boundary for later phases.

## Scope

- Inventory terminal/process guard names, config fields, audit payloads, IPC
  messages, environment variables, tests, and docs.
- Define which names are historical implementation names and which new names
  are canonical.
- Define config migration rules.
- Do not move code in this phase.

## Inventory Summary

Terminal-owned backend config that needed to move:

- `surfaces.terminal.process_guard.enabled`
- `surfaces.terminal.process_guard.backend`
- `TerminalProcessGuardLayerConfig`
- `TerminalProcessGuardConfig`

Surface-specific process mediation config that remains terminal-owned:

- `surfaces.terminal.process_mediation`
- aliases: `process_interception`, `browser_launch_mediation`
- `ProcessInterceptionDecision`
- `ProcessInterceptionHandlerConfig`
- `ProcessInterceptionHandlerKind`

Environment and audit names that remained compatibility-sensitive:

- `EREBOR_TERMINAL_*`
- `EREBOR_GUARD_*`
- `EREBOR_PROCESS_INTERCEPTION*`
- `EREBOR_RUNTIME_INTERCEPTION_*`
- process-exec audit records with `surface="terminal"` and
  `action="process_exec"`

## Migration Rule

1. Add `session.interception` as the canonical backend config.
2. Drop `surfaces.terminal.process_guard` from runtime config and public core
   config types.
3. Derive the same Linux ptrace process-exec backend launch plan from session
   config.
4. Keep process mediation under the terminal/process surface.
5. Keep process-exec audit as terminal/process audit.
6. Add filesystem and network routing only after the router can preserve
   session, pid, process, cwd, and initiating terminal action attribution.

## Checkpoint

```sh
rg -n "process_guard|process_interception|process_mediation|TerminalProcess|ProcessInterception|EREBOR_PROCESS|EREBOR_TERMINAL|EREBOR_GUARD|linux_ptrace|linux-ptrace|process_exec" crates/erebor-runtime-core/src/config.rs crates/erebor-runtime-session/src/lib.rs crates/erebor-runtime-session/src/os/linux/process_guard.rs crates/erebor-runtime-session/src/os/linux/process_guard/interception.rs crates/erebor-runtime-ipc/proto/erebor/runtime/ipc/v1/control.proto crates/erebor-runtime-ipc/src/v1.rs crates/erebor-runtime-terminal/src/lib.rs
```

No Rust tests are required for this phase because it is a planning inventory.

## Acceptance

- Every terminal/process behavior that must remain green after config migration
  is documented.
- The plan distinguishes backend ownership from terminal/process surface
  ownership.
- No terminal/process policy behavior is intentionally broken.

## Phase 1 Result

Done. The inventory established that backend lifecycle belongs to
`session.interception`, while process-exec policy, terminal audit, and browser
launch mediation remain terminal/process surface behavior.
