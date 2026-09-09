# Lightweight Scenario Maintainability Todo

This work makes the Rust qualification scenarios short to add and safe to
operate. It does not change Mithril production architecture or complete the
active product phase.

## Intended end state

A new scenario supplies its fixture inputs, calls the public production owner,
performs the physical action, and checks the result. Shared fixtures own only
temporary resources, process lifetime, readiness, cleanup, and failure
diagnostics. They do not reproduce a production operation sequence.

## Implementation order

- [ ] Add one shared synchronous readiness helper and improve the existing
  cleanup owners. Verify their timeout diagnostics and idempotent cleanup.
- [ ] Migrate the Control TLS scenarios to an owned server fixture. Keep each
  `NodeControlConnector` operation and security assertion in its test.
- [ ] Migrate the effect-process scenarios to the shared readiness and cleanup
  support. Keep each `KernelHost`, policy, binding, effect, and evidence
  operation visible in its scenario.
- [ ] Migrate the network scenarios. Keep the production network policy and
  socket operations visible, including every fail-closed assertion.
- [ ] Migrate the direct-runtime gate and recovered-container scenarios. Keep
  the production OCI hook and node recovery operations identical to the
  Kubernetes lane.
- [ ] Migrate the direct-runtime entry-role scenario in small behavior groups.
  Preserve the current result schema and all policy, identity, mount, evidence,
  administrative-exec, upgrade, and cleanup assertions.
- [ ] Migrate the native identity and Kubernetes identity scenarios. Keep the
  production identity and binding owner calls visible and preserve the paired
  Kubernetes operations.
- [ ] Document the minimal scenario pattern and the focused, lightweight,
  Kubernetes, and full repository commands.
- [ ] Run the lightweight physical qualification before the paired Kubernetes
  qualification. If Kubernetes finds a missing condition, add that condition
  to the lightweight scenario before an implementation change or Kubernetes
  retry.

## Commit rule

Commit the shared tooling after its focused checks pass. Then commit each
scenario migration separately after its focused lightweight check passes. Do
not combine the scenario migrations into one commit.

