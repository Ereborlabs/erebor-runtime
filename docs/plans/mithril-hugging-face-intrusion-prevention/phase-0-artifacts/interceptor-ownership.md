# Phase 0 Interceptor Ownership Decision

Status: Approved implementation boundary for Phase 0; product wiring begins only in an approved later phase.

## Crate boundary

- `erebor-interceptor-abi` owns portable interception requests, decisions, closed kernel map layouts, and the generated Rust/C ABI. `erebor-runtime-core::interception` remains a source-compatible re-export.
- `erebor-interceptor` will own Linux feature probing, the only BPF object loader, links, maps, pin-root lease, event drain, and kernel error translation. Phase 0 keeps its disposable feasibility object and runner in `mithril-e2e`; it does not create a placeholder product crate.
- `mithril-node` will embed `erebor-interceptor`. It will not start a sibling loader process.

The current Session interception broker, ptrace backend, shim mediation, routing, and Session lifecycle remain in `erebor-runtime-session`. They are Session-only compatibility and mediation paths, not portable kernel ABI and not future BPF ownership.

## Exclusive loader owner

| Deployment mode | Loader/link/map/pin-root owner | Runtime relationship |
| --- | --- | --- |
| Runtime only | the Runtime daemon embeds `erebor-interceptor` and holds its exclusive pin-root lease | no other process may load the Erebor object set |
| Mithril only | `mithril-node` embeds `erebor-interceptor` and holds the lease | no Runtime loader exists |
| Co-resident | `mithril-node` embeds `erebor-interceptor` and holds the lease | Runtime is an authenticated Session/cgroup client only |

An independent Runtime BPF loader after this shared owner exists is a rejected contract. A second lease acquisition is an admission failure, never a fallback to two map generations.

## Compatibility proof

Existing consumers keep importing `erebor_runtime_core::interception`; those names now denote the types from `erebor-interceptor-abi`. Existing Session broker/backend tests therefore exercise the same type identity and behavior without an adapter or duplicate representation. The Phase 0 Rust/C layout and golden-byte tests cover the new kernel boundary separately.

## Relationship to the kernel-native plan

This decision replaces that plan's provisional “new Linux-only enforcement crate” name with `erebor-interceptor` while preserving its ownership: one existing policy authority lowers immutable images; one Interceptor owner performs kernel lifecycle; Session admission and filesystem storage keep their current owners. It does not turn the Interceptor into a second policy engine or authorize a product daemon in Phase 0.
