# Phase 0 Interceptor Ownership Decision

Status: Implemented by Phases 0 and 1.

## Crate boundary

- `erebor-interceptor-abi` owns portable interception requests and decisions plus the physically qualified Rust/C layouts. Pinned `cbindgen` generates the C header from the Rust definitions during every build and rejects checked-header drift. `erebor-runtime-core::interception` remains a source-compatible re-export.
- `erebor-interceptor` owns Linux preflight, the only BPF object loader, links, maps, pin-root lease, exact pin/readback manifest, clean rollback/shutdown, and kernel error translation. `mithril-e2e` calls this owner for qualification; it has no independent libbpf loader.
- `mithril-node` embeds `erebor-interceptor`. It does not start a sibling loader process. The co-resident Runtime surface is a peer-credential-authenticated, exact-cgroup-scoped, read-only local client.

The current Session interception broker, ptrace backend, shim mediation, routing, and Session lifecycle remain in `erebor-runtime-session`. They are Session-only compatibility and mediation paths, not portable kernel ABI and not future BPF ownership.

## Exclusive loader owner

| Deployment mode | Loader/link/map/pin-root owner | Runtime relationship |
| --- | --- | --- |
| Runtime only | the Runtime daemon embeds `erebor-interceptor` and holds its exclusive pin-root lease | no other process may load the Erebor object set |
| Mithril only | `mithril-node` embeds `erebor-interceptor` and holds the lease | no Runtime loader exists |
| Co-resident | `mithril-node` embeds `erebor-interceptor` and holds the lease | Runtime is an authenticated Session/cgroup client only |

An independent Runtime BPF loader after this shared owner exists is a rejected contract. A second lease acquisition is an admission failure, never a fallback to two map generations.

## Compatibility proof

Existing consumers keep importing `erebor_runtime_core::interception`; those names denote the portable types from `erebor-interceptor-abi`. Existing Session broker/backend tests therefore exercise the same type identity and behavior without a duplicate representation. The feasibility object compiles against the checked-in x86, arm64, arm, and riscv kernel headers. Only the physically proved x86 file-open slice is frozen as supported; every other effect remains explicitly unsupported.

## Relationship to the kernel-native plan

This decision replaces that plan's provisional “new Linux-only enforcement crate” name with `erebor-interceptor` while preserving its ownership: one existing policy authority lowers immutable images; one Interceptor owner performs kernel lifecycle; Session admission and filesystem storage keep their current owners. The BPF source uses direct libbpf map declarations in the checked Tetragon/KubeArmor style and a checked-in `vmlinux` wrapper. Its x86 header is generated locally; arm64 is from Tetragon; arm and riscv are from AgentSight. They are compile targets, not cross-platform physical support claims. The host owner uses direct safe `libbpf-rs` APIs with its fully vendored libbpf/libelf/zlib build; pinned `cbindgen` is the Rust-to-C ABI generator. No copied upstream daemon, generated Rust skeleton, second policy engine, or second loader is present.
