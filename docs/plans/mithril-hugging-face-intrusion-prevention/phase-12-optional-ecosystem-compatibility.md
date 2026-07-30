# Phase 12: Optional Ecosystem Compatibility

Status: Not started. Optional post-core phase.

Master plan: [Mithril Hugging Face Intrusion Prevention](./README.md)

## Purpose

Consume useful existing Falco, Tetragon, Hubble/Cilium, EDR, SIEM, or provider
content/evidence without deploying a second default node gatherer or weakening
Mithril's owned guarantees.

Phase 11 must remain production-complete when every optional adapter is absent.

## Depends On

Phase 11 must be approved for launch or the user must explicitly approve one
compatibility adapter earlier as an isolated integration. Each adapter has its
own license, trust, source-health, permission, and duplication review.

## Phase Scope

### Falco Content Compatibility

Import a documented subset of:

- rules;
- macros;
- lists;
- exceptions;
- priorities;
- tags; and
- supported field references.

For each imported artifact retain original version/digest, source event type,
field mapping, unsupported/weakened predicates, Mithril-native equivalent,
required coverage, and replay corpus.

Do not embed or deploy Falco's kernel driver, `libpman`, libscap, C++ rule
engine, Falcosidekick, or Talon as the Mithril node path.

### Tetragon Compatibility Input

If a customer already runs Tetragon, accept selected typed events/health as an
independent optional source. Preserve Tetragon policy/sensor/version/native IDs,
process-cache gap flags, event loss, and coverage.

Do not:

- fork the Go daemon as Mithril;
- expose raw TracingPolicy as Mithril policy;
- replace Mithril native task identity with Tetragon process cache identity;
- let Tetragon signals prove prevention; or
- attach overlapping programs by default.

On a Mithril-protected node, an adapter must prefer an existing remote/control
source or explicitly reject overlapping collection. One gatherer remains the
default.

### Hubble/Cilium

When already installed, consume stable APIs for:

- workload/security identity;
- flow/drop verdicts;
- DNS/FQDN history;
- service identity; and
- independent source health.

Deduplicate one physical effect observed by Mithril socket/packet paths and
Hubble flow. Removing Cilium/Hubble must not weaken Mithril's baseline network
enforcement.

No adapter enables Envoy, L7 parsing, route change, or TLS termination without
a separate operator-approved architecture change.

### Existing EDR/SIEM And Other Sources

Treat alerts as source-native evidence:

- authenticate sender and tenant/asset;
- preserve raw envelope/content/version;
- record delivery cursor/sequence/health;
- map only supported fields;
- retain contradictory observations; and
- give the adapter no profile-map or response authority.

A vendor alert, severity, or AI conclusion cannot authorize response.

### Reduced-Tier Built-In LSM And Launch Hardening

Evaluate generated AppArmor/SELinux enforcement for nodes without the required
BPF LSM hook set. A reduced backend is advertised only for effect classes whose
object identity, policy generation, denial result, telemetry, restart, and
incident bypass tests prove the same named guarantee. It is not called
full-tier merely because a policy loaded.

Separately offer operator-approved launch hardening:

- mount namespace and read-only/idmapped mount changes;
- a monotonic inherited Landlock filesystem floor applied by the container
  runtime child before exec; and
- a seccomp-BPF syscall floor for unused syscall families.

These are H-class deployment changes, not Mithril's deployment-preserving
baseline. Landlock cannot be retrofitted to an arbitrary live task, seccomp
lacks resolved object/application semantics, and mount isolation does not
provide per-process role decisions. Each proposal is simulated, separately
approved, applied by the runtime owner, and verified without being credited to
BPF LSM.

Seccomp-filtered ptrace or seccomp user notification may be researched as a
declared compatibility/diagnostic tier. It is not called equivalent to the
in-kernel path without operation-specific context-switch, tracer-failure,
object-resolution, TOCTOU, and incident-bypass proof.

## Hugging Face Test Increment

For every adapter:

- replay incident-relevant content;
- prove the adapter adds an independently sourced observation or finding
  predicate;
- deduplicate it against owned Mithril evidence;
- remove or degrade the adapter and prove local prevention/correlation claims
  change only when they explicitly require that source;
- feed malicious/prompt-injection source fields and prove no policy/response
  action executes; and
- repeat the relevant incident scenario with the adapter absent.

## Code-Backed Tests

- artifact/schema/version/license/provenance tests;
- source authentication, cursor/loss, replay, duplicate, and redaction tests;
- unsupported/weakened predicate visibility;
- owned-versus-adapter event dedupe;
- contradiction and late-evidence versioning;
- adapter compromise cannot mutate BPF/profile/response state;
- removal leaves Phase 11 baseline conformance passing;
- no new privileged node component in the default Helm topology; and
- performance/resource cost is separately measured.

Reduced/hardening tests additionally prove:

- every claimed AppArmor/SELinux effect class against the same local incident
  bypass and postcondition matrix;
- Landlock/mount/seccomp launch ordering and inability to retrofit live tasks;
- BPF LSM role policy remains independently effective when optional floors are
  absent;
- optional floors do not break the legitimate unchanged control after the
  operator adopts that separate fixture variant; and
- no reduced/diagnostic path inherits a full-tier claim without equivalent
  proof.

## Live Probe

Run only the probe portions touched by the adapter, then rerun the full
Phase 11 baseline with the adapter disabled.

## Checkpoint

For each adapter, run the common repository gates, provenance/schema/coverage/
dedupe/security tests, its incident replay/live slice, and the complete Phase
11 baseline with the adapter absent. Record default Helm topology before and
after to prove no second required gatherer appeared.

## Acceptance

- every optional source has independent provenance and coverage;
- imported content states unsupported/weakened semantics;
- duplicate physical effects are not double counted;
- no optional product becomes the node chassis or canonical identity owner;
- no adapter can install policy or invoke response through read/event access;
- no second default privileged gatherer is introduced;
- removal leaves Phase 11 incident prevention guarantees intact; and
- operational cost and failure behavior are explicit.

## Explicit Stop Point

Stop after each independently approved adapter. Do not bundle adapters into the
default deployment merely because their code is available.

## Phase Result

State: Not started.

Record adapter/version/license, source permissions, schema/content mappings,
coverage/dedupe/security tests, incident replay, disabled-baseline result,
performance, and final state.
