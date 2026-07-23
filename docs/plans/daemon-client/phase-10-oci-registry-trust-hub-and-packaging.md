# Phase 10: OCI Registry, Trust, Hub, And Packaging

Status: Deferred later phase. It is not a dependency of the Linux daemon/client
core. It starts only after Phase 9 and explicit approval.

## Purpose

Add OCI pull, push, tag, discovery, and formal installed-product
packaging without trusting tags, registry metadata, or “safe” marketing labels
as enforcement evidence.

The daemon, not the CLI, fetches and verifies every artifact that may affect an
admitted session.

This is the first external package-admission phase. It owns local OCI-layout
import, publisher-signature verification, trust policy, expiry, revocation,
publisher scope, stale-receipt checks, and the deferred formal bundle.

Hub discovery uses a signed OCI catalog artifact through the same registry
client, credential boundary, network rules, cache, and trust machinery as
packages. This is the correct simpler shape because it removes a second remote
protocol without allowing catalog metadata to authorize content. A catalog is
always discovery data; registry content and the complete verification graph
remain authoritative for install and run.

## Scope

### OCI Artifact Contract

- Publish an Erebor package as an OCI Image Manifest v1.1 with an
  Erebor-specific `artifactType`, typed config descriptor, and
  content-addressed support layers. That package manifest is the subject named
  by signature/attestation referrers. Define and test stable v1 media types for:
  - agent package configuration;
  - policy package configuration;
  - adapter support artifacts;
  - compatibility reports;
  - Erebor review statements; and
  - revocation statements.
- Use OCI subject/referrer relationships for Notary signatures, SLSA/in-toto
  provenance, SPDX or CycloneDX SBOMs, compatibility reports, and scoped review
  attestations. Do not use the archived ORAS artifact-manifest experiment.
- Establish the Notary Project signature envelope and trust-policy semantics
  through the approved verifier boundary. Invoke the official `notation`
  executable pinned by version and artifact digest without a shell, with only
  daemon-owned layout/reference/configuration inputs. Pin and validate its
  version-specific result contract before issuing Erebor's canonical receipt;
  do not substitute signature-envelope parsing for verification. The verifier
  configuration must bind the active trust policy, trust stores, revocation
  state, and any permitted verification plugin to the receipt/admission
  generation.
- Accept a provenance, SBOM assertion, compatibility report, review, or
  revocation statement only when its subject digest, statement type, issuer,
  signature, and scope satisfy root trust policy. Merely attaching a referrer
  in a registry never authenticates its claim.
- Add canonical manifest/reference parsing and digest computation in a domain
  owner. Tags are mutable lookup inputs; only a manifest digest identifies
  stored or admitted content.

### Registry Client

- Add a narrow async registry client boundary in
  `erebor-runtime-daemon`. Prefer the maintained `oci-client` Rust crate for
  OCI Distribution authentication, manifests, blobs, push, and referrers rather
  than wrapping Docker/ORAS CLIs or hand-writing the protocol.
- At implementation start, pin and record the selected crate version and audit
  its redirect, credential, maximum-size, digest, cancellation, and referrer
  behavior. Wrap missing safeguards locally; do not fork registry behavior into
  the CLI.
- Support:

  ```text
  erebor search QUERY
  erebor pull NAME[:TAG]|NAME@DIGEST
  erebor push LOCAL_REF REMOTE_REF
  erebor agent import OCI_LAYOUT
  erebor agent tag SOURCE TARGET
  erebor agent inspect|verify|install|ls|rm
  erebor registry login|logout|ls
  ```

- On pull, resolve a tag once, fetch by the returned digest, independently hash
  every manifest/blob, discover required referrers, verify trust, then
  atomically publish the local package and alias. A failed pull leaves neither
  a usable alias nor a partially verified package.
- On local `agent import`, consume the caller-owned OCI layout through the
  Phase 2 UID-dropped descriptor broker, copy it into a daemon-owned temporary
  root, verify its complete signature/trust graph, then atomically publish the
  package and alias. It must reject path swaps, malformed layouts, unsigned or
  wrongly scoped content, and partial writes without retaining usable content.
- Agent packages that declare a Docker image bind its exact OCI descriptor.
  Pull/installation verifies that image content separately, and session start
  still uses the admitted local digest with implicit Docker pull disabled.
- On push, require an existing valid local subject and all policy-required
  signatures/attestations. Upload by digest and update a remote tag only after
  content completion. `push` never silently creates a publisher signature or
  asks the privileged daemon to use an author's private signing key.
  Server-side authorization remains authoritative.
- Registry blob bytes never traverse daemon IPC. The CLI sends references and
  bounded credentials/input; the daemon streams typed progress.

### Credentials And Network Safety

- Registry credentials are UID-scoped. `login` reads a secret from stdin or an
  approved credential helper, sends it over the authenticated Unix socket, and
  never accepts it in an argv flag or log field.
- An organization catalog artifact uses the credentials of its configured OCI
  registry namespace. There is no separate Hub token or credential path.
- Prefer a root-approved credential helper or OS credential vault invoked
  under the caller UID with a pinned executable, clean environment, bounded
  protocol, timeout, and captured/redacted errors, so the daemon holds a
  credential only for the request that needs it. An optional daemon-managed
  vault requires a documented threat model, key source/rotation/recovery
  contract, UID and registry associated
  data, and explicit root configuration; “encrypted beside a root-only host
  key” is not by itself an accepted security boundary. Files, helper argv,
  errors, telemetry, inspect output, and child environments must not expose
  the secret.
- HTTPS certificate validation is mandatory. An explicit root-only development
  registry allowlist may permit loopback HTTP; a user request cannot.
- The registry client and signed-catalog refresh use one root-owned proxy/DNS
  policy rather than inherited daemon environment. Validate the configured
  origin before and after DNS resolution, redirect, and reconnect; deny
  loopback, link-local, cloud metadata, Unix/file URLs, and private ranges
  unless that exact class/origin is root-allowed. A user-controlled reference
  cannot turn the root daemon into a general SSRF client.
- Never forward `Authorization` across registry origins or unapproved
  redirects. Bound manifest, referrer count, layer count, blob size, total
  transfer, decompressed size, concurrency, retry, and time.
- Validate extracted layer paths against absolute paths, `..`, symlinks,
  hardlinks, device nodes, FIFOs, ownership tricks, and decompression bombs.
  Prefer content use without extraction; when extraction is required, publish
  only from a safe temporary root after complete verification.

### Trust, Attestations, And Revocation

- Root daemon trust policy selects permitted registries, repository scopes,
  publisher certificate identities, signature threshold, required provenance,
  compatibility runner/OS/Erebor-version statements, review programs, expiry,
  and maximum offline verification age.
- Compatibility reports use the same versioned
  `RunnerCapabilityDocument` schema defined in Phase 2 and exposed in Phase 3.
  An attestation names the exact runner implementation id/version, capability
  schema version, required capability values, OS/architecture, Erebor version,
  and conformance suite. It does not introduce a registry-specific capability
  vocabulary.
- Treat each claim precisely:
  - publisher signature proves the configured identity signed the digest;
  - provenance proves only its signed build statement;
  - compatibility proves only the named test matrix;
  - review proves only the signed scope and expiry; and
  - none replaces runtime policy or enforcement.
- Root trust configuration has static local deny entries and may name a signed
  revocation-feed URI, trusted signer/threshold, refresh interval, and maximum
  age. The daemon maintains the resulting digest-addressed snapshot, which may
  revoke a package digest, signature/certificate identity, publisher scope, or
  attestation. Catalog metadata is never the authoritative feed. New
  install/run admission checks both static entries and the current snapshot.
- Offline admission is allowed only when root policy permits it and the cached
  signature, required attestations, and revocation snapshot are within their
  configured age. Otherwise fail with a retryable trust-refresh error.
- Revocation blocks new installations and sessions. Existing sessions follow
  an explicit root policy (`leave_running` or `terminate`) recorded as a
  lifecycle event. `review-required` is not a lifecycle action and is not used;
  a future human workflow would require its own concrete timeout/default
  behavior. Phase 5 must not silently kill or silently ignore sessions.

### Signed Hub Catalog Artifact

- Do not define a Hub HTTP API, Hub client, Hub-specific token, or Hub fixture
  server. A configured public or organization Hub is a signed OCI catalog
  artifact in a root-allowed registry namespace.
- Publish a versioned catalog artifact type and typed config that contain the
  discovery fields needed for `erebor search`: package references and digests,
  publisher identity, platform/adapter/runner facts, and narrow certification
  labels. The catalog's signature, issuer, scope, freshness, and digest are
  checked by the same trust machinery as other OCI artifacts.
- `erebor search` refreshes and searches the verified local catalog snapshot.
  `erebor pull` independently resolves the selected registry reference,
  verifies the complete OCI graph, and then atomically publishes content. A
  catalog entry cannot install content, satisfy trust, override revocation, or
  change the final digest.
- Root configuration may select one or more public or organization catalog
  artifact references, or no Hub. Catalog refresh uses the same registry
  credential, origin, retry, cancellation, progress, cache, and GC owners as
  package transport. Hub is not an Erebor engine or daemon target.
- The first product intentionally offers deterministic search over a refreshed
  signed snapshot rather than server-side fuzzy ranking or personalized search.
  A future hosted query API needs its own approved phase; it must not appear as
  hidden behavior behind the registry client.
- This is a correctness-preserving simplification, not a trust shortcut: one
  remote transport and one verifier reduce divergence, while final admission
  continues to require the independently verified registry graph and current
  root trust policy.

### Installed Product Packaging

- Build the public `erebor` and `erebord` binaries, root-owned private helpers,
  Linux systemd unit, default root configuration, and uninstall-with-data-
  retention instructions as one versioned installed-product bundle.
- The bundle records its build provenance and compatibility with the daemon,
  client, helper, package schema, and selected runner implementations. It does
  not itself certify the newly distributed product. Re-run the applicable Phase
  9 evidence before advertising Phase 10 capabilities as supported.
- Installation and update paths preserve root-owned state and never convert old
  workspace-local `.erebor/sessions` data into daemon state. Package transport
  or an installer cannot replace a running daemon's socket, lock, or helpers
  without the controlled upgrade contract in Phase 9.

### Cache And Garbage Collection

- Share content by digest across users while keeping aliases, credentials,
  installations, policy packages/sets, and sessions UID-scoped.
- Use leases for active pulls, installed packages, live/retained sessions,
  signatures, and required attestations. GC is mark-and-sweep from durable
  references; it never follows user-controlled symlinks or deletes leased
  content.
- Concurrent same-digest pulls coalesce or safely converge. Concurrent tag
  resolution may produce different digests but cannot overwrite a session's
  resolved digest.

## Non-Goals

- Do not implement a custom registry server, hosted Hub deployment, or a
  bespoke Hub query protocol in this phase.
- Do not build a private-key package-authoring/signing service into `erebord`;
  publish the accepted OCI/signature contract so author tools can produce
  importable content.
- Do not download executable adapter plugins.
- Do not claim that signed, compatible, or reviewed means intrinsically safe.
- Do not permit mutable tags in `SessionSpec`.
- Do not make this later distribution capability a prerequisite for the
  daemon/client core or a claim that a local root-curated package was signed.

## Checkpoint

Extend `examples/codex-app-server` with the Phase 10 distribution walkthrough:
package pull/verification, formal installation, and signed OCI catalog. Use a
disposable local registry fixture and redact registry credentials and tokens.

Add a local OCI registry fixture, signed-catalog fixture, publisher/trust
fixtures, and e2e tests covering:

- anonymous/basic/bearer auth, login/logout, redirect credential isolation,
  TLS failure, DNS rebinding/SSRF targets, inherited-proxy rejection, timeout,
  retry, and cancellation;
- tag-to-digest resolution, digest mismatch, corrupt/truncated/oversized blobs,
  malicious layers, concurrent pulls, interrupted pull recovery, push, and GC;
- descriptor-broker local OCI-layout import, including path-swap rejection,
  unsigned/untrusted/expired/wrong-scope layouts, stale receipt rejection, and
  no usable content after a failed copy or verification;
- native referrers plus the OCI referrers-tag fallback;
- missing/invalid/expired/wrong-scope signatures and every required attestation;
- revocation and offline maximum-age behavior;
- catalog metadata disagreeing with registry content;
- UID isolation for credentials, aliases, installs, push, and private
  registries;
- signed-feed versus catalog-label revocation disagreement and each
  existing-session
  revocation action; and
- Docker package image-descriptor mismatch and proof of no implicit pull.

Run the Phase 5 registry/trust section of `lifecycle-probe.md`, then:

Run parsing, canonicalization, trust-policy, fixture-client, and failure-vector
tests in the normal workspace lane. Extend the serial Ubuntu 24.04
`privileged-linux` installed-product target with staged daemon/client registry
operations, two-UID credential isolation, and exact capability-attestation
admission. Registry fixtures may be local, but required systemd/cgroup/sudo
conditions still fail rather than skip in that lane.

```sh
rtk cargo fmt --all -- --check
rtk cargo test --workspace --all-targets --all-features
rtk cargo clippy --workspace --all-targets --all-features -- -D warnings
rtk git diff --check
```

## Required Evidence

- Published v1 media-type and manifest/referrer examples.
- Registry dependency/version and safeguard audit.
- Credential-helper/vault threat model and secret-lifetime evidence.
- Known-good signature/provenance/compatibility/review chain with exact digests.
- Pinned Notation artifact/version/result-contract audit, including the active
  trust-policy, trust-store, revocation, and verification-plugin bindings.
- Proof that compatibility attestations and session admission use the exact
  Phase 2 `RunnerCapabilityDocument` schema and runner implementation version.
- Every required trust and revocation rejection result.
- Redirect credential-leak and malicious-layer negative results.
- Catalog-versus-registry disagreement result proving registry verification
  wins.
- Cache/lease/GC and concurrent pull results.

## Acceptance

- A mutable tag becomes an immutable verified local digest before install or
  run.
- A local OCI layout becomes an installable package only after descriptor-broker
  copy, complete verification, and atomic daemon-store publication.
- Registry and catalog data cannot bypass publisher trust, attestations,
  revocation, package validation, policy, or runner admission.
- Pull/push/tag/search behave through the daemon with bounded progress streams.
- Credentials remain UID-scoped and are not exposed to another origin, user,
  log, or process argv.
- Agent and policy packages retain distinct schemas while sharing digest,
  signature, registry, cache, and revocation machinery.
- Sessions keep working from pinned local content when offline policy permits;
  stale trust state fails honestly.

## Stop Point

Stop after Phase 10 evidence and the result update. It does not authorize any
earlier or future phase.

## Phase 10 Result

State: Not started.
