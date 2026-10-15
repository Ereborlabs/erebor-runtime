# Araphor Binary Package Storage Review

Use the [approved plan](../plans/araphor-production-dataflow-simplification.md)
for scope and the [current review](araphor-performance-simplification-review.md)
for the shared execution flow. This guide owns the storage and OCI contracts.

## Intended end state

Keep one descriptor and raw executable buffers in the existing package revision
row. Use OCI manifest identity for local transport and trust pins. The package
owner prepares a revision. AnalysisStore owns its transaction, revision notice,
retention, recovery, and usage charges.

## Implementation review flow

[PackageBundleV1](../../crates/araphor-data/src/package/bundle.rs) The external package admission validates the current local OCI artifact
  -> [StoredArtifact](../../crates/araphor-data/src/package/storage.rs) the package owner separates one descriptor, implementation metadata, and raw executable bytes
  -> [AnalysisStore::install_package](../../crates/araphor-data/src/analysis/packages/revisions.rs) the store writes the complete immutable revision in one transaction
  -> [PackageRevisionV1::decode_artifact](../../crates/araphor-data/src/analysis/packages/model.rs) loading parses one descriptor and the remaining metadata
  -> [StoredArtifact::decode](../../crates/araphor-data/src/package/storage.rs) loading reads binary fields directly into the owned executable buffers
  -> [AnalysisPackageOwner::load_bundle](../../crates/araphor-data/src/package/lifecycle/revisions.rs) existing bundle validation, authority, and runtime admission remain

[AnalysisStore::open_leased](../../crates/araphor-data/src/analysis/mod.rs) A database opens
  -> [AnalysisStore::open_leased](../../crates/araphor-data/src/analysis/mod.rs) the store requires its current schema version
  -> [AnalysisStore::validate_state](../../crates/araphor-data/src/analysis/schema.rs) the store validates current rows, references, and charges
  -> [StoredArtifact::validate](../../crates/araphor-data/src/package/storage.rs) the store validates each current binary frame and content-derived size

## Owners and representation

The development store uses schema 22. The descriptor column contains the only
descriptor copy. The artifact column contains a three-field CBOR array: version
2, metadata bytes, and raw binary buffers. Metadata contains implementations and
fixtures. Executable placeholders are empty. Buffer order follows implementation
order, then each native implementation's dependency order. Decode rejects an
unsupported version, count difference, nonempty placeholder, truncation, or
trailing bytes.

The store charges actual descriptor and artifact lengths. The frame and row
have no separate encoded byte count. Decimal JSON byte counting and its frame
field are removed. Recovery decodes the current frame and reconstructs the same
charges. Runtime bundle and input leases charge owned buffers separately.
DuckDB owns physical pages. No compatibility reader or migration exists.

An immutable retry compares the saved artifact before encoding the candidate.
An admitted immutable bundle retains its OCI digest and executable identities.
Current trust and grant checks remain at admission and commit. Content identity
does not supply authority.

## Recovery and backup

[Backup and restore](../../crates/araphor-data/src/analysis/backup.rs) accept the
current schema, validate rows and references, retain store identity and commit
revision, and advance the recovery epoch through the existing owner. A failed
restore cannot publish a partial store.

The [native loader](../../crates/araphor-data/src/package/native/mod.rs) checks
code identity, dependency bytes, platform, and ABI. Storage keeps raw executable
bytes; it does not interpret them. Collection uses the existing revision
retention path. There is no second blob store.

## Local OCI transport and admission

[PackageBundleV1::read](../../crates/araphor-data/src/package/bundle.rs) The author or client supplies an OCI directory or layout archive
  -> [Content](../../crates/araphor-analysis-sdk/src/oci.rs) the SDK verifies descriptor sizes, SHA-256 hashes, media types, and the canonical Araphor manifest and config
  -> [PackageOci::decode](../../crates/araphor-data/src/package/oci.rs) Data fills ordered empty metadata slots from typed raw layers and checks reconstructed identity
  -> [PackageRequestV1::encode](../../crates/araphor-data/src/package/model/request.rs) the client encodes request metadata and the OCI archive as separate CBOR byte strings
  -> [ClientGrpcOwner](../../crates/mithril-control/src/client_grpc/packages.rs) Control decodes the binary request from the existing gRPC bytes field
  -> [PackageTrustPinV1](../../crates/mithril-control/src/client_auth/packages.rs) Control requires the selected tenant's exact `sha256:` manifest pin and current grant
  -> [AnalysisPackageOwner::admit_artifact](../../crates/araphor-data/src/package/execution.rs) the package owner admits each shared executable once and retains each export's SQL and binding checks
  -> [AnalysisStore::install_package](../../crates/araphor-data/src/analysis/packages/revisions.rs) the existing store commits the immutable package revision

The SDK owns OCI representation and content checks. Data owns package meaning,
raw-slot order, and bundle validation. Control remains the trust and grant
authority. A content digest does not authorize installation or execution.

The artifact uses an OCI Image Manifest with schema version 2, a fixed Araphor
artifact type, and a typed config. The config has package metadata and ordered
blob descriptors. Wasm, native code, native dependencies, Python artifacts,
and fixture Arrow IPC remain raw typed layers. Their metadata slots are empty.
This canonical Araphor subset permits reconstruction of the same manifest
identity after durable loading. OCI itself does not define canonical JSON.
The digest is SHA-256 of exact manifest bytes, written as `sha256:` followed
by 64 lowercase hexadecimal characters. Bare hexadecimal trust pins are invalid.

The request is a three-field CBOR array: version 1, metadata JSON bytes, and
OCI archive bytes. Install and update metadata exclude the bundle. Other
operations require an empty archive. The request rejects trailing bytes and
has no separate aggregate size cap. The user also removed the descriptor-only
1 MiB cap, OCI package 32 MiB cap, and stored revision 64 MiB cap. Package gRPC
clients and the server remove the aggregate message cap for package transport.
OCI exact descriptor sizes, digests, format checks, runtime data limits, and
store usage accounting remain.

Directory reads retain file descriptors and open each component without
following symbolic links. They require regular files. Archive reads
do not extract content. They reject duplicate paths, links, special entries,
unsafe names, missing or changed referenced blobs, and nonzero trailing data.
Unreferenced layout content does not become admitted package content.

The current transport requires fresh development packages and stores. There
is no JSON bundle fallback or older-format reader. The existing
[OCI design](../plans/mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/extensible-security-packages-design.md)
points to the deferred registry and trust owner. This local format adds no
network client, registry credentials, publisher verification, cache, or GC owner.

Read [SDK OCI tests](../../crates/araphor-analysis-sdk/src/oci/tests.rs),
[package OCI tests](../../crates/araphor-data/src/package/oci/tests.rs),
[request tests](../../crates/araphor-data/src/package/model/request/tests.rs), and
[trust-pin tests](../../crates/mithril-control/src/client_auth/packages/tests.rs).
They cover descriptor identity, raw-layer order, malformed input,
directory links, request framing, changed-content denial, and authority locking.
These are source test routes. Read the
[current verification](../plans/araphor-performance-simplification-todo.md)
before treating them as passed for this source.

### Explicit input declarations

[InputPort](../../crates/araphor-analysis-sdk/src/model.rs) Each input declares its port and source
  -> [Package::validate](../../crates/araphor-analysis-sdk/src/descriptor.rs) the SDK checks source and mode combinations and exact local output references
  -> [PackageBundleV1::validate](../../crates/araphor-data/src/package/admission.rs) Data checks the dependency closure from output references
  -> [ModelOperation::inputs](../../crates/araphor-data/src/query/model/operation.rs) the query owner resolves table and query inputs

`InputMode::Provided` accepts table sources. The caller supplies all datasets;
output references still retain dependency edges. `Resolved` accepts table and
query sources. A table names a built-in relation or an exact package output.
Zero-input models also declare the mode. `Model::new` defaults to `Provided`.
There is no separate package dependency
list, SQL binding map, or missing-key fallback. Computation ports and the native
and Wasm evaluation ABI remain unchanged.

## Verification

[Codec tests](../../crates/araphor-data/src/package/storage/tests.rs) retain
mixed implementations, dependency order, exact bytes and digests, malformed
frames, and actual encoded charges. [Revision tests](../../crates/araphor-data/src/package/lifecycle/revisions.rs)
retain immutable retry, changed-content rejection, reopen, and a 33 MiB artifact.
[Backup tests](../../crates/araphor-data/src/analysis/backup.rs) retain restore
and malformed-input checks. [Graph recovery tests](../../crates/araphor-data/src/analysis/graph_rows/tests/recovery.rs)
retain history, backup, and corruption checks. Native execution needs separate
artifact-qualified tests; opaque buffer round trips do not prove execution.

Earlier receipts and failed attempts remain in
`7b7b407adf347d389984553a4d212bfce37b75b5:docs/guides/araphor-binary-package-storage-review.md`.
They apply only to their captured source. The earlier exact native E2E retry
passes on Linux x86_64 GNU with glibc 2.39; its first failure remains unexplained.
It does not qualify later source or another platform. The Data test target below
ten minutes and a causal runtime speed improvement remain unproven.
