# Replace DuckDB with versioned Fjall

## Intended end state

Data owns one versioned Fjall database and its commit boundary. Its live branch
contains table state, Graph records, package state, results, evidence references,
notification state, and consumed input positions. Raw event payloads remain in
the existing append-only segments. There is no second event payload archive.

One published Data view binds an exact native snapshot to an exact raw prefix.
Native DataFusion plans read that view and the required changes. Package
definitions start subscriptions. A package decides whether to use Graph and
which Graph changes to stage. Data commits those changes with package state
and input progress. Packages cannot commit the transaction.

Data reads original committed logs to select subscription wakes. An unrelated
transaction cannot cause a package source wake. A failed step cannot acknowledge
its input. Retained historical reads and branches survive compaction and reopen.
Graph semantics remain in Araphor Graph; engine branches contain no package
or Graph knowledge.

The performance goals remain notification creation below 100 milliseconds and
the requested 100-fold improvement. Neither result follows from engine selection.
Use the same incident workload and measurement boundaries to prove them.

## Storage quota removal, 2026-11-10

The user removes Data storage quotas. This instruction supersedes the earlier
configured-capacity requirements and reader-permit records below.
`StorageLimitsV1`, `data_storage`, `open_with_limits`, `restore_with_limits`,
reader permits, and the storage-quota error are removed. The API keeps `open`,
`open_with_retention`, `restore`, `storage_usage`, and `storage_health`.
No ignored limit argument or replacement quota remains.

Data keeps actual file, allocated-byte, and free-space measurements. Data also
keeps leases, read cancellation, current trace authority, transaction locks,
Required-input retention floors, durable consumer positions, and real I/O errors.
`RetentionLimitsV1` remains a separate raw-retention policy. Query execution and
package memory budgets remain separate resource owners.

Backup callbacks record the expected native file inventory. They do not admit
bytes or entries. Data compares file names and lengths, checks checksums and raw
records, and publishes the temporary bundle after sync. Restore retains bundle
validation, the exclusive lease, the pending marker, exact identity checks, and
recovery before it removes the marker. Trace obligation metadata and revision
counters remain integrity data. The physical format remains 10.

Eight native backup cases replace the old SQL backup family. The cases preserve
incomplete traces, the 17 MiB raw segment, writer exclusion, held views, duplicate
stamp failure, source immutability, physical bundle faults, semantic faults,
recovery floors, and restart. Quota-only refusal cases are removed. Real disk-full
and file-size failure cases remain. These changes do not establish a latency gain.
Final qualification and the incident result are recorded in the current evidence.

## Current replacement work, 2026-11-10

Result: **Not done for the complete replacement and performance proof**.
The current source uses the native Data owner through the public storage API.
The connected replacement removes the SQL Data owner, SQL Graph backend,
caller backend switches, DuckDB dependencies, and vendored DuckDB code.
The default production release build and unchanged incident pass. SQL-only
fixture ports, finite-history collection, and complete qualification remain open.

| Owner | Current work and completion proof |
| --- | --- |
| Data and Araphor Graph | Complete native API parity and remove obsolete SQL fixtures and dependencies. Require the default production and E2E builds. |
| Fixture retirement | The context, catalogue, image, backup, profile, and managed binary-storage SQL families have native replacements. Native cases preserve typed publication, large records, rollback, backup, contexts, state, history, notices, raw expiry, and Arrow values. Other Data unit fixtures still need native ports. Quota-only cases are removed by user instruction. |
| Storage lifecycle | Data storage quotas are removed. Keep usage reporting, retention, collection, and checkpoint/restore integrity. Recovery preserves acknowledged raw input and distinguishes a failed raw append from a poisoned native engine. Complete qualification remains open. |
| Subscription and execution | Ordinary Query resumes from its saved original-log position. Partial ordinals replay the same original commit. Thirteen native Query and six native input cases pass. Keep retained native DataFusion plans and durable managed consumption. Complete production qualification and obsolete fixture ports remain open. |
| Original journal collection | Checkpoint saves safe filtered positions and releases eligible sealed journals. All durable generations, the published cut, and the shared reader protect their anchors. Removed and dormant generations remain revivable. Native MVCC history stays retained. |
| Notifications | Keep batch writes and durable Pending before external delivery. Measure durable creation and public receipt separately. |
| Performance | Matched release runs with prepared descriptor reuse measure durable creation at 42.151–71.520 ms. The measured gain against DuckDB is 7.89 to 9.80 fold. The 100-fold target is not met. |

Current evidence:

- The two managed binary-storage SQL fixtures have native replacements. The
  large case retains the original small instance, 17 MiB definition description,
  16 MiB plus one byte reason, two independent calls, and checkpoint values
  two and three. Rejected publication preserves the pending attempt, instance,
  call heads, Data revision, and journal head. No result or checkpoint leaks.
  The native cases check binary envelopes, exact definition bytes, dependency
  identities, public result reads, historical reads, completed retries, reopen,
  backup, and restore. Sixty-five point-reference reads check stable identity
  and foreign-tenant rejection. They do not claim parity with the removed
  batch-wrapper ordering mechanism. The old batch wrappers had no production
  callers. No wrapper API or second output archive is restored.
  The final focused run passes 123 managed cases in 29.68 seconds and six
  lifecycle cases. Read `managed-storage-second.log` and
  `managed-storage-final-native.log` under
  `output/araphor-fjall-migration-20261110`. Other obsolete Data fixtures remain.

- Managed preparation retains the descriptor bytes with the parsed contract.
  Publication reads the current descriptor under the Data writer. Equal bytes
  reuse the parsed contract. Different bytes use the existing parse, pin, and
  package equality checks. Equivalent JSON remains valid. Changed exports,
  malformed JSON, and wrong package pins retain their existing errors.
  Read allocation charges remain on each metadata read. Parse allocation
  charges apply only when a parse occurs. The retained buffer is charged once.
  No global cache, durable archive, public API, or format is added.
  The final focused run passes 121 managed cases in 12.83 seconds and six
  lifecycle cases in 0.29 seconds. The new case checks all five descriptor
  variants, rollback, same-attempt repair, and reopen.
  Both matched unchanged incident pairs pass. Median commit validation falls
  from 1.807–1.856 ms to 1.112–1.113 ms. Durable creation measures
  42.151–71.520 ms after this change and 42.404–78.044 ms before it.
  The second notification improves in one pair and increases in the other.
  These samples do not prove a consistent gain for every notification.
  Public receipt measures 50.321–88.374 ms after this change. Whole-test time
  measures 2.08–2.09 seconds. Matched DuckDB creation measures
  335.570–614.586 ms; public receipt measures 394.723–708.770 ms; whole-test
  time measures 5.08 seconds. The paired creation gain is 7.89–9.80 fold.
  Workload hashes, profiles, and measurement boundaries remain equal.
  The 100-fold target remains **Not done**. Read `descriptor-frame-build.json`,
  `descriptor-frame-comparison.json`, `descriptor-frame-stages.json`, and
  `descriptor-frame-final-native.log` under
  `output/araphor-fjall-migration-20261110`.

- Graph publication reuses returned-call contracts already checked against the
  current view under the same Data writer. An unreturned manifest call still
  loads its current contract. The existing all-call declaration and complete
  stored-mapping checks remain. The publication permits additional mappings
  retained for a candidate version. Admission, version preparation, revival,
  and recovery keep their existing contract reads. No new cache or format is
  added. Two native regressions check an unreturned relation change, rollback,
  same-attempt success after repair, and publication from a capture made before
  a candidate extends the writer union. The final focused run passes
  120 managed cases in 12.63 seconds and six lifecycle cases in 0.30 seconds.
  Both matched unchanged incident pairs pass. Median Graph staging falls from
  3.194–3.200 ms to 1.604–1.666 ms. Durable creation measures
  44.222–74.645 ms after the replacement and 46.543–81.769 ms before it.
  Public receipt measures 52.252–90.227 ms after the replacement. Whole-test
  time measures 2.20–2.25 seconds. Matched DuckDB creation measures
  338.981–644.293 ms; public receipt measures 409.746–747.479 ms; whole-test
  time measures 5.35–5.37 seconds. The paired creation gain is 7.56–10.37 fold.
  Workload hashes, profiles, and measurement boundaries remain equal.
  The 100-fold target remains **Not done**. These pairs do not establish a
  sustained latency bound. Read `graph-contracts-build.json`,
  `graph-contracts-comparison.json`, `graph-contracts-stages.json`, and
  `graph-contracts-final-native.log` under
  `output/araphor-fjall-migration-20261110`.

- A compile-only Data unit diagnostic after profile retirement reports
  887 errors, including cascading errors. The command is `cargo test --offline
  -p araphor-data --lib --no-run --message-format=json`. The largest groups are
  obsolete managed and dependency fixtures. This diagnostic runs no tests and
  does not identify 887 production defects. Read `post-profile-fixtures.json`
  and `post-profile-fixtures-build.jsonl` in the same evidence directory.
  The complete Data unit target remains **Not done**.

- The complete legacy profile SQL fixture family is removed. Ten native cases
  replace the remaining root, captured-context, state, notice, and Arrow cases.
  The original atom snapshot, manifest, source identity, and Arrow assertions
  remain. Cancellation and rejected changes preserve Data revision, original
  journal position, context rows, and processor heads. The changed-context case
  uses a valid new profile and succeeds with the unchanged context on the same
  attempt. Completed admission retries write nothing. Failed attempts finish
  through the normal lifecycle before stable reopen checks.
  Native sealing advances the current head. The state case then creates a new
  live interval and repairs the older sealed interval. The newer history cannot
  replace the live head. Notice rows preserve independent interval values and
  historical cuts. A new managed publication can write its own receipt while
  it leaves the Notice revision unchanged. DataFusion package SQL owns notice
  threshold selection; the removed Data threshold API is not restored.
  The unused private `ProfileWrite` enum is removed. Typed profile APIs remain.
  After removal, `cargo test --offline --release -p araphor-data --features
  test-fixtures --test native_managed --test native_lifecycle --
  --test-threads=1` passes 118 managed cases in 13.00 seconds and six lifecycle
  cases in 0.29 seconds. Read `profile-contracts-final-native.log` under
  `output/araphor-fjall-migration-20261110`. Result: **Done for profile fixture
  retirement**. This change establishes no additional incident latency gain.
  Other obsolete fixtures and complete qualification remain **Not done**.

- Causal constructs its required finding relation directly. The previous
  factory constructs four domain relations and discards three. The replacement
  keeps the same relation name, node kind, and property schema. No SDK, ABI,
  validation, or component lifetime changes. A temporary diagnostic attributes
  2.345–2.360 ms of each median guest call to package construction. Both markers
  are removed after one unchanged successful incident. The diagnostic patch and
  result remain in `guest-probe.patch`, `guest-probe-incident.json`, and
  `guest-probe-breakdown.json` under
  `output/araphor-fjall-migration-20261110`.
  Both matched incident pairs pass with unchanged test and definition hashes.
  Creation measures 44.157–82.437 ms after the replacement and
  49.254–86.804 ms immediately before it. Public receipt measures
  53.124–99.965 ms after the replacement. Whole-test time measures
  2.26–2.30 seconds. Median component calls fall from 5.893–6.292 ms to
  4.651–5.099 ms. Matched DuckDB creation measures 325.501–645.427 ms;
  public receipt measures 394.637–752.137 ms; whole-test time measures
  5.45–5.54 seconds. The paired creation gain is 7.34–9.87 fold.
  These short pairs do not establish a sustained latency bound.
  The focused native Query target passes all three selected cases in
  2.68 seconds. The cases compare the complete descriptor and JSON bytes,
  commit real Wasm Graph mutations with consumed progress, and retain indexed
  versions. Read `direct-finding-query.log` in the same evidence directory.
  The 100-fold target remains **Not done**. Read `direct-finding-build.json`,
  `direct-finding-comparison.json`, and `direct-finding-calls.json` in the
  same evidence directory.

- Native profile expiry-gap parity is **Done for the four gap contracts**.
  The legacy SQL gap module is removed. Eight native cases preserve the
  original `a`, `bc`, `d` batches, two-record interior expiry, zero retained
  floor, exact clipped proofs, Required rejection, rollback, retries,
  compaction, and reopen. A later expiry cannot authorize a gap in an older
  capture. A valid non-gap result from that capture survives publication and
  restart. Missing or changed accepted gaps reject reopen. Initial profile and
  interval IDs remain independent. The final managed commit checks cancellation
  after its test hook. The former global raw-count helper has no production
  callers and is test-only. The final focused command passes 108 native managed
  cases in 2.34 seconds and six lifecycle cases in 0.14 seconds. Read
  `profile-gap-before-valid.log`, `profile-gap-verified-proof.log`, and
  `profile-gap-final-native.log` under
  `output/araphor-fjall-migration-20261110`. At that qualification, ten other
  legacy profile cases remained. The later grouped port above replaces those
  cases. This parity change establishes no incident latency gain over the
  preceding native source. Both current production incident pairs pass with
  unchanged test and definition hashes. Creation measures 47.035–83.606 ms;
  public receipt measures 55.053–99.452 ms. Whole-test time is 2.10–2.12 seconds.
  Matched DuckDB creation measures 333.982–620.317 ms, with public receipt at
  393.711–713.503 ms and whole-test time at 5.11–5.12 seconds. The paired
  creation gain is 7.01–8.04 fold. The 100-fold target remains **Not done**.
  Read `profile-parity-comparison.json` and `profile-parity-build.json` in the
  same evidence directory.

- Scoped native Graph reads are **Done** for retained property lookup.
  `Graph::scoped_view` reads one relation and one writer through five metadata
  point reads. Data keeps the existing layer, member, schema, reservation, and
  canonical-candidate checks. The old whole-Graph setup is removed from
  `Values::load`. All 14 native Graph cases pass in 0.72 seconds. All 24 native
  Data domain cases pass in 2.57 seconds. Both opposite-order incident pairs
  pass. Durable creation measures 49.130–91.787 ms. Public receipt measures
  57.319–107.847 ms. Whole-test time is 2.26–2.32 seconds. The preceding native
  pairs measure 46.825–86.908 ms for creation; these timings establish no
  end-to-end gain. The matched DuckDB control measures 333.715–632.588 ms for
  creation, 400.419–737.869 ms for public receipt, and 5.31–5.32 seconds for
  the whole test. The 100-fold target remains **Not done**. Read
  `scoped-graph-comparison.json`, `scoped-graph-build.json`,
  `scoped-graph-native-tests.log`, and `scoped-data-tests.log` under
  `output/araphor-fjall-migration-20261110`. The Graph test command enables
  `native-store`; the earlier default-feature command selected zero tests and
  supplies no qualification.

- A package frontier experiment is **Not applied**. It compares normalized
  coverage projections and adds shared claim dependency keys. Five focused
  cases and all six matched incident runs pass, but the third notification
  regresses in both pairs. The native control measures 86.701–87.694 ms from
  collector receipt to durable creation. The experiment measures
  109.166–111.005 ms. Public receipt measures 102.404–103.573 ms before and
  125.486–125.510 ms after. The experiment also misses canonical event arrival
  when the audit is already indexed and the coverage projection stays equal.
  Coverage equality does not establish unchanged raw input. The source and
  tests are restored to the preceding native implementation. Read
  `coverage-frontier-comparison.json`, `coverage-claims-build.json`, and
  `coverage-frontier-unapplied` under
  `output/araphor-fjall-migration-20261110`. The patch remains an unapplied
  artifact. No performance gain is claimed.

- Aggregate component timers now separate wire checks, encoding, invocation,
  decoding, instantiation, guest calls, and cleanup. Graph callbacks also report
  their native service intervals. The unchanged diagnostic incident passes in
  2.24 seconds. Median guest calls measure 5.988 ms for `detect` and 6.423 ms
  for `index`. Median Graph callback time measures 1.204 ms for detection
  staging and 1.506 ms for index reads. Detection makes no Graph reads.
  These measurements include guest wire and runtime work; the remaining time
  is not a pure analysis measurement. The 31 Wasm runtime cases pass serially
  in 34.38 seconds. An earlier parallel run times out before guest entry in
  `dropped_runtime_future_retains_worker_until_completion`; its unchanged exact
  rerun and serial suite pass. The cause is not established. Read
  `graph-callback-breakdown.json`, `graph-callback-runtime.log`, and
  `component-phases-runtime.log` under
  `output/araphor-fjall-migration-20261110`. These timers establish attribution,
  not a performance gain.

- The processor history SQL fixture is removed. Its native replacement checks
  exactly four same-key versions through historical snapshots. Registration,
  two results, and retirement preserve context watermarks and result bodies.
  Retries and rejected commits do not advance Data revision or the original
  journal. Two raw records expire. The version chain survives compaction and
  reopen. Native recovery rejects all five former SQL corruption classes.
  `cargo test --offline --release -p araphor-data --features test-fixtures
  --test native_managed processor` passes all three cases in 0.47 seconds.
  Result: **Done for processor history fixture retirement**. Other SQL fixture
  ports and the complete replacement remain **Not done**.

- Host evaluation checks are consolidated at each execution boundary. The
  checked host value supplies encoding, narrowed Graph capability, and bounded
  output decoding. Guest, IPC, command, output, and current-authority checks
  remain. The compiler uses Wasmtime's supported `Speed` mode. All 90 SDK
  cases and 31 Wasm runtime cases pass. Current ABI fixtures preserve request
  and table layout checks. The added host-pointer offset check also passes.
  The unchanged release incident passes in two opposite-order pairs. Durable
  creation measures 48.825–85.716 ms; public receipt measures 56.820–101.549 ms.
  Whole-test time is 2.12–2.16 seconds. The paired DuckDB control measures
  330.549–591.894 ms for durable creation and 392.560–693.307 ms for public
  receipt. Its whole-test time is 5.08–5.14 seconds. Each run preserves
  18 collector inputs, 16,384 bulk rows, and three durable creations.
  These pairs establish no clear latency gain over the preceding native
  release. The 100-fold target remains **Not done**. Read
  `output/araphor-fjall-migration-20261110/checked-evaluation-comparison.json`,
  `checked-evaluation-phases.json`, `checked-evaluation-build.json`,
  `checked-evaluation-sdk-final.log`, `checked-evaluation-runtime.log`, and
  `checked-evaluation-host-layout.log` in the same directory. Initial package
  phase sums pass their exact interval check. The largest phase is evaluation,
  with medians of 7.043 and 6.569 ms before check consolidation. Further
  attribution is required before the next replacement.

- A native shared-library preparation experiment is **Not applied**. Matched
  release pairs show no measured incident gain. The unchanged production source
  measures 49.939–91.869 ms from collector receipt to durable creation. The
  experiment measures 49.799–88.833 ms. The paired DuckDB control measures
  335.300–610.966 ms. Each run has 18 collector inputs, 16,384 bulk rows, and
  three durable creations. Source inspection confirms that `causal_bundle`
  selects the Wasm Causal component. Shared-library loading is outside this
  incident path. The experiment is removed from production. Its patch, tests,
  and review text remain under
  `output/araphor-fjall-migration-20261110/native-preparation-unapplied`.
  Read `native-prepare-comparison.json` and the before/after build records in
  the same evidence directory. Five stale Wasm runtime fixture calls now pass
  the absent host explicitly. The fixture array matches its four actual
  components. All 20 existing Wasm runtime cases pass in 15.68 seconds after
  the experiment is removed. These fixture repairs establish no latency gain.

- Data storage quota removal and native backup fixture retirement are **Done**
  for the focused source boundary. The final native run passes 8 backup cases,
  3 crash cases, 6 lifecycle cases, 99 managed cases, 4 notification cases, and
  26 package cases. The managed snapshot fixture now expects exact
  `Missing: Source Graph snapshot`. Its unchanged fixture has no package state;
  the previous `Unsupported` assertion predates native snapshot support.
  A native Query trace case passes capture, revocation, and denied execution.
  The two process-isolated file-size fault cases pass in 3.76 seconds. The
  fixture copies the complete native backup tree, including empty directories.
  Raw append failure sends no ACK. Checkpoint-export failure follows an existing
  raw ACK and preserves source readiness. Recovery, exact retry, and reopen pass.
  The unchanged incident passes in 14.37 seconds in the debug profile. This
  result is functional proof only. The workload and definition hashes match
  the paired release record. Full CI, physical disk-full qualification, and
  the complete Data unit target remain unqualified. Read
  `output/araphor-fjall-migration-20261110/no-storage-quota-results.json`,
  `no-storage-quota-native.log`, `no-storage-quota-final.log`, and
  `no-storage-quota-incident.log`, and `no-storage-quota-io-export.log` in the same directory.

- At `0b8490cbd`, a compile-only Data unit diagnostic still fails. The command
  is `cargo test --offline -p araphor-data --lib --no-run --message-format=json`.
  It reports 1,060 errors, including cascading errors. This count does not
  identify 1,060 production defects. The largest source groups include backup
  fixtures, managed fixtures, and dependency fixtures. The diagnostic does not
  run tests. The 48 recorded native context/package cases remain passing
  evidence for their stated scope. Do not treat those cases as full unit-target
  qualification. The next agreed replacement uses public native backup APIs.
  Preserve the old assertions before removing their source. Read
  `output/araphor-fjall-migration-20261110/remaining-fixtures.json` and
  `remaining-fixtures-build.jsonl` in the same directory.
- Sixteen native catalogue/image cases pass in 13.85 seconds and replace
  fifteen old SQL cases. The retained dependency-order regression first fails
  on reopen. `PackageHeader::check` now sorts only its temporary ID vectors
  before comparison. Reopen preserves the reordered stored vector and exact
  image digest. The nine malformed-row branches keep their exact status,
  retry, and source errors. Public package revision and image reads use one
  configured reader permit and one view. Sixteen occupied slots, cancellation
  priority, and full permit release pass. The unchanged 33 MiB artifact,
  shared and explicit dependency uninstall, definition roots, reinstall,
  backup, and no-execution assertions pass. The separate private verifier and
  witness fixtures remain open. These changes establish no new incident gain.
  After old fixture removal, all 22 native context cases pass in 34.59 seconds
  and all 26 native package cases pass in 14.03 seconds. Existing warnings remain.
  Read `output/araphor-fjall-migration-20261110/package-order-before.log` and
  `package-catalogue-final.log` in the same directory.
- Five unused SQL storage files and five empty legacy package modules are
  removed. The production Data library passes `cargo check --offline -p
  araphor-data --lib` in 11.77 seconds. Existing warnings remain. The two
  `ResolvedInput` SQL files remain active native DataFusion queries. Twenty-five
  review links now use the verified successful DuckDB source revision; the
  guide text remains available as historical evidence. Current readers use
  the native storage review guide. No runtime test or timing comparison is
  repeated for these unreachable files. Read
  `output/araphor-fjall-migration-20261110/obsolete-sql-check.log`.
- Ten native package-context cases pass in 32.92 seconds. The collection
  regression first fails because targeted collection decodes another tenant's
  malformed context. Targeted collection and uninstall now scope roots,
  package headers, and dependency counts to their tenant. The existing owner
  index supplies context roots. Global collection remains strict and rejects
  malformed contexts without a Data revision or journal change. Repair and
  retry pass. The unchanged large closure has 1,025 artifacts, 1,024
  dependencies, metadata above one MiB, and 1,025 dependency exports. Backup,
  restore, digest equality, seven forged fields, exact retries, corruption,
  and a dependency removed after verification in the same transaction pass.
  The old ten-case SQL family is replaced. The two private verifier unit tests
  still require a native port. These checks establish no new latency gain.
  Final qualification after SQL fixture removal passes all 22 native context
  cases in 33.66 seconds and all ten native package cases in 0.21 seconds.
  Read `output/araphor-fjall-migration-20261110/context-collection-before.log`
  and `context-package-final.log` in the same directory.
- The connected release at `d429b0d08` passes two opposite-order incident
  pairs against the saved successful DuckDB release. Native durable creation
  is 49.947–88.429 ms; DuckDB is 334.639–601.712 ms. Paired gains are
  6.70–7.30 fold. Native public receipt is 59.273–123.986 ms; DuckDB is
  396.252–702.923 ms. Whole-test time is 2.12–2.23 seconds native and
  5.10–5.13 seconds DuckDB. Each run has 18 collector inputs, 16,384 bulk
  rows, and three durable creations. The workload hashes, release profiles,
  logging, and compiler-idle checks match. These runs meet the measured
  sub-100 ms creation target. They do not meet the 100-fold target or prove
  a sustained latency bound. The journal and resume corrections establish
  lifecycle behavior; these pairs do not establish a new latency gain over
  the preceding native version. Read
  `output/araphor-fjall-migration-20261110/cdc-replacement-comparison.json` and
  `cdc-replacement-provenance.json` in the same directory.
- Ordinary Query now calls `subscribe_inputs_since` with its saved consumed
  position. A partial position uses the previous Data cut and replays the
  original commit; a whole-commit position starts after that cut. The existing
  shared walker and selectors supply matching input. There is no demand-head
  scan or new change index. Store identity is checked before replay. Only
  `AnalysisInputExpired` maps to lawful log expiry; decoder and I/O failures
  keep their existing categories. The four public resume cases pass in
  2.54 seconds. All thirteen native Query cases pass in 34.24 seconds,
  including managed execution, Graph publication, finite runs, and version
  rollback. Six native input cases pass in 4.27 seconds. The exact bounded
  revision-1/ordinal-2 assertion now uses explicit original-log replay from
  zero. Fresh subscriptions start at their captured cut; replay for another
  subscriber does not wake them. The empty old SQL head module is removed.
  Read `output/araphor-fjall-migration-20261110/query-resume-after.log`,
  `query-native-execution-final.log`, and `native-saved-position.log`.
- Native checkpoint now collects acknowledged original journals. The minimum
  saved cursor includes every durable input generation and the shared reader.
  Fresh subscriptions capture under the same scan lock. Explicit subscriptions
  behind the acknowledged floor fail even if an old snapshot cached its cursor.
  The no-consumer check passes in 0.12 seconds. The two-consumer check passes
  in 0.93 seconds; the slower consumer and a rejected publication prevent
  release. Actual successful consumption permits release and restart replay.
  Removal, recreation, and old-generation revival pass in 0.53 seconds.
  Notification completion, exact retry, compaction, and no redelivery after
  restart pass after actual collection in 3.29 seconds. Six storage lifecycle
  checks pass in 1.31 seconds. Sixteen managed input cases pass in 3.76 seconds.
  The unchanged explicit complete-snapshot check also passes.
  Read `output/araphor-fjall-migration-20261110/native-journal-*.log`.
- At commit `e504189e3`, the broader `native_inputs` target had five passing cases and one existing
  failure: `raw_position_is_the_last_matching_record_in_the_original_span`.
  Fresh subscription position is zero; the assertion expects revision 1,
  ordinal 2. This case does not call checkpoint, and the committed pre-collection
  path had the same behavior. Query could incorrectly wait on a resumed ordinary
  read because that path treated the zero position as complete. The saved-cut
  correction above resolves that gap through original-log replay. This earlier
  qualification did not pass the complete target.
- The original public `coverage_changes` and `coverage_report` methods now
  use the native owner. Each read holds a reader permit and captures one
  Data view. Four focused cases pass in 0.21 seconds. They check an arrival
  after capture, persisted references, backup and restore, tenant and source
  scope, damaged unselected reports, corrupt references, and mid-read
  cancellation. Three default-feature cases pass in 0.43 seconds, including
  exact receipt history through raw expiry and reopen. The five replaced
  SQL cases and their local history helpers are removed. The historical
  corruption case remains pending its native port. Read
  `output/araphor-fjall-migration-20261110/native-coverage-parity.log` and
  `output/araphor-fjall-migration-20261110/native-coverage-default.log`.
- Staged Graph contracts now read package metadata through the same native
  transaction. Full-image authentication still reads the complete artifact.
  The public rollback regression fails on the old body read and passes on the
  metadata path. Three Graph checks pass in 0.14 seconds. Two opposite-order
  release pairs pass the unchanged incident. Median Graph staging changes
  from 5.039–5.549 ms to 3.243–3.424 ms. Durable notification creation changes
  are mixed: before 50.552–92.323 ms, after 49.794–88.307 ms. These runs do
  not establish an end-to-end gain. The 100-fold target remains **Not done**.
  Read `output/araphor-fjall-migration-20261110/staged-contract-comparison.json`.
- The release diagnostic with adjacent managed commit timers passes the
  unchanged incident in 2.07 seconds. Durable creation is 51.461, 76.219,
  and 86.388 ms; public receipt is 59.879, 88.493, and 102.181 ms. Nine
  package commits have median Graph staging of 4.870 ms, validation of
  1.885 ms, and durable commit of 1.001 ms. The eight inner timers sum to
  the existing transaction-work interval. This is an unpaired diagnostic;
  it establishes no new gain. Read
  `output/araphor-fjall-migration-20261110/native-phases-breakdown.json`.
- Four native coverage checks pass in 0.81 seconds. The bounded change case
  checks six exact reports, point reads, no-op retries, conflicting content,
  and rejected references with a changed Data revision. Native batches can
  contain multiple coverage reports at one Data revision. The old SQL
  `UNIQUE(commit_revision)` assertion does not apply to that existing contract.
  Its mixed SQL test is removed after the native behavior check passes.
  DuckDB interrupt, `EXPLAIN`, and SQL schema-only tests are also removed.
  Other behavior tests remain until their native ports pass. Read
  `output/araphor-fjall-migration-20261110/native-coverage-port.log`.
- Native backup and restore now have process-exit checks at eight actual
  durability boundaries. Three focused tests pass in 1.47 seconds. They check
  exact raw pages and native context state, final backup publication, incomplete
  restore rejection, recovery epochs, source readiness, and unchanged backup
  files. The replaced SQL backup and restore crash cases are removed. Read
  `output/araphor-fjall-migration-20261110/native-crash-final.log`.
- Commit `abdc4694e` contains the connected production cutover. Its qualification
  uses native format 9. The package-row replacement keeps metadata in `P`,
  and the original artifact body has a disjoint same-ID
  key. Routine contract reads use metadata only. Full reads join the body from
  the same cut. Native format 10 rejects older native stores. Ten package
  lifecycle, twelve context-proof, three Graph authority, and one format-rejection
  checks pass. The matched release build passed in 6 minutes 29 seconds.
- Two opposite-order native pairs pass the unchanged incident. Package metadata
  separation reduces collector-to-durable creation from 143.985–265.681 ms to
  50.864–89.282 ms, a measured 2.78–3.48-fold gain. Whole-test time decreases
  from 2.88–2.93 seconds to 2.09–2.12 seconds. Read
  `output/araphor-fjall-migration-20261110/package-header-comparison.json`.
- Two opposite-order matched DuckDB/native release pairs also pass. Native
  durable creation is 50.864–88.972 ms; DuckDB is 328.286–607.395 ms. The paired
  gain is 6.45–7.36 fold. Native public receipt is 58.730–104.749 ms; DuckDB is
  393.279–701.488 ms. Whole-test time is 2.08–2.12 seconds native and 5.03–5.09
  seconds DuckDB. Each run has 18 collector inputs, 16,384 bulk rows, and three
  durable notification creations. Test and definition hashes match the saved
  control. Read `output/araphor-fjall-migration-20261110/duckdb-header-comparison.json`.
  These short pairs meet the measured sub-100 ms creation target. They do not
  establish a sustained latency guarantee, and the 100-fold target is not met.
- The final connected release build passed in 7 minutes 20 seconds. The unchanged
  incident passed in 3.03 seconds. Collector receipt to durable notification
  creation was 147.276, 255.605, and 268.944 milliseconds. Public receipt was
  155.453, 266.644, and 285.581 milliseconds. Read
  `output/araphor-fjall-migration-20261110/public-cutover-incident-run3.json`.
  This run is unpaired. It proves neither performance target.
- Commit `4a99e7304` adds native Graph identity reads without property chunks.
  The 13 native Graph tests passed in 2.43 seconds.
- The native release incident build passed. The first native incident run
  failed in 91.73 seconds. The package committed its input, but Data did not
  emit `managed_commit_timing`. The unchanged test waits for that event.
  After the native commit event was restored, the unchanged incident passed
  in 3.10 seconds. That release build used optimization level 3, no debug
  information, and disabled debug assertions and overflow checks.
- In that successful run, collector receipt to durable notification creation
  was 137.893, 284.968, and 287.109 milliseconds. Collector receipt to public
  notification receipt was 147.791, 297.636, and 324.387 milliseconds. Read
  `output/araphor-fjall-migration-20261110/public-cutover-incident-run2.json`.
  This is an unpaired diagnostic run. Later Source read changes are not in
  that binary. Neither performance target is proved.
- The connected draft adds retained Source snapshots, package-owned state
  rows, indexed traversal, and Source binding reads for notifications. Expanded
  domain checks passed: 24 cases. These changes do not yet prove a latency gain.
- Fjall `7fd777c` and `lsm-tree` `56d74411` add admission before checkpoint
  output is created. Data checks backup capacity through that API. Restore
  checks entry limits before it creates the target. The focused engine checks
  passed: three Fjall cases and two LSM metadata cases.
- The draft restores Required-input byte and age admission from committed
  processor positions and original raw spans. Retention uses the same reconciled
  minima. Ordinary metadata writes check actual capacity; maintenance can free
  an over-capacity store. Six native lifecycle cases passed in 0.21 seconds.
  Read the [native storage review guide](../guides/araphor-native-storage-review.md)
  for the current owners, commit flow, checks, and remaining limits.
- Configured notification route and related-state bounds pass seven focused
  preparation cases. The indexed notification suite passes four cases.

Complete connected replacements before repeating their passing checks. Read the
[current execution priority](#current-execution-priority-2026-11-10) for the
implementation order. The records below describe earlier source states; they
do not qualify the current replacement.

## Previous qualification records
Research date: 2026-11-09. Result: **Research complete; production migration not done**.
This record proposes the production integration of the completed engine forks.
The optional native Graph participant and its existing package PoC caller are
now [qualified](../../crates/araphor-graph/examples/storage_poc/results/native-graph-2026-11-09/README.md).
The comparison records a slowdown. Production Data integration and the incident
performance targets remain **Not done**.
The optional native Data metadata owner now commits and publishes the existing
PoC's source, Graph, context state, and checkpoint writes. Its
[qualification](../../crates/araphor-graph/examples/storage_poc/results/native-data-2026-11-09/README.md)
passes five integration cases and the unchanged package workloads. The small
mixed timing differences establish no repeatable performance gain. The complete
production transaction and raw-view migration remain **Not done**.
The existing raw owner now publishes a shared persistent metadata root after
its durable append. Nine focused integration cases and the unchanged incident
pass. The [qualification](results/araphor-raw-index-2026-11-09.md) records the
source and limits. This does not establish a speedup. The combined raw/native
production Data view and cutover remain **Not done**.
The default-limit native owner now combines its exact raw prefix and native
snapshot. Actual Evidence and coverage storage passes 16 focused cases with
the existing transaction and schema regressions. Read the
[native raw qualification](results/araphor-native-raw-2026-11-09.md).
Production admission, routing, remaining transaction families, retention,
backup, and cutover remain **Not done**. No incident speedup is established.
Native package/image and definition admission and reads now pass 24 focused
cases with the existing storage regressions. Read the
[catalogue qualification](results/araphor-native-catalogue-2026-11-09.md).
At that catalogue qualification, collection, uninstall reclamation, capacity
accounting, qualified context/fact admission, managed lifecycle, and production
routing were **Not done**.
The native context owner now admits guarded batches, checked values, and
qualified interned values with the existing retained proof and fact decoder.
Thirty-four focused cases pass, including a current-owner shared-helper case.
Read the [context qualification](results/araphor-native-context-2026-11-09.md).
Context providers, managed results, notification lookups/effects, configured
capacity, collection, and production routing remain **Not done**.
Native managed admission and ordinary start/stop now use the existing manifest,
grant, retained-pin, and lifecycle contracts. New Graph mappings and declarations
share the admission transaction. Exact retries stage no writes. Read the
[managed qualification](results/araphor-native-managed-2026-11-09.md).
Attempt-dependent lifecycle, capture, result publication, consumed progress,
production activation, CDC routing, and notification batching remain **Not done**.
Native Arrow extraction now reads actual Evidence, coverage, and context rows
from one captured native/raw view. Body-free context indexes bound change and
owner reads. The shared raw scanner and Arrow builders preserve existing rows,
positions, witnesses, and references. Read the
[extraction qualification](results/araphor-native-extraction-2026-11-09.md).
At that extraction qualification, managed sealing and attempts were **Not done**.
Native managed capture now seals actual Arrow inputs. Native attempts preserve
live claims, pending indexes, terminal outcomes, failure status, and interrupted
frontier settlement. Read the
[attempt qualification](results/araphor-native-attempts-2026-11-09.md).
Shared publication validation now passes the unchanged incident. Read the
[shared validation qualification](results/araphor-shared-publication-2026-11-09.md).
That qualification checks the DuckDB production path. At that source state,
native successful publication was **Not done**; no matched gain was established.
The optional native Selected boundary now saves actual results, checkpoints,
Graph changes, findings, references, and consumed progress in one Data batch.
It restores actual priors and checks captured receipts and Graph authority on
reopen. Seventy focused Data tests pass. The unchanged production incident also
passes for the shared proof/import checks. Read the
[publication qualification](results/araphor-native-publication-2026-11-09.md).
This still uses DuckDB in production and establishes no native speedup.
Other destination owners, production providers, original-log routing, indexed
source-header maintenance, notifications, capacity, retention, backup, cutover,
and removal remain **Not done**.
Native result metadata and historical replay now use one captured view and
actual saved checkpoints. Indexed raw predecessors preserve historical
freshness after later appends and reopen. Seventy-three focused Data tests pass.
Read the [result-read qualification](results/araphor-native-result-reads-2026-11-09.md).
Production provider binding, cutover, and both performance targets remain
**Not done**.
Native finding and manifest tables now use saved publication cuts, visible
producer authority, and stable canonical tokens. A shared tenant index avoids
foreign publication reads without a durable format change. Seventy-four focused
Data cases pass. Read the
[finding-read qualification](results/araphor-native-finding-reads-2026-11-09.md).
Production provider binding, original-log routing, notifications, cutover, and
both performance targets remain **Not done**.
Optional native input routing now walks the original Fjall batches and raw
entries after a committed Data view. Shared readers stop at the published cut,
route matching positions, and replay after a saved view. Eighty-one focused
Data cases pass. Read the
[input-routing qualification](results/araphor-native-input-routing-2026-11-09.md).
At the input-routing qualification, durable consumer records, atomic
acknowledgement, collection floors, query resume parity, production binding,
cutover, and both targets were **Not done**.
Optional native managed subscriptions now save their exact interest and log
cut. Exhaustive completed captures advance consumed progress in the result and
Graph transaction. Recovery checks the actual successful capture. Ninety
focused Data cases pass. Read the
[consumption qualification](results/araphor-native-consumption-2026-11-10.md).
Result: **Done for optional native managed input consumption**. Production
query coverage mapping, collection floors, retention, notification batches,
backup, cutover, removal, and both incident targets remain **Not done**.
Native notification storage now supplies indexed finding/concern lookups,
ordered context pages, and checked batches of immutable versions. Historical
inserts and exact retries preserve current lookup membership. Read the
[notification storage qualification](results/araphor-native-notification-2026-11-10.md).
Result: **Done for optional native notification storage**. At that qualification, finding provenance,
prepared notification reads, production delivery batches, durable notification
consumption, retention, backup, cutover, DuckDB removal, and both incident
targets were **Not done**.
Native finding batches now read requested groups at saved publication cuts.
They use actual opening producers, retained historical parents, and one shared
witness, proof, and context accumulator. One hundred focused Data cases pass.
Read the [provenance qualification](results/araphor-native-provenance-2026-11-10.md).
Result: **Done for optional native finding provenance reads**. At that
qualification, native notification preparation, delivery batches, production
binding, retention, backup, cutover, DuckDB removal, and both incident targets
were **Not done**.
Native notification preparation now captures one view and returns the existing
prepared batch. Charged indexed reads supply current findings, routes,
obligations, exact pending subjects, and historical routes. Actual producers
supply proof; canonical values supply comparison only. One hundred and five
focused Data cases pass. Read the
[preparation qualification](results/araphor-native-prepared-2026-11-10.md).
Result: **Done for optional native notification preparation**. Production router
binding, delivery batches, durable notification consumption, retention, backup,
cutover, DuckDB removal, and both incident targets remain **Not done**.
Optional native Query now binds the existing DataFusion plans, source indexes,
package Graph journals, and managed subscriptions to native Data. The combined
gate passes 112 tests in 11 suites. Read the
[Query qualification](results/araphor-native-query-2026-11-10.md).
Result: **Done for optional native Query binding**. Production Control and
Analysis still use DuckDB. Production sink and router binding, delivery
batches, durable notification consumption, remaining storage owners, capacity,
retention, backup, cutover, removal, and both incident targets remain **Not done**.
Native Data now supports the remaining managed lifecycle operations and history
reads. Activation subscriptions walk lifecycle records through the shared original
journal reader. The final gate passes 120 tests in 11 suites, including actual
version promotion, rollback, recreation, consumer retirement, and reopen. Read the
[lifecycle qualification](results/araphor-native-lifecycle-2026-11-10.md).
Result: **Done for native Data lifecycle and original-log activation**. Production
Analysis host and sink binding, remaining storage owners, notification delivery,
capacity, retention, backup, cutover, DuckDB removal, and both incident targets
remain **Not done**. Production still uses DuckDB. No native gain is established.
Native Query now separates finite execution from durable input consumption.
First following execution and revived older generations restore complete source
coverage before they consume live changes. Guard rejection, stale admission,
restart, and post-capture input remain covered. The gate passes 127 tests in
11 suites. Read the [startup qualification](results/araphor-native-startup-2026-11-10.md).
Result: **Done for optional native subscription startup and version changes**.
Production binding, remaining storage owners, notification delivery, capacity,
retention, backup, cutover, DuckDB removal, and both incident targets remain
**Not done**. No native production speedup is measured.
Native Data now stores processor results and typed managed Profiles with
their contexts, reference pins, interval heads, notices, and consumed input.
The native gate passes 135 tests in 11 suites. Read the
[processor and Profile qualification](results/araphor-native-progress-2026-11-10.md).
Result: **Done for native processor registration, immutable results, retirement,
and typed managed Profile publication**. Native expiry/resume proof, production
binding, remaining storage owners, notification delivery, capacity, retention,
backup, cutover, DuckDB removal, and both incident targets remain **Not done**.
The shared-progress library tests fail to compile. At that qualification, the
production binding check failed with 24 errors. No native production speedup is measured.

Native Data now stores Graph source publications and retained membership with
the same Selected result, Graph journals, reference pins, and consumed input.
The frozen gate passes 144 tests in 11 suites. Read the
[source qualification](results/araphor-native-source-2026-11-10.md).
Result: **Done for optional native source publication and retained input reads**.
Source finding providers and notification revisions remain **Not done** and
return `Unsupported`. Recovery can scan growing membership repeatedly. The
native Analysis binding check failed with 14 errors at that qualification. Production still uses
DuckDB. Cutover, removal, and both incident targets remain **Not done**.

The optional native Analysis host and DataFusion sink now use native Data
commit, lease, and original-log activation types. The frozen gate passes 96
cases in four suites. Default and native Analysis library checks and native
library Clippy pass. Read the [host qualification](results/araphor-native-host-2026-11-10.md).
Result: **Done for optional native Selected/copy host binding**. Graph and
Profile sink destinations compile but are not qualified at runtime by these
four new cases. At that host qualification, native builds exclude the
constructor for the DuckDB notification router. Native notifications, Source providers, production cutover,
removal, and both incident targets remain **Not done**.

The optional native Router now uses the existing prepared batch and native
context writes. Pending is durable before the sink effect; its outcome is
durable after the effect. The frozen gate passes 17 cases in four suites. Read
the [Router qualification](results/araphor-native-router-2026-11-10.md).
Result: **Done for optional native Router binding and concern delivery**.
The cases do not qualify actual finding routing. Native Host notification
binding, Source providers and revisions, durable notification consumption,
notification write batches, configured capacity, retention, backup, cutover,
DuckDB removal, and both incident targets remain **Not done**. Production
still uses DuckDB. No native production speedup is measured.

The native Source reader now supplies finding values, provenance, scalar
manifests, and whole Graph revisions. Per-instance window winners preserve
independent packages on the same source. Historical reads use each retained
publication cut. Source finding revisions share one value during notification
preparation. Native format 6 adds the winner index and rejects older formats.
Read the [Source read qualification](results/araphor-native-source-reads-2026-11-10.md).
Result: **Done for optional native Source finding and revision reads**.
Full Source snapshots, metadata bodies, binding-scoped reads, mutable Graph
notices, and bounded recovery cost remain **Not done**. Native notification
completion and batches, capacity, retention, backup, production cutover,
DuckDB removal, and both incident targets remain **Not done**. Production
still uses DuckDB. No native production speedup is measured.

The native notification provider now supplies Arrow rows from one captured
view. Current reads use context heads; exact requests use immutable versions.
Finding scalar reads cache publication authority per result. The actual
notification SQL runs through native DataFusion and a finite Subscription to
the Router and its Pending-before-effect boundary. Read the
[notification provider qualification](results/araphor-native-notification-tables-2026-11-10.md).
Result: **Done for optional native notification snapshot reads and finite SQL
delivery**. Affected-key reads, durable notification completion, write batches,
native Host notification admission, capacity, retention, backup, production
cutover, DuckDB removal, and both incident targets remain **Not done**.
Production still uses DuckDB. No native production speedup is measured.

The native Router now stages ordered immutable context versions and commits
Pending across ready obligations before sink effects. Outcomes join the next
delivery kind or the final batch. Direct delivery uses the same procedure.
Read the [batch qualification](results/araphor-native-notification-batches-2026-11-10.md).
Result: **Done for native notification delivery batches**. Durable notification
CDC completion, affected-key reads, native Host admission, capacity, retention,
collection, backup, production cutover, DuckDB removal, and both incident targets
remain **Not done**. Production still uses DuckDB. No native speedup is measured.

The optional native Host now runs its notification SQL definition with a durable
consumer. Data commits final outcomes, exact context references, completion
receipts, and consumed input together. Pending batches remain separate from
completion. Reopen validates retained native cuts; joined shutdown releases the
query worker before store reopen. Native format 7 adds completion receipts.
Read the [notification CDC qualification](results/araphor-native-notification-consumption-2026-11-10.md).
Result: **Done for optional native notification CDC completion and Host concern
delivery**. Actual Source/finding delivery, affected-key reads, remaining storage
owners, capacity, retention, collection, backup, public Data cutover, DuckDB
removal, and both incident targets remain **Not done**. Production still uses
DuckDB. No native production speedup is measured.

Native Data now records source recovery ranges without advancing accepted
cursors or creating source bindings. Historical extraction reads the ranges
under its actual budget. Original committed batches route matching Removal
changes. Reopen checks range order and the recovery relation notice. Native
format 8 adds this authority and rejects earlier formats. The focused gate
passes 155 tests in nine suites. Read the
[source recovery qualification](results/araphor-native-source-recovery-2026-11-10.md).
Result: **Done for optional native source recovery records, extraction, and CDC**.
Configured capacity, retention, trace storage, backup, complete Source providers,
public Data cutover, DuckDB removal, and both incident targets remain **Not done**.
Production still uses DuckDB. No native performance gain is measured.

The active user goal now approves that integration. No benchmark is added. Read the
[storage design](../plans/araphor-log-graph-storage.md),
[engine contract](../plans/fjall-versioned-storage.md), and
[latest incident result](../plans/araphor-execution-handoff.md#follow-transactions-use-the-recorded-input-cut-2026-11-05)
with this record. Earlier measurements do not describe a completed migration.

Source: Runtime `d30dceaba`, Fjall `a04286570637`, and `lsm-tree` `2e1b5df34ffc`.
Both engine checkouts use `feat/versioned-storage`. Unrelated working changes
are outside this research.

## Measured starting point

The latest qualified incident result passes. Its workload includes four evidence
streams on two nodes, 16,384 background logical records, 16,402 total raw records,
and three notifications. The definition calls the Causal package's `index` and
`detect` exports. The partial incident must produce no finding. See the
[test](../../crates/mithril-e2e/src/discovery/packages/required/incident/incremental.rs#L695)
and [default definition](../../packages/default-definitions/causal.yaml).

| Existing measured boundary | Recorded result |
| --- | ---: |
| Collector receipt to first durable notification creation, three episode medians | 1,659.962 / 3,041.402 / 3,300.817 ms |
| Graph publication to notification creation, same episodes | 334.079 / 486.592 / 559.939 ms |
| Final later managed commit, median | 960.515 ms |
| Private preparation inside that commit | 118.467 ms |
| Transaction work inside that commit | 786.845 ms |
| Final durable commit call inside that commit | 51.528 ms |
| Publication-row preparation inside transaction work | 266.034 ms |
| Graph journal work inside transaction work | 366.222 ms |
| Native Graph application inside Graph journal work | 277.772 ms |

These intervals are nested. Do not add child intervals to their parents.
They do not give a complete, disjoint breakdown of collector-to-creation time.
The final later commit, its SQL storage requests, and notification processing
are concrete replacement targets. Source capture and package input processing
also remain on the path. Replacing only the 51.528 ms commit call cannot meet
the complete latency goal. The
[handoff](../plans/araphor-execution-handoff.md#follow-transactions-use-the-recorded-input-cut-2026-11-05)
records the paired runs; their original JSON remains at
`/tmp/araphor-recorded-follow-pairs-20261105/`.

The completed engine's unchanged PoC has an ordinary combined median of
4.655 ms, p95 of 7.668 ms, and maximum of 8.171 ms across 112 samples.
This interval includes source write, original-journal wake, package Graph work,
atomic Graph/progress commit, output wake, and result read. It excludes production
DataFusion input capture and notification processing. The
[reviewed evidence](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/simplification/README.md)
does not establish an incident speedup or large-history performance.

## Required runtime flow

```text
Control accepts a raw-only event batch
  -> Data completes the existing raw segment append and durable sync.
  -> Data publishes the new raw prefix with the unchanged metadata snapshot.
  -> Data signals its raw log reader that committed data is available.
  -> The reader walks actual committed raw entries after its saved position.
  -> The reader routes matching source positions to existing subscription interests.

A context, table, Graph, or finding mutation commits
  -> One Fjall batch saves the rows and their indexes.
  -> SyncAll completes and returns the exact native revision and journal cursor.
  -> Data publishes the matching snapshot and native owners.
  -> Data's journal reader decodes the committed batch.
  -> Data routes only matching input changes after the subscriber's consumed position.

A package subscription receives matching input progress
  -> Query captures one Data view and the interval after its saved input position.
  -> Providers supply changed keys and the declared before and after Arrow inputs.
  -> The saved native DataFusion plan performs the declared SQL and package calls.
  -> Package code reads indexed Graph data only when its algorithm needs Graph.
  -> Package code stages the changes that it selects.

The package step is ready
  -> Data checks existing authority, state heads, evidence, and recorded input cut.
  -> Araphor Graph adds prepared membership, property, and adjacency changes.
  -> One branch transaction saves all outputs, state, result references, and input progress.
  -> Data completes SyncAll and publishes one matching Data view.
  -> Journal routing wakes subscribers to the changed output.
  -> Later input remains pending after the consumed input cut.

Notification input changes
  -> The saved notification plan selects changed findings and affected obligations.
  -> The router prepares the required obligations and pending delivery attempts.
  -> Data saves the batch and the router's consumed input position atomically.
  -> Delivery performs the existing live authority check outside the write transaction.
  -> Data saves delivery outcomes through the same notification owner.

Execution fails, or a durable commit outcome is uncertain
  -> Data does not publish unconfirmed output or acknowledge its input.
  -> An uncertain commit stops new captures and writes until recovery.
  -> Recovery restores durable state, history protection, and saved consumer positions.
  -> Retry reads from the last committed input position.
```

First-source admission can require a metadata commit before the raw-only path.
That commit follows the metadata flow above. It must not start Graph analysis;
the running package definition owns that work.

## Parts that must change

| Current source owner | Replacement and removal |
| --- | --- |
| [Data store](../../crates/araphor-data/src/analysis/mod.rs#L108), [connections](../../crates/araphor-data/src/analysis/connection.rs#L412), and [read control](../../crates/araphor-data/src/analysis/read.rs#L257) | Own the versioned database, live branch, typed keys, and published views. Remove DuckDB writer/read connections, SQL transactions, and native query interrupt plumbing. Keep leases, cancellation, admission, and uncertain-commit behavior. |
| [Raw journal](../../crates/araphor-data/src/analysis/raw.rs#L557), [segment I/O](../../crates/araphor-data/src/analysis/raw_segments.rs#L230), and [SQL projection](../../crates/araphor-data/src/analysis/raw_catalog.rs#L607) | Keep durable raw bytes, receipts, and exact cursor ranges. Publish a shared immutable index of committed raw entries. Remove lazy raw-to-SQL projection and reader dependence on `project_raw`. No Fjall payload copy or extra Fjall sync is required for each raw-only append. |
| [Input registration and publication](../../crates/araphor-data/src/analysis/inputs/mod.rs#L43) and [interest matching](../../crates/araphor-data/src/analysis/inputs/interest.rs) | Keep actual native-plan interests. Replace producer calls to `inputs.publish` and `inputs.metadata` with log-reader routing. Index interests by branch, tenant, and relation, with existing source/owner selectors. Do not scan all subscribers for every changed row. |
| [Managed commit](../../crates/araphor-data/src/analysis/managed/commit.rs#L156), [Graph commit](../../crates/araphor-data/src/analysis/managed/graph/commit.rs#L438), and [source state](../../crates/araphor-data/src/analysis/managed/source.rs) | Replace SQL joins/appends with indexed typed reads and one write set. Preserve the complete atomic result/state/Graph/progress boundary. Prepare private Arrow values before the writer scope. Reuse retained call state; do not restore all earlier outputs on each wake. |
| [Graph storage](../../crates/araphor-graph/src/store.rs#L27), [layers](../../crates/araphor-graph/src/layers.rs#L28), [dictionaries](../../crates/araphor-graph/src/dictionary.rs), [properties](../../crates/araphor-graph/src/properties.rs), and [read views](../../crates/araphor-graph/src/read/view.rs#L13) | Replace SQL dictionaries, membership intervals, endpoint joins, and reconstruction with stable keys, native historical snapshots, and direct/reverse adjacency. Keep opaque Graph/writer/owner IDs and typed Arrow values. Use Data's supplied transaction; Graph does not open a database or commit. |
| [Data Graph rows](../../crates/araphor-data/src/analysis/graph_rows/store/mod.rs), [native relations](../../crates/araphor-data/src/analysis/graph_rows/store/relations.rs), and [finding reads](../../crates/araphor-data/src/analysis/extraction/graph/native.rs) | Store result membership, producers, finding projections, provenance, and evidence indexes in the same live branch. Remove duplicate SQL membership preparation. Data retains package attribution; generic Graph retains no detector rules or package definitions. |
| [Table extraction](../../crates/araphor-data/src/analysis/extraction.rs#L1767) and [Arrow table builders](../../crates/araphor-data/src/analysis/extraction/tables/mod.rs) | Read exact key/prefix/range selections from a pinned view. Build requested Arrow columns. Reuse immutable Arrow chunks. Remove SQL staging and complete-table reconstruction from ordinary change reads. |
| [Query sources](../../crates/araphor-query/src/sources/mod.rs), [change contracts](../../crates/araphor-query/src/definition/package/changes.rs#L9), [progress](../../crates/araphor-query/src/stream/progress.rs), and [saved execution](../../crates/araphor-query/src/stream/physical/runtime.rs) | Bind the new views, log positions, and affected-key reads to existing providers. Keep native plans, package-call operators, joins, filters, windows, and declared change contracts. A CDC signal does not make arbitrary SQL incremental. |
| [Notification processing](../../crates/araphor-analysis/src/notification/reactive.rs), [saves](../../crates/araphor-analysis/src/notification/store.rs#L133), [attempts](../../crates/araphor-analysis/src/notification/attempt.rs), and [Data notification indexes](../../crates/araphor-data/src/analysis/notification.rs) | Replace per-obligation context commits and repeated lookup cycles with one bounded preparation and batch save. Keep route selection, retry, escalation, ordering, and pending-before-effect behavior. Route changes must reevaluate their affected existing findings. |
| [Contexts](../../crates/araphor-data/src/analysis/context.rs), [packages](../../crates/araphor-data/src/analysis/packages/mod.rs), [definitions](../../crates/araphor-data/src/analysis/definitions.rs), [progress](../../crates/araphor-data/src/analysis/progress.rs), and [trace](../../crates/araphor-data/src/analysis/trace.rs) | Replace their SQL records and indexes, including exact version references, installation, lifecycle, coverage, trace intent, and completion. Preserve existing artifact and raw-file ownership. |
| [Retention](../../crates/araphor-data/src/analysis/retention.rs), [capacity](../../crates/araphor-data/src/analysis/capacity.rs), [validation](../../crates/araphor-data/src/analysis/schema.rs), [backup](../../crates/araphor-data/src/analysis/backup.rs), and [recovery](../../crates/araphor-data/src/analysis/connection.rs#L288) | Replace database-specific operations and accounting. Coordinate native history, CDC floors, evidence pins, file deletion, branch deletion, and reopen. A native snapshot alone is not a complete Data backup. |
| [Cargo dependencies](../../Cargo.toml), [Graph feature](../../crates/araphor-graph/Cargo.toml), and [storage fixtures](../../crates/mithril-e2e/src/discovery/data_store.rs) | Pin both forks. Remove DuckDB dependencies and vendor patches once no caller requires them. Replace database-file inspection and SQL corruption fixtures with equivalent native checks. Keep the selected incident's workload and assertions. |

The native Graph PoC in
[native.rs](../../crates/araphor-graph/examples/storage_poc/native.rs) supplies
an indexed layout and package parity evidence. Move its useful storage work to
the production owners. Do not ship its multi-engine benchmark dispatch, fixture
assumptions, full-prefix collection helpers, or unrestricted property cache.

Current Graph traversal already uses
[native committed memory indexes](../../crates/araphor-graph/src/committed.rs#L283).
DuckDB still supplies metadata, durable writes, and recovery. Preserve useful
indexed reads and shared Arrow buffers within the published view. Moving every
warm read to disk does not establish an improvement.

Update the published raw index by sharing unchanged tree paths. Do not copy the
complete source catalogue on each append. Keep the finite read/file lease;
an inactive subscription or historical engine snapshot must not hold every raw
file open or prevent evidence retention.

The current [attempt registration](../../crates/araphor-data/src/analysis/managed/commit.rs#L25)
also commits before execution. Fold ordinary step bookkeeping into the final
atomic write after retry and recovery parity is proved. Keep installation,
grants, activation, and lifecycle at their existing durable boundaries.

## Storage, revisions, and Graph history

Use one live engine branch for the complete atomic Data state. Separate key
families by record kind and tenant. Do not create a storage branch per package,
Graph, writer, or table: the existing branch transaction writes one branch.
Graph writer IDs and layer IDs retain their current meanings.

Mutable rows and adjacency postings use stable keys. Native versions retain
their earlier values and strong deletions. Immutable context versions, result
IDs, and layer IDs remain semantic identities where current APIs reference them.
An immutable revision-to-cut index is control metadata, not a revision suffix
on every mutable key.

Keep three coordinates distinct:

- Data revision and ordinal identify the public committed input order.
- Native `Revision` selects a retained metadata/Graph view.
- Physical raw positions and Fjall `Cursor` values identify resumable log progress.

The engine returns its exact native revision only after commit. Data
needs that cut in a durable index in the same batch. Fjall `cceaa84` adds the
consuming `BranchWriteTransaction::commit_stamped(keys)`.
It uses the existing private
[batch revision stamps](../../fjall/src/batch/mod.rs#L69). Each supplied key
receives the exact native revision of this batch. Duplicate keys and collisions
with staged puts/removes are errors. Stamps are writes; a stamps-only commit is
nonempty. There is no provisional revision read. Empty or over-width stamp keys
return an invalid-input error before sequence allocation. This API is **Done**;
its production Data caller and the production migration remain **Not done**.

Data stamps `cut/<Data revision>` and required `layer-cut/<layer ID>` records.
To open Data revision R, seek the greatest metadata cut-index entry at or before
R, then call `branch.read_at(cut)`. Combine it with raw entries through R.
Create an initial cut-index entry before admitting source input. A raw-only
revision reuses the prior metadata cut and needs no extra database transaction
or raw-format change. Do not obtain a historical cut by sampling today's head
or rebuilding an index from journals that can be reclaimed.

The ordinary Graph view selects each writer's latest layer at the common Data
cut. A request that explicitly selects older writer layers needs the retained
native view for each selected writer. Put writer identity in membership and
adjacency prefixes, read each prefix at its selected cut, and merge through
existing Graph ownership rules. Enumerating only today's adjacency loses edges
that existed at an older selected layer. Keep the opened Data revision in member
values for existing origin/provenance behavior.

Use the TerminusDB principles already selected in the storage design: immutable
layer identity and parent, dictionary reuse, membership additions/removals,
indexed traversal, and separate head publication. Native MVCC replaces manual
storage-version intervals. It does not replace Graph ownership or package
analysis. Encode durable property chunks once with the existing Arrow IPC path;
reuse live Arrow buffers and charge them to existing memory owners. Preserve
valid long binary keys and property values through engine-width fragmentation.

A database checkout or fork uses `read_at` or `fork` on a retained native cut.
A full Data checkout must also bind its historical raw prefix and evidence
availability. Fjall does not fork or retain external raw files. A storage fork
does not activate package jobs or notification delivery. Branch merge is outside
the implemented engine contract.

History policy changes have separate durable engine commits. Install an
open-ended retained range before the first source write. Advance its lower
bound during maintenance from committed result, replay, and evidence references.
Protect the replacement range before releasing the old policy. Do not add one
policy commit per package step and claim that publication still needs only one
sync. This simple range retains intermediate revisions too; measure that storage
cost before proposing finer retention.

## CDC and incremental execution

The current [input owner](../../crates/araphor-data/src/analysis/inputs/mod.rs#L43)
is selective, but its producers publish change descriptions after their own
commits. It does not walk Fjall's original journal. Replace the producer route,
not the subscription API. Use one Data-owned reader per log domain and fan out
matched progress; do not open a journal reader for each package.

Fjall supplies `journal_feed`, `next_batch`, `wait`, cancellation, and
`retain_after`. Its
[items](../../fjall/src/cdc.rs#L13) contain branch/keyspace identity, key, new
value, and deletion. They have no query, tenant, finding-selection, or package
semantics. Data decodes its own typed keys and applies the existing input
selectors. Auxiliary index changes must not create duplicate source work.
An internal log-reader wake for available bytes is distinct from a package
source wake. `Feed::wait` blocks; keep it on the blocking owner and bridge
matched progress into existing async watches.

The current raw log remains the CDC source for event payloads. Walk its durable
entry positions and spans. A wake carries a high-water position, not the only
copy of the delta. Coalesced wakes must consume the complete required interval.
Data must not route a Fjall batch before the corresponding Data view is visible.

Registration must capture the view and both log starts under the floor
coordinator before collection can advance. A feed or snapshot handle does not
retain the journal. Save consumed positions with the step's output before
advancing the durable minimum floor. Keep physical scan progress separate from
completed matching work. Filtered traffic can advance a consumer's safe scan
position without calling its package; persist that progress before using it for
collection. Never skip pending matched input or create an acknowledgement loop
from the coordinator's own records.

Bind a saved scan position to the same subscription interest and job generation.
Coalesce filtered progress with ordinary commits. If only filtered traffic stops
collection, save a metadata-only checkpoint through Data. Save the decoded input
cursor, not a sampled head or the checkpoint's own cursor. Exclude coordinator
records from application source matching. Stop before the first matching batch
whose processing has not committed. A shared reader's scan head alone cannot
authorize collection for its consumers.

Native CDC contains no old values. Preserve required native history so providers
can obtain before and after values for the affected keys. Preserve raw references
when changes can remove evidence. History retention, journal retention, and raw
evidence retention have separate owners and floors. Releasing one does not
release the other two. Expired history must be reported; do not silently replace
it with current state.

Retain the saved native plan. Bind each execution to the exact view and changed
key interval. Push projection, key, prefix, and range selection into providers
when this avoids storage reads. Keep other expressions in native DataFusion.
This follows the official
[provider contract](https://datafusion.apache.org/library-user-guide/custom-table-providers.html).
Its current documentation is guidance; the checked-out dependency remains
DataFusion 55.0.0.

An input delta is not a complete incremental join result. Reuse the package's
declared affected/before/after contracts and native join operators. A new event
may require an older Graph neighbor or table row. The package can request that
indexed state; do not send only new rows and lose the earlier evidence. Existing
finite snapshot SQL keeps its complete semantics and measured cost. Unsupported
incremental plans remain an explicit implementation gap. A full evaluation on
each wake does not qualify as the incremental end state. The selected incident
definition must consume changes and indexed state on its ordinary update path.
This migration adds no custom join, aggregate, SQL evaluator, or automatic
incrementalization framework.

Materialize distinguishes readable history from completed input progress and
requires a consistent logical time across sources. That distinction supports
the proposed Data view and separate retention/consumption positions; it is not
evidence that Fjall supplies a Materialize execution engine. See
[source frontiers](https://materialize.com/docs/sql/explain-timestamp/).

## Delivery, recovery, and removal order

### Current execution priority, 2026-11-10

The user directs production retirement before more separate component
qualification. Continue with one connected production cutover:

1. Make the public Data store and managed transaction types resolve to the native
   owner. Keep Control, Observability, Query, and Analysis on those same types.
   Remove backend choices at callers. Compiler errors identify the remaining
   required APIs; temporary errors in the cutover draft are not a task blocker.
2. Complete those real owners in the same draft: trace storage, usage reporting,
   retention and deletion recovery, backup, package collection, and
   Source reads. Preserve their existing contracts. Do not add methods that
   ignore supplied limits or return success without the required work.
3. Remove the replaced SQL owner, projections, connection pools, schema code,
   dependencies, and obsolete fixtures. Preserve equivalent failure assertions
   and the exact incident. No permanent SQL fallback or second archive remains.
4. Run the unchanged production incident through the replacement. Replace any
   stage that repeatedly reads unchanged history with native change inputs and
   indexed state. Then measure the matched successful builds and both latency
   targets at the existing boundaries.

Use focused checks at a completed replacement boundary. Repeat a passing suite
only when a subsequent change, failure, or unresolved concern requires it.
Commit verified replacements. Full CI remains excluded during iteration.
The complete production replacement and performance proof remain **Not done**.

### Historical implementation order, 2026-11-09

This order records the earlier source state. The current priority above replaces
it. At that earlier state, the router decoded a batch but saved individual state
transitions through context commits. Batch preparation and the durable outbox
replace that storage procedure. Preserve each required pending-before-effect boundary.
Do not promise exactly-once external delivery; an effect and a local commit are
not one transaction. Keep current attempt identity and retry behavior.

The original order was:

1. Add and qualify exact cut stamping. Keep engine APIs generic. This API is
   complete at Fjall `cceaa84`; no production migration is complete yet.
2. Replace native Graph storage through Data-supplied native snapshots and write
   transactions. Use the existing package PoC as the first caller. Replace its
   duplicate storage algorithm with the production owner. Freeze its old control
   before changing the adapter. Keep workloads and logical assertions.
3. Add the Data view and typed transaction boundary with that real Graph
   participant. Replace every Data record in the atomic result boundary, including
   contexts, packages, state, evidence pins, results, and progress. Prove raw-only
   revision mapping, old readers during SyncAll, and rollback. Build the complete
   replacement before switching a running store. Do not split authoritative Graph
   and progress between two engines.
4. Connect raw and Fjall log readers, interest routing, native providers, and
   retained change-input execution. Remove producer-supplied source publications
   and raw-to-SQL projection when the replacement covers their callers.
5. Replace notification row commits with the batch outbox and changed-key reads.
   Run the unchanged incident path, then remove the old notification storage path.
6. Complete retention, capacity, validation, recovery, and backup/restore parity.
   Use a closed/quiescent native copy if no safe native backup API is available;
   copying live SST/WAL files is not a snapshot protocol. Restore native history
   and consumer floors before maintenance or collection. Check both external raw
   segments and referenced immutable artifacts.
7. Remove DuckDB schemas, connections, appenders, SQL-only fixtures, dependencies,
   and unused vendor overrides. Preserve the existing supported Data APIs and
   equivalent failure tests. Do not leave a permanent dual-backend framework.

No in-place conversion or legacy decoder is proposed here. Never open an existing
DuckDB directory as a new empty Fjall store. Use a separate new-format directory;
deployment migration of existing retained databases needs its own explicit scope.

## Proof and performance acceptance

Use the existing combined/stable PoCs as engine regression checks. Use only
`discovery::packages::required::incident::incremental::follows_incremental_sources`
for the incident performance comparison. Preserve its definition, data volumes,
partial-chain check, finding/evidence assertions, history checks, and timeouts.

Before and after binaries need matched release settings and source/lock records.
Use the existing paired-run procedure with no concurrent build. Report initial
creation, both later creations, bulk completion, public notification receipt,
and whole-test time separately. Attribute collector receipt and creation to the
actual incident input, not a later metadata commit. Keep successful complete-run
comparisons separate from the earlier failed 347.854-second run and older,
different workloads. Compute a 100-fold ratio only for the same boundary and
workload. Three notifications do not establish a production p99.

Reuse existing correctness cases for atomic failure, retry/reopen, raw retention,
Graph multi-owner membership, endpoint removal, exact historical results, source
selection, windows, revocation, delivery attempts, backup, and recovery. Add only
the missing regression checks at their owners. In particular, check registration
during commit, filtered traffic, pending input during collection/restart, and
before-images after compaction. A source wake must require matching unconsumed
input. Lifecycle and declared clock events retain their own wake reasons.

Record stage timings and work counts from the same successful incident runs.
If a stage still scans unchanged history or saves each row separately, replace
that procedure before tuning engine settings. Small changes within host variation
are not improvement evidence. Do not invent stage budgets or forecast a speedup
from the PoC. Keep full CI out of iteration, as requested. Production cutover,
sub-100 ms creation, and the 100-fold result remain **Not done** until measured.
