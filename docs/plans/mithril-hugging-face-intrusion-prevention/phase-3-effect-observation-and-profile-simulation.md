# Phase 3: Effect Observation And Profile Simulation

Status: Done. All 39 required Phase 4/5 input fixtures have an exact simulated
or hard-safety result. The privileged Rust probe and the runtime-specific
operator cases pass for the qualified physical slice. No prevention claim is
made.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 3 runbook](./manual-testing/phase-3-manual-acceptance.md)  
Closure matrix: [Phase 3 closure matrix](./phase-3-closure-matrix.md)
Implementation review: [Phase 3 implementation review guide](./phase-3-implementation-review.md)
Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Implement the complete source-policy compiler and observe-only local effect
model. Prove that every future deny is paired with the real actor, object,
hook, state, and physical result before enabling policy enforcement.

## Scope And Design Coverage

Chapters 10-21 and 28-31; Appendices A.11-A.14.

## Deliverables

### D3.1 — Source policy and compiler in Mithril Control

Implement the closed parser, registries, selectors, roles, entries,
transitions, effects, bounded exceptions, dispositions, exact conflicts,
canonical bytes, signatures, anti-rollback, and deterministic lowering.
Unknown/duplicate/open fields reject. Policy names may be reused; generations
and signed content remain exact.

### D3.2 — Candidate generation and simulation

Build complete inactive map generations, read them back, run deterministic
simulation, and generate explanations without activating physical denial.
Non-path selectors expand to finite exact keys; hierarchical paths compile to
the bounded component graph and exact-object candidate stage.

### D3.3 — Meta canonical path and mount-view implementation

Implement the approved bounded `d_name` vector, state graph/wildcards,
mount-root index, lowest-`mnt_id_unique` selection, selected parent/mountpoint
walk, actor `MountSecurityViewV1`, topology snapshot, DIRTY state, and strict
unresolved result. The bind-alias fixture must resolve the original tracked
`/var/run/secrets/service/config.json`, not the later
`/work/input/job-42/config.json` target. Version 1 does not cache final
decisions. It also leaves resolved path-candidate caching disabled unless a
separate hostile alias-equivalence proof shows that every cache key preserves
the exact component/mount-chain match; a bare exact-file-object cache is not
sufficient for pre-existing hard-link aliases.

### D3.4 — Observe-only effect families

Using the shared Interceptor, attribute the Phase 0-qualified exec, executable
memory, file/create/mutate, credentials, delegated I/O, IPC/process-control,
socket/network, device/ioctl/derived-object, privilege, mount, and
self-protection paths. Each event carries exact actor/object/operation/stage and
whether the physical effect completed.

### D3.5 — Exact object and dynamic-state models

Implement mount/file/socket/channel/device/derived-capability generations,
opened-file provenance, immutable executable classification, mm/VMA snapshot
identity, persistent object state, relationship candidates, and dynamic floors
without claiming byte provenance.

### D3.6 — Honest observe semantics

`OBSERVE` may allow only a simulatable policy denial and emit `WOULD_DENY` or
`WOULD_REJECT`. Missing identity, corrupt generation, prior LSM denial,
emergency restriction, ambiguous topology, and unsupported physical boundary
retain their hard-safety result.

### D3.7 — Standing incident observe increment

Run the unchanged HF worker and legitimate controls. Produce stable simulated
decisions for the managed/local branches of `HF-002` through `HF-012`, with
special focus on the earliest complete `HF-008` file-object block, without
changing application behavior or claiming prevention. Pure in-memory and
outside-authority branches retain their honest non-prevention result.

## Checkpoint

One deterministic signed candidate generation simulates every Phase 4/5
fixture with exact actor/object/stage/result, and the bounded canonical path
matcher passes its hostile corpus. Policy denial remains physically disabled.

## Required Tests And Fixtures

- Policy/config/generation goldens and exact-conflict/exception tests.
- Observe/simulate the exact Phase 4 first-owned IDs:
  `ADMIN-EXEC-APPROVAL-001`, `DEVICE-DERIVED-001`,
  `FILE-CONTENT-RACE-002`, `FILE-FD-PASS-001`, `FILE-IDENTITY-001`,
  `FILE-MMAP-001`, `FILE-MMAP-SHARED-011`, `FILE-NAMESPACE-001`,
  `FILE-SA-TOKEN-OPEN-001`, `FILE-VMA-SNAPSHOT-001`, `HF-LOCAL-001`,
  `IPC-ASYNC-UNSUPPORTED-010`, `IPC-PEER-RACE-004`,
  `IPC-PROCESS-CHANNEL-009`, `IPC-RELATIONSHIP-ALLOW-003`,
  `IPC-RELATIONSHIP-UNMATCHED-005`, `LSM-DENY-SATURATION-001`,
  `MEM-EXEC-001`,
  `MEM-KERNEL-MAP-002`, `MOUNT-ATTR-001`, `MOUNT-CAS-002`,
  `MOUNT-PROPAGATION-003`, `MOUNT-SNAPSHOT-004`, `SELF-PROTECT-001`, and
  `STATE-FORK-IPC-002`, `STATE-PERSISTENT-FILE-LIFETIME-007`.
- Observe/simulate the exact Phase 5 first-owned IDs:
  `FILE-DELEGATED-EGRESS-001`, `HF-004-RESULT-001`,
  `HF-011-READ-RESULT-001`, `HF-NET-001`, `IPC-LOCAL-INET-008`,
  `NET-ACCEPT-PASS-001`, `NET-DNS-EXFIL-001`, `NET-NS-PASS-001`,
  `NET-RECV-001`, `NET-REWRITE-001`, `NET-SHARED-RESPONSE-002`,
  `NET-SOCKCTL-001`, and `NET-SOCKET-LIFE-001`.
- Path bind/rename/link/mount ambiguity, pre-existing hard-link alias cache
  equivalence, ordinary-subdirectory limits, and oldest-mount controls must
  accompany `MOUNT-SNAPSHOT-004`, `FILE-IDENTITY-001`, and
  `MOUNT-PROPAGATION-003`.
- Upstream-dossier regression tests for every adopted path/task/map pattern.

## Acceptance

- Every allocated local effect has exact actor/object attribution or an exact
  unsupported/unresolved result.
- The canonical path graph is verifier-qualified at declared bounds and passes
  the oldest-mount example.
- Compiler output is deterministic and cannot activate a partial generation.
- Observe mode never converts broken identity/state into allow.
- No product prevention claim is exposed.

## Excluded

Active local policy denial, final packet fencing, durable remote evidence,
distributed graphing, and response.

## Phase Result

```text
State: Done.
Validated architecture revision/digest: policy-and-protection-algorithm-architecture-readable.md at SHA-256 22678b9c0379ff915fe595059f3da2789c3e32cdf54d61656c7257175263d14a.
Completed deliverable IDs: D3.1-D3.7. The closure matrix records the exact Phase 3 result and later owner for all 39 required Phase 4/5 fixture inputs. D3.5 is complete for the Phase 3 classification contract: exact file and mount-view handling and the narrow represented local types are implemented; every unqualified positive model remains explicit unsupported or ambiguous and belongs to its later owning phase.
Files and durable owners changed: mithril-control::policy owns the closed restricted YAML parser, reference and bound validation, deterministic CBOR, Ed25519 candidate and rollback envelopes, exact conflicts, finite local cells and defaults, bounded component graph, typed effect lowering, honest simulation, and the 51-case observation oracle. mithril-node::NodePolicyGenerationOwner verifies candidates, enforces anti-rollback, derives local handles, installs and reads back immutable candidate rows, resolves live exact files, snapshots mount views, selects the oldest unique mount, and proposes exact DIRTY-to-CLEAN reconciliation. erebor-interceptor remains the only libbpf-rs loader and one native RingBuffer reader. The production object owns the bounded component walk, graph lookup, namespace-global mount mutation state, reconciliation CAS, dynamic exact-file binding, typed effect decisions, hard-safety results, and per-CPU loss health. mithril-e2e::EffectTestRunner owns the assertion-bearing self-cleaning privileged host oracle. examples/mithril-effect-observation-manual retains separate real Docker, CRI, raw nsenter, hard-link, bind-alias, mount-attack, saturation, latency, and unsupported-network operator cases.
Correctness and simplicity result: one C/CO-RE object and one libbpf-rs owner serve every container. The BPF decision is fixed before best-effort ring reservation, prior LSM errno is returned unchanged, multi-operation wrappers stop after the first nonzero result, and ring loss cannot change the result. Exact device decisions use the qualified object and ioctl-command axes. Process-target and exact Unix-stream rows use only the narrow represented operations. The compiler rejects positive process-control and positive exact Unix-stream decisions. An unmatched Unix-stream operation keeps its configured unmatched-policy result. A file candidate requires a CLEAN mount-namespace view, stable epoch/snapshot before and after the bounded component graph, exact live mount/device/inode/generation identity, and a retained read-back profile. Mount topology state is keyed by mount namespace rather than the mutating task's cgroup, so an external privileged task entering a protected namespace marks it DIRTY too. Reconciliation refuses to clean the view when the configured exact mount/device/inode/generation changed. Covered mount hooks retain the mutation in task storage until syscall exit and accept only an exact userspace epoch/version proposal. The LSM paths alone use the namespace-view spin lock; the tracing exit path uses BPF atomic version/pending updates and decrements pending last because Linux rejects spin-lock maps for tracing programs. A configured creation errno is explicitly sign-extended and verifier-bounded to `[-MAX_ERRNO, -1]`, with `-EACCES` as the invalid-value fallback. Task storage receives only a verifier-trusted typed hook task or `bpf_get_current_task_btf()` result. Real-parent topology uses exact CO-RE-read coordinates; an ordinary fork attaches the already proven creator cookie, while `CLONE_PARENT`, `CLONE_THREAD`, reparenting, and independent roots retain the architecture's coordinate-only representation instead of inventing a cookie or passing a scalar probe-read pointer to task storage. No final decision cache or second path engine was added. An identical recovered generation is verified in place and is never downgraded to PREPARING. Reader exit is a node failure. Both the Rust probe and manual cases own bounded cleanup.
Upstream-adoption dossier IDs used: KA-LSM-DECISION-001 and KA-READER-CAPACITY-005 for decision-before-telemetry and ring-loss behavior; TG-GENERIC-LSM-003, TG-VMLINUX-HEADER-006, TG-VMLINUX-ARM64-007, TG-CONCURRENCY-LOSS-005, AS-VMLINUX-ARM-001, and AS-VMLINUX-RISCV-002 for explicit CO-RE programs, generated multi-architecture headers, per-CPU scratch, and concurrency/loss practices; META-MOUNT-ROOT-001, META-OLDEST-MOUNT-002, and META-COMPONENT-GRAPH-003 for the bounded mount-root traversal and component graph. The local implementation adds actor-view snapshot validation, DIRTY ordering, exact proposal CAS, and final object/profile revalidation required by the Mithril architecture.
Fixture cases and exact physical results: the closed parser, deterministic compiler, exact conflict handling, default expansion, signatures, one-use rollback, immutable install recovery, bounded graph, oldest-mount nested-alias walk, hard-link non-transfer, namespace-global DIRTY/CAS model, exact-object reconciliation rejection, ring liveness and loss, ABI layout, production-object layout, and checked multi-architecture compilation are automated. The machine-readable simulation oracle covers 51 classified cases and all 39 required future fixture IDs. The final VM observation record has exact_open_observed=true and exact_open_denied_before_effect=false. It has hard_link_alias_denied=true, bind_alias_canonicalized=true, protected_mount_race_denied=true, external_mount_replacement_failed_closed=true, and exact_object_restored_after_reconciliation=true. saturation_preserved_network_denial=true and saturation_preserved_benign_allow=true after saturation_opens=50000. pin_root_removed=true, lease_removed=true, cgroup_removed=true, and fixture_root_removed=true. The final observation evidence SHA-256 is 71c09e60a614ed96ae9b4050804c2607996cda2e3785152372642ea6bc06215a. The closure matrix states the physical limit for each fixture.
Commands and exact source state covered: source 30f3b2ee9a8870d01d8b14f32eb817fcf2a38a71 passed the privileged Rust probe and the final Docker operator cases. Documentation-only commits follow it. The final repository CI command is recorded after the last documentation edit. Checked x86, arm64, arm, and riscv production-object compilation is compile evidence only.
Platform/kernel/runtime manifests: the final probe ran on x86_64 Linux 6.8.0-137-generic with BPF LSM, runtime BTF, cgroup v2, unique mount IDs, Docker 29.1.3, and python:3.13-slim-bookworm at image digest sha256:00faa2debb87529f9f0764e9491d8ba400a3678976616c3bd7cb193745ac20d1. Earlier K3s CRI records remain supplemental transport evidence. Compilation is not a non-x86 physical claim.
Performance/capacity results: the observation ring is bounded at 4 MiB, recent userspace history at 1,024 records, compiled exact cells at 65,536, and the path model at 4,096 states and 64 components. The final Rust probe has measured_opens=10000, saturation_opens=50000, baseline_average_open_ns=8638, and observed_average_open_ns=12755. The separate Docker operator result has 10,000 opens, zero loss, 10,839.40 ns baseline, and 35,649.58 ns observed per open. Final platform and capacity qualification belongs to Phase 11.
Unsupported/degraded paths: LOCAL_EFFECT_OBSERVATION remains DEGRADED and LOCAL_EFFECT_PREVENTION remains unsupported. A signed candidate DENY is physically allowed and reported as WOULD_DENY. Exact file and mount-view handling and narrow typed Unix-stream, device-ioctl, and process-target models exist. Positive exact Unix relationships and positive process-control decisions are rejected. Unqualified derived authority, other IPC and asynchronous channels, complete memory and VMA provenance, persistent provenance, privilege authority, self-protection, propagation, automount/referral, and cross-namespace fan-out retain explicit hard-safe results. Exact-file configuration still needs a live resolver plus a nonzero operator or filesystem inode generation and is not yet a rotation-aware runtime binding. Runtime observation is bounded and non-durable. A pre-existing represented bind alias canonicalizes correctly, but its signed denial remains observe-only. A new protected mount attempt is physically hard-denied because its mount object is unqualified.
Remaining work in this phase: none. Complete positive memory, VMA, persistent-state, derived-authority, propagation, relationship, and network models remain assigned to later phases. They are not Phase 3 closure work.
Next phase not authorized.
```

## Closure update — 2026-08-18

The [closure matrix](./phase-3-closure-matrix.md) supersedes the earlier
blocked qualification updates below. It distinguishes exact simulation,
physical proof, explicit hard-safety results, and later-phase work for every
required fixture.

At source `30f3b2ee9a8870d01d8b14f32eb817fcf2a38a71`, the x86_64 Linux
`6.8.0-137-generic` disposable VM passed the final privileged Rust probe and
the Docker direct-file, bind-alias, hard-link, mount-attack,
unsupported-network, 50,000-open saturation, and 10,000-open latency cases.
The final Rust result SHA-256 is
`71c09e60a614ed96ae9b4050804c2607996cda2e3785152372642ea6bc06215a`.
It records observe-only exact access, hard-safe topology races, explicit loss,
unchanged hard and benign results during saturation, and complete scoped
cleanup. The operator-record hashes are in the closure matrix.

The machine-readable simulation oracle contains 51 cases and all 39 required
future fixture IDs. `STATE-FORK-IPC-002`, which was missing from the earlier
50-case record, is now required by the test and has the exact
`IPC/IPC_ACCESS/INHERITED_IPC_CHANNEL` → `WOULD_DENY` result.

Phase 4 owns active signed local denial and remaining positive local models.
Phase 5 owns network enforcement. Phase 6 owns durable evidence and recovery.
Phase 11 owns final platform and capacity qualification. None of that work is
included in this result.

## Qualification update — 2026-08-12

The current disposable VM harness completed the production-object effect probe
in `OBSERVE` mode. The evidence file SHA-256 is
`2496f280c36942292bb31f08bc29ddb794dc67c07d2c2afe9a51505df82536ab`.
The probe recorded these physical results:

- The exact secret open completed and produced `WOULD_DENY`.
- The hard-link alias did not inherit the approved path class.
- The later bind alias canonicalized to the represented source object.
- Protected and external mount-replacement races failed closed until exact
  reconciliation restored the object.
- A paused reader and 50,000 opens did not change the network hard result or
  the benign control.
- The 10,000-sample BASELINE distribution recorded p50=6821 ns, p95=7906 ns,
  p99=60240 ns, and maximum=477409 ns.
- The 10,000-sample OBSERVE distribution recorded p50=8353 ns, p95=8691 ns,
  p99=180059 ns, and maximum=699532 ns.
- The cleanup fields for the fixture root, pin root, lease file, and cgroup are
  true.

An earlier real Docker manual case also passed. The protected container read the
secret in observe mode, Mithril emitted the exact `WOULD_DENY`, and the shell
removed its node process, tasks, pins, state, lease, configuration, and logs.

The earlier optional k3s lane passed Pod readiness, CRI discovery, workload-root
discovery, overlay storage, and projected-token discovery. Its record SHA-256
is `905a3ad84106e975cc1cde8b68cb24c861079f8baf3b616c597ec14e234f2503`.
It was substrate evidence only.

The phase stays **Blocked** until the remaining required manual cases are
recorded.

## Qualification update — 2026-08-15

At source commit `e9b380a`, the production effect probe passed in `OBSERVE`
mode on x86_64 Linux `6.8.0-137-generic`. The evidence file SHA-256 is
`3317b52ede0b9d4ea4acd3b5ab3e4926d9d8edecad96a40801a7bcbed0ad275c`.
It recorded `exact_open_observed=true` and
`exact_open_denied_before_effect=false`. The inherited-descriptor and
delegated-I/O checks also remained observe-only.

The probe recorded successful mount propagation and mount-attribute
reconciliation, failed-closed external replacement, and exact-object recovery.
Its pin root, lease, cgroup, and fixture-root cleanup fields are true. The
reconciliation check ran before exact effects and did not use a workload file
access as a warmup.

The phase remains **Blocked**. This evidence does not complete the manual
acceptance matrix.

The operator-facing command
`bash examples/mithril-effect-observation-manual/compile-observe-policy.sh`
also passed. It compiled 19 exact cells and verified a deterministic signed
candidate. It does not replace a physical CRI effect result.

## Qualification update — 2026-08-15 — K3s CRI OBSERVE

At source commit `bd325aa`, the retained x86_64 Linux
`6.8.0-137-generic` VM ran the production K3s CRI lane in `OBSERVE` mode.
The real `kubectl exec` task had `task_cookie=19` and retained the
`external_runtime_root` and `runtime_external_restricted` classification.
It read the exact read-only hostPath object successfully. The retained output
recorded `family=2`, `operation=2`, `reason=WOULD_DENY`,
`result=UNKNOWN_AFTER_PRE_EFFECT`, `exact_object_key_id=7`, and
`kernel_result=0`.

The lane removed its namespace, fixture, pin root, and Mithril links. This
closes the K3s CRI observation row. The phase remains **Blocked** because the
remaining manual matrix is not complete.

## Qualification update — 2026-08-15 — Direct CRI exact file

At source `e38a117`, the retained x86_64 Linux `6.8.0-137-generic` VM ran the
production K3s CRI lane in `OBSERVE` and `PROTECT` mode. The staged guest
script SHA-256 was
`380fd7c73d33aefc320ff7919160db38c29be7d06b59f6dc51dd5b715fcf4018`.

- `OBSERVE` evidence:
  `/tmp/mithril-phase3-direct-cri-evidence.eWjKKw/observe-clean.txt`,
  SHA-256 `c6cdd686dde59b84fa362b1c3e4e3d8e839bac44339081b8611cfc985057b994`.
  Direct `crictl exec` task 19 and `kubectl exec` task 80 were
  `external_runtime_root:runtime_external_restricted`. Both baseline reads
  succeeded. Each exact secret event reported family 2, operation 2, key 7,
  `WOULD_DENY`, `UNKNOWN_AFTER_PRE_EFFECT`, and kernel result 0. The task 80
  benign read reported key 8 and `EXACT_POLICY_ALLOW`.
- `PROTECT` evidence:
  `/tmp/mithril-phase3-direct-cri-evidence.eWjKKw/protect-clean.txt`,
  SHA-256 `a3a5a16e8abc67e0d919b4650c62e0a1ce75c0df206c96028d93c8790351f8ab`.
  Direct task 19 and `kubectl` task 80 again had the restricted external
  classification. Each baseline read succeeded. Each exact secret event
  reported family 2, operation 2, key 7, `EXACT_POLICY_DENY`,
  `DENIED_BEFORE_EFFECT`, and kernel result -13. The task 80 benign read
  reported key 8 and
  `EXACT_POLICY_ALLOW`.

Both commands used `pipefail` and exited 0. Each postflight check found the
namespace, exact pin root, fixture root, and lane root absent. It found no
Mithril pin or process. Only unrelated BPF link 1 remained.

This closes only the direct-CRI exact-file row. It does not qualify projected
token behavior or the remaining manual matrix. The phase remains **Blocked**.

## Qualification update — 2026-08-15 — Readable direct-CRI OBSERVE operator case

At source commit `4a6ff2b1cfafa9cf3310b30353d9417cc5b919c4`, an operator ran
`examples/mithril-effect-observation-manual/cri-file-observe.sh` against a
fresh K3s CRI binding. The run used Pod UID
`3adc7e25-a0a2-4b09-a53c-2b656027ecc1`, container ID
`a8d52808cca2394589f10ae11807e51b371a36f5a64f3a1f776a57b7d151e3ae`,
and a run-scoped writable host directory mounted at
`/var/lib/mithril/manual-shared`. The script exited 0. Its stdout SHA-256 is
`f5ca9565f5f5b7976211043ebfb816d3cb1bc071fdcfd6d8ac2b0d1df40c6023`.

The script inspected the released CRI probe. It required
`creator_task_cookie=null`, `root_class=external_runtime_root`,
`installed_role_class=runtime_external_restricted`, and a positive task
cookie. It then required an event for that task cookie with `family=2`,
`operation=2`, `reason=WOULD_DENY`, `result=UNKNOWN_AFTER_PRE_EFFECT`, and
`exact_object_key_id=7`. The probe opened the exact secret and completed the
scripted one-byte read attempt after its release gate. The script does not
parse or assert `kernel_result`. This record makes no kernel-result claim.

Provenance SHA-256: mithril-node
`b9dc1ffa54801adfe2fa3bac7565a60f04e2febed1e8578f8911b1ecdd0622e0`;
mithril-inspect
`c4efaa3adba740c3f919b142fd08bb0d725c8d308179edbe1cbb905e276a6079`;
mithril-policy
`72383137eb0a7bd8881b13d62b57fdc4ee5587b6ec584e1298f20fa563bfc91a`;
observation runtime
`6109f8ed4f032845a75a02480a6fb966a4669ca1417720e36dc3157721c6cdf9`;
CRI script
`643bf68ab72cc1eab995272df0e9c15b7008e79877890807ac2523a10a204c18`;
identity runtime
`b010d7a0a86a2e015181dc88440b84dab4fda4b988e63a3cf3f5aeb9e3d77b8f`;
policy source
`d0c595aba5dec9becca2af29b52af875388b32bc68e4701aa926d4b2f5824c3c`;
seal request
`22b2f40bd3dea1d5a1aa66962a22008ce0ec887e28ee753f1fc27fb8814f7b3e`;
generated node configuration
`dc153866cc44a3167db5bcc36b10276c91eef3cbf94fb43136c3de27df661adc`;
generated Pod manifest
`286ef5b66169497d3401c7d2d5241ced15c7a92b384226c0791a8450eee3c85d`;
and run provenance
`0b01ed7370f8b5772b0e112c7500a3eb4a8ad5cda4a6a502a9fb520d473b0612`.
No signing key was transferred. The run reused a matching guest test key.

The script removed its node, task, pins, state, lease, configuration, and
logs. External cleanup then removed both owned Pods, the namespace, and the
fixture root. Final VM inspection found no named namespace, fixture root,
Mithril process, or Mithril BPF pin. Only unrelated BPF link 1 remained. The
staging root
`/var/tmp/mithril-manual-phase3-c52da253-20260815t154608z` remains because it
retains the archive and run evidence. Retain it only until nonsecret evidence
is copied, its hashes are verified, and scoped deletion is authorized. Then
remove only this root. Do not change its external symlink targets. This is one
direct-CRI OBSERVE operator case. The remaining manual matrix is not complete.
Phase 3 remains **Blocked**.

## Manual VM update — 2026-08-17

On the retained manual VM, the operator ran
`cri-file-observe.sh` and `nsenter-file-observe.sh` with no arguments. Each
script created its own K3s Pod, live CRI binding, and writable shared directory.
Each script printed `PASS` and removed its node, pins, lease, state, Pod, and
fixture.

The direct CRI case required the exact task cookie, `OPEN_READ`, `WOULD_DENY`,
`UNKNOWN_AFTER_PRE_EFFECT`, and object key `7`. The `nsenter` case required the
same event plus the external restricted-root identity. Both scripts opened the
exact secret and completed the scripted one-byte read attempt. They do not
assert `kernel_result`. This records two manual observe cases only. The phase
remains **Blocked**.
