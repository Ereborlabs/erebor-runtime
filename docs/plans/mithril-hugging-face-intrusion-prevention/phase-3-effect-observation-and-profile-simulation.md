# Phase 3: Effect Observation And Profile Simulation

Status: Blocked. The current source passed the disposable privileged VM
observation probe. A Mithril CRI effect run and the remaining manual matrix
are not recorded. No prevention claim is made.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 3 runbook](./manual-testing/phase-3-manual-acceptance.md)  
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
  `STATE-PERSISTENT-FILE-LIFETIME-007`.
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
State: Blocked.
Validated architecture revision/digest: policy-and-protection-algorithm-architecture-readable.md at SHA-256 4a445b4015c4868a87af4893398068c5f362452c316d0cb8d06c038d41ffc0d8.
Completed deliverable IDs: D3.1-D3.4, D3.6, and D3.7 are code-backed. D3.5 has exact file and mount-view handling plus narrow typed Unix-stream, device-ioctl, and process-target models. The compiler rejects positive exact Unix relationships and positive process-control decisions. Other unqualified mechanisms keep explicit hard-safe results. The current source passed the privileged VM observation probe. A qualified Mithril CRI effect run and the remaining manual matrix are not recorded. The state remains Blocked.
Files and durable owners changed: mithril-control::policy owns the closed restricted YAML parser, reference and bound validation, deterministic CBOR, Ed25519 candidate and rollback envelopes, exact conflicts, finite local cells and defaults, bounded component graph, typed effect lowering, honest simulation, and the 50-case observation oracle. mithril-node::NodePolicyGenerationOwner verifies candidates, enforces anti-rollback, derives local handles, installs and reads back immutable candidate rows, resolves live exact files, snapshots mount views, selects the oldest unique mount, and proposes exact DIRTY-to-CLEAN reconciliation. erebor-interceptor remains the only libbpf-rs loader and one native RingBuffer reader. The production object owns the bounded component walk, graph lookup, namespace-global mount mutation state, reconciliation CAS, dynamic exact-file binding, typed effect decisions, hard-safety results, and per-CPU loss health. mithril-e2e::EffectTestRunner owns the assertion-bearing self-cleaning privileged host oracle. examples/mithril-effect-observation-manual retains separate real Docker, CRI, raw nsenter, hard-link, bind-alias, mount-attack, saturation, latency, and unsupported-network operator cases.
Correctness and simplicity result: one C/CO-RE object and one libbpf-rs owner serve every container. The BPF decision is fixed before best-effort ring reservation, prior LSM errno is returned unchanged, multi-operation wrappers stop after the first nonzero result, and ring loss cannot change the result. Exact device decisions use the qualified object and ioctl-command axes. Process-target and exact Unix-stream rows use only the narrow represented operations. The compiler rejects positive process-control and positive exact Unix-stream decisions. An unmatched Unix-stream operation keeps its configured unmatched-policy result. A file candidate requires a CLEAN mount-namespace view, stable epoch/snapshot before and after the bounded component graph, exact live mount/device/inode/generation identity, and a retained read-back profile. Mount topology state is keyed by mount namespace rather than the mutating task's cgroup, so an external privileged task entering a protected namespace marks it DIRTY too. Reconciliation refuses to clean the view when the configured exact mount/device/inode/generation changed. Covered mount hooks retain the mutation in task storage until syscall exit and accept only an exact userspace epoch/version proposal. The LSM paths alone use the namespace-view spin lock; the tracing exit path uses BPF atomic version/pending updates and decrements pending last because Linux rejects spin-lock maps for tracing programs. A configured creation errno is explicitly sign-extended and verifier-bounded to `[-MAX_ERRNO, -1]`, with `-EACCES` as the invalid-value fallback. Task storage receives only a verifier-trusted typed hook task or `bpf_get_current_task_btf()` result. Real-parent topology uses exact CO-RE-read coordinates; an ordinary fork attaches the already proven creator cookie, while `CLONE_PARENT`, `CLONE_THREAD`, reparenting, and independent roots retain the architecture's coordinate-only representation instead of inventing a cookie or passing a scalar probe-read pointer to task storage. No final decision cache or second path engine was added. An identical recovered generation is verified in place and is never downgraded to PREPARING. Reader exit is a node failure. Both the Rust probe and manual cases own bounded cleanup.
Upstream-adoption dossier IDs used: KA-LSM-DECISION-001 and KA-READER-CAPACITY-005 for decision-before-telemetry and ring-loss behavior; TG-GENERIC-LSM-003, TG-VMLINUX-HEADER-006, TG-VMLINUX-ARM64-007, TG-CONCURRENCY-LOSS-005, AS-VMLINUX-ARM-001, and AS-VMLINUX-RISCV-002 for explicit CO-RE programs, generated multi-architecture headers, per-CPU scratch, and concurrency/loss practices; META-MOUNT-ROOT-001, META-OLDEST-MOUNT-002, and META-COMPONENT-GRAPH-003 for the bounded mount-root traversal and component graph. The local implementation adds actor-view snapshot validation, DIRTY ordering, exact proposal CAS, and final object/profile revalidation required by the Mithril architecture.
Fixture cases and exact physical results: the closed parser, deterministic compiler, exact conflict handling, default expansion, signatures, one-use rollback, immutable install recovery, bounded graph, oldest-mount nested-alias walk, hard-link non-transfer, namespace-global DIRTY/CAS model, exact-object reconciliation rejection, ring liveness and loss, ABI layout, production-object layout, and checked multi-architecture compilation are automated. The machine-readable simulation oracle covers 50 classified cases. The current VM observation record has exact_open_observed=true and exact_open_denied_before_effect=false. It has hard_link_alias_denied=true, bind_alias_canonicalized=true, protected_mount_race_denied=true, external_mount_replacement_failed_closed=true, and exact_object_restored_after_reconciliation=true. The explicit hard-safety fields for anonymous exec, file creation and mutation, IPC, ptrace, signal, namespace privilege, device ioctl, BPF, and self-protection are true. saturation_preserved_network_denial=true and saturation_preserved_benign_allow=true after saturation_opens=50000. pin_root_removed=true, lease_removed=true, cgroup_removed=true, and fixture_root_removed=true. The observation evidence SHA-256 is 2496f280c36942292bb31f08bc29ddb794dc67c07d2c2afe9a51505df82536ab. These fields record the implemented slice only. They do not prove every required observation fixture.
Commands and exact source state covered: the disposable VM record under /tmp/mithril-vm-source18-final covers the current observation implementation. Repository CI results are recorded separately after the final repository edit. Checked x86, arm64, arm, and riscv production-object compilation is compile evidence only.
Platform/kernel/runtime manifests: the current probe ran on x86_64 Linux 6.8.0-136-generic with LSM order lockdown,capability,landlock,yama,apparmor,bpf, runtime BTF SHA-256 9aa9eb9e8108bff44e685830315fb7a442bafd99778314cdd6de0fb72868829f, cgroup v2, and unique mount IDs. The verifier constraints and the production implementation described above remain unchanged. The optional k3s lane recorded k3s v1.35.5+k3s1, Pod readiness, CRI endpoint unix:///run/k3s/containerd/containerd.sock, workload-root discovery, overlay storage, and projected-token discovery. Its record SHA-256 is 905a3ad84106e975cc1cde8b68cb24c861079f8baf3b616c597ec14e234f2503. This is substrate evidence only. It does not run a Mithril CRI binding or effect decision. Compilation is not a non-x86 physical claim.
Performance/capacity results: the observation ring is bounded at 4 MiB, recent userspace history at 1,024 records, compiled exact cells at 65,536, and the path model at 4,096 states and 64 components. The VM record has measured_opens=10000 and saturation_opens=50000. Its BASELINE distribution has sample_count=10000, p50=6821 ns, p95=7906 ns, p99=60240 ns, maximum=477409 ns, and raw_samples_sha256=cce53272e67763a1d82865d4e96119637a5ca1c1b52a4cb380f108e1c85451d5. Its OBSERVE distribution has sample_count=10000, p50=8353 ns, p95=8691 ns, p99=180059 ns, maximum=699532 ns, and raw_samples_sha256=31aec8e8beba8c42f235cb3588dd4ce44f8fb65679832a46310c6b84690dfab7. The recorded averages are baseline_average_open_ns=8063 and observed_average_open_ns=9765.
Unsupported/degraded paths: LOCAL_EFFECT_OBSERVATION remains DEGRADED and LOCAL_EFFECT_PREVENTION remains unsupported. A signed candidate DENY is physically allowed and reported as WOULD_DENY. Exact file and mount-view handling and narrow typed Unix-stream, device-ioctl, and process-target models exist. Positive exact Unix relationships and positive process-control decisions are rejected. Unqualified derived authority, other IPC and asynchronous channels, complete memory and VMA provenance, persistent provenance, privilege authority, self-protection, propagation, automount/referral, and cross-namespace fan-out retain explicit hard-safe results. Exact-file configuration still needs a live resolver plus a nonzero operator or filesystem inode generation and is not yet a rotation-aware runtime binding. Runtime observation is bounded and non-durable. A pre-existing represented bind alias canonicalizes correctly, but its signed denial remains observe-only. A new protected mount attempt is physically hard-denied because its mount object is unqualified.
Remaining work in this phase: run a real Mithril CRI effect integration on a kernel that supplies unique mount IDs, and run the remaining manual matrix. Complete memory and VMA provenance, persistent provenance, derived authority, propagation, and positive relationship models remain outside the qualified observation slice. Change State to Done only if every required observation oracle passes.
Next phase not authorized: yes.
```

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

The optional k3s lane passed Pod readiness, CRI discovery, workload-root
discovery, overlay storage, and projected-token discovery. Its record SHA-256
is `905a3ad84106e975cc1cde8b68cb24c861079f8baf3b616c597ec14e234f2503`.
It proves the runtime substrate only. It does not prove a Mithril CRI binding
or effect decision.

The phase stays **Blocked** until a Mithril CRI effect case runs on a qualified
kernel and the remaining required manual cases are recorded.
