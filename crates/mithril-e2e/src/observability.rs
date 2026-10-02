use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::fd::{AsFd as _, FromRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use erebor_interceptor::diagnostic::{
    DiagnosticBackend, DiagnosticFrame, DiagnosticMode, DiagnosticResult, DiagnosticStop,
    PREPARATION_LIMIT,
};
use erebor_interceptor::{KernelHostConfig, KernelHostOwner};
use serde::{Deserialize, Serialize};

mod lifecycle;

type ProofResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn kubernetes_cgroup_path(path: &Path) -> bool {
    ["/sys/fs/cgroup/kubepods", "/sys/fs/cgroup/kubepods.slice"]
        .iter()
        .any(|root| {
            path.strip_prefix(root).is_ok_and(|relative| {
                relative.components().count() >= 2
                    && relative
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_)))
            })
        })
}

#[derive(Serialize)]
struct CaseResult {
    name: &'static str,
    result: DiagnosticResult,
    frames: Vec<erebor_interceptor::diagnostic::DiagnosticFrame>,
    observed_program_ids: BTreeSet<u64>,
    observed_map_ids: BTreeSet<u64>,
    observed_link_ids: BTreeSet<u64>,
    hash_entries: BTreeMap<u64, u32>,
    map_memlock_bytes: BTreeMap<u64, Option<u64>>,
    kernel_runtime: BTreeMap<u32, KernelRunTime>,
    cleanup_verified: bool,
    enforcement_manifest_unchanged: bool,
}

#[derive(Serialize)]
struct KernelRunTime {
    name: String,
    kind: u32,
    run_time_ns: u64,
    run_count: u64,
    recursion_misses: u64,
}

struct KernelRuntimeStats {
    _lease: OwnedFd,
}

impl KernelRuntimeStats {
    #[allow(unsafe_code)]
    fn open() -> ProofResult<Self> {
        // SAFETY: The syscall has no pointer inputs and returns a new owned descriptor.
        let fd = unsafe {
            libbpf_rs::libbpf_sys::bpf_enable_stats(libbpf_rs::libbpf_sys::BPF_STATS_RUN_TIME)
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: This owner closes the successful syscall descriptor once.
        Ok(Self {
            _lease: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }
}

impl CaseResult {
    fn attached(frame: &DiagnosticFrame) -> bool {
        frame.stderr && frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n"
    }

    fn verify(&self) -> ProofResult<()> {
        if self.hash_entries.values().any(|entries| *entries > 4096)
            || (matches!(self.name, "syscall-errors" | "failed-opens")
                && self.hash_entries.is_empty())
        {
            return Err(format!(
                "{}: the diagnostic map-key ceiling is not proved",
                self.name
            )
            .into());
        }
        let diagnostics: Vec<_> = self
            .frames
            .iter()
            .filter(|frame| frame.stderr)
            .flat_map(|frame| frame.bytes.iter().copied())
            .collect();
        let diagnostics = String::from_utf8_lossy(&diagnostics);
        if matches!(
            self.name,
            "quiet"
                | "histogram"
                | "graceful"
                | "deadline"
                | "forced-kill"
                | "syscall-errors"
                | "failed-opens"
        ) {
            if self.result.attach_notification_ms.is_none()
                || !self.frames.iter().any(Self::attached)
                || self.observed_program_ids.is_empty()
            {
                return Err(
                    format!("{}: qualified capture readiness is missing", self.name).into(),
                );
            }
            let stop = match self.name {
                "quiet" | "histogram" | "forced-kill" => DiagnosticStop::Cancelled,
                "graceful" => DiagnosticStop::Exited,
                _ => DiagnosticStop::Deadline,
            };
            if self.result.stop != stop
                || if self.name == "forced-kill" {
                    !self.result.forced_kill
                        || !self.result.output_incomplete
                        || self.result.exit_code.is_some()
                } else {
                    self.result.forced_kill
                        || self.result.output_incomplete
                        || self.result.exit_code != Some(0)
                }
            {
                return Err(
                    format!("{}: capture did not reach its expected result", self.name).into(),
                );
            }
        }
        if matches!(
            self.name,
            "parse-error" | "probe-limit" | "unsafe-helper" | "unsupported-hook" | "partial-attach"
        ) && (self.result.stop != DiagnosticStop::Exited
            || self.result.exit_code.is_none_or(|code| code == 0)
            || self.result.forced_kill
            || self.result.output_incomplete
            || self.result.attach_notification_ms.is_some()
            || self.frames.iter().any(Self::attached))
        {
            return Err(format!("{}: the expected backend rejection is missing", self.name).into());
        }
        if self.name == "unsupported-hook"
            && (!diagnostics.lines().any(|line| {
                line == "ERROR: Probe does not exist: rawtracepoint:araphor_missing_hook_5f6d"
            }) || [
                "Read-only file system",
                "Permission denied",
                "Operation not permitted",
            ]
            .iter()
            .any(|error| diagnostics.contains(error)))
        {
            return Err("unsupported-hook: missing-hook rejection was not proved".into());
        }
        if self.name == "probe-limit" && !diagnostics.contains("exceeds") {
            return Err("probe-limit: the backend did not report its probe ceiling".into());
        }
        if self.name == "unsafe-helper" && !diagnostics.contains("unsafe") {
            return Err("unsafe-helper: the backend did not reject the unsafe function".into());
        }
        if self.name == "histogram"
            && !self.frames.iter().any(|frame| {
                serde_json::from_slice::<serde_json::Value>(&frame.bytes)
                    .is_ok_and(|value| value["type"] == "hist")
            })
        {
            return Err("histogram: final histogram output is missing".into());
        }
        if self.name == "partial-attach"
            && (!diagnostics.contains("Error attaching probe: 'kprobe:araphor_missing_hook_5f6d'")
                || !self.kernel_runtime.iter().any(|(id, sample)| {
                    self.result.program_ids.contains(id)
                        && sample.kind == libbpf_rs::ProgramType::PerfEvent as u32
                        && sample.name == "10"
                        && sample.run_count > 0
                }))
        {
            return Err(
                "partial-attach: requested interval execution before failure is unproved".into(),
            );
        }
        if !self.cleanup_verified
            || !self.enforcement_manifest_unchanged
            || self.result.cleanup_verified == Some(false)
        {
            return Err(format!("{}: resource cleanup failed", self.name).into());
        }
        if self.name == "parse-error" {
            let output: Vec<_> = self
                .frames
                .iter()
                .flat_map(|frame| frame.bytes.iter().copied())
                .collect();
            if !String::from_utf8_lossy(&output)
                .contains("ERROR: unexpected end of file, expected {")
            {
                return Err("parse-error: compiler did not reach source parsing".into());
            }
        }
        if self.name == "compile-valid"
            && (self.result.stop != DiagnosticStop::Exited
                || self.result.exit_code != Some(0)
                || self.result.forced_kill
                || self.result.output_incomplete
                || self.result.attach_notification_ms.is_some()
                || !self.result.program_ids.is_empty()
                || !self.result.map_ids.is_empty()
                || !self.observed_program_ids.is_empty()
                || !self.observed_map_ids.is_empty()
                || !self.observed_link_ids.is_empty())
        {
            return Err("compile-valid: compilation failed or loaded a program".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ResourceSnapshot {
    pub(crate) programs: BTreeSet<u64>,
    pub(crate) maps: BTreeSet<u64>,
    pub(crate) links: BTreeSet<u64>,
}

impl ResourceSnapshot {
    pub(crate) fn read() -> ProofResult<Self> {
        if !rustix::process::geteuid().is_root() {
            return Err("BPF inventory requires root".into());
        }
        Ok(Self {
            programs: libbpf_rs::query::ProgInfoIter::default()
                .map(|item| u64::from(item.id))
                .collect(),
            maps: libbpf_rs::query::MapInfoIter::default()
                .map(|item| u64::from(item.id))
                .collect(),
            links: libbpf_rs::query::LinkInfoIter::default()
                .map(|item| u64::from(item.id))
                .collect(),
        })
    }
}

pub struct ObservabilityQualification {
    output: PathBuf,
}

impl ObservabilityQualification {
    pub fn new(output: PathBuf) -> Self {
        Self { output }
    }

    pub fn owned_capture(&self) -> ProofResult<()> {
        use crate::control_fixture::{MtlsFixture, OutagePolicyFixture, OUTAGE_TENANT_ID};
        use ed25519_dalek::SigningKey;
        use mithril_control::{
            ControlStore, DiscoveryDigestV1, TraceBatchV1, TraceCleanupV1, TraceExchangeV1,
            TraceExecutionGrantV1, TraceFrameKindV1, TraceFrameV1, TraceOwner, TraceReadAccessV1,
            TraceRecipeV1, TraceRequestV1, TraceTargetV1, TraceTerminalReasonV1, TraceTerminalV1,
            TraceUploadV1,
        };
        use mithril_node::TrustCache;

        fs::create_dir(&self.output)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let tls = MtlsFixture::new(false)?;
            let fixture = OutagePolicyFixture::new(ControlStore::open(tls.path().join("inventory"))?);
            let facts = fixture.inventory(&fixture.resource(1)?)?;
            let fact = facts.first().ok_or("missing workload fact")?.clone();
            drop(fixture);
            let key = SigningKey::from_bytes(&[23; 32]);
            let control = Self::trace_control(&tls, &key)?;
            let data = control.analysis_store().ok_or("missing analysis store")?;
            let owner = TraceOwner::new(data);
            let index = tls.path().join("control-store/discovery-index.sqlite");
            if index.try_exists()? {
                return Err("discovery started before diagnostic acceptance".into());
            }
            control.replace_kubernetes_workload_inventory(facts)?;
            let server = tls.start(control.clone()).await?;
            let result = tokio::time::timeout(Duration::from_secs(20), async {
                let connector = tls.connector(&server, "node-a", [7; 16]);
                let mut cache = TrustCache::load(&tls.path().join("trace-trust"))?;
                let mut registration = OutagePolicyFixture::registration([7; 16], false);
                registration.effect_prevention_claims_enabled = false;
                let mut connection = connector.connect(registration.clone(), true, &mut cache).await?;
                let now = u64::try_from(
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos(),
                )?;
                let tenant = *uuid::Uuid::parse_str(OUTAGE_TENANT_ID)?.as_bytes();
                let target = TraceTargetV1 {
                    fact_digest: DiscoveryDigestV1::of(&fact)?,
                    fact,
                    runtime_container_id: "1".repeat(64),
                    node_boot_id: [7; 16],
                    cgroup_id: 17,
                    binding_id: [3; 16],
                    binding_nonce: [4; 16],
                    root_cgroup_live_interval_id: [5; 16],
                    container_generation: 1,
                    label_epoch: 1,
                };
                let grant = TraceExecutionGrantV1 {
                    tenant_id: tenant,
                    grant_id: [7; 16],
                    principal: "qualification".into(),
                    namespace_uids: [target.fact.namespace_uid.clone()].into(),
                    node_ids: ["node-a".into()].into(),
                    recipe_digests: [TraceRecipeV1::FailedOpens.digest()?].into(),
                    host_diagnostic: false,
                    valid_until_unix_ns: now + 120_000_000_000,
                };
                let access = TraceReadAccessV1 {
                    tenant_id: tenant,
                    namespace_uids: grant.namespace_uids.clone(),
                    node_ids: grant.node_ids.clone(),
                    host_sensitive: false,
                    valid_until_unix_ns: grant.valid_until_unix_ns,
                    revoked: false,
                };
                let request = TraceRequestV1 {
                    tenant_id: tenant,
                    request_id: [6; 16],
                    source: TraceRecipeV1::FailedOpens.manifest()?.source,
                    targets: vec![target],
                    unresolved: Vec::new(),
                    collection_seconds: 30,
                };
                connection.report_readiness(true, true).await?;
                let state = control.accept_trace(request.clone(), grant.clone(), None)?;
                if control.accept_trace(request.clone(), grant.clone(), None)? != state {
                    return Err("acceptance retry changed durable state".into());
                }
                let mut changed = request.clone();
                changed.collection_seconds += 1;
                let conflict = control.accept_trace(changed, grant.clone(), None)
                    .err().ok_or("changed request was accepted")?;
                if conflict.code() != tonic::Code::AlreadyExists {
                    return Err(format!("changed request failed for another reason: {conflict}").into());
                }
                let dispatch = connection.exchange_diagnostics(&TraceExchangeV1::default()).await?
                    .dispatch.ok_or("missing signed dispatch")?;
                let now = u64::try_from(
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos(),
                )?;
                dispatch.verify(&key.verifying_key(), tenant, "node-a", [7; 16], now)?;
                if dispatch.accepted.request != request {
                    return Err("dispatch changed accepted inputs".into());
                }
                let id = dispatch.accepted.execution_id(0)?;
                let frame = TraceFrameV1 {
                    execution_id: id,
                    sequence: 1,
                    kind: TraceFrameKindV1::Data,
                    bytes: b"external output fixture\n".to_vec(),
                };
                let mut exchange = TraceExchangeV1 {
                    retained: vec![id],
                    resolved: None,
                    output: Some(TraceUploadV1 {
                        request_id: request.request_id,
                        target_index: 0,
                        original_node_boot_id: [7; 16],
                        batch: TraceBatchV1 {
                            execution_id: id,
                            frames: vec![frame.clone()],
                            terminal: None,
                        },
                    }),
                };
                let first = connection.exchange_diagnostics(&exchange).await?;
                let ack = first.acknowledgement.as_ref().ok_or("missing output ack")?;
                if ack.execution_id != id || ack.last_sequence != 1 || ack.terminal.is_some()
                    || first.dispatch.is_some()
                {
                    return Err("output acknowledgement changed the retained sequence".into());
                }
                drop(connection);
                let mut connection = connector.connect(registration, true, &mut cache).await?;
                let replay = connection.exchange_diagnostics(&exchange).await?;
                if replay != first {
                    return Err("output retry changed its acknowledgement".into());
                }
                let mut changed = exchange.clone();
                changed.output.as_mut().ok_or("missing output")?.batch.frames[0].bytes.push(b'!');
                let rejected = connection.exchange_diagnostics(&changed).await
                    .err().ok_or("conflicting output was accepted")?;
                if !matches!(&rejected, mithril_node::Error::ControlRpc { source, .. }
                    if source.code() == tonic::Code::AlreadyExists)
                {
                    return Err(format!("conflicting output failed for another reason: {rejected}").into());
                }
                let terminal = TraceTerminalV1 {
                    execution_id: id,
                    reason: TraceTerminalReasonV1::Completed,
                    last_sequence: 1,
                    output_bytes: frame.bytes.len() as u64,
                    output_incomplete: false,
                    kernel_lost_events: None,
                    ready_at_unix_ns: None,
                    exit_code: Some(0),
                    forced_kill: false,
                    cleanup: TraceCleanupV1::Unknown,
                };
                let batch = &mut exchange.output.as_mut().ok_or("missing output")?.batch;
                batch.frames.clear();
                batch.terminal = Some(terminal.clone());
                let completed = connection.exchange_diagnostics(&exchange).await?;
                if completed.acknowledgement.as_ref().and_then(|ack| ack.terminal.as_ref()) != Some(&terminal)
                    || completed.dispatch.is_some()
                    || connection.exchange_diagnostics(&exchange).await? != completed
                {
                    return Err("terminal retry changed its acknowledgement".into());
                }
                let retained = owner.output(tenant, request.request_id, 0, &access, now, 0)?;
                if retained != vec![TraceBatchV1 {
                    execution_id: id,
                    frames: vec![frame],
                    terminal: Some(terminal),
                }] || owner.read(tenant, request.request_id, &access, now)? != (state.clone(), dispatch.accepted)
                {
                    return Err("retained trace changed after retry or conflict".into());
                }
                if index.try_exists()? {
                    return Err("diagnostics started a discovery index".into());
                }
                Ok::<_, Box<dyn std::error::Error>>((serde_json::json!({
                    "schema_version": 1,
                    "case": "owned-capture",
                    "scope": "owner-upload",
                    "result": "PASS",
                    "proof_boundary": "Owner-upload leg: production Control and Node transport with external target and output fixtures. The node_capture leg records Node spool and process supervision separately. Neither leg proves a Node process crash, BPF cleanup, enforcement, or performance.",
                    "physical": false,
                    "performance_claim": false,
                    "discovery_index_present": false,
                    "source_sha256": hex::encode(request.source.sha256),
                    "state": state,
                    "output_ack": first.acknowledgement,
                    "replay_ack": replay.acknowledgement,
                    "terminal_ack": completed.acknowledgement,
                    "request_conflict": format!("{:?}", conflict.code()),
                    "output_conflict": "AlreadyExists",
                    "retained": retained,
                }), request, grant))
            }).await;
            let shutdown = server.shutdown().await;
            let (mut record, request, grant) = result??;
            shutdown?;
            drop(owner);
            drop(control);
            drop(crate::control_fixture::reopen_control_store(&tls.path().join("control-store")).await?);
            record["storage_recovery"] = self.owned_storage(&tls, &key, request.clone(), grant.clone()).await?;
            record["node_capture"] = self.owned_node(&key, request, grant).await?;
            self.write("result.json", &record)
        })
    }

    fn trace_control(
        tls: &crate::control_fixture::MtlsFixture,
        key: &ed25519_dalek::SigningKey,
    ) -> ProofResult<mithril_control::ControlPlane> {
        let mut config = tls.configuration()?;
        config.trust = mithril_control::TrustGenerationV1 {
            generation: 1,
            bundle_digest: String::new(),
            policy_issuer_sequence_epoch: 1,
            policy_signers: vec![mithril_control::PolicySignerTrustV1 {
                signing_key_id: "trace-key".into(),
                ed25519_public_key_hex: hex::encode(key.verifying_key().as_bytes()),
                revoked: false,
            }],
        }
        .with_computed_bundle_digest();
        let parts = config.into_parts()?;
        if let Some(error) = parts.data_error {
            return Err(error.into());
        }
        Ok(parts
            .control
            .with_trace_signer("trace-key".into(), 1, key.clone())?)
    }

    async fn owned_storage(
        &self,
        tls: &crate::control_fixture::MtlsFixture,
        key: &ed25519_dalek::SigningKey,
        mut request: mithril_control::TraceRequestV1,
        mut grant: mithril_control::TraceExecutionGrantV1,
    ) -> ProofResult<serde_json::Value> {
        use crate::control_fixture::{reopen_control_store, OutagePolicyFixture};
        use mithril_control::{
            TraceBatchV1, TraceExchangeV1, TraceFrameKindV1, TraceFrameV1, TraceOwner,
            TraceReadAccessV1, TraceUploadV1,
        };
        use mithril_node::TrustCache;

        request.request_id = [8; 16];
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos(),
        )?;
        grant.valid_until_unix_ns = now + 120_000_000_000;
        let access = TraceReadAccessV1 {
            tenant_id: request.tenant_id,
            namespace_uids: grant.namespace_uids.clone(),
            node_ids: grant.node_ids.clone(),
            host_sensitive: false,
            valid_until_unix_ns: grant.valid_until_unix_ns,
            revoked: false,
        };
        let control = Self::trace_control(tls, key)?;
        let data = control.analysis_store().ok_or("missing analysis store")?;
        control.replace_kubernetes_workload_inventory(
            request
                .targets
                .iter()
                .map(|target| target.fact.clone())
                .collect(),
        )?;
        let server = tls.start(control.clone()).await?;
        let mut registration = OutagePolicyFixture::registration([7; 16], false);
        registration.effect_prevention_claims_enabled = false;
        let mut cache = TrustCache::load(&tls.path().join("storage-trust"))?;
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            let connector = tls.connector(&server, "node-a", [7; 16]);
            let mut connection = connector
                .connect(registration.clone(), true, &mut cache)
                .await?;
            connection.report_readiness(true, true).await?;
            control.accept_trace(request.clone(), grant, None)?;
            let dispatch = connection
                .exchange_diagnostics(&TraceExchangeV1::default())
                .await?
                .dispatch
                .ok_or("missing storage dispatch")?;
            let id = dispatch.accepted.execution_id(0)?;
            let batch = TraceBatchV1 {
                execution_id: id,
                frames: vec![TraceFrameV1 {
                    execution_id: id,
                    sequence: 1,
                    kind: TraceFrameKindV1::Data,
                    bytes: b"synced output fixture\n".to_vec(),
                }],
                terminal: None,
            };
            let exchange = TraceExchangeV1 {
                retained: vec![id],
                resolved: None,
                output: Some(TraceUploadV1 {
                    request_id: request.request_id,
                    target_index: 0,
                    original_node_boot_id: [7; 16],
                    batch: batch.clone(),
                }),
            };
            data.set_commit_hook(araphor_data::AnalysisCommitStage::AfterSync, || {
                Err(araphor_data::Error::Io {
                    path: "diagnostic AfterSync fixture".into(),
                    source: std::io::Error::from(std::io::ErrorKind::StorageFull),
                    location: snafu::Location::default(),
                })
            })?;
            let mut errors = Vec::new();
            for expected in [tonic::Code::Unavailable, tonic::Code::DataLoss] {
                match connection.exchange_diagnostics(&exchange).await {
                    Err(mithril_node::Error::ControlRpc { source, .. })
                        if source.code() == expected =>
                    {
                        errors.push(format!("{:?}", source.code()));
                    }
                    other => {
                        return Err(format!(
                            "failed store returned an ACK or wrong error: {other:?}"
                        )
                        .into())
                    }
                }
            }
            if data.storage_health()?.write_ready {
                return Err("failed sync hook left the data writer ready".into());
            }
            Ok::<_, Box<dyn std::error::Error>>((exchange, batch, errors))
        })
        .await;
        let shutdown = server.shutdown().await;
        drop(data);
        drop(control);
        let (exchange, batch, errors) = result??;
        shutdown?;
        drop(reopen_control_store(&tls.path().join("control-store")).await?);

        let control = Self::trace_control(tls, key)?;
        let server = tls.start(control.clone()).await?;
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            let connector = tls.connector(&server, "node-a", [7; 16]);
            let mut connection = connector.connect(registration, true, &mut cache).await?;
            let reply = connection.exchange_diagnostics(&exchange).await?;
            let ack = reply
                .acknowledgement
                .as_ref()
                .ok_or("missing recovered ACK")?;
            if ack.execution_id != batch.execution_id
                || ack.last_sequence != 1
                || ack.terminal.is_some()
                || connection.exchange_diagnostics(&exchange).await? != reply
            {
                return Err("recovered output retry changed its ACK".into());
            }
            let owner = TraceOwner::new(control.analysis_store().ok_or("missing recovered data")?);
            let retained =
                owner.output(request.tenant_id, request.request_id, 0, &access, now, 0)?;
            if retained != vec![batch]
                || owner
                    .read(request.tenant_id, request.request_id, &access, now)?
                    .1
                    .request
                    != request
            {
                return Err("store recovery changed the accepted request or synced output".into());
            }
            if tls
                .path()
                .join("control-store/discovery-index.sqlite")
                .try_exists()?
            {
                return Err("store recovery started a discovery index".into());
            }
            Ok::<_, Box<dyn std::error::Error>>(serde_json::json!({
                "fault_stage": "AfterSync",
                "fault_input": "injected StorageFull error after a real diagnostic segment sync",
                "error_codes": errors,
                "acknowledgement": reply.acknowledgement,
                "retained": retained,
            }))
        })
        .await;
        let shutdown = server.shutdown().await;
        let record = result??;
        shutdown?;
        Ok(record)
    }

    async fn owned_node(
        &self,
        key: &ed25519_dalek::SigningKey,
        mut request: mithril_control::TraceRequestV1,
        mut grant: mithril_control::TraceExecutionGrantV1,
    ) -> ProofResult<serde_json::Value> {
        use crate::control_fixture::{reopen_control_store, MtlsFixture, OutagePolicyFixture};
        use erebor_interceptor_abi::{BindingLifecycleStateV1, ExecutionSetBindingStateV1};
        use mithril_control::{
            TraceCleanupV1, TraceExchangeV1, TraceFrameKindV1, TraceOwner, TraceReadAccessV1,
            TraceTerminalReasonV1, TraceUploadV1,
        };
        use mithril_node::{NodeTraceOwner, TraceTargetLeaseV1, TrustCache};
        use std::os::unix::fs::MetadataExt as _;
        use std::sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Arc,
        };

        let tls = MtlsFixture::new(false)?;
        let mut control = Self::trace_control(&tls, key)?;
        let mut data = control
            .analysis_store()
            .ok_or("missing Node capture data")?;
        let mut owner = TraceOwner::new(data.clone());
        control.replace_kubernetes_workload_inventory(
            request
                .targets
                .iter()
                .map(|target| target.fact.clone())
                .collect(),
        )?;
        let mut server = Some(tls.start(control.clone()).await?);
        let mut registration = OutagePolicyFixture::registration([7; 16], false);
        registration.effect_prevention_claims_enabled = false;
        let mut cache = TrustCache::load(&tls.path().join("node-trust"))?;
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            let mut records = Vec::new();
            for (name, expected, request_id) in [
                ("target-replacement", TraceTerminalReasonV1::TargetChanged, 9),
                ("cancel", TraceTerminalReasonV1::Cancelled, 10),
                ("partition-expiry", TraceTerminalReasonV1::Deadline, 11),
                ("store-failure", TraceTerminalReasonV1::Deadline, 12),
                ("store-before-append", TraceTerminalReasonV1::Deadline, 13),
            ] {
                let before_append = name == "store-before-append";
                let local_expiry = matches!(name, "partition-expiry" | "store-failure" | "store-before-append");
                let mut fault_codes = Vec::new();
                let mut failed = None;
                let mut recovered_prefix = Vec::new();
                let mut recovered_receipt = None;
                let root = tls.path().join(name);
                fs::create_dir(&root)?;
                let target_path = root.join("target");
                fs::create_dir(&target_path)?;
                request.request_id = [request_id; 16];
                request.collection_seconds = 30;
                request.targets[0].cgroup_id = fs::metadata(&target_path)?.ino();
                let target = request.targets[0].clone();
                let state = ExecutionSetBindingStateV1 {
                    node_boot_id: target.node_boot_id.into(),
                    binding_id: target.binding_id.into(),
                    binding_nonce: target.binding_nonce.into(),
                    root_cgroup_live_interval_id: target.root_cgroup_live_interval_id.into(),
                    root_cgroup_id: target.cgroup_id,
                    label_epoch: target.label_epoch,
                    container_generation: target.container_generation,
                    lifecycle_state: BindingLifecycleStateV1::Active,
                    ..Default::default()
                };
                let generation = Arc::new(AtomicU64::new(state.container_generation));
                let readback = generation.clone();
                let lease = TraceTargetLeaseV1::fixture(target.clone(), target_path, move || {
                    Ok(Some(ExecutionSetBindingStateV1 {
                        container_generation: readback.load(Ordering::Acquire),
                        ..state
                    }))
                })?;
                let launches = Arc::new(AtomicUsize::new(0));
                let starts = launches.clone();
                let pid_path = root.join("child.pid");
                let child_path = pid_path.clone();
                let command = move || {
                    starts.fetch_add(1, Ordering::AcqRel);
                    let mut command = Command::new("/bin/sh");
                    command.args([
                        "-c",
                        "cat >/dev/null; printf '%s' \"$$\" >\"$1\"; printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; printf 'node-owned output\\n'; exec sleep 60",
                        "trace-fixture",
                    ]).arg(&child_path);
                    command
                };
                let mut node = NodeTraceOwner::open_fixture(
                    &root, request.tenant_id, "node-a".into(), [7; 16], command.clone(),
                )?;
                let connector = tls.connector(server.as_ref().ok_or("Control is absent")?, "node-a", [7; 16]);
                let mut connection = connector.connect(registration.clone(), true, &mut cache).await?;
                connection.report_readiness(true, true).await?;
                let now = u64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos())?;
                grant.valid_until_unix_ns = now + 120_000_000_000;
                control.accept_trace(request.clone(), grant.clone(), None)?;
                let dispatch = connection.exchange_diagnostics(&TraceExchangeV1::default()).await?
                    .dispatch.ok_or("missing Node capture dispatch")?;
                if dispatch.accepted.request != request {
                    return Err("Node capture dispatch changed the accepted request".into());
                }
                let dispatch_key = cache.policy_signing_key(&dispatch.signing_key_id, dispatch.issuer_epoch)?;
                let mut connection = Some(connection);
                if name == "partition-expiry" {
                    drop(connection.take());
                    server.take().ok_or("Control is absent")?.shutdown().await?;
                }
                let supplied_now = if local_expiry {
                    dispatch.accepted.deadline_unix_ns - 5_000_000_000
                } else {
                    u64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos())?
                };
                let id = node.admit(dispatch.clone(), Some(lease), &dispatch_key, supplied_now)?;
                if node.admit(dispatch.clone(), None, &dispatch_key, supplied_now)? != id {
                    return Err("duplicate dispatch changed execution identity".into());
                }
                let ready_limit = Instant::now() + Duration::from_secs(3);
                loop {
                    let frames = node.frames(id, 0)?;
                    if frames.iter().any(|frame| frame.kind == TraceFrameKindV1::Diagnostic
                        && frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n")
                        && frames.iter().any(|frame| frame.kind == TraceFrameKindV1::Data
                            && frame.bytes == b"node-owned output\n")
                    {
                        break;
                    }
                    if Instant::now() >= ready_limit {
                        return Err("Node capture did not spool the process output".into());
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                node.reap()?;
                if launches.load(Ordering::Acquire) != 1 || node.terminal(id)?.is_some() {
                    return Err("Node capture respawned or stopped before the case input".into());
                }
                let pid: u32 = fs::read_to_string(&pid_path)?.parse()?;
                if name == "target-replacement" {
                    generation.fetch_add(1, Ordering::AcqRel);
                } else if name == "cancel" {
                    owner.cancel(request.tenant_id, request.request_id, &grant.principal, false)?;
                    let reply = connection.as_mut().ok_or("Control connection is absent")?
                        .exchange_diagnostics(&TraceExchangeV1 {
                        retained: vec![id], ..Default::default()
                    }).await?;
                    if reply.cancel != vec![id] || reply.dispatch.is_some() {
                        return Err("Control did not cancel the retained execution".into());
                    }
                    for id in reply.cancel {
                        node.cancel(id);
                    }
                } else if matches!(name, "store-failure" | "store-before-append") {
                    let batch = node.next_batch(id, 0)?.ok_or("missing active Node output")?;
                    if batch.frames.len() != 2 || batch.terminal.is_some() {
                        return Err("Node output was not active before the storage fault".into());
                    }
                    let exchange = TraceExchangeV1 {
                        retained: vec![id], resolved: None,
                        output: Some(TraceUploadV1 {
                            request_id: request.request_id, target_index: 0,
                            original_node_boot_id: [7; 16], batch: batch.clone(),
                        }),
                    };
                    let stage = if before_append {
                        araphor_data::AnalysisCommitStage::BeforeAppend
                    } else {
                        araphor_data::AnalysisCommitStage::AfterSync
                    };
                    data.set_commit_hook(stage, move || {
                        Err(araphor_data::Error::Io {
                            path: if before_append {
                                "active Node BeforeAppend fixture"
                            } else {
                                "active Node AfterSync fixture"
                            }.into(),
                            source: std::io::Error::from(std::io::ErrorKind::StorageFull),
                            location: snafu::Location::default(),
                        })
                    })?;
                    let codes: &[tonic::Code] = if before_append {
                        &[tonic::Code::Unavailable]
                    } else {
                        &[tonic::Code::Unavailable, tonic::Code::DataLoss]
                    };
                    for &expected in codes {
                        match connection.as_mut().ok_or("Control connection is absent")?
                            .exchange_diagnostics(&exchange).await
                        {
                            Err(mithril_node::Error::ControlRpc { source, .. })
                                if source.code() == expected
                                    && (!before_append || source.message().contains("active Node BeforeAppend fixture")) =>
                                    fault_codes.push(format!("{:?}", source.code())),
                            other => return Err(format!("active Node upload returned an ACK or wrong error: {other:?}").into()),
                        }
                    }
                    node.reap()?;
                    if data.storage_health()?.write_ready != before_append || node.terminal(id)?.is_some()
                        || node.next_batch(id, 0)?.as_ref() != Some(&batch)
                    {
                        return Err("failed upload changed active Node output or writer readiness".into());
                    }
                    if before_append {
                        drop(connection.take());
                        server.take().ok_or("Control is absent")?.shutdown().await?;
                    }
                    failed = Some(batch);
                }
                drop(connection);
                let end_limit = Instant::now() + Duration::from_secs(if local_expiry { 15 } else { 5 });
                let terminal = loop {
                    node.reap()?;
                    if let Some(terminal) = node.terminal(id)? {
                        break terminal;
                    }
                    if Instant::now() >= end_limit {
                        return Err("Node capture did not stop at its local bound".into());
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                };
                if terminal.reason != expected || terminal.cleanup != TraceCleanupV1::Unknown
                    || terminal.kernel_lost_events.is_some() || !terminal.output_incomplete
                    || Path::new(&format!("/proc/{pid}")).exists()
                {
                    return Err(format!("Node capture returned an incorrect terminal: {terminal:?}").into());
                }
                let batch = node.next_batch(id, 0)?.ok_or("missing Node output batch")?;
                if batch.frames.len() != 2 || batch.terminal.as_ref() != Some(&terminal) {
                    return Err("Node capture lost output or its terminal".into());
                }
                drop(node);
                let mut node = NodeTraceOwner::open_fixture(
                    &root, request.tenant_id, "node-a".into(), [7; 16], command,
                )?;
                let now = u64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos())?;
                let duplicate_now = if local_expiry { dispatch.accepted.deadline_unix_ns } else { now };
                let duplicate = node.admit(dispatch.clone(), None, &dispatch_key, duplicate_now);
                if local_expiry {
                    if !matches!(duplicate, Err(araphor_observability::Error::Observability {
                        code: mithril_control::TraceErrorCodeV1::Expired, ..
                    })) {
                        return Err("Node accepted an expired cached dispatch".into());
                    }
                } else if duplicate? != id {
                    return Err("Node reopen changed execution identity".into());
                }
                if node.next_batch(id, 0)?.as_ref() != Some(&batch) || launches.load(Ordering::Acquire) != 1 {
                    return Err("Node reopen changed output or repeated execution".into());
                }
                let access = TraceReadAccessV1 {
                    tenant_id: request.tenant_id, namespace_uids: grant.namespace_uids.clone(),
                    node_ids: grant.node_ids.clone(), host_sensitive: false,
                    valid_until_unix_ns: grant.valid_until_unix_ns, revoked: false,
                };
                if let Some(failed) = &failed {
                    if let Some(server) = server.take() {
                        server.shutdown().await?;
                    }
                    drop(owner);
                    drop(data);
                    drop(control);
                    drop(reopen_control_store(&tls.path().join("control-store")).await?);
                    control = Self::trace_control(&tls, key)?;
                    control.replace_kubernetes_workload_inventory(
                        request.targets.iter().map(|target| target.fact.clone()).collect(),
                    )?;
                    data = control.analysis_store().ok_or("missing recovered Node data")?;
                    owner = TraceOwner::new(data.clone());
                    let prefix = owner.output(request.tenant_id, request.request_id, 0, &access, now, 0)?;
                    let (_, intent) = data.trace_intent(request.tenant_id, request.request_id)?
                        .ok_or("missing recovered diagnostic intent")?;
                    let binding = intent.bindings.iter().find(|binding| binding.identity.execution_id == id)
                        .ok_or("missing recovered diagnostic binding")?;
                    recovered_receipt = data.trace_receipt(&binding.identity)?;
                    if before_append {
                        if !prefix.is_empty() || recovered_receipt.as_ref().is_none_or(|receipt| {
                            receipt.last_sequence != 0 || receipt.output_bytes != 0
                                || receipt.commit_revision != 0 || receipt.terminal.is_some()
                        }) {
                            return Err(format!("data reopen retained output before the raw append: {prefix:?}; {recovered_receipt:?}").into());
                        }
                    } else if prefix != vec![failed.clone()] {
                        return Err("data reopen lost or changed the synced Node prefix".into());
                    }
                    if !data.storage_health()?.write_ready {
                        return Err("data reopen left the writer unready".into());
                    }
                    recovered_prefix = prefix;
                }
                if server.is_none() {
                    server = Some(tls.start(control.clone()).await?);
                }
                let connector = tls.connector(server.as_ref().ok_or("Control is absent")?, "node-a", [7; 16]);
                let mut connection = connector.connect(registration.clone(), true, &mut cache).await?;
                let exchange = TraceExchangeV1 {
                    retained: vec![id], resolved: None,
                    output: Some(TraceUploadV1 {
                        request_id: request.request_id, target_index: 0,
                        original_node_boot_id: [7; 16], batch: batch.clone(),
                    }),
                };
                let first = connection.exchange_diagnostics(&exchange).await?;
                let replay = connection.exchange_diagnostics(&exchange).await?;
                let ack = first.acknowledgement.as_ref().ok_or("missing Node output ACK")?;
                if ack.execution_id != id || ack.last_sequence != terminal.last_sequence
                    || ack.terminal.as_ref() != Some(&terminal) || replay != first
                {
                    return Err("Node output replay changed its durable ACK".into());
                }
                node.acknowledge(id, &terminal)?;
                if node.next_batch(id, 0)?.is_some() {
                    return Err("Node retained an acknowledged upload".into());
                }
                let retained = owner.output(request.tenant_id, request.request_id, 0, &access, now, 0)?;
                if retained != vec![batch] {
                    return Err("Control retained different Node output".into());
                }
                let (_, intent) = data.trace_intent(request.tenant_id, request.request_id)?
                    .ok_or("missing diagnostic intent")?;
                let binding = intent.bindings.iter().find(|binding| binding.identity.execution_id == id)
                    .ok_or("missing diagnostic binding")?;
                let receipt = data.trace_receipt(&binding.identity)?
                    .ok_or("missing diagnostic receipt")?;
                records.push(serde_json::json!({
                    "name": name, "accepted": dispatch.accepted, "target": target,
                    "process_id": pid, "launch_count": launches.load(Ordering::Acquire),
                    "process_reaped": true, "terminal_reopen": true,
                    "control_stopped": name == "partition-expiry" || before_append,
                    "partition_before_admission": name == "partition-expiry",
                    "supplied_now": supplied_now,
                    "signed_deadline": dispatch.accepted.deadline_unix_ns,
                    "collection_seconds": request.collection_seconds,
                    "expired_dispatch_rejected": local_expiry,
                    "storage_fault": failed.as_ref().map(|batch| if before_append {
                        serde_json::json!({
                            "stage": "BeforeAppend", "error_codes": fault_codes,
                            "fault_input": "injected StorageFull error before the raw append",
                            "writer_unready": false, "active_output_retained": true,
                            "upload_acknowledged": false, "control_stopped_after_failure": true,
                            "recovered_prefix": recovered_prefix,
                            "recovered_receipt": recovered_receipt.as_ref().map(|receipt| serde_json::json!({
                                "last_sequence": receipt.last_sequence, "output_bytes": receipt.output_bytes,
                                "commit_revision": receipt.commit_revision, "terminal": receipt.terminal,
                            })), "data_reopened": true,
                        })
                    } else { serde_json::json!({
                        "stage": "AfterSync", "error_codes": fault_codes,
                        "fault_input": "injected StorageFull error after syncing active Node output",
                        "writer_unready": true, "active_output_retained": true,
                        "recovered_prefix": batch, "data_reopened": true,
                    }) }),
                    "acknowledgement": ack, "replay_ack": replay.acknowledgement,
                    "retained": retained, "receipt": {
                        "identity": receipt.identity, "last_sequence": receipt.last_sequence,
                        "output_bytes": receipt.output_bytes, "terminal": receipt.terminal,
                        "retained_floor": receipt.retained_floor,
                        "commit_revision": receipt.commit_revision,
                    },
                    "storage": data.storage_health()?,
                }));
            }
            if tls.path().join("control-store/discovery-index.sqlite").try_exists()? {
                return Err("Node capture started a discovery index".into());
            }
            Ok::<_, Box<dyn std::error::Error>>(serde_json::json!({
                "scope": "node-owner-chain", "result": "PASS", "cases": records,
                "proof_boundary": "Production Control, Node spool and Interceptor supervision use external process, binding-state and admission-clock inputs. Partition and storage cases use five seconds left on the signed lease and a 30-second backend collection limit. BeforeAppend injects StorageFull before the raw write and leaves the writer ready. Reopen finds no prefix and a zero-progress terminal reservation. AfterSync injects StorageFull after a real segment sync and leaves the writer unready. Reopen recovers the synced prefix. Attach notifications are simulated. Node reopen follows a retained terminal, not a process crash. NodeChassis retry scheduling, physical disk-full, BPF cleanup, enforcement, and performance are not tested. Physical limits remain unknown.",
                "discovery_index_present": false, "physical": false, "performance_claim": false,
            }))
        }).await;
        let shutdown = if let Some(server) = server {
            server.shutdown().await
        } else {
            Ok(())
        };
        let record = result??;
        shutdown?;
        Ok(record)
    }

    pub fn pod_recipes(
        &self,
        executable: PathBuf,
        digest: [u8; 32],
        cgroup: &Path,
    ) -> ProofResult<()> {
        use mithril_control::{TraceFrameKindV1, TraceFrameV1, TraceRecipeV1};
        use std::os::unix::fs::MetadataExt as _;
        fs::create_dir(&self.output)?;
        if !kubernetes_cgroup_path(cgroup) || !cgroup.is_dir() {
            return Err("the recipe target is not a Kubernetes cgroup".into());
        }
        let held = fs::File::open(cgroup)?;
        let cgroup_id = held.metadata()?.ino();
        let baseline = ResourceSnapshot::read()?;
        let backend = DiagnosticBackend::new(executable, digest)?;
        let mut results = Vec::new();
        for recipe in [TraceRecipeV1::SyscallErrors, TraceRecipeV1::FailedOpens] {
            for pod in ["foreign", "target"] {
                let capture = backend.start(
                    &recipe.manifest()?.source.bytes,
                    cgroup_id,
                    DiagnosticMode::Capture,
                    Duration::from_secs(3),
                )?;
                let mut frames = Vec::new();
                let deadline = Instant::now() + Duration::from_secs(12);
                let mut ready = false;
                while Instant::now() < deadline && !capture.is_finished() {
                    for frame in capture.frames().try_iter() {
                        ready |= CaseResult::attached(&frame);
                        frames.push(frame);
                    }
                    if ready {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                if !ready {
                    return Err("recipe attachment did not become ready".into());
                }
                if fs::metadata(cgroup)?.ino() != cgroup_id {
                    return Err("Pod cgroup changed before probe".into());
                }
                let probe = Command::new("/usr/local/bin/k3s")
                    .args([
                        "kubectl",
                        "-n",
                        "araphor-observability-qualification",
                        "exec",
                        pod,
                        "--",
                        "/bin/cat",
                        "/araphor-observability-missing-file",
                    ])
                    .output()?;
                if probe.status.code() != Some(1) {
                    return Err("Pod did not report the expected failed open".into());
                }
                while !capture.is_finished() {
                    frames.extend(capture.frames().try_iter());
                    std::thread::sleep(Duration::from_millis(10));
                }
                frames.extend(capture.frames().try_iter());
                let terminal = capture.finish()?;
                let measurements: Vec<_> = frames
                    .iter()
                    .flat_map(|frame| {
                        recipe
                            .measurements(&TraceFrameV1 {
                                execution_id: [1; 16],
                                sequence: frame.sequence,
                                kind: if frame.stderr {
                                    TraceFrameKindV1::Diagnostic
                                } else {
                                    TraceFrameKindV1::Data
                                },
                                bytes: frame.bytes.clone(),
                            })
                            .unwrap_or_default()
                    })
                    .collect();
                let expected = if pod == "foreign" {
                    measurements.is_empty()
                } else {
                    measurements
                        .iter()
                        .any(|row| row.errno == -libc::ENOENT as i64 && row.count > 0)
                };
                results.push(serde_json::json!({ "recipe": recipe, "probe_pod": pod,
                    "cgroup": cgroup, "cgroup_id": cgroup_id, "frames": frames,
                    "measurements": measurements, "terminal": terminal }));
                fs::write(
                    self.output.join("pod-recipes.json"),
                    serde_json::to_vec_pretty(&results)?,
                )?;
                if !expected
                    || terminal.forced_kill
                    || terminal.output_incomplete
                    || terminal.cleanup_verified != Some(true)
                {
                    return Err(format!(
                        "recipe attribution or cleanup failed: {recipe:?} {pod}: {terminal:?}"
                    )
                    .into());
                }
                let cleanup_deadline = Instant::now() + Duration::from_secs(2);
                while ResourceSnapshot::read()? != baseline && Instant::now() < cleanup_deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                if ResourceSnapshot::read()? != baseline {
                    return Err("recipe changed the BPF resource baseline".into());
                }
            }
        }
        Ok(())
    }

    pub fn backend(
        &self,
        executable: PathBuf,
        digest: [u8; 32],
        retained_pin_root: Option<PathBuf>,
    ) -> ProofResult<()> {
        fs::create_dir(&self.output)?;
        let _runtime_stats = KernelRuntimeStats::open()?;
        let directory = tempfile::tempdir()?;
        let pin_root = retained_pin_root.unwrap_or_else(|| {
            PathBuf::from(format!(
                "/sys/fs/bpf/araphor-observability-{}",
                uuid::Uuid::new_v4()
            ))
        });
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let host = KernelHostOwner::new(KernelHostConfig::identity(
            "/sys/kernel/btf/vmlinux",
            directory.path().join("lease"),
            Some(pin_root),
            boot.trim(),
            1,
        ))
        .start()?;
        let result = self.backend_cases(&host, executable, digest);
        let cleanup = host.decommission();
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error.into()),
            (Err(error), Err(cleanup)) => {
                Err(format!("{error}; enforcement cleanup also failed: {cleanup}").into())
            }
        }
    }

    fn backend_cases(
        &self,
        host: &erebor_interceptor::KernelHost,
        executable: PathBuf,
        digest: [u8; 32],
    ) -> ProofResult<()> {
        let backend = DiagnosticBackend::new(executable.clone(), digest)?;
        let baseline = ResourceSnapshot::read()?;
        Self::missing_btf()?;
        if ResourceSnapshot::read()? != baseline {
            return Err("missing BTF changed live resources".into());
        }
        self.write(
            "missing-btf.json",
            &serde_json::json!({
                "owner": "KernelHostOwner",
                "stage": "preflight",
                "missing_runtime_btf_rejected": true,
            }),
        )?;
        self.write("baseline.json", &baseline)?;
        self.write("enforcement-manifest.json", host.manifest())?;
        let cases = [
            (
                "compile-timeout",
                "BEGIN { @x = count(); }",
                DiagnosticMode::Compile,
                false,
            ),
            (
                "oversize-output",
                "BEGIN { printf(\"%1048577d\\n\", 1); exit(); }",
                DiagnosticMode::Capture,
                false,
            ),
            (
                "raw-output",
                "iter:task { printf(\"not-json\\n\"); }",
                DiagnosticMode::Capture,
                false,
            ),
            (
                "probe-limit",
                "tracepoint:syscalls:sys_enter_* { @x = count(); }",
                DiagnosticMode::Capture,
                false,
            ),
            (
                "unsafe-helper",
                "BEGIN { system(\"true\"); }",
                DiagnosticMode::Capture,
                false,
            ),
            (
                "compile-valid",
                "BEGIN { @x = count(); }",
                DiagnosticMode::Compile,
                false,
            ),
            (
                "parse-error",
                "this is not bpftrace",
                DiagnosticMode::Compile,
                false,
            ),
            (
                "unsupported-hook",
                "rawtracepoint:araphor_missing_hook_5f6d { @x = count(); }",
                DiagnosticMode::Capture,
                false,
            ),
            (
                "quiet",
                include_str!("../fixtures/observability/quiet.bt"),
                DiagnosticMode::Capture,
                true,
            ),
            (
                "histogram",
                include_str!("../fixtures/observability/histogram.bt"),
                DiagnosticMode::Capture,
                true,
            ),
            (
                "graceful",
                "interval:s:1 { @x = count(); exit(); }",
                DiagnosticMode::Capture,
                false,
            ),
            (
                "partial-attach",
                include_str!("../fixtures/observability/partial-attach.bt"),
                DiagnosticMode::Capture,
                false,
            ),
            (
                "deadline",
                include_str!("../fixtures/observability/quiet.bt"),
                DiagnosticMode::Capture,
                false,
            ),
            (
                "forced-kill",
                include_str!("../fixtures/observability/quiet.bt"),
                DiagnosticMode::Capture,
                true,
            ),
            (
                "syscall-errors",
                include_str!("../fixtures/observability/syscall-errors.bt"),
                DiagnosticMode::Capture,
                false,
            ),
            (
                "failed-opens",
                include_str!("../fixtures/observability/failed-opens.bt"),
                DiagnosticMode::Capture,
                false,
            ),
        ];
        let mut results = Vec::new();
        for (name, source, mode, cancel) in cases {
            let capture = backend.start(
                source.as_bytes(),
                1,
                mode,
                Duration::from_secs(if cancel || name == "graceful" { 3 } else { 1 }),
            )?;
            let mut attached = None;
            let mut frames = Vec::new();
            let mut observed_program_ids = BTreeSet::new();
            let mut observed_map_ids = BTreeSet::new();
            let mut observed_link_ids = BTreeSet::new();
            let mut hash_entries = BTreeMap::new();
            let mut map_memlock_bytes = BTreeMap::new();
            let mut kernel_runtime = BTreeMap::new();
            let mut stopped = false;
            while !capture.is_finished() {
                for frame in capture.frames().try_iter() {
                    if attached.is_none() && CaseResult::attached(&frame) {
                        attached = Some(Instant::now());
                    }
                    frames.push(frame);
                }
                let live = ResourceSnapshot::read()?;
                observed_program_ids.extend(live.programs.difference(&baseline.programs).copied());
                observed_map_ids.extend(live.maps.difference(&baseline.maps).copied());
                observed_link_ids.extend(live.links.difference(&baseline.links).copied());
                for map in libbpf_rs::query::MapInfoIter::default().filter(|map| {
                    observed_map_ids.contains(&u64::from(map.id)) && map.ty.is_hash_map()
                }) {
                    hash_entries.insert(u64::from(map.id), map.max_entries);
                }
                for program in libbpf_rs::query::ProgInfoIter::default()
                    .filter(|program| observed_program_ids.contains(&u64::from(program.id)))
                {
                    kernel_runtime.insert(
                        program.id,
                        KernelRunTime {
                            name: program.name.to_string_lossy().into_owned(),
                            kind: program.ty as u32,
                            run_time_ns: program.run_time_ns,
                            run_count: program.run_cnt,
                            recursion_misses: program.recursion_misses,
                        },
                    );
                }
                for id in live.maps.difference(&baseline.maps) {
                    let memory = libbpf_rs::MapHandle::from_map_id(*id as u32)
                        .ok()
                        .and_then(|map| libbpf_rs::MapFdInfo::from_fd(map.as_fd()).ok())
                        .and_then(|info| info.memlock);
                    map_memlock_bytes.insert(*id, memory);
                }
                if !stopped
                    && ((name == "forced-kill"
                        && attached.is_some()
                        && !observed_program_ids.is_empty())
                        || (name == "compile-timeout" && capture.process_id().is_some()))
                {
                    let pid = capture
                        .process_id()
                        .and_then(|pid| rustix::process::Pid::from_raw(pid as i32))
                        .ok_or("diagnostic process disappeared")?;
                    let fd =
                        rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
                    rustix::process::pidfd_send_signal(&fd, rustix::process::Signal::STOP)?;
                    if name == "forced-kill" {
                        capture.cancel();
                    }
                    stopped = true;
                }
                if cancel && attached.is_some_and(|time| time.elapsed() > Duration::from_secs(2)) {
                    capture.cancel();
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            frames.extend(capture.frames().try_iter());
            let result = capture.finish()?;
            host.verify_live_manifest()?;
            let after = ResourceSnapshot::read()?;
            let record = CaseResult {
                name,
                result,
                frames,
                observed_program_ids,
                observed_map_ids,
                observed_link_ids,
                hash_entries,
                map_memlock_bytes,
                kernel_runtime,
                cleanup_verified: after == baseline,
                enforcement_manifest_unchanged: true,
            };
            self.write(&format!("{name}.json"), &record)?;
            record.verify()?;
            if name == "compile-timeout"
                && (!record.result.forced_kill
                    || record.result.stop
                        != erebor_interceptor::diagnostic::DiagnosticStop::Deadline)
            {
                return Err("compile-timeout: preparation did not stop at its deadline".into());
            }
            if name == "oversize-output"
                && record.result.stop != erebor_interceptor::diagnostic::DiagnosticStop::OutputLimit
            {
                return Err("oversize-output: frame limit was not reached".into());
            }
            if name == "raw-output"
                && !record
                    .frames
                    .iter()
                    .any(|frame| frame.bytes == b"not-json\n")
            {
                return Err("raw-output: backend output was not preserved".into());
            }
            results.push(record);
        }
        self.write("backend-results.json", &results)?;
        self.parent_death(host, &baseline, &executable, digest)?;
        Ok(())
    }

    pub fn parent_fixture(&self, executable: PathBuf, digest: [u8; 32]) -> ProofResult<()> {
        fs::create_dir(&self.output)?;
        let capture = DiagnosticBackend::new(executable, digest)?.start(
            include_bytes!("../fixtures/observability/quiet.bt"),
            1,
            DiagnosticMode::Capture,
            Duration::from_secs(30),
        )?;
        let started = Instant::now();
        while !capture.is_finished()
            && started.elapsed() < PREPARATION_LIMIT + Duration::from_secs(2)
        {
            for frame in capture.frames().try_iter() {
                if CaseResult::attached(&frame) {
                    self.write(
                        "pid.json",
                        &capture
                            .process_id()
                            .ok_or("parent fixture exited before readiness")?,
                    )?;
                    self.write("ready-pending.json", &frame)?;
                    fs::rename(
                        self.output.join("ready-pending.json"),
                        self.output.join("ready.json"),
                    )?;
                    capture.frames().iter().for_each(drop);
                    return Err(format!(
                        "parent fixture ended before parent death: {:?}",
                        capture.finish()?
                    )
                    .into());
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err("parent fixture did not report qualified attachment readiness".into())
    }

    fn parent_death(
        &self,
        host: &erebor_interceptor::KernelHost,
        baseline: &ResourceSnapshot,
        executable: &Path,
        digest: [u8; 32],
    ) -> ProofResult<()> {
        let path = self.output.join("parent-fixture");
        if path.exists() {
            return Err("parent fixture output already exists".into());
        }
        let mut fixture = QualificationChild(
            Command::new(std::env::current_exe()?)
                .arg("--parent-fixture")
                .arg("--executable")
                .arg(executable)
                .args(["--sha256", &hex::encode(digest)])
                .arg("--output-directory")
                .arg(&path)
                .spawn()?,
        );
        let started = Instant::now();
        let mut observed = ResourceSnapshot {
            programs: BTreeSet::new(),
            maps: BTreeSet::new(),
            links: BTreeSet::new(),
        };
        let mut ready = false;
        while started.elapsed() < PREPARATION_LIMIT + Duration::from_secs(2) {
            if fixture.0.try_wait()?.is_some() {
                return Err("parent fixture exited before qualified readiness".into());
            }
            let live = ResourceSnapshot::read()?;
            observed
                .programs
                .extend(live.programs.difference(&baseline.programs).copied());
            observed
                .maps
                .extend(live.maps.difference(&baseline.maps).copied());
            observed
                .links
                .extend(live.links.difference(&baseline.links).copied());
            if Self::parent_ready(&path, &live, baseline)? {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if !ready {
            return Err("parent fixture did not reach qualified attachment readiness".into());
        }
        fixture.0.kill()?;
        fixture.0.wait()?;
        let cleanup_started = Instant::now();
        loop {
            if ResourceSnapshot::read()? == *baseline {
                break;
            }
            if cleanup_started.elapsed() >= Duration::from_secs(5) {
                return Err("parent death left BPF resources".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        host.verify_live_manifest()?;
        self.write("parent-death-program-ids.json", &observed.programs)?;
        self.write("parent-death-map-ids.json", &observed.maps)?;
        self.write("parent-death-link-ids.json", &observed.links)?;
        Ok(())
    }

    fn parent_ready(
        path: &Path,
        live: &ResourceSnapshot,
        baseline: &ResourceSnapshot,
    ) -> ProofResult<bool> {
        let bytes = match fs::read(path.join("ready.json")) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if !CaseResult::attached(&serde_json::from_slice::<DiagnosticFrame>(&bytes)?) {
            return Err("parent fixture readiness is not an attachment notification".into());
        }
        Ok(live
            .programs
            .difference(&baseline.programs)
            .next()
            .is_some())
    }

    fn write(&self, name: &str, value: &impl Serialize) -> ProofResult<()> {
        fs::write(
            self.output.join(Path::new(name)),
            serde_json::to_vec_pretty(value)?,
        )?;
        Ok(())
    }

    fn missing_btf() -> ProofResult<()> {
        let directory = tempfile::tempdir()?;
        let missing = directory.path().join("missing.btf");
        let owner = KernelHostOwner::new(KernelHostConfig::identity(
            &missing,
            directory.path().join("lease"),
            None,
            "qualification",
            1,
        ));
        match owner.preflight() {
            Err(erebor_interceptor::Error::InvalidConfiguration { path, reason, .. })
                if path == missing && reason == "runtime BTF is not a regular file" =>
            {
                Ok(())
            }
            _ => Err("missing BTF did not fail before attachment".into()),
        }
    }
}

struct QualificationChild(std::process::Child);

impl Drop for QualificationChild {
    fn drop(&mut self) {
        let _kill = self.0.kill();
        let _wait = self.0.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_owned_upload() -> ProofResult<()> {
        let directory = tempfile::tempdir()?;
        let owner = ObservabilityQualification::new(directory.path().join("owned"));
        owner.owned_capture()?;
        let path = owner.output.join("result.json");
        let bytes = fs::read(&path)?;
        let record: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(record["case"], "owned-capture");
        assert_eq!(record["scope"], "owner-upload");
        assert_eq!(record["result"], "PASS");
        assert_eq!(record["physical"], false);
        assert_eq!(record["performance_claim"], false);
        assert_eq!(record["discovery_index_present"], false);
        assert_eq!(record["output_ack"], record["replay_ack"]);
        assert_eq!(record["output_ack"]["last_sequence"], 1);
        assert_eq!(record["retained"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            record["retained"][0]["frames"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(record["terminal_ack"]["terminal"]["cleanup"], "Unknown");
        assert!(record["terminal_ack"]["terminal"]["kernel_lost_events"].is_null());
        assert_eq!(record["storage_recovery"]["fault_stage"], "AfterSync");
        assert_eq!(
            record["storage_recovery"]["error_codes"],
            serde_json::json!(["Unavailable", "DataLoss"])
        );
        assert_eq!(
            record["storage_recovery"]["acknowledgement"]["last_sequence"],
            1
        );
        assert_eq!(
            record["storage_recovery"]["retained"][0]["frames"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
        let node = &record["node_capture"];
        assert_eq!(node["scope"], "node-owner-chain");
        assert_eq!(node["result"], "PASS");
        assert_eq!(node["physical"], false);
        assert_eq!(node["performance_claim"], false);
        assert_eq!(node["discovery_index_present"], false);
        let cases = node["cases"].as_array().ok_or("missing Node cases")?;
        assert_eq!(cases.len(), 5);
        for (case, reason) in cases.iter().zip([
            "TargetChanged",
            "Cancelled",
            "Deadline",
            "Deadline",
            "Deadline",
        ]) {
            assert_eq!(case["launch_count"], 1);
            assert_eq!(case["process_reaped"], true);
            assert_eq!(case["terminal_reopen"], true);
            assert_eq!(case["acknowledgement"], case["replay_ack"]);
            assert_eq!(case["acknowledgement"]["last_sequence"], 2);
            assert_eq!(case["acknowledgement"]["terminal"]["reason"], reason);
            assert_eq!(case["acknowledgement"]["terminal"]["cleanup"], "Unknown");
            assert!(case["acknowledgement"]["terminal"]["kernel_lost_events"].is_null());
            assert_eq!(
                case["retained"][0]["frames"].as_array().map(Vec::len),
                Some(2)
            );
        }
        assert_eq!(cases[2]["control_stopped"], true);
        assert_eq!(cases[2]["partition_before_admission"], true);
        for case in &cases[2..] {
            assert_eq!(case["expired_dispatch_rejected"], true);
            assert_eq!(case["collection_seconds"], 30);
            assert_eq!(
                case["signed_deadline"]
                    .as_u64()
                    .ok_or("missing signed deadline")?
                    - case["supplied_now"]
                        .as_u64()
                        .ok_or("missing supplied time")?,
                5_000_000_000
            );
        }
        let fault = &cases[3]["storage_fault"];
        assert_eq!(fault["stage"], "AfterSync");
        assert_eq!(
            fault["error_codes"],
            serde_json::json!(["Unavailable", "DataLoss"])
        );
        assert_eq!(fault["writer_unready"], true);
        assert_eq!(fault["active_output_retained"], true);
        assert_eq!(fault["data_reopened"], true);
        assert!(fault["recovered_prefix"]["terminal"].is_null());
        assert_eq!(
            fault["recovered_prefix"]["frames"],
            cases[3]["retained"][0]["frames"]
        );
        assert_eq!(cases[3]["storage"]["write_ready"], true);
        let fault = &cases[4]["storage_fault"];
        assert_eq!(cases[4]["name"], "store-before-append");
        assert_eq!(cases[4]["control_stopped"], true);
        assert_eq!(fault["stage"], "BeforeAppend");
        assert_eq!(fault["error_codes"], serde_json::json!(["Unavailable"]));
        assert_eq!(fault["writer_unready"], false);
        assert_eq!(fault["active_output_retained"], true);
        assert_eq!(fault["upload_acknowledged"], false);
        assert_eq!(fault["control_stopped_after_failure"], true);
        assert_eq!(fault["recovered_prefix"], serde_json::json!([]));
        assert_eq!(fault["recovered_receipt"]["last_sequence"], 0);
        assert_eq!(fault["recovered_receipt"]["output_bytes"], 0);
        assert_eq!(fault["recovered_receipt"]["commit_revision"], 0);
        assert!(fault["recovered_receipt"]["terminal"].is_null());
        assert_eq!(fault["data_reopened"], true);
        assert_eq!(cases[4]["storage"]["write_ready"], true);
        assert_eq!(cases[4]["retained"].as_array().map(Vec::len), Some(1));
        assert!(owner.owned_capture().is_err());
        assert_eq!(fs::read(path)?, bytes);
        Ok(())
    }

    fn capture_case(name: &'static str) -> CaseResult {
        let mut frames = vec![DiagnosticFrame {
            sequence: 1,
            stderr: true,
            bytes: b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n".to_vec(),
        }];
        if name == "histogram" {
            frames.push(DiagnosticFrame {
                sequence: 2,
                stderr: false,
                bytes: b"{\"type\":\"hist\",\"data\":{}}\n".to_vec(),
            });
        }
        CaseResult {
            name,
            result: DiagnosticResult {
                process_id: 1,
                stop: match name {
                    "quiet" | "histogram" | "forced-kill" => DiagnosticStop::Cancelled,
                    "graceful" => DiagnosticStop::Exited,
                    _ => DiagnosticStop::Deadline,
                },
                exit_code: (name != "forced-kill").then_some(0),
                forced_kill: name == "forced-kill",
                output_incomplete: name == "forced-kill",
                emitted_frames: frames.len() as u64,
                retained_bytes: frames.iter().map(|frame| frame.bytes.len()).sum(),
                elapsed_ms: 3_000,
                attach_notification_ms: Some(100),
                program_ids: BTreeSet::from([11]),
                map_ids: BTreeSet::from([12]),
                cleanup_verified: Some(true),
                peak_rss_kib: None,
            },
            frames,
            observed_program_ids: BTreeSet::from([11]),
            observed_map_ids: BTreeSet::from([12]),
            observed_link_ids: BTreeSet::new(),
            hash_entries: BTreeMap::from([(12, 4096)]),
            map_memlock_bytes: BTreeMap::new(),
            kernel_runtime: BTreeMap::new(),
            cleanup_verified: true,
            enforcement_manifest_unchanged: true,
        }
    }

    #[test]
    fn observability_backend_capture_readiness() -> ProofResult<()> {
        for name in [
            "quiet",
            "histogram",
            "graceful",
            "deadline",
            "forced-kill",
            "syscall-errors",
            "failed-opens",
        ] {
            let mut record = capture_case(name);
            record.verify()?;
            record.result.attach_notification_ms = None;
            assert!(record.verify().is_err(), "{name}: missing notification");
            record.result.attach_notification_ms = Some(100);
            record.frames[0].stderr = false;
            assert!(record.verify().is_err(), "{name}: stdout marker");
            record.frames[0].stderr = true;
            for bytes in [
                b"Attaching 1 probe...\n".as_slice(),
                b"__BPFTRACE_NOTIFY_PROBES_ATTACHED extra\n".as_slice(),
            ] {
                record.frames[0].bytes = bytes.to_vec();
                assert!(record.verify().is_err(), "{name}: wrong marker");
            }
            record.frames[0].bytes = b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n".to_vec();
            record.observed_program_ids.clear();
            assert!(record.verify().is_err(), "{name}: no observed program");
        }
        Ok(())
    }

    #[test]
    fn observability_backend_map_capacity() -> ProofResult<()> {
        let mut record = capture_case("syscall-errors");
        record.verify()?;
        record.hash_entries.insert(12, 4097);
        assert!(record.verify().is_err());
        record.hash_entries.clear();
        assert!(record.verify().is_err());
        Ok(())
    }

    #[test]
    fn observability_backend_capture_outcome() -> ProofResult<()> {
        for name in [
            "quiet",
            "histogram",
            "graceful",
            "deadline",
            "forced-kill",
            "syscall-errors",
            "failed-opens",
        ] {
            let mut record = capture_case(name);
            record.verify()?;
            let stop = record.result.stop;
            record.result.stop = DiagnosticStop::PreparationDeadline;
            assert!(record.verify().is_err(), "{name}: preparation failure");
            record.result.stop = stop;
            record.result.output_incomplete = !record.result.output_incomplete;
            assert!(record.verify().is_err(), "{name}: output completeness");
            record.result.output_incomplete = !record.result.output_incomplete;
            record.result.forced_kill = !record.result.forced_kill;
            assert!(record.verify().is_err(), "{name}: wrong termination");
            record.result.forced_kill = !record.result.forced_kill;
            record.result.exit_code = Some(1);
            assert!(record.verify().is_err(), "{name}: unsuccessful capture");
        }
        Ok(())
    }

    #[test]
    fn observability_backend_partial_proof() -> ProofResult<()> {
        let mut record = capture_case("quiet");
        record.name = "partial-attach";
        record.result.stop = DiagnosticStop::Exited;
        record.result.exit_code = Some(255);
        record.result.attach_notification_ms = None;
        record.observed_program_ids = BTreeSet::from([11, 12]);
        record.frames[0].bytes =
            b"ERROR: Error attaching probe: 'kprobe:araphor_missing_hook_5f6d'\n".to_vec();
        assert!(
            record.verify().is_err(),
            "loaded programs do not prove attachment"
        );
        record.kernel_runtime.insert(
            11,
            KernelRunTime {
                name: "10".into(),
                kind: libbpf_rs::ProgramType::PerfEvent as u32,
                run_time_ns: 100,
                run_count: 1,
                recursion_misses: 0,
            },
        );
        record.verify()?;
        record.result.program_ids.clear();
        assert!(
            record.verify().is_err(),
            "another child's program is not proof"
        );
        record.result.program_ids.insert(11);
        for (name, kind, count) in [
            ("BEGIN", libbpf_rs::ProgramType::RawTracepoint, 1),
            ("10", libbpf_rs::ProgramType::RawTracepoint, 1),
            ("1", libbpf_rs::ProgramType::PerfEvent, 1),
            ("10", libbpf_rs::ProgramType::PerfEvent, 0),
        ] {
            record.kernel_runtime.insert(
                11,
                KernelRunTime {
                    name: name.into(),
                    kind: kind as u32,
                    run_time_ns: 100,
                    run_count: count,
                    recursion_misses: 0,
                },
            );
            assert!(
                record.verify().is_err(),
                "unrelated or idle program is not proof"
            );
        }
        Ok(())
    }

    #[test]
    fn observability_backend_hook_rejection() -> ProofResult<()> {
        let mut record = capture_case("quiet");
        record.name = "unsupported-hook";
        record.result.stop = DiagnosticStop::Exited;
        record.result.exit_code = Some(1);
        record.result.attach_notification_ms = None;
        record.frames[0].bytes =
            b"ERROR: Probe does not exist: rawtracepoint:araphor_missing_hook_5f6d\n".to_vec();
        record.verify()?;
        record.result.exit_code = Some(0);
        assert!(record.verify().is_err());
        record.result.exit_code = None;
        assert!(record.verify().is_err());
        record.result.exit_code = Some(1);
        record.result.stop = DiagnosticStop::Deadline;
        assert!(record.verify().is_err());
        record.result.stop = DiagnosticStop::Exited;
        record.result.attach_notification_ms = Some(100);
        assert!(record.verify().is_err());
        record.result.attach_notification_ms = None;
        for bytes in [
            b"ERROR: bpftrace currently only supports running as the root user.\n".as_slice(),
            b"ERROR: Error attaching probe: 'kprobe:another_hook'\n".as_slice(),
            b"WARNING: araphor_missing_hook_5f6d is not traceable\n".as_slice(),
            b"create_probe_event: Read-only file system\nERROR: Error attaching probe: 'kprobe:araphor_missing_hook_5f6d'\n".as_slice(),
            b"create_probe_event: Permission denied\nERROR: Error attaching probe: 'kprobe:araphor_missing_hook_5f6d'\n".as_slice(),
            b"Read-only file system\nERROR: Probe does not exist: rawtracepoint:araphor_missing_hook_5f6d\n".as_slice(),
            b"Permission denied\nERROR: Probe does not exist: rawtracepoint:araphor_missing_hook_5f6d\n".as_slice(),
            b"Operation not permitted\nERROR: Probe does not exist: rawtracepoint:araphor_missing_hook_5f6d\n".as_slice(),
        ] {
            record.frames[0].bytes = bytes.to_vec();
            assert!(record.verify().is_err());
        }
        Ok(())
    }

    #[test]
    fn observability_backend_compile_resources() -> ProofResult<()> {
        let mut record = capture_case("graceful");
        record.name = "compile-valid";
        record.result.attach_notification_ms = None;
        record.result.program_ids.clear();
        record.result.map_ids.clear();
        record.frames.clear();
        record.observed_program_ids.clear();
        record.observed_map_ids.clear();
        record.hash_entries.clear();
        record.verify()?;
        record.result.program_ids.insert(11);
        assert!(record.verify().is_err());
        record.result.program_ids.clear();
        record.result.map_ids.insert(12);
        assert!(record.verify().is_err());
        record.result.map_ids.clear();
        record.observed_link_ids.insert(13);
        assert!(record.verify().is_err());
        assert_eq!(
            serde_json::to_value(&record)?["observed_link_ids"],
            serde_json::json!([13]),
        );
        record.observed_link_ids.clear();
        record.observed_map_ids.insert(12);
        assert!(record.verify().is_err());
        Ok(())
    }

    #[test]
    fn observability_backend_parent_readiness() -> ProofResult<()> {
        let directory = tempfile::tempdir()?;
        let baseline = ResourceSnapshot {
            programs: BTreeSet::from([1]),
            maps: BTreeSet::new(),
            links: BTreeSet::new(),
        };
        let mut live = baseline.clone();
        live.programs.insert(2);
        fs::write(directory.path().join("pid.json"), b"123")?;
        assert!(!ObservabilityQualification::parent_ready(
            directory.path(),
            &live,
            &baseline,
        )?);
        let mut frame = capture_case("quiet").frames.remove(0);
        let path = directory.path().join("ready.json");
        fs::write(&path, serde_json::to_vec(&frame)?)?;
        assert!(!ObservabilityQualification::parent_ready(
            directory.path(),
            &baseline,
            &baseline,
        )?);
        assert!(ObservabilityQualification::parent_ready(
            directory.path(),
            &live,
            &baseline,
        )?);
        frame.stderr = false;
        fs::write(&path, serde_json::to_vec(&frame)?)?;
        assert!(
            ObservabilityQualification::parent_ready(directory.path(), &live, &baseline,).is_err()
        );
        frame.stderr = true;
        frame.bytes = b"Attaching 1 probe...\n".to_vec();
        fs::write(&path, serde_json::to_vec(&frame)?)?;
        assert!(
            ObservabilityQualification::parent_ready(directory.path(), &live, &baseline,).is_err()
        );
        Ok(())
    }

    #[test]
    fn observability_target_latency_fixture_needs_no_protected_file_writes() -> ProofResult<()> {
        let status = Command::new("python3")
            .arg("-c")
            .arg(
                r#"
import builtins, ctypes, errno, os, pathlib, sys, time
source = pathlib.Path(sys.argv[1]).read_text()
names = []
class Libc:
    def prctl(self, operation, value, *args):
        names.append(ctypes.string_at(value).decode())
        return 0
ctypes.CDLL = lambda *args, **kwargs: Libc()
def denied(*args, **kwargs):
    raise PermissionError(errno.EACCES, 'protected file operation')
builtins.open = denied
os.open = denied
os.rename = denied
os.path.exists = lambda path: True
time.sleep = lambda delay: None
sys.argv = ['observability.py', '/work']
exec(compile(source, 'observability.py', 'exec'))
assert len(names) == 10 and all(name.startswith(f'tr{i}:') for i, name in enumerate(names)), names
"#,
            )
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/process/observability.py"))
            .status()?;
        assert!(status.success());
        Ok(())
    }

    #[test]
    fn observability_target_accepts_the_k3s_systemd_cgroup_layout() {
        assert!(kubernetes_cgroup_path(Path::new(
            "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod123.slice/cri-containerd-456.scope"
        )));
        assert!(kubernetes_cgroup_path(Path::new(
            "/sys/fs/cgroup/kubepods/besteffort/pod123/456"
        )));
        assert!(!kubernetes_cgroup_path(Path::new(
            "/sys/fs/cgroup/kubepods-other/456"
        )));
        assert!(!kubernetes_cgroup_path(Path::new(
            "/sys/fs/cgroup/system.slice/456"
        )));
    }

    #[test]
    fn observability_backend_missing_btf_rejects_before_attach() -> ProofResult<()> {
        ObservabilityQualification::missing_btf()
    }

    #[test]
    fn observability_backend_root_refusal_is_not_a_parse_proof() {
        let record = CaseResult {
            name: "parse-error",
            result: DiagnosticResult {
                process_id: 1,
                stop: erebor_interceptor::diagnostic::DiagnosticStop::Exited,
                exit_code: Some(1),
                forced_kill: false,
                output_incomplete: false,
                emitted_frames: 1,
                retained_bytes: 0,
                elapsed_ms: 1,
                attach_notification_ms: None,
                program_ids: BTreeSet::new(),
                map_ids: BTreeSet::new(),
                cleanup_verified: None,
                peak_rss_kib: None,
            },
            frames: vec![erebor_interceptor::diagnostic::DiagnosticFrame {
                sequence: 1,
                stderr: true,
                bytes: b"ERROR: bpftrace currently only supports running as the root user.\n"
                    .to_vec(),
            }],
            observed_program_ids: BTreeSet::new(),
            observed_map_ids: BTreeSet::new(),
            observed_link_ids: BTreeSet::new(),
            hash_entries: BTreeMap::new(),
            map_memlock_bytes: BTreeMap::new(),
            kernel_runtime: BTreeMap::new(),
            cleanup_verified: true,
            enforcement_manifest_unchanged: true,
        };
        assert!(record.verify().is_err());
    }
}
