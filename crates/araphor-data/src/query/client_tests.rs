use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use duckdb::types::{TimeUnit, Value};
use futures_core::stream::FusedStream;
use futures_util::StreamExt;
use tokio::sync::{oneshot, watch};

use super::tests::QueryFixture;
use super::{
    QueryAuthorization, QueryCheckpoint, QueryClock, QueryErrorCode, QueryFrame, QueryGrant,
    QueryLimits, QueryOperation, QueryOwner, QueryPayload, QueryPlan, QueryResult, QuerySql,
    QueryStream, QueryTerminalReason,
};
use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisReadControl, AnalysisSelectionV1,
    ContextSensitivityV1, EvidenceRecord, EvidenceRetentionOwner, Result, StorePositionV1,
    TraceBatchV1, TraceBindingV1, TraceCleanupV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1,
    TraceIntentV1, TraceOutputReceiptV1, TraceRecipeV1, TraceTerminalReasonV1, TraceTerminalV1,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type ClockGate = (oneshot::Sender<()>, mpsc::Receiver<()>);
const WAIT: Duration = Duration::from_secs(5);

struct Clock {
    now: Arc<AtomicU64>,
    reads: AtomicUsize,
    gate: Mutex<Option<ClockGate>>,
}

impl Clock {
    fn new(now: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now)),
            reads: AtomicUsize::new(0),
            gate: Mutex::new(None),
        }
    }

    fn arm(&self) -> TestResult<(oneshot::Receiver<()>, mpsc::Sender<()>)> {
        let (entered, entering) = oneshot::channel();
        let (release, released) = mpsc::channel();
        *self.gate.lock().map_err(|_| "clock gate lock failed")? = Some((entered, released));
        Ok((entering, release))
    }
}

impl QueryClock for Clock {
    fn now_ns(&self) -> Result<u64> {
        let now = self.now.load(Ordering::SeqCst);
        if self.reads.fetch_add(1, Ordering::SeqCst) == 1 {
            let gate = self
                .gate
                .lock()
                .map_err(|_| {
                    crate::QueryInvalidSnafu {
                        field: "test clock",
                    }
                    .build()
                })?
                .take();
            if let Some((entered, released)) = gate {
                let _entered = entered.send(());
                released.recv_timeout(WAIT).map_err(|_| {
                    crate::QueryInvalidSnafu {
                        field: "test clock gate",
                    }
                    .build()
                })?;
            }
        }
        Ok(now)
    }
}

struct Authority {
    grant: QueryGrant,
    now: Arc<AtomicU64>,
    changes: watch::Sender<u64>,
    until: u64,
}

impl Authority {
    fn new(grant: QueryGrant, now: Arc<AtomicU64>) -> Self {
        let (changes, _) = watch::channel(grant.revision);
        Self {
            grant,
            now,
            changes,
            until: 10_000_000_000_000,
        }
    }

    fn revoke(&self) {
        self.changes.send_replace(self.grant.revision + 1);
    }
}

impl QueryAuthorization for Authority {
    fn check(&self, grant: &QueryGrant) -> Result<()> {
        let expected = &self.grant;
        if *self.changes.borrow() != expected.revision
            || self.now.load(Ordering::SeqCst) >= self.until
            || grant.principal != expected.principal
            || grant.revision != expected.revision
            || grant.selection.tenant_id != expected.selection.tenant_id
        {
            return crate::QueryDeniedSnafu.fail();
        }
        Ok(())
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    fn expires_ns(&self) -> Option<u64> {
        Some(self.until)
    }
}

struct ClientFixture {
    data: QueryFixture,
    owner: Arc<QueryOwner>,
    grant: QueryGrant,
    authority: Arc<Authority>,
    clock: Arc<Clock>,
}

impl ClientFixture {
    fn target(&self, index: u8) -> TestResult<AnalysisContextVersionV1> {
        let binding = uuid::Uuid::from_bytes([index; 16]).to_string();
        let generation = format!("{index:064x}");
        let fact = crate::WorkloadTargetFactV1 {
            node_id: self.data.source.node_id.clone(),
            workload_binding_generation_digest: generation.clone(),
            execution_set_id: uuid::Uuid::from_bytes([index; 16]).to_string(),
            cluster_uid: "cluster-a".into(),
            namespace_uid: "namespace-a".into(),
            controller_uid: "controller-a".into(),
            service_account_uid: "account-a".into(),
            pod_uid: format!("pod-{index}"),
            container_id: format!("containerd://{index}"),
            container_name: "application".into(),
            container_kind: crate::ContainerKindV1::Application,
            image_digest: "sha256:retained-image".into(),
            pod_labels: std::collections::BTreeMap::from([("app".into(), "fixture".into())]),
            kubernetes: Some(crate::KubernetesWorkloadIdentityV1 {
                namespace_name: "default".into(),
                pod_name: format!("workload-{index}"),
                profile_id: "profile-a".into(),
                policy_source_revision_id: "source-a".into(),
                binding_id: binding.clone(),
                protected_scope_id: "scope-a".into(),
                workload_selector_id: "selector-a".into(),
                kubernetes_node_name: "worker-a".into(),
                kubernetes_node_uid: "worker-uid-a".into(),
                node_boot_id: uuid::Uuid::from_bytes(self.data.source.node_boot_id).to_string(),
                label_epoch: self.data.source.label_epoch,
            }),
        };
        Ok(AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: self.data.source.tenant_id,
                owner_id: "mithril-control/target".into(),
                entity_key: binding.into_bytes(),
                lifetime_key: generation.into_bytes(),
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: serde_json::to_vec(&fact)?,
        })
    }

    fn trace(&self, request: u8) -> Result<TraceIntentV1> {
        let source = TraceRecipeV1::FailedOpens.manifest()?.source;
        let intent = TraceIntentV1 {
            tenant_id: self.data.source.tenant_id,
            request_id: [request; 16],
            bindings: vec![TraceBindingV1 {
                identity: TraceIdentityV1 {
                    tenant_id: self.data.source.tenant_id,
                    request_id: [request; 16],
                    execution_id: [request; 16],
                    node_id: self.data.source.node_id.clone(),
                    node_boot_id: self.data.source.node_boot_id,
                    source_sha256: source.sha256,
                },
                binding_id: [request; 16],
                namespace_uid: "trace-namespace".into(),
            }],
            source,
            authority: b"opaque Control record".to_vec(),
            accepted_unix_ns: 100,
            deadline_unix_ns: 1_000_000_000,
            host_sensitive: false,
        };
        self.data.store.accept_trace(&intent)?;
        Ok(intent)
    }

    fn trace_frame(
        &self,
        intent: &TraceIntentV1,
        sequence: u64,
        bytes: &[u8],
    ) -> Result<TraceOutputReceiptV1> {
        let identity = &intent.bindings[0].identity;
        self.data.store.append_trace(
            identity,
            &TraceBatchV1 {
                execution_id: identity.execution_id,
                frames: vec![TraceFrameV1 {
                    execution_id: identity.execution_id,
                    sequence,
                    kind: TraceFrameKindV1::Data,
                    bytes: bytes.to_vec(),
                }],
                terminal: None,
            },
            101 + sequence,
        )
    }

    fn trace_terminal(&self, intent: &TraceIntentV1) -> Result<TraceOutputReceiptV1> {
        let identity = &intent.bindings[0].identity;
        let receipt = self.data.store.trace_receipt(identity)?;
        self.data.store.append_trace(
            identity,
            &TraceBatchV1 {
                execution_id: identity.execution_id,
                frames: Vec::new(),
                terminal: Some(TraceTerminalV1 {
                    execution_id: identity.execution_id,
                    reason: TraceTerminalReasonV1::Completed,
                    last_sequence: receipt.as_ref().map_or(0, |value| value.last_sequence),
                    output_bytes: receipt.as_ref().map_or(0, |value| value.output_bytes),
                    output_incomplete: false,
                    kernel_lost_events: None,
                    ready_at_unix_ns: None,
                    exit_code: Some(0),
                    forced_kill: false,
                    cleanup: TraceCleanupV1::Verified,
                }),
            },
            200,
        )
    }

    fn local() -> TestResult<Self> {
        Self::new(200, 100)
    }

    fn new(rows: usize, now: u64) -> TestResult<Self> {
        let data = QueryFixture::new()?;
        let owner = Arc::new(QueryOwner::new(
            data.store.clone(),
            QueryLimits {
                output_rows: rows,
                ..Default::default()
            },
        )?);
        let grant = QueryGrant {
            principal: "client-operator".into(),
            revision: 1,
            selection: AnalysisSelectionV1::new(data.source.tenant_id, vec![data.source.clone()]),
        };
        let clock = Arc::new(Clock::new(now));
        let authority = Arc::new(Authority::new(grant.clone(), clock.now.clone()));
        Ok(Self {
            data,
            owner,
            grant,
            authority,
            clock,
        })
    }

    fn bounded() -> TestResult<Self> {
        let mut fixture = Self::new(200, 100)?;
        let capacity = 64 * 1024;
        fixture.owner = Arc::new(QueryOwner::new(
            fixture.data.store.clone(),
            QueryLimits {
                input_bytes: capacity,
                output_bytes: capacity,
                input_capacity: capacity,
                output_capacity: capacity,
                global_evaluations: 1,
                extract_timeout: Duration::from_secs(30),
                evaluate_timeout: Duration::from_secs(30),
                ..Default::default()
            },
        )?);
        Ok(fixture)
    }

    fn gate(&self) -> TestResult<(mpsc::Receiver<()>, mpsc::Sender<()>)> {
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        *self
            .owner
            .scan_gate
            .lock()
            .map_err(|_| "scan gate lock failed")? = Some((entered, released));
        Ok((entering, release))
    }

    async fn entered(entering: &mpsc::Receiver<()>) -> TestResult {
        tokio::time::timeout(WAIT, async {
            loop {
                match entering.try_recv() {
                    Ok(()) => return Ok(()),
                    Err(mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
                    Err(mpsc::TryRecvError::Disconnected) => return Err("scan gate closed".into()),
                }
            }
        })
        .await?
    }

    fn inputs(&self, alive: bool) -> TestResult {
        let inputs = self
            .owner
            .input_refs
            .lock()
            .map_err(|_| "input reference lock failed")?;
        assert!(!inputs.is_empty());
        assert!(inputs
            .iter()
            .all(|input| input.upgrade().is_some() == alive));
        Ok(())
    }

    fn commit(&self, cursor: u64, now: u64, operation: u32, target: u8) -> TestResult {
        self.data.commit(
            cursor,
            now,
            EvidenceRecord {
                operation,
                policy_rule_id: 42,
                execution_set_id: vec![target; 16].into(),
                ..Default::default()
            },
        )
    }

    fn plan(&self, sql: &str, parameters: Vec<Value>, follow: bool) -> Result<QueryPlan> {
        QueryPlan::client(
            self.grant.clone(),
            QuerySql::admit(sql, parameters, follow)?,
        )
    }

    fn tenant(&mut self) {
        self.grant.selection = AnalysisSelectionV1::tenant(self.data.source.tenant_id);
        self.authority = Arc::new(Authority::new(self.grant.clone(), self.clock.now.clone()));
    }

    async fn query(&self, plan: &QueryPlan) -> Result<QueryResult> {
        self.owner
            .query_client(
                plan.clone(),
                self.authority.clone(),
                self.clock.now.load(Ordering::SeqCst),
                Arc::new(AnalysisReadControl::default()),
            )
            .await
    }

    fn follow(&self, plan: QueryPlan, checkpoint: Option<QueryCheckpoint>) -> Result<QueryStream> {
        self.owner
            .follow_client_clock(plan, checkpoint, self.authority.clone(), self.clock.clone())
    }

    fn stream(&self, plan: QueryPlan, checkpoint: Option<QueryCheckpoint>) -> Result<QueryStream> {
        self.owner
            .stream_client_clock(plan, checkpoint, self.authority.clone(), self.clock.clone())
    }

    async fn next(stream: &mut QueryStream) -> TestResult<QueryFrame> {
        let frame = tokio::time::timeout(WAIT, stream.next())
            .await?
            .ok_or("client stream closed before its expected frame")??;
        Ok(frame)
    }

    fn checkpoint(frame: &QueryFrame) -> TestResult<QueryCheckpoint> {
        match &frame.payload {
            QueryPayload::Checkpoint { checkpoint, .. } => Ok(checkpoint.clone()),
            payload => Err(format!("expected checkpoint, received {payload:?}").into()),
        }
    }

    fn result(frame: &QueryFrame, operation: QueryOperation) -> TestResult<&QueryResult> {
        match (&frame.payload, operation) {
            (QueryPayload::Append { result, .. }, QueryOperation::Append)
            | (QueryPayload::Replace { result, .. }, QueryOperation::Replace) => Ok(result),
            (payload, _) => Err(format!("expected {operation:?}, received {payload:?}").into()),
        }
    }

    async fn cancel(stream: &mut QueryStream) -> TestResult {
        stream.cancel()?;
        for _ in 0..4 {
            let frame = Self::next(stream).await?;
            if matches!(
                frame.payload,
                QueryPayload::Terminal {
                    reason: QueryTerminalReason::Cancelled,
                    ..
                }
            ) {
                drop(frame);
                assert!(tokio::time::timeout(WAIT, stream.next())
                    .await?
                    .transpose()?
                    .is_none());
                tokio::time::timeout(WAIT, &mut stream.task).await??;
                return Ok(());
            }
            if !matches!(
                frame.payload,
                QueryPayload::Append { .. } | QueryPayload::Checkpoint { .. }
            ) {
                return Err(format!("unexpected cancellation frame: {:?}", frame.payload).into());
            }
        }
        Err("client cancellation did not close within four frames".into())
    }

    async fn current_query(&self) -> TestResult {
        let mut grant = self.grant.clone();
        grant.revision += 1;
        let sql = QuerySql::admit("SELECT COUNT(*) FROM events", vec![], false)?;
        let authority = Arc::new(Authority::new(grant.clone(), self.clock.now.clone()));
        let plan = QueryPlan::client(grant, sql)?;
        let result = self
            .owner
            .query_client(
                plan,
                authority,
                self.clock.now.load(Ordering::SeqCst),
                Arc::new(AnalysisReadControl::default()),
            )
            .await?;
        assert_eq!(result.rows, vec![vec![Value::BigInt(2)]]);
        assert_eq!(result.sources.len(), 1);
        Ok(())
    }
}

#[tokio::test]
async fn query_catalog_relations() -> TestResult {
    let mut fixture = ClientFixture::local()?;
    fixture.tenant();
    let context = fixture.target(1)?;
    fixture.data.store.commit_context(&context)?;
    let mut foreign = context.clone();
    foreign.key.tenant_id = [9; 16];
    fixture.data.store.commit_context(&foreign)?;
    let mut unrelated = context.clone();
    unrelated.key.owner_id = "mithril-control/policy".into();
    unrelated.body = b"unrelated owner bytes".to_vec();
    fixture.data.store.commit_context(&unrelated)?;
    let plan = fixture.plan(
        "SELECT node_id,node_boot_id,binding_id,pod_name,container_kind FROM targets",
        vec![],
        false,
    )?;
    let selection = plan.dependencies(100)?;
    assert!(selection.targets && selection.targets_only && selection.all_contexts);
    assert!(!selection.all_sources && !selection.all_traces);
    let result = fixture.query(&plan).await?;
    assert_eq!(plan.operation(), QueryOperation::Replace);
    assert_eq!(
        result.rows,
        vec![vec![
            Value::Text(fixture.data.source.node_id.clone()),
            Value::Blob(fixture.data.source.node_boot_id.to_vec()),
            Value::Blob(vec![1; 16]),
            Value::Text("workload-1".into()),
            Value::Text("APPLICATION".into()),
        ]]
    );
    let plan = fixture.plan(
        "SELECT COUNT(*) FROM targets t JOIN context_versions c ON t.tenant_id=c.tenant_id AND t.entity_key=c.entity_key AND t.lifetime_key=c.lifetime_key AND t.owner_revision=c.owner_revision WHERE c.owner_id='mithril-control/target'",
        vec![],
        false,
    )?;
    assert!(!plan.dependencies(100)?.targets_only);
    assert_eq!(
        fixture.query(&plan).await?.rows,
        vec![vec![Value::BigInt(1)]]
    );
    let plan = fixture.plan(
        "SELECT recipe,version,source,source_sha256,parameter,hook,capability_status,example FROM trace_recipes ORDER BY recipe",
        vec![],
        false,
    )?;
    let selection = plan.dependencies(100)?;
    assert!(!selection.all_contexts && !selection.all_sources && !selection.all_traces);
    let result = fixture.query(&plan).await?;
    assert_eq!(result.rows.len(), 2);
    for (row, recipe, name) in [
        (
            &result.rows[0],
            TraceRecipeV1::FailedOpens,
            "failed-opens@1",
        ),
        (
            &result.rows[1],
            TraceRecipeV1::SyscallErrors,
            "syscall-errors@1",
        ),
    ] {
        let manifest = recipe.manifest()?;
        assert_eq!(row[0], Value::Text(name.into()));
        assert_eq!(row[1], Value::UInt(1));
        assert_eq!(row[2], Value::Blob(manifest.source.bytes));
        assert_eq!(row[3], Value::Blob(manifest.source.sha256.to_vec()));
        assert_eq!(row[4], Value::Text(manifest.parameter));
        assert_eq!(row[5], Value::Text(manifest.hook));
        assert_eq!(row[6], Value::Text("unknown".into()));
        assert!(matches!(&row[7], Value::Text(value) if value.contains(name)));
    }
    let plan = fixture.plan(
        "SELECT relation,COUNT(*) FROM catalog WHERE relation IN ('targets','trace_recipes') GROUP BY relation ORDER BY relation",
        vec![],
        false,
    )?;
    assert_eq!(
        fixture.query(&plan).await?.rows,
        vec![
            vec![Value::Text("targets".into()), Value::BigInt(28)],
            vec![Value::Text("trace_recipes".into()), Value::BigInt(17)],
        ]
    );
    fixture.grant.selection.nodes.push("absent-node".into());
    let plan = fixture.plan("SELECT COUNT(*) FROM targets", vec![], false)?;
    assert_eq!(
        fixture.query(&plan).await?.rows,
        vec![vec![Value::BigInt(0)]]
    );
    fixture.grant.selection.nodes.clear();
    fixture.grant.selection.binding_ids.push([2; 16]);
    let plan = fixture.plan("SELECT COUNT(*) FROM targets", vec![], false)?;
    assert_eq!(
        fixture.query(&plan).await?.rows,
        vec![vec![Value::BigInt(0)]]
    );
    fixture.grant.selection.binding_ids.clear();
    let mut altered = fixture.target(2)?;
    altered.key.entity_key = b"altered binding".to_vec();
    fixture.data.store.commit_context(&altered)?;
    let plan = fixture.plan("SELECT COUNT(*) FROM targets", vec![], false)?;
    assert!(matches!(
        fixture.query(&plan).await,
        Err(crate::Error::QueryInvalid {
            field: "target context",
            ..
        })
    ));
    Ok(())
}

#[tokio::test]
async fn query_target_follow() -> TestResult {
    let mut fixture = ClientFixture::local()?;
    fixture.tenant();
    let plan = fixture.plan("SELECT COUNT(*) FROM targets", vec![], true)?;
    let mut stream = fixture.stream(plan, None)?;
    drop(ClientFixture::next(&mut stream).await?);
    let frame = ClientFixture::next(&mut stream).await?;
    assert_eq!(
        ClientFixture::result(&frame, QueryOperation::Replace)?.rows,
        vec![vec![Value::BigInt(0)]]
    );
    drop(frame);
    drop(ClientFixture::next(&mut stream).await?);
    fixture.data.store.commit_context(&fixture.target(1)?)?;
    let frame = ClientFixture::next(&mut stream).await?;
    assert_eq!(
        ClientFixture::result(&frame, QueryOperation::Replace)?.rows,
        vec![vec![Value::BigInt(1)]]
    );
    drop(frame);
    drop(ClientFixture::next(&mut stream).await?);
    fixture.authority.revoke();
    assert!(matches!(
        tokio::time::timeout(WAIT, stream.next()).await?,
        Some(Err(crate::Error::QueryDenied { .. }))
    ));
    assert!(tokio::time::timeout(WAIT, stream.next()).await?.is_none());
    tokio::time::timeout(WAIT, &mut stream.task).await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_trace_relations() -> TestResult {
    let mut fixture = ClientFixture::local()?;
    fixture.tenant();
    let intent = fixture.trace(7)?;
    let bytes = br#"{"type":"map","data":{"@errors":{"-13":7}}}"#;
    fixture.trace_frame(&intent, 1, bytes)?;
    let receipt = fixture.trace_terminal(&intent)?;
    let plan = fixture.plan("SELECT target_index,binding_id,last_sequence,output_bytes,kernel_lost_events,terminal_reason FROM traces", vec![], false)?;
    let result = fixture.query(&plan).await?;
    assert_eq!(
        result.rows,
        vec![vec![
            Value::UInt(0),
            Value::Blob(vec![7; 16]),
            Value::UBigInt(1),
            Value::UBigInt(bytes.len() as u64),
            Value::Null,
            Value::Text("Completed".into())
        ]]
    );
    drop(result);
    let plan = fixture.plan("SELECT execution_id,sequence,syscall_id,errno,count,cumulative,atomic_snapshot,unit FROM trace_measurements", vec![], false)?;
    assert_eq!(plan.operation(), QueryOperation::Replace);
    let result = fixture.query(&plan).await?;
    assert_eq!(
        result.rows,
        vec![vec![
            Value::Blob(vec![7; 16]),
            Value::UBigInt(1),
            Value::Null,
            Value::BigInt(-13),
            Value::UBigInt(7),
            Value::Boolean(true),
            Value::Boolean(false),
            Value::Text("count".into())
        ]]
    );
    drop(result);
    let plan = fixture.plan("SELECT execution_id,target_index,sequence,kind,bytes FROM trace_output WHERE request_id = ?", vec![Value::Blob(vec![7; 16])], false)?;
    assert_eq!(plan.operation(), QueryOperation::Append);
    let result = fixture.query(&plan).await?;
    let raw = fixture.data.store.read_trace(
        &intent.bindings[0].identity,
        1,
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(
        result.positions,
        raw.positions
            .iter()
            .copied()
            .chain(raw.terminal_position)
            .collect::<Vec<_>>()
    );
    assert_eq!(result.rows.len(), 2);
    assert_eq!(
        result.rows[0],
        vec![
            Value::Blob(vec![7; 16]),
            Value::UInt(0),
            Value::UBigInt(1),
            Value::Text("data".into()),
            Value::Blob(bytes.to_vec())
        ]
    );
    assert_eq!(
        result.rows[1],
        vec![
            Value::Blob(vec![7; 16]),
            Value::UInt(0),
            Value::UBigInt(2),
            Value::Text("terminal".into()),
            Value::Blob(serde_json::to_vec(
                receipt.terminal.as_ref().ok_or("terminal absent")?
            )?)
        ]
    );
    let explicit = AnalysisSelectionV1::new(fixture.data.source.tenant_id, Vec::new());
    let grant = QueryGrant {
        selection: explicit,
        ..fixture.grant.clone()
    };
    let empty = QueryPlan::client(
        grant,
        QuerySql::admit("SELECT COUNT(*) FROM trace_output", Vec::new(), false)?,
    )?;
    assert_eq!(
        fixture.query(&empty).await?.rows,
        vec![vec![Value::BigInt(0)]]
    );
    let mut foreign = intent.clone();
    foreign.tenant_id = [2; 16];
    foreign.bindings[0].identity.tenant_id = foreign.tenant_id;
    fixture.data.store.accept_trace(&foreign)?;
    fixture.trace_terminal(&foreign)?;
    assert_eq!(fixture.query(&plan).await?.rows.len(), 2);
    let expected = result.rows.clone();
    drop(result);
    let ClientFixture {
        data,
        owner,
        authority,
        ..
    } = fixture;
    drop(owner);
    let QueryFixture {
        store,
        _directory: directory,
        ..
    } = data;
    drop(store);
    let owner = Arc::new(QueryOwner::new(
        Arc::new(crate::AnalysisStore::open(
            directory.path().join("analysis"),
        )?),
        QueryLimits::default(),
    )?);
    let reopened = owner
        .query_client(
            plan,
            authority,
            100,
            Arc::new(AnalysisReadControl::default()),
        )
        .await?;
    assert_eq!(reopened.rows, expected);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_trace_stream() -> TestResult {
    let mut fixture = ClientFixture::local()?;
    fixture.tenant();
    let plan = fixture.plan(
        "SELECT execution_id,target_index,sequence,kind,bytes FROM trace_output",
        vec![],
        true,
    )?;
    let mut stream = fixture.follow(plan.clone(), None)?;
    assert!(matches!(
        ClientFixture::next(&mut stream).await?.payload,
        QueryPayload::Metadata(_)
    ));
    let frame = ClientFixture::next(&mut stream).await?;
    assert!(ClientFixture::result(&frame, QueryOperation::Append)?
        .rows
        .is_empty());
    drop(frame);
    let _initial = ClientFixture::next(&mut stream).await?;
    let intent = fixture.trace(8)?;
    fixture.trace_terminal(&intent)?;
    let frame = tokio::time::timeout(WAIT, async {
        loop {
            let frame = ClientFixture::next(&mut stream).await?;
            match &frame.payload {
                QueryPayload::Append { result } if !result.rows.is_empty() => {
                    break Ok::<_, Box<dyn std::error::Error + Send + Sync>>(frame);
                }
                QueryPayload::Append { .. } | QueryPayload::Checkpoint { .. } => {}
                _ => return Err("unexpected trace follow frame".into()),
            }
        }
    })
    .await??;
    let result = ClientFixture::result(&frame, QueryOperation::Append)?;
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0][2], Value::UBigInt(1));
    assert_eq!(result.rows[0][3], Value::Text("terminal".into()));
    let terminal = fixture.data.store.read_trace(
        &intent.bindings[0].identity,
        1,
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(
        result.positions,
        vec![terminal
            .terminal_position
            .ok_or("terminal position absent")?]
    );
    drop(frame);
    let frame = ClientFixture::next(&mut stream).await?;
    assert!(matches!(
        frame.payload,
        QueryPayload::Checkpoint {
            exhausted: true,
            ..
        }
    ));
    let checkpoint = ClientFixture::checkpoint(&frame)?;
    ClientFixture::cancel(&mut stream).await?;
    let mut resumed = fixture.follow(plan, Some(checkpoint))?;
    let _metadata = ClientFixture::next(&mut resumed).await?;
    let frame = ClientFixture::next(&mut resumed).await?;
    assert!(ClientFixture::result(&frame, QueryOperation::Append)?
        .rows
        .is_empty());
    drop(frame);
    let _checkpoint = ClientFixture::next(&mut resumed).await?;
    ClientFixture::cancel(&mut resumed).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_trace_revocation() -> TestResult {
    let mut fixture = ClientFixture::local()?;
    fixture.tenant();
    let intent = fixture.trace(9)?;
    fixture.trace_frame(
        &intent,
        1,
        br#"{"type":"map","data":{"@errors":{"-13":1}}}"#,
    )?;
    let plan = fixture.plan("SELECT sequence FROM trace_output", vec![], true)?;
    let mut stream = fixture.follow(plan, None)?;
    let metadata = ClientFixture::next(&mut stream).await?;
    tokio::time::timeout(WAIT, async {
        while stream.queued() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let (mut state, _) = fixture
        .data
        .store
        .trace_intent(intent.tenant_id, intent.request_id)?
        .ok_or("trace absent")?;
    state.cancel_requested = true;
    state = fixture.data.store.update_trace(&state)?;
    metadata.check_read().await?;
    state.read_revoked = true;
    fixture.data.store.update_trace(&state)?;
    assert!(matches!(
        metadata.check_read().await,
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        tokio::time::timeout(WAIT, stream.next()).await?,
        Some(Err(crate::Error::QueryDenied { .. }))
    ));
    assert!(stream.is_terminated());
    assert!(stream.next().await.is_none());
    tokio::time::timeout(WAIT, &mut stream.task).await??;
    let mut grant = fixture.grant.clone();
    grant.selection = AnalysisSelectionV1::new(intent.tenant_id, Vec::new());
    grant
        .selection
        .traces
        .push(intent.bindings[0].identity.clone());
    let plan = QueryPlan::client(
        grant,
        QuerySql::admit("SELECT sequence FROM trace_output", Vec::new(), false)?,
    )?;
    assert!(matches!(
        fixture.query(&plan).await,
        Err(crate::Error::QueryDenied { .. })
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_trace_read_runtime() -> TestResult {
    use futures_util::FutureExt as _;
    let mut fixture = ClientFixture::local()?;
    fixture.tenant();
    let _intent = fixture.trace(10)?;
    let plan = fixture.plan("SELECT execution_id FROM traces", Vec::new(), false)?;
    let result = fixture.query(&plan).await?;
    let frame = QueryFrame::data(&plan, result)?;
    let result = std::thread::spawn(move || frame.check_read().now_or_never())
        .join()
        .map_err(|_| "read guard panicked outside Tokio")?;
    assert!(matches!(
        result,
        Some(Err(crate::Error::QueryInvalid {
            field: "query read runtime",
            ..
        }))
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_binding_selection() -> TestResult {
    let mut fixture = ClientFixture::local()?;
    fixture.tenant();
    for cursor in 1..=3 {
        fixture.data.commit(
            cursor,
            cursor,
            EvidenceRecord {
                operation: cursor as u32,
                decision_context: (cursor != 3).then(|| crate::EvidenceDecisionContext {
                    binding_id: vec![cursor as u8; 16],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )?;
    }
    let first = fixture.trace(1)?;
    fixture.trace_terminal(&first)?;
    let second = fixture.trace(2)?;
    fixture.trace_terminal(&second)?;
    fixture
        .grant
        .selection
        .nodes
        .push(fixture.data.source.node_id.clone());
    fixture.grant.selection.binding_ids.push([1; 16]);
    fixture.authority = Arc::new(Authority::new(
        fixture.grant.clone(),
        fixture.clock.now.clone(),
    ));
    let result = fixture
        .query(&fixture.plan("SELECT operation FROM events", Vec::new(), false)?)
        .await?;
    assert_eq!(result.rows, vec![vec![Value::UInt(1)]]);
    let result = fixture
        .query(&fixture.plan("SELECT execution_id FROM traces", Vec::new(), false)?)
        .await?;
    assert_eq!(result.rows, vec![vec![Value::Blob(vec![1; 16])]]);
    fixture.grant.selection.nodes = vec!["absent-node".into()];
    let plan = fixture.plan("SELECT COUNT(*) FROM events", Vec::new(), false)?;
    assert_eq!(
        fixture.query(&plan).await?.rows,
        vec![vec![Value::BigInt(0)]]
    );
    Ok(())
}

#[test]
fn query_client_trusted_entry() -> TestResult {
    let fixture = ClientFixture::local()?;
    let plan = fixture.plan("SELECT operation FROM events", vec![], true)?;
    assert!(matches!(
        fixture.owner.query_at(&plan, 100),
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        fixture
            .owner
            .query_cancel(&plan, 100, &AnalysisReadControl::default()),
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        fixture.owner.follow(plan.clone(), None),
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        fixture
            .owner
            .follow_clock(plan.clone(), None, fixture.clock.clone()),
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        QueryPlan::new(fixture.grant.selection.clone(), plan.template().clone()),
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(fixture
        .owner
        .input_refs
        .lock()
        .map_err(|_| "input reference lock failed")?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn query_client_in_process() -> TestResult {
    let fixture = ClientFixture::local()?;
    fixture.commit(1, 1, 7, 4)?;
    let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?;
    fixture.authority.check(&fixture.grant)?;
    let result = fixture.query(&plan).await?;
    assert_eq!(result.rows, vec![vec![Value::BigInt(1)]]);
    drop(result);
    let inputs = fixture
        .owner
        .input_refs
        .lock()
        .map_err(|_| "input reference lock failed")?;
    assert!(!inputs.is_empty());
    assert!(inputs.iter().all(|input| input.upgrade().is_none()));
    drop(inputs);
    let trusted = fixture.data.plan(super::QueryTemplate::OperationCounts)?;
    let result = fixture.owner.query_at(&trusted, 100)?;
    assert_eq!(result.rows, vec![vec![Value::UInt(7), Value::BigInt(1)]]);
    Ok(())
}

#[tokio::test]
async fn query_client_scheduler() -> TestResult {
    let fixture = ClientFixture::bounded()?;
    fixture.commit(1, 1, 7, 4)?;
    let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?;
    let (entering, release) = fixture.gate()?;
    let owner = fixture.owner.clone();
    let authority = fixture.authority.clone();
    let request = plan.clone();
    let task = tokio::spawn(async move {
        owner
            .query_client(
                request,
                authority,
                100,
                Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?),
            )
            .await
    });
    ClientFixture::entered(&entering).await?;
    fixture.inputs(true)?;
    tokio::time::timeout(WAIT, tokio::time::sleep(Duration::from_millis(1))).await?;
    assert!(!task.is_finished());
    assert!(matches!(
        fixture.query(&plan).await,
        Err(crate::Error::AnalysisBusy { .. })
    ));
    release.send(())?;
    let result = tokio::time::timeout(WAIT, task).await???;
    assert_eq!(result.rows, vec![vec![Value::BigInt(1)]]);
    drop(result);
    fixture.inputs(false)?;
    drop(
        fixture
            .owner
            .budget
            .evaluate(fixture.grant.selection.tenant_id)?,
    );
    drop(
        fixture
            .owner
            .budget
            .output(fixture.owner.limits.output_bytes)?,
    );
    Ok(())
}

#[tokio::test]
async fn query_client_cancel() -> TestResult {
    let fixture = ClientFixture::bounded()?;
    fixture.commit(1, 1, 7, 4)?;
    let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?;
    let before = fixture.data.store.meta()?;
    let (entering, release) = fixture.gate()?;
    let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?);
    let query = control.clone();
    let owner = fixture.owner.clone();
    let authority = fixture.authority.clone();
    let request = plan.clone();
    let task =
        tokio::spawn(async move { owner.query_client(request, authority, 100, query).await });
    ClientFixture::entered(&entering).await?;
    control.cancel()?;
    assert!(!task.is_finished());
    fixture.inputs(true)?;
    assert!(fixture
        .owner
        .budget
        .evaluate(fixture.grant.selection.tenant_id)
        .is_err());
    assert!(fixture.owner.budget.output(1).is_err());
    release.send(())?;
    ClientFixture::entered(&entering).await?;
    let result = tokio::time::timeout(WAIT, task).await??;
    assert!(
        matches!(result, Err(crate::Error::AnalysisReadCancelled { .. })),
        "{result:?}"
    );
    assert!(fixture.owner.native_failed.load(Ordering::Acquire));
    fixture.inputs(false)?;
    assert_eq!(fixture.data.store.meta()?, before);
    fixture.commit(2, 2, 8, 4)?;
    let result = fixture.query(&plan).await?;
    assert_eq!(result.rows, vec![vec![Value::BigInt(2)]]);
    drop(result);
    drop(
        fixture
            .owner
            .budget
            .evaluate(fixture.grant.selection.tenant_id)?,
    );
    drop(
        fixture
            .owner
            .budget
            .output(fixture.owner.limits.output_bytes)?,
    );
    Ok(())
}

#[tokio::test]
async fn query_client_drop() -> TestResult {
    let fixture = ClientFixture::bounded()?;
    fixture.commit(1, 1, 7, 4)?;
    let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?;
    let before = fixture.data.store.meta()?;
    let (entering, release) = fixture.gate()?;
    let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?);
    let query = control.clone();
    let owner = fixture.owner.clone();
    let authority = fixture.authority.clone();
    let request = plan.clone();
    let task =
        tokio::spawn(async move { owner.query_client(request, authority, 100, query).await });
    ClientFixture::entered(&entering).await?;
    task.abort();
    assert!(matches!(
        tokio::time::timeout(WAIT, task).await?,
        Err(error) if error.is_cancelled()
    ));
    assert!(matches!(
        control.check(),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    fixture.inputs(true)?;
    assert!(fixture
        .owner
        .budget
        .evaluate(fixture.grant.selection.tenant_id)
        .is_err());
    assert!(fixture.owner.budget.output(1).is_err());
    assert!(matches!(
        fixture.query(&plan).await,
        Err(crate::Error::AnalysisBusy { .. })
    ));
    release.send(())?;
    ClientFixture::entered(&entering).await?;
    tokio::time::timeout(WAIT, async {
        loop {
            match fixture
                .owner
                .budget
                .evaluate(fixture.grant.selection.tenant_id)
            {
                Ok(lease) => {
                    drop(lease);
                    return Ok::<_, crate::Error>(());
                }
                Err(crate::Error::AnalysisBusy { .. }) => tokio::task::yield_now().await,
                Err(error) => return Err(error),
            }
        }
    })
    .await??;
    assert!(fixture.owner.native_failed.load(Ordering::Acquire));
    fixture.inputs(false)?;
    drop(
        fixture
            .owner
            .budget
            .output(fixture.owner.limits.output_bytes)?,
    );
    assert_eq!(fixture.data.store.meta()?, before);
    fixture.commit(2, 2, 8, 4)?;
    let result = fixture.query(&plan).await?;
    assert_eq!(result.rows, vec![vec![Value::BigInt(2)]]);
    Ok(())
}

#[test]
fn query_client_follow_admission() -> TestResult {
    let fixture = ClientFixture::local()?;
    for sql in [
        "SELECT operation FROM events",
        "SELECT COUNT(*) FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '300 seconds' OR operation = 7",
        "SELECT COUNT(*) FROM events WHERE received_at <= CURRENT_TIMESTAMP - INTERVAL '300 seconds'",
    ] {
        let plan = fixture.plan(sql, vec![], false)?;
        assert!(
            matches!(
                fixture
                    .owner
                    .follow_client(plan.clone(), None, fixture.authority.clone()),
                Err(crate::Error::QueryDenied { .. })
            ),
            "{sql}"
        );
        assert!(
            matches!(
                fixture.follow(plan, None),
                Err(crate::Error::QueryDenied { .. })
            ),
            "{sql}"
        );
    }
    assert!(fixture
        .owner
        .input_refs
        .lock()
        .map_err(|_| "input reference lock failed")?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn query_client_capacity() -> TestResult {
    let fixture = ClientFixture::local()?;
    let limits = QueryLimits {
        input_bytes: 1_024,
        output_bytes: 4_096,
        input_capacity: 1_024,
        output_capacity: 4_096,
        ..Default::default()
    };
    let owner = QueryOwner::new(fixture.data.store.clone(), limits.clone())?;
    drop(owner);
    for changed in [
        QueryLimits {
            input_capacity: 1_023,
            ..limits.clone()
        },
        QueryLimits {
            output_capacity: 4_095,
            ..limits.clone()
        },
    ] {
        assert!(matches!(
            QueryOwner::new(fixture.data.store.clone(), changed),
            Err(crate::Error::QueryInvalid { .. })
        ));
    }
    for changed in [
        QueryLimits {
            output_rows: 201,
            ..Default::default()
        },
        QueryLimits {
            output_bytes: 1024 * 1024 + 1,
            ..Default::default()
        },
    ] {
        let owner = Arc::new(QueryOwner::new(fixture.data.store.clone(), changed)?);
        let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?;
        assert!(matches!(
            owner
                .query_client(
                    plan,
                    fixture.authority.clone(),
                    100,
                    Arc::new(AnalysisReadControl::default())
                )
                .await,
            Err(crate::Error::QueryInvalid { .. })
        ));
        let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], true)?;
        assert!(matches!(
            owner.follow_client(plan, None, fixture.authority.clone()),
            Err(crate::Error::QueryInvalid { .. })
        ));
        assert!(owner
            .input_refs
            .lock()
            .map_err(|_| "input reference lock failed")?
            .is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn query_client_expired_authority() -> TestResult {
    let fixture = ClientFixture::local()?;
    fixture.commit(1, 1, 7, 4)?;
    let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?;
    fixture
        .clock
        .now
        .store(fixture.authority.until - 1, Ordering::SeqCst);
    fixture.authority.check(&fixture.grant)?;
    fixture
        .clock
        .now
        .store(fixture.authority.until, Ordering::SeqCst);
    let control = Arc::new(AnalysisReadControl::default());
    control.cancel()?;
    assert!(matches!(
        fixture
            .owner
            .query_client(plan.clone(), fixture.authority.clone(), 100, control)
            .await,
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        fixture.query(&plan).await,
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(fixture
        .owner
        .input_refs
        .lock()
        .map_err(|_| "input reference lock failed")?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn query_client_bounds() -> TestResult {
    let fixture = ClientFixture::new(200, 10_000)?;
    for (index, now) in [1, 999, 1_000, 1_001, 1_999, 2_000, 3_000]
        .into_iter()
        .enumerate()
    {
        fixture.commit(index as u64 + 1, now, (index % 3) as u32, 4)?;
    }
    for predicate in [
        "received_at >= TIMESTAMP '1970-01-01 00:00:00.000001'",
        "received_at > TIMESTAMP '1970-01-01 00:00:00.000001'",
        "received_at <= TIMESTAMP '1970-01-01 00:00:00.000001'",
        "received_at BETWEEN TIMESTAMP '1970-01-01 00:00:00.000001' AND TIMESTAMP '1970-01-01 00:00:00.000002'",
    ] {
        let direct = fixture.plan(
            &format!("SELECT source_cursor FROM events WHERE {predicate} ORDER BY source_cursor"),
            vec![],
            false,
        )?;
        let complete = fixture.plan(
            &format!("SELECT source_cursor FROM events WHERE ({predicate}) OR FALSE ORDER BY source_cursor"),
            vec![],
            false,
        )?;
        let actual = fixture.query(&direct).await?;
        let expected = fixture.query(&complete).await?;
        assert_eq!(actual.scanned_bytes, None);
        assert_eq!(actual.input_bytes, None);
        assert_eq!(expected.scanned_bytes, None);
        assert_eq!(expected.input_bytes, None);
        assert_eq!(actual.rows, expected.rows, "{predicate}");
        assert_eq!(expected.input_rows, 7);
        assert!(actual.input_rows < expected.input_rows, "{predicate}");
        assert!(!actual.limited && !expected.limited);
    }
    let direct = fixture.plan(
        "SELECT source_cursor FROM events WHERE received_at >= $1 AND received_at <= $2 ORDER BY source_cursor",
        vec![Value::Timestamp(TimeUnit::Microsecond, 1), Value::Timestamp(TimeUnit::Microsecond, 2)],
        false,
    )?;
    assert_eq!(
        fixture.query(&direct).await?.rows,
        vec![
            vec![Value::UBigInt(3)],
            vec![Value::UBigInt(4)],
            vec![Value::UBigInt(5)],
            vec![Value::UBigInt(6)]
        ]
    );
    for sql in [
        "SELECT source_cursor FROM events WHERE received_at >= TIMESTAMP '1970-01-01 00:00:00.000002' OR operation = 0 ORDER BY source_cursor",
        "WITH chosen AS (SELECT source_cursor FROM events WHERE received_at >= TIMESTAMP '1970-01-01 00:00:00.000002') SELECT source_cursor FROM chosen ORDER BY source_cursor",
        "SELECT a.source_cursor FROM events a LEFT JOIN events b ON a.source_cursor = b.source_cursor WHERE a.received_at >= TIMESTAMP '1970-01-01 00:00:00.000002' ORDER BY a.source_cursor",
    ] {
        let plan = fixture.plan(sql, vec![], false)?;
        let result = fixture.query(&plan).await?;
        assert_eq!(result.input_rows, 7, "{sql}");
        assert!(!result.rows.is_empty());
        assert!(!result.limited);
    }
    Ok(())
}

#[tokio::test]
async fn query_client_tenant_scope() -> TestResult {
    let fixture = ClientFixture::new(200, 100)?;
    for (cursor, operation, target) in [(1, 7, 4), (2, 99, 5), (3, 8, 4), (4, 99, 5), (5, 99, 0)] {
        fixture.commit(cursor, cursor, operation, target)?;
    }
    let mut other = fixture.data.source.clone();
    other.source_id = [6; 16];
    fixture.data.commit_as(
        &other,
        0,
        1,
        6,
        EvidenceRecord {
            operation: 99,
            policy_rule_id: 42,
            execution_set_id: vec![5; 16].into(),
            ..Default::default()
        },
    )?;
    let mut foreign = other.clone();
    foreign.tenant_id = [9; 16];
    foreign.source_id = [7; 16];
    fixture.data.commit_as(
        &foreign,
        0,
        1,
        7,
        EvidenceRecord {
            operation: 99,
            policy_rule_id: 42,
            execution_set_id: vec![5; 16].into(),
            ..Default::default()
        },
    )?;
    let count = fixture.plan(
        "SELECT COUNT(*) FROM events WHERE policy_rule_id = 42",
        vec![],
        false,
    )?;
    let result = fixture.query(&count).await?;
    assert_eq!(result.rows, vec![vec![Value::BigInt(5)]]);
    assert_eq!(result.input_rows, 5);
    assert_eq!(result.scanned_bytes, None);
    assert_eq!(result.input_bytes, None);
    assert_eq!(result.sources.len(), 1);
    assert_eq!(result.sources[0].receipt.identity, fixture.data.source);
    drop(result);
    let rows = fixture
        .query(&fixture.plan("SELECT * FROM events", vec![], false)?)
        .await?;
    let schema = super::input::SCHEMAS
        .iter()
        .find(|schema| schema.name == "events")
        .ok_or("event schema is absent")?;
    assert_eq!(
        rows.columns,
        schema
            .columns
            .iter()
            .map(|field| field.0)
            .collect::<Vec<_>>()
    );
    assert_eq!(rows.types.len(), schema.columns.len());
    assert_eq!(rows.rows.len(), 5);
    assert_eq!(rows.positions.len(), 5);
    assert!(!rows
        .columns
        .iter()
        .any(|name| name.starts_with("__araphor_")));
    let target = rows
        .columns
        .iter()
        .position(|name| name == "execution_set_id")
        .ok_or("target column is absent")?;
    assert_eq!(
        rows.rows
            .iter()
            .map(|row| row[target].clone())
            .collect::<Vec<_>>(),
        [4, 5, 4, 5, 0].map(|target| Value::Blob(vec![target; 16]))
    );
    drop(rows);
    let selected = fixture.plan(
        "SELECT COUNT(*) FROM events WHERE execution_set_id = $1 AND policy_rule_id = 42",
        vec![Value::Blob(vec![4; 16])],
        false,
    )?;
    assert_eq!(
        fixture.query(&selected).await?.rows,
        vec![vec![Value::BigInt(2)]]
    );
    for sql in [
        "SELECT COUNT(execution_set_id) FROM events",
        "SELECT COUNT(*) FROM events WHERE execution_set_id IS NULL",
        "SELECT e.operation FROM events e JOIN events f ON e.execution_set_id = f.execution_set_id",
        "SELECT operation FROM events ORDER BY execution_set_id",
        "SELECT * FROM coverage",
    ] {
        fixture.plan(sql, vec![], false)?;
    }
    assert!(fixture
        .plan(
            "SELECT __araphor_commit_revision FROM events",
            vec![],
            false
        )
        .is_err());
    let mut grant = fixture.grant.clone();
    grant.selection.sources.push(other);
    let plan = QueryPlan::client(
        grant.clone(),
        QuerySql::admit("SELECT COUNT(*) FROM events", vec![], false)?,
    )?;
    let result = fixture.query(&plan).await?;
    assert_eq!(result.rows, vec![vec![Value::BigInt(6)]]);
    assert_eq!(result.sources.len(), 2);
    assert!(result
        .sources
        .iter()
        .all(|source| source.receipt.identity.tenant_id == fixture.grant.selection.tenant_id));
    drop(result);
    grant.selection.sources.clear();
    let plan = QueryPlan::client(
        grant.clone(),
        QuerySql::admit("SELECT COUNT(*) FROM events", vec![], false)?,
    )?;
    assert_eq!(
        fixture.query(&plan).await?.rows,
        vec![vec![Value::BigInt(0)]]
    );
    grant.selection.sources.push(foreign.clone());
    assert!(matches!(
        QueryPlan::client(
            grant.clone(),
            QuerySql::admit("SELECT COUNT(*) FROM events", vec![], false)?
        ),
        Err(crate::Error::QueryDenied { .. })
    ));
    grant.selection.tenant_id = foreign.tenant_id;
    let plan = QueryPlan::client(
        grant,
        QuerySql::admit("SELECT COUNT(*) FROM events", vec![], false)?,
    )?;
    assert!(matches!(
        fixture.query(&plan).await,
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        fixture.owner.query_at(&count, 100),
        Err(crate::Error::QueryDenied { .. })
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_client_append_resume() -> TestResult {
    let fixture = ClientFixture::new(2, 100)?;
    for (cursor, operation) in [(1, 9), (2, 7), (3, 9), (4, 7), (5, 7), (6, 9)] {
        fixture.commit(cursor, cursor, operation, 4)?;
    }
    let plan = fixture.plan(
        "SELECT operation FROM events WHERE operation = 7",
        vec![],
        true,
    )?;
    let mut stream = fixture.follow(plan.clone(), None)?;
    let metadata = ClientFixture::next(&mut stream).await?;
    let QueryPayload::Metadata(metadata) = &metadata.payload else {
        return Err("client metadata is absent".into());
    };
    assert_eq!(metadata.columns.len(), 1);
    assert_eq!(metadata.columns[0].name, "operation");
    let frame = ClientFixture::next(&mut stream).await?;
    let result = ClientFixture::result(&frame, QueryOperation::Append)?;
    assert_eq!(result.columns, ["operation"]);
    assert_eq!(
        result.rows,
        vec![vec![Value::UInt(7)], vec![Value::UInt(7)]]
    );
    assert_eq!(
        result
            .positions
            .iter()
            .map(|position| position.commit_revision)
            .collect::<Vec<_>>(),
        vec![2, 4]
    );
    assert!(result.limited && !result.exhausted);
    drop(frame);
    let first = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
    assert_eq!(
        first.position(),
        Some(StorePositionV1 {
            commit_revision: 4,
            ordinal: u32::MAX
        })
    );
    ClientFixture::cancel(&mut stream).await?;

    let mut resumed = fixture.follow(plan.clone(), Some(first))?;
    assert!(matches!(
        ClientFixture::next(&mut resumed).await?.payload,
        QueryPayload::Metadata(_)
    ));
    let frame = ClientFixture::next(&mut resumed).await?;
    let result = ClientFixture::result(&frame, QueryOperation::Append)?;
    assert_eq!(result.columns, ["operation"]);
    assert_eq!(result.rows, vec![vec![Value::UInt(7)]]);
    assert_eq!(
        result.positions,
        vec![StorePositionV1 {
            commit_revision: 5,
            ordinal: 0
        }]
    );
    assert!(!result.limited && result.exhausted);
    drop(frame);
    let complete = ClientFixture::checkpoint(&ClientFixture::next(&mut resumed).await?)?;
    assert_eq!(
        complete.position(),
        Some(StorePositionV1 {
            commit_revision: 6,
            ordinal: u32::MAX
        })
    );
    ClientFixture::cancel(&mut resumed).await?;

    fixture.commit(7, 7, 7, 4)?;
    let mut resumed = fixture.follow(plan, Some(complete))?;
    assert!(matches!(
        ClientFixture::next(&mut resumed).await?.payload,
        QueryPayload::Metadata(_)
    ));
    let frame = ClientFixture::next(&mut resumed).await?;
    let result = ClientFixture::result(&frame, QueryOperation::Append)?;
    assert_eq!(result.rows, vec![vec![Value::UInt(7)]]);
    assert_eq!(
        result.positions,
        vec![StorePositionV1 {
            commit_revision: 7,
            ordinal: 0
        }]
    );
    drop(frame);
    let _complete = ClientFixture::checkpoint(&ClientFixture::next(&mut resumed).await?)?;
    ClientFixture::cancel(&mut resumed).await?;
    Ok(())
}

#[tokio::test]
async fn query_stream_snapshot() -> TestResult {
    let mut fixture = ClientFixture::new(2, 100)?;
    fixture.tenant();
    for cursor in 1..=3 {
        fixture.commit(cursor, cursor, cursor as u32, 4)?;
    }
    for (sql, operation, rows, limited) in [
        (
            "SELECT operation FROM events",
            QueryOperation::Append,
            2,
            true,
        ),
        (
            "SELECT COUNT(*) FROM events",
            QueryOperation::Replace,
            1,
            false,
        ),
    ] {
        let plan = fixture.plan(sql, vec![], false)?;
        let mut stream = fixture.stream(plan.clone(), None)?;
        let frame = ClientFixture::next(&mut stream).await?;
        assert!(matches!(frame.payload, QueryPayload::Metadata(_)));
        drop(frame);
        let frame = ClientFixture::next(&mut stream).await?;
        let result = ClientFixture::result(&frame, operation)?;
        assert_eq!(result.rows.len(), rows);
        assert_eq!(result.limited, limited);
        if operation == QueryOperation::Replace {
            assert_eq!(result.rows, vec![vec![Value::BigInt(3)]]);
        }
        drop(frame);
        let checkpoint = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
        assert!(matches!(
            fixture.stream(plan, Some(checkpoint.clone())),
            Err(crate::Error::QueryInvalid {
                field: "checkpoint requires follow",
                ..
            })
        ));
        let frame = ClientFixture::next(&mut stream).await?;
        assert!(matches!(frame.payload, QueryPayload::Terminal {
            reason: QueryTerminalReason::Completed,
            last_checkpoint: Some(ref captured), ..
        } if captured == &checkpoint));
        drop(frame);
        assert!(tokio::time::timeout(WAIT, stream.next()).await?.is_none());
        assert!(stream.is_terminated());
        assert!(stream.next().await.is_none());
        tokio::time::timeout(WAIT, &mut stream.task).await??;
    }
    Ok(())
}

#[tokio::test]
async fn query_stream_empty() -> TestResult {
    let mut fixture = ClientFixture::local()?;
    fixture.tenant();
    let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?;
    let mut stream = fixture.stream(plan, None)?;
    let frame = ClientFixture::next(&mut stream).await?;
    assert!(matches!(frame.payload, QueryPayload::Metadata(_)));
    drop(frame);
    let frame = ClientFixture::next(&mut stream).await?;
    assert_eq!(
        ClientFixture::result(&frame, QueryOperation::Replace)?.rows,
        vec![vec![Value::BigInt(0)]]
    );
    drop(frame);
    assert!(matches!(
        ClientFixture::next(&mut stream).await?.payload,
        QueryPayload::Checkpoint { .. }
    ));
    assert!(matches!(
        ClientFixture::next(&mut stream).await?.payload,
        QueryPayload::Terminal {
            reason: QueryTerminalReason::Completed,
            ..
        }
    ));
    assert!(tokio::time::timeout(WAIT, stream.next()).await?.is_none());
    tokio::time::timeout(WAIT, &mut stream.task).await??;
    Ok(())
}

#[tokio::test]
async fn query_tenant_retained_boots() -> TestResult {
    let mut fixture = ClientFixture::local()?;
    fixture.tenant();
    fixture.commit(1, 10, 7, 4)?;
    let mut current = fixture.data.source.clone();
    current.node_boot_id = [4; 16];
    current.source_id = [5; 16];
    fixture.data.commit_as(
        &current,
        0,
        1,
        20,
        EvidenceRecord {
            operation: 8,
            policy_rule_id: 42,
            ..Default::default()
        },
    )?;
    let mut other = current.clone();
    other.node_id = "other-node".into();
    other.source_id = [6; 16];
    fixture.data.commit_as(
        &other,
        0,
        1,
        30,
        EvidenceRecord {
            operation: 9,
            policy_rule_id: 42,
            ..Default::default()
        },
    )?;
    let mut foreign = other.clone();
    foreign.tenant_id = [9; 16];
    foreign.source_id = [7; 16];
    fixture.data.commit_as(
        &foreign,
        0,
        1,
        40,
        EvidenceRecord {
            operation: 10,
            policy_rule_id: 42,
            ..Default::default()
        },
    )?;
    let plan = fixture.plan(
        "SELECT operation FROM events WHERE policy_rule_id = 42 ORDER BY operation",
        vec![],
        false,
    )?;
    let result = fixture.query(&plan).await?;
    assert_eq!(
        result.rows,
        vec![
            vec![Value::UInt(7)],
            vec![Value::UInt(8)],
            vec![Value::UInt(9)]
        ]
    );
    assert_eq!(result.sources.len(), 3);
    assert!(result
        .sources
        .iter()
        .any(|source| source.receipt.identity == fixture.data.source));
    assert!(result
        .sources
        .iter()
        .any(|source| source.receipt.identity == current));
    drop(result);
    fixture.grant.selection.nodes.push(current.node_id.clone());
    let result = fixture
        .query(&fixture.plan(
            "SELECT operation FROM events WHERE received_utc_ns >= 20 ORDER BY operation",
            vec![],
            false,
        )?)
        .await?;
    assert_eq!(result.rows, vec![vec![Value::UInt(8)]]);
    assert_eq!(result.sources.len(), 2);
    drop(result);
    fixture.grant.selection = AnalysisSelectionV1::new(current.tenant_id, vec![]);
    assert_eq!(
        fixture
            .query(&fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?)
            .await?
            .rows,
        vec![vec![Value::BigInt(0)]]
    );
    Ok(())
}

#[test]
fn query_tenant_relation_scope() -> TestResult {
    let mut fixture = ClientFixture::local()?;
    fixture.tenant();
    fixture
        .grant
        .selection
        .nodes
        .push(fixture.data.source.node_id.clone());
    for (sql, sources, contexts, nodes) in [
        ("SELECT COUNT(*) FROM events", true, false, true),
        ("SELECT COUNT(*) FROM coverage", true, false, true),
        ("SELECT COUNT(*) FROM context_versions", false, true, false),
        ("SELECT COUNT(*) FROM catalog", false, false, false),
    ] {
        let plan = fixture.plan(sql, vec![], false)?;
        let selection = plan.dependencies(100)?;
        assert_eq!(selection.all_sources, sources, "{sql}");
        assert_eq!(selection.all_contexts, contexts, "{sql}");
        assert_eq!(!selection.nodes.is_empty(), nodes, "{sql}");
    }
    Ok(())
}

#[tokio::test]
async fn query_tenant_new_sources() -> TestResult {
    let mut fixture = ClientFixture::local()?;
    fixture.tenant();
    let plan = fixture.plan("SELECT operation FROM events", vec![], true)?;
    let mut stream = fixture.stream(plan.clone(), None)?;
    let frame = ClientFixture::next(&mut stream).await?;
    assert!(matches!(frame.payload, QueryPayload::Metadata(_)));
    drop(frame);
    let frame = ClientFixture::next(&mut stream).await?;
    assert!(ClientFixture::result(&frame, QueryOperation::Append)?
        .rows
        .is_empty());
    drop(frame);
    let _empty = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
    fixture.commit(1, 10, 7, 4)?;
    let frame = ClientFixture::next(&mut stream).await?;
    let result = ClientFixture::result(&frame, QueryOperation::Append)?;
    assert_eq!(result.rows, vec![vec![Value::UInt(7)]]);
    assert_eq!(result.sources[0].receipt.identity, fixture.data.source);
    drop(frame);
    let first = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
    let mut next = fixture.data.source.clone();
    next.node_boot_id = [4; 16];
    next.source_id = [5; 16];
    fixture.data.commit_as(
        &next,
        0,
        1,
        20,
        EvidenceRecord {
            operation: 8,
            ..Default::default()
        },
    )?;
    let frame = ClientFixture::next(&mut stream).await?;
    let result = ClientFixture::result(&frame, QueryOperation::Append)?;
    assert_eq!(result.rows, vec![vec![Value::UInt(8)]]);
    assert_eq!(result.positions.len(), 1);
    assert!(result.positions[0] > first.position().ok_or("first position is absent")?);
    assert_eq!(result.sources.len(), 2);
    drop(frame);
    let second = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
    ClientFixture::cancel(&mut stream).await?;
    let mut stream = fixture.stream(plan, Some(second))?;
    let frame = ClientFixture::next(&mut stream).await?;
    assert!(matches!(frame.payload, QueryPayload::Metadata(_)));
    drop(frame);
    let frame = ClientFixture::next(&mut stream).await?;
    assert!(ClientFixture::result(&frame, QueryOperation::Append)?
        .rows
        .is_empty());
    drop(frame);
    let _checkpoint = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
    ClientFixture::cancel(&mut stream).await?;
    Ok(())
}

#[tokio::test]
async fn query_tenant_new_contexts() -> TestResult {
    let mut fixture = ClientFixture::local()?;
    fixture.tenant();
    let plan = fixture.plan("SELECT COUNT(*) FROM context_versions", vec![], true)?;
    let mut stream = fixture.stream(plan, None)?;
    let frame = ClientFixture::next(&mut stream).await?;
    assert!(matches!(frame.payload, QueryPayload::Metadata(_)));
    drop(frame);
    let frame = ClientFixture::next(&mut stream).await?;
    assert_eq!(
        ClientFixture::result(&frame, QueryOperation::Replace)?.rows,
        vec![vec![Value::BigInt(0)]]
    );
    drop(frame);
    let _empty = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
    let context = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: fixture.data.source.tenant_id,
            owner_id: "policy".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: b"context".to_vec(),
    };
    let mut foreign = context.clone();
    foreign.key.tenant_id = [9; 16];
    fixture.data.store.commit_context(&foreign)?;
    fixture.data.store.commit_context(&context)?;
    let frame = ClientFixture::next(&mut stream).await?;
    assert_eq!(
        ClientFixture::result(&frame, QueryOperation::Replace)?.rows,
        vec![vec![Value::BigInt(1)]]
    );
    drop(frame);
    let _checkpoint = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
    stream.cancel()?;
    let frame = ClientFixture::next(&mut stream).await?;
    assert!(matches!(
        frame.payload,
        QueryPayload::Terminal {
            reason: QueryTerminalReason::Cancelled,
            ..
        }
    ));
    drop(frame);
    assert!(tokio::time::timeout(WAIT, stream.next()).await?.is_none());
    tokio::time::timeout(WAIT, &mut stream.task).await??;
    Ok(())
}

#[tokio::test]
async fn query_stream_cursor_floor() -> TestResult {
    let mut fixture = ClientFixture::local()?;
    fixture.tenant();
    fixture.commit(1, 1, 7, 4)?;
    fixture
        .data
        .store
        .backup(&fixture.data.root().join("backups/first"))?;
    let plan = fixture.plan("SELECT operation FROM events", vec![], true)?;
    let mut stream = fixture.stream(plan.clone(), None)?;
    drop(ClientFixture::next(&mut stream).await?);
    drop(ClientFixture::next(&mut stream).await?);
    let checkpoint = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
    ClientFixture::cancel(&mut stream).await?;
    fixture.commit(2, 2, 8, 4)?;
    let retention = EvidenceRetentionOwner::new(&fixture.data.store);
    let expires = 3 * 24 * 60 * 60 * 1_000_000_000_u64;
    assert_eq!(
        retention
            .retain(&fixture.data.source, expires)?
            .removed_records,
        1
    );
    assert_eq!(
        retention
            .retain(&fixture.data.source, expires)?
            .removed_records,
        1
    );
    let floor = fixture
        .data
        .store
        .replay_floor(fixture.data.source.tenant_id)?
        .ok_or("replay floor is absent")?;
    let position = checkpoint
        .position()
        .ok_or("checkpoint position is absent")?;
    assert!(position < floor);
    let mut stream = fixture.stream(plan, Some(checkpoint.clone()))?;
    let frame = ClientFixture::next(&mut stream).await?;
    assert!(matches!(frame.payload, QueryPayload::Error {
        code: QueryErrorCode::CursorExpired, position: Some(captured), floor: Some(retained),
        last_checkpoint: Some(ref last), ..
    } if captured == position && retained == floor && last == &checkpoint));
    drop(frame);
    assert!(tokio::time::timeout(WAIT, stream.next()).await?.is_none());
    assert!(stream.is_terminated());
    tokio::time::timeout(WAIT, &mut stream.task).await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_client_timer_replace() -> TestResult {
    let fixture = ClientFixture::new(200, 3_000_000_000)?;
    fixture.commit(1, 2_000_000_000, 7, 4)?;
    let meta = fixture.data.store.meta()?;
    let plan = fixture.plan(
        "SELECT COUNT(*) FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '1 seconds'",
        vec![],
        true,
    )?;
    let (entering, release) = fixture.clock.arm()?;
    assert!(fixture.clock.changes().is_none());
    assert!(WAIT < QueryLimits::default().heartbeat);
    let mut stream = fixture.follow(plan, None)?;
    let proof: TestResult<_> = match tokio::time::timeout(WAIT, async {
        let metadata = ClientFixture::next(&mut stream).await?;
        assert!(matches!(metadata.payload, QueryPayload::Metadata(_)));
        let initial = ClientFixture::next(&mut stream).await?;
        let first = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
        entering.await?;
        // Keep the idle loop's old sample. Only its expiry timer can wake it.
        fixture.clock.now.store(4_000_000_000, Ordering::SeqCst);
        release.send(())?;
        let expired = ClientFixture::next(&mut stream).await?;
        let complete = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
        Ok((initial, first, expired, complete))
    })
    .await
    {
        Ok(proof) => proof,
        Err(error) => Err(error.into()),
    };
    let _released = release.send(());
    let cleanup = ClientFixture::cancel(&mut stream).await;
    let (initial, first, expired, complete) = proof?;
    cleanup?;
    for (frame, count, now, expiry) in [
        (&initial, 1, 3_000_000_000, Some(4_000_000_000)),
        (&expired, 0, 4_000_000_000, None),
    ] {
        let result = ClientFixture::result(frame, QueryOperation::Replace)?;
        assert_eq!(result.rows, vec![vec![Value::BigInt(count)]]);
        assert_eq!(result.evaluated_utc_ns, now);
        assert_eq!(result.next_expiry_ns, expiry);
        assert_eq!(result.meta, meta);
        assert!(!frame.clock_changed);
    }
    assert_eq!(first, complete);
    assert_eq!(fixture.data.store.meta()?, meta);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_client_quiet_revoke() -> TestResult {
    let fixture = ClientFixture::new(200, 100)?;
    fixture.commit(1, 1, 7, 4)?;
    let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], true)?;
    let mut stream = fixture.follow(plan.clone(), None)?;
    assert!(matches!(
        ClientFixture::next(&mut stream).await?.payload,
        QueryPayload::Metadata(_)
    ));
    let frame = ClientFixture::next(&mut stream).await?;
    assert_eq!(
        ClientFixture::result(&frame, QueryOperation::Replace)?.rows,
        vec![vec![Value::BigInt(1)]]
    );
    drop(frame);
    let _checkpoint = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
    fixture.authority.revoke();
    assert!(WAIT < QueryLimits::default().heartbeat);
    tokio::time::timeout(WAIT, &mut stream.task).await??;
    assert!(matches!(
        stream.next().await,
        Some(Err(crate::Error::QueryDenied { .. }))
    ));
    assert!(stream.is_terminated());
    assert!(stream.next().await.is_none());
    assert!(matches!(
        fixture.query(&plan).await,
        Err(crate::Error::QueryDenied { .. })
    ));
    drop(stream);
    fixture.commit(2, 2, 8, 4)?;
    fixture.current_query().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_client_buffered_revoke() -> TestResult {
    let fixture = ClientFixture::new(200, 100)?;
    fixture.commit(1, 1, 7, 4)?;
    let plan = fixture.plan("SELECT operation FROM events", vec![], true)?;
    let mut stream = fixture.follow(plan, None)?;
    assert!(matches!(
        ClientFixture::next(&mut stream).await?.payload,
        QueryPayload::Metadata(_)
    ));
    tokio::time::timeout(WAIT, async {
        while stream.queued() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(stream.queued(), 1);
    fixture.authority.revoke();
    assert!(matches!(
        stream.next().await,
        Some(Err(crate::Error::QueryDenied { .. }))
    ));
    assert!(stream.is_terminated());
    assert!(stream.next().await.is_none());
    drop(stream);
    tokio::time::timeout(WAIT, async {
        while Arc::strong_count(&fixture.owner) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    fixture.commit(2, 2, 8, 4)?;
    fixture.current_query().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_client_output_limit() -> TestResult {
    let fixture = ClientFixture::new(2, 100)?;
    fixture.commit(1, 1, 7, 4)?;
    fixture.commit(2, 2, 8, 4)?;
    let sql = "SELECT operation, COUNT(*) FROM events GROUP BY operation ORDER BY operation";
    let plan = fixture.plan(sql, vec![], false)?;
    let result = fixture.query(&plan).await?;
    assert_eq!(
        result.rows,
        vec![
            vec![Value::UInt(7), Value::BigInt(1)],
            vec![Value::UInt(8), Value::BigInt(1)]
        ]
    );
    assert!(!result.limited);
    drop(result);
    let mut stream = fixture.follow(fixture.plan(sql, vec![], true)?, None)?;
    assert!(matches!(
        ClientFixture::next(&mut stream).await?.payload,
        QueryPayload::Metadata(_)
    ));
    let frame = ClientFixture::next(&mut stream).await?;
    let result = ClientFixture::result(&frame, QueryOperation::Replace)?;
    assert_eq!(result.rows.len(), 2);
    assert!(!result.limited);
    drop(frame);
    let complete = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
    fixture.commit(3, 3, 9, 4)?;
    let frame = ClientFixture::next(&mut stream).await?;
    let QueryPayload::Error {
        code,
        last_checkpoint,
        ..
    } = &frame.payload
    else {
        return Err(format!(
            "expected complete-output failure, received {:?}",
            frame.payload
        )
        .into());
    };
    assert_eq!(*code, QueryErrorCode::ResultTooLarge);
    assert_eq!(last_checkpoint.as_ref(), Some(&complete));
    drop(frame);
    assert!(tokio::time::timeout(WAIT, stream.next())
        .await?
        .transpose()?
        .is_none());
    tokio::time::timeout(WAIT, &mut stream.task).await??;
    let result = fixture.query(&plan).await?;
    assert_eq!(result.rows.len(), 2);
    assert!(result.limited);
    drop(result);
    let count = fixture
        .query(&fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?)
        .await?;
    assert_eq!(count.rows, vec![vec![Value::BigInt(3)]]);
    assert!(!count.limited);
    Ok(())
}
