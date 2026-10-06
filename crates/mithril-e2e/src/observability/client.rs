use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use araphor_data::{AnalysisStore, EvidenceRetentionOwner};
use ed25519_dalek::SigningKey;
use erebor_interceptor_abi::{
    BindingLifecycleStateV1, EffectObservationV1, ExecutionSetBindingStateV1,
};
use erebor_runtime_client::{AraphorClient, AraphorProfile};
use erebor_runtime_ipc::araphor::{self as proto, query_frame, query_value};
use mithril_control::{
    ClientAuth, ClientGrpcConfig, ClientGrpcOwner, ClientListener, ClientListenerConfig,
    DiscoveryDigestV1, InvestigateGrant, TraceAcceptedV1, TraceExchangeV1, TraceParticipantStateV1,
    TraceParticipantV1, TraceResolvedV1, TraceTargetV1, TraceUploadV1,
};
use mithril_node::{
    ControlConnection, EvidenceIdV1, EvidenceWal, EvidenceWalLimits, NodeControlMessage,
    NodeTraceOwner, ObservationCanonicalizer, TemporalCoverageV1, TraceTargetLeaseV1, TrustCache,
};
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot};

use super::{ObservabilityQualification, ProofResult};
use crate::control_fixture::oidc::OidcFixture;
use crate::control_fixture::{
    free_address, ControlServerFixture, MtlsFixture, OutagePolicyFixture,
};

const SQL: &str = "SELECT count(*) AS count FROM trace_output";
const WINDOW: &str = "SELECT count(*) AS count FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '5 seconds'";
const BROWSER_WINDOW: &str = "SELECT count(*) AS count FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '10 seconds'";
const WAIT: Duration = Duration::from_secs(10);

enum CaptureCommand {
    Seed([u8; 16], oneshot::Sender<Result<(), String>>),
    Stop,
}

struct ClientFixture {
    tls: MtlsFixture,
    provider: OidcFixture,
    server: Option<ControlServerFixture>,
    node_server: ControlServerFixture,
    listener: ClientListenerConfig,
    grpc: ClientGrpcOwner,
    store: Arc<AnalysisStore>,
    auth: Arc<ClientAuth>,
    client: AraphorClient,
    profile: PathBuf,
    source: PathBuf,
    root: PathBuf,
    target: proto::InputSelection,
    accepted: Arc<Mutex<Vec<TraceAcceptedV1>>>,
    acknowledged: Arc<Mutex<BTreeMap<[u8; 16], u64>>>,
    commands: mpsc::Sender<CaptureCommand>,
    driver: tokio::task::JoinHandle<Result<(), String>>,
}

struct CaptureFixture {
    node: NodeTraceOwner,
    connection: ControlConnection,
    trust: TrustCache,
    target: TraceTargetV1,
    path: PathBuf,
    accepted: Arc<Mutex<Vec<TraceAcceptedV1>>>,
    acknowledged: Arc<Mutex<BTreeMap<[u8; 16], u64>>>,
}

struct CliProcess {
    child: Child,
    stdout: BufReader<ChildStdout>,
    pidfd: OwnedFd,
    log: File,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCommand {
    command: String,
    trace_id: Option<String>,
}

impl ObservabilityQualification {
    pub fn query_trace_client(
        &self,
        executable: Option<PathBuf>,
        assets: Option<PathBuf>,
        browser: bool,
    ) -> ProofResult<()> {
        if browser {
            if executable.is_some()
                || assets
                    .as_ref()
                    .is_none_or(|path| !path.is_absolute() || !path.join("index.html").is_file())
            {
                return Err("browser fixture requires built assets, not a CLI executable".into());
            }
        } else if assets.is_some()
            || executable
                .as_ref()
                .is_none_or(|path| !path.is_absolute() || !path.is_file())
        {
            return Err("client qualification requires the built CLI executable".into());
        }
        if self.output.exists() {
            if fs::read_dir(&self.output)?.next().is_some() {
                return Err("client fixture output must be empty".into());
            }
        } else {
            fs::create_dir(&self.output)?;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let mut fixture = ClientFixture::start(&self.output, assets, browser).await?;
            let result = tokio::time::timeout(Duration::from_secs(180), async {
                if browser {
                    fixture.browser().await
                } else {
                    fixture
                        .native(executable.as_deref().ok_or("CLI executable is absent")?)
                        .await
                }
            })
            .await;
            let stopped = fixture.shutdown().await;
            let result: ProofResult<Value> = result.map_err(Into::into).and_then(|value| value);
            match (result, stopped) {
                (Ok(record), Ok(())) => self.write("result.json", &record),
                (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
                (Err(error), Err(stopped)) => {
                    Err(format!("{error}; fixture shutdown failed: {stopped}").into())
                }
            }
        })
    }
}

impl ClientFixture {
    async fn start(root: &Path, assets: Option<PathBuf>, browser: bool) -> ProofResult<Self> {
        let root = fs::canonicalize(root)?;
        let tls = MtlsFixture::in_directory(tempfile::tempdir_in(&root)?, false)?;
        let key = SigningKey::from_bytes(&[23; 32]);
        let control = ObservabilityQualification::trace_control(&tls, &key)?;
        let store = control
            .analysis_store()
            .ok_or("client fixture data is absent")?;
        let inventory =
            OutagePolicyFixture::new(mithril_control::ControlStore::open(root.join("inventory"))?);
        let fact = inventory
            .inventory(&inventory.resource(1)?)?
            .into_iter()
            .next()
            .ok_or("client fixture target is absent")?;
        drop(inventory);
        let (mut request, _) = ObservabilityQualification::trace_inputs(fact, Self::now()?)?;
        request.targets[0].binding_id = *uuid::Uuid::parse_str(
            &request.targets[0]
                .fact
                .kubernetes
                .as_ref()
                .ok_or("client fixture binding is absent")?
                .binding_id,
        )?
        .as_bytes();
        let path = root.join("target");
        fs::create_dir(&path)?;
        request.targets[0].cgroup_id = fs::metadata(&path)?.ino();
        let target = request.targets.remove(0);
        control.replace_kubernetes_workload_inventory(vec![target.fact.clone()])?;
        let node_server = tls.start(control.clone()).await?;
        let mut trust = TrustCache::load(&root.join("node-trust"))?;
        let mut registration = OutagePolicyFixture::registration([7; 16], false);
        registration.effect_prevention_claims_enabled = false;
        let connector = tls.connector(&node_server, "node-a", [7; 16]);
        let mut connection = connector.connect(registration, true, &mut trust).await?;
        connection.report_readiness(true, true).await?;
        if !browser {
            Self::seed(&mut connection, &root, request.tenant_id).await?;
        }
        let commit = root.join("commit");
        let finish = root.join("finish");
        fs::write(&commit, b"0")?;
        fs::write(&finish, b"0")?;
        let backend = move || {
            let mut command = std::process::Command::new("/bin/sh");
            command
                .args([
                    "-c",
                    concat!(
                "cat >/dev/null; ",
                "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; ",
                "printf '%s\\n' '{\"type\":\"map\",\"data\":{\"@errors\":{\"EACCES\":1}}}'; ",
                "seen=$(cat \"$1\"); end=$(cat \"$2\"); ",
                "while [ \"$(cat \"$2\")\" = \"$end\" ]; do ",
                "next=$(cat \"$1\"); if [ \"$next\" != \"$seen\" ]; then ",
                "printf 'observed <script>text</script>\\033[31m\\n'; seen=$next; fi; ",
                "sleep 0.01; done"
            ),
                    "client-backend",
                ])
                .arg(&commit)
                .arg(&finish);
            command
        };
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let acknowledged = Arc::new(Mutex::new(BTreeMap::new()));
        fs::create_dir(root.join("node"))?;
        let capture = CaptureFixture {
            node: NodeTraceOwner::open_fixture(
                &root.join("node"),
                request.tenant_id,
                "node-a".into(),
                [7; 16],
                backend,
            )?,
            connection,
            trust,
            target: target.clone(),
            path,
            accepted: Arc::clone(&accepted),
            acknowledged: Arc::clone(&acknowledged),
        };
        let (sender, commands) = mpsc::channel(1);
        let driver = tokio::spawn(async move {
            capture
                .run(commands)
                .await
                .map_err(|error| error.to_string())
        });
        let provider = OidcFixture::start(&tls.files, "client-qualification").await?;
        let address = free_address()?;
        let endpoint = format!("https://localhost:{}", address.port());
        provider.allow_redirect(&format!("{endpoint}/oidc/session"))?;
        let config = ClientListenerConfig {
            listen: address,
            tls_certificate_path: tls.files.server_certificate.clone(),
            tls_private_key_path: tls.files.server_key.clone(),
            auth: provider.auth(&endpoint, Some(request.tenant_id), tls.files.ca.clone()),
            administrative: None,
            investigation: Some(ClientGrpcConfig::default()),
            assets,
        };
        let auth = Arc::new(ClientAuth::load(&config.auth).await?);
        let grpc = ClientGrpcOwner::new(control, Arc::clone(&auth), ClientGrpcConfig::default())?;
        let listener =
            ClientListener::new(config.clone(), Arc::clone(&auth), None, Some(grpc.clone()))?;
        let server = ControlServerFixture::client(listener, address).await?;
        let credential = root.join("credential");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&credential)?
            .write_all(b"fixture-access")?;
        let profile = root.join("client.json");
        let tenant = uuid::Uuid::from_bytes(request.tenant_id).to_string();
        fs::write(
            &profile,
            serde_json::to_vec(&json!({
                "endpoint": endpoint, "tenant_id": tenant,
                "credential_file": credential, "ca_file": tls.files.ca,
            }))?,
        )?;
        let client = AraphorClient::connect(AraphorProfile::read(&profile)?).await?;
        let source = root.join("source.bt");
        fs::write(&source, &request.source.bytes)?;
        let selection = proto::InputSelection {
            target: format!("pod-uid/{}", target.fact.pod_uid),
            cluster: target.fact.cluster_uid.clone(),
            container: target.fact.container_name.clone(),
            node_ids: Vec::new(),
        };
        let fixture = Self {
            tls,
            provider,
            server: Some(server),
            node_server,
            listener: config,
            grpc,
            store,
            auth,
            client,
            profile,
            source,
            root,
            target: selection,
            accepted,
            acknowledged,
            commands: sender,
            driver,
        };
        let rows = fixture.query_rows().await?;
        if browser {
            fixture.auth.replace_grants(Vec::new())?;
        }
        fs::write(
            fixture.root.join("ready.json"),
            serde_json::to_vec(&json!({
                "schema_version": 1, "endpoint": endpoint, "tenant_id": tenant,
                "target": fixture.target, "ca_file": fixture.tls.files.ca,
                "certificate_file": fixture.tls.files.server_certificate,
                "profile_file": fixture.profile, "source_file": fixture.source,
            "sql": SQL, "expected_columns": ["count"], "expected_rows": Self::expected(&rows),
                "oidc_issuer": fixture.provider.issuer,
                "callback": format!("{endpoint}/oidc/session"),
                "physical": false, "cleanup": "Unknown",
            }))?,
        )?;
        Ok(fixture)
    }

    async fn seed(
        connection: &mut ControlConnection,
        root: &Path,
        tenant: [u8; 16],
    ) -> ProofResult<()> {
        let canonical = ObservationCanonicalizer::new(
            tenant.into(),
            EvidenceIdV1::new(3, 4),
            1,
            [7; 16].into(),
        )?;
        let observation = canonical.normalize_kernel(
            EffectObservationV1 {
                observed_boottime_ns: 1,
                source_sequence: 1,
                task_cookie: 1,
                reason: 9,
                physical_result: 1,
                effect_family: 1,
                operation: 1,
                ..Default::default()
            },
            EvidenceIdV1::new(5, 6),
            TemporalCoverageV1::Unknown,
            i64::try_from(Self::now()?)?,
        )?;
        let mut wal = EvidenceWal::open(
            root.join("event-wal"),
            EvidenceWalLimits {
                maximum_retained_records: 1,
                maximum_batch_records: 1,
                ..EvidenceWalLimits::default()
            },
        )?;
        let cursor = wal.append(&observation)?;
        connection
            .send_evidence_batch(wal.next_batch().ok_or("event batch is absent")?)
            .await?;
        match tokio::time::timeout(WAIT, connection.next_message()).await?? {
            NodeControlMessage::EvidenceAck(ack) if ack.contiguous_cursor == cursor => {
                wal.acknowledge(ack)?;
            }
            _ => return Err("event has no exact durable ACK".into()),
        }
        if wal.acknowledged_cursor() != cursor {
            return Err("event WAL did not retain the exact ACK".into());
        }
        Ok(())
    }

    fn now() -> ProofResult<u64> {
        Ok(u64::try_from(
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        )?)
    }

    fn expected(rows: &[Vec<u64>]) -> Vec<Vec<String>> {
        rows.iter()
            .map(|row| row.iter().map(u64::to_string).collect())
            .collect()
    }

    async fn query_rows(&self) -> ProofResult<Vec<Vec<u64>>> {
        self.query_count(None).await
    }

    async fn query_count(
        &self,
        selection: Option<proto::InputSelection>,
    ) -> ProofResult<Vec<Vec<u64>>> {
        tokio::time::timeout(WAIT, async {
            loop {
                if let Some(rows) = self.query_sample(selection.clone()).await? {
                    return Ok(rows);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?
    }

    async fn query_sample(
        &self,
        selection: Option<proto::InputSelection>,
    ) -> ProofResult<Option<Vec<Vec<u64>>>> {
        let mut stream = self
            .client
            .query(proto::QueryRequest {
                sql: SQL.into(),
                selection,
                ..Default::default()
            })
            .await
            .map_err(|error| {
                let detail: String = format!("{error:?}").chars().take(4096).collect();
                std::io::Error::other(detail)
            })?;
        let mut rows = Vec::new();
        let mut complete = false;
        while let Some(frame) = tokio::time::timeout(WAIT, stream.message()).await?? {
            match frame.payload {
                Some(query_frame::Payload::Rows(data)) => {
                    if data.limited || data.rows.len() != 1 || data.rows[0].values.len() != 1 {
                        return Err("native aggregate changed its bounded shape".into());
                    }
                    let count = match data.rows[0].values[0].kind {
                        Some(query_value::Kind::Signed(value)) => u64::try_from(value)?,
                        Some(query_value::Kind::Unsigned(value)) => value,
                        _ => return Err("native aggregate is not an integer".into()),
                    };
                    rows.push(vec![count]);
                }
                Some(query_frame::Payload::Terminal(done)) if done.reason == "Completed" => {
                    complete = true
                }
                Some(query_frame::Payload::Error(error))
                    if error.code == "Busy" && rows.is_empty() && !complete =>
                {
                    return Ok(None);
                }
                Some(query_frame::Payload::Error(error)) => {
                    let detail: String = format!("{error:?}").chars().take(4096).collect();
                    return Err(format!("native aggregate failed: {detail}").into());
                }
                _ => {}
            }
        }
        if !complete || rows.len() != 1 {
            return Err("native aggregate has no complete result".into());
        }
        Ok(Some(rows))
    }

    fn advance(&self, name: &str) -> ProofResult<()> {
        let path = self.root.join(name);
        let value: u64 = fs::read_to_string(&path)?.parse()?;
        let pending = path.with_extension("pending");
        fs::write(
            &pending,
            value
                .checked_add(1)
                .ok_or("fixture counter overflows")?
                .to_string(),
        )?;
        fs::rename(pending, path)?;
        Ok(())
    }

    async fn commit(&self) -> ProofResult<Value> {
        let sequences = tokio::time::timeout(WAIT, async {
            loop {
                let records = self
                    .accepted
                    .lock()
                    .map_err(|_| "capture fixture lock failed")?
                    .clone();
                let sequences = {
                    let acknowledged = self
                        .acknowledged
                        .lock()
                        .map_err(|_| "capture ACK lock failed")?;
                    let mut sequences = BTreeMap::new();
                    for record in records {
                        let id = record.execution_id(0)?;
                        if !self
                            .root
                            .join("node")
                            .join("diagnostics")
                            .join(hex::encode(id))
                            .join("ack.json")
                            .is_file()
                        {
                            sequences.insert(id, *acknowledged.get(&id).unwrap_or(&0));
                        }
                    }
                    sequences
                };
                if !sequences.is_empty() && sequences.values().all(|sequence| *sequence >= 2) {
                    return Ok::<_, Box<dyn std::error::Error>>(sequences);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        let before = self.query_rows().await?;
        self.advance("commit")?;
        let rows = tokio::time::timeout(WAIT, async {
            loop {
                let rows = self.query_rows().await?;
                let complete = {
                    let acknowledged = self
                        .acknowledged
                        .lock()
                        .map_err(|_| "capture ACK lock failed")?;
                    sequences.iter().all(|(id, sequence)| {
                        acknowledged.get(id).is_some_and(|next| next > sequence)
                    })
                };
                if complete && rows[0][0] > before[0][0] {
                    return Ok::<_, Box<dyn std::error::Error>>(rows);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        Ok(
            json!({"expected_columns": ["count"], "expected_rows": Self::expected(&rows),
            "durable_ack": true}),
        )
    }

    async fn finish(&self) -> ProofResult<()> {
        self.advance("finish")?;
        tokio::time::timeout(WAIT, async {
            loop {
                let records = self
                    .accepted
                    .lock()
                    .map_err(|_| "capture fixture lock failed")?
                    .clone();
                if records.is_empty() {
                    return Err::<(), Box<dyn std::error::Error>>("no trace is active".into());
                }
                let mut complete = true;
                for accepted in records {
                    self.client
                        .get_trace(proto::GetTraceRequest {
                            trace_id: accepted.request.request_id.to_vec(),
                        })
                        .await?;
                    let id = accepted.execution_id(0)?;
                    complete &= self
                        .root
                        .join("node")
                        .join("diagnostics")
                        .join(hex::encode(id))
                        .join("ack.json")
                        .is_file();
                }
                if complete {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?
    }

    async fn state(&self, trace: &str) -> ProofResult<Value> {
        let id = uuid::Uuid::parse_str(trace)?;
        let detail = self
            .client
            .get_trace(proto::GetTraceRequest {
                trace_id: id.as_bytes().to_vec(),
            })
            .await?;
        let receipt = detail.receipt.as_ref().ok_or("trace has no receipt")?;
        let complete = {
            let records = self
                .accepted
                .lock()
                .map_err(|_| "capture fixture lock failed")?;
            records
                .iter()
                .find(|record| record.request.request_id == *id.as_bytes())
                .map(|record| record.execution_id(0))
                .transpose()?
                .is_some_and(|execution| {
                    self.root
                        .join("node")
                        .join("diagnostics")
                        .join(hex::encode(execution))
                        .join("ack.json")
                        .is_file()
                })
        };
        let mut terminal = Vec::new();
        let mut result = None;
        if complete {
            let mut stream = self
                .client
                .watch_trace(proto::WatchTraceRequest {
                    trace_id: id.as_bytes().to_vec(),
                    bookmark: Vec::new(),
                })
                .await?;
            for _ in 0..128 {
                let frame = tokio::time::timeout(WAIT, stream.message())
                    .await??
                    .ok_or("completed trace has no final result")?;
                match frame.payload {
                    Some(proto::trace_frame::Payload::Terminal(value)) => terminal.push(value),
                    Some(proto::trace_frame::Payload::Result(value)) => {
                        result = Some(value);
                        break;
                    }
                    _ => {}
                }
            }
            if result.is_none() {
                return Err("completed trace exceeded its frame bound".into());
            }
        }
        Ok(
            json!({"trace_id": trace, "source": String::from_utf8(detail.source.clone())?,
            "source_sha256": hex::encode(&receipt.source_sha256),
            "cancel_requested": receipt.cancel_requested,
            "node_ids": detail.targets.iter().map(|target| target.node_id.clone()).collect::<Vec<_>>(),
            "detail": detail, "terminal": terminal, "result": result}),
        )
    }

    async fn browser(&mut self) -> ProofResult<Value> {
        let (sender, mut commands) = mpsc::channel(1);
        let reader = std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut input = stdin.lock();
            loop {
                let mut line = String::new();
                let read = std::io::Read::take(&mut input, 4097).read_line(&mut line);
                let result = read.map_err(|error| error.to_string()).and_then(|count| {
                    if count == 0 || count > 4096 || !line.ends_with('\n') {
                        return Err("fixture stdin ended or exceeded its bound".into());
                    }
                    serde_json::from_str::<FixtureCommand>(&line).map_err(|error| error.to_string())
                });
                let stop = !matches!(&result, Ok(value) if value.command != "shutdown");
                if sender.blocking_send(result).is_err() || stop {
                    break;
                }
            }
        });
        while let Some(command) = commands.recv().await {
            let command = command.map_err(std::io::Error::other)?;
            let mut reply = match command.command.as_str() {
                "grant" => {
                    let tenant = AraphorProfile::read(&self.profile)?.tenant_id;
                    self.auth.replace_grants(vec![InvestigateGrant {
                        subject: self.provider.subject.clone(),
                        tenant_id: tenant,
                    }])?;
                    json!({})
                }
                "revoke" => {
                    self.auth.replace_grants(Vec::new())?;
                    json!({})
                }
                "commit" => self.commit().await?,
                "window" => {
                    if self.root.join("event-wal").exists()
                        || !self
                            .accepted
                            .lock()
                            .map_err(|_| "capture fixture lock failed")?
                            .is_empty()
                    {
                        return Err("the browser window must be seeded once before capture".into());
                    }
                    let tenant =
                        *uuid::Uuid::parse_str(&AraphorProfile::read(&self.profile)?.tenant_id)?
                            .as_bytes();
                    let (sender, completed) = oneshot::channel();
                    self.commands
                        .send(CaptureCommand::Seed(tenant, sender))
                        .await?;
                    tokio::time::timeout(WAIT, completed)
                        .await??
                        .map_err(std::io::Error::other)?;
                    json!({"sql": BROWSER_WINDOW, "durable_ack": true})
                }
                "finish" => {
                    self.finish().await?;
                    json!({"durable_ack": true})
                }
                "reconnect" => {
                    self.restart().await?;
                    json!({"listener_restarted": true})
                }
                "trace-state" => {
                    self.state(command.trace_id.as_deref().ok_or("trace ID is required")?)
                        .await?
                }
                "shutdown" => json!({}),
                _ => return Err("unknown fixture command".into()),
            };
            reply["command"] = json!(command.command);
            reply["ok"] = json!(true);
            let mut stdout = std::io::stdout().lock();
            serde_json::to_writer(&mut stdout, &reply)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
            if command.command == "shutdown" {
                break;
            }
        }
        reader.join().map_err(|_| "fixture stdin reader failed")?;
        Ok(
            json!({"case": "query-trace-client", "browser_fixture": true,
            "physical": false, "performance_claim": false, "result": "PASS"}),
        )
    }

    async fn window(&self, executable: &Path) -> ProofResult<Value> {
        let mut window = CliProcess::spawn(
            executable,
            &self.profile,
            &self.root,
            "window",
            &["sql", WINDOW, "--follow", "--duration", "15s"],
        )?;
        let first = window.until("query_replace").await?;
        window.until("query_checkpoint").await?;
        let expired = window.until("query_replace").await?;
        let before = first["frame"]["payload"]["Rows"]["evaluated_utc_ns"]
            .as_u64()
            .ok_or("initial window time is absent")?;
        let after = expired["frame"]["payload"]["Rows"]["evaluated_utc_ns"]
            .as_u64()
            .ok_or("expired window time is absent")?;
        if CliProcess::count(&first)? != 1
            || CliProcess::count(&expired)? != 0
            || first["frame"]["operation"] != proto::QueryOperation::Replace as i32
            || expired["frame"]["operation"] != proto::QueryOperation::Replace as i32
            || first["frame"]["read_revision"] != expired["frame"]["read_revision"]
            || after <= before
        {
            return Err("CLI window did not replace expired input without a commit".into());
        }
        window.interrupt()?;
        if window.end().await? != Some(130) {
            return Err("CLI window interruption failed".into());
        }
        Ok(json!({"initial": first, "expired": expired, "durable_ack": true}))
    }

    async fn restart(&mut self) -> ProofResult<()> {
        let server = self.server.take().ok_or("client listener is absent")?;
        tokio::time::timeout(WAIT, server.shutdown()).await??;
        let listener = ClientListener::new(
            self.listener.clone(),
            Arc::clone(&self.auth),
            None,
            Some(self.grpc.clone()),
        )?;
        self.server = Some(ControlServerFixture::client(listener, self.listener.listen).await?);
        Ok(())
    }

    async fn completed(&self, executable: &Path) -> ProofResult<Value> {
        let source = self.source.to_str().ok_or("source path is not UTF-8")?;
        let mut trace = CliProcess::spawn(
            executable,
            &self.profile,
            &self.root,
            "completed",
            &[
                "trace",
                "--file",
                source,
                "--target",
                &self.target.target,
                "--cluster",
                &self.target.cluster,
                "--container",
                &self.target.container,
                "--duration",
                "30s",
            ],
        )?;
        let receipt = trace.until("trace_receipt").await?;
        trace.until("trace_output").await?;
        self.finish().await?;
        let terminal = trace.until("trace_terminal").await?;
        let result = trace.until("trace_result").await?;
        let exit = trace.end().await?;
        if terminal["frame"]["payload"]["Terminal"]["reason"] != "Completed"
            || terminal["frame"]["payload"]["Terminal"]["cleanup"] != "Unknown"
            || terminal["frame"]["payload"]["Terminal"]["output_incomplete"] != false
            || result["frame"]["payload"]["Result"]["complete"] != true
            || result["frame"]["payload"]["Result"]["cleanup_complete"] != false
            || result["frame"]["payload"]["Result"]["output_incomplete"] != false
            || result["frame"]["payload"]["Result"]["missing_targets"] != json!([])
            || exit != Some(4)
        {
            return Err("normal CLI completion concealed its partial fixture cleanup".into());
        }
        let trace_id: Vec<u8> = serde_json::from_value(receipt["frame"]["trace_id"].clone())?;
        if self
            .client
            .get_trace(proto::GetTraceRequest { trace_id })
            .await?
            .receipt
            .is_none_or(|receipt| receipt.cancel_requested)
        {
            return Err("normal CLI completion requested cancellation".into());
        }
        Ok(json!({"receipt": receipt, "terminal": terminal, "result": result, "exit": exit}))
    }

    async fn expire(&self, trace: &[u8], bookmark: Vec<u8>) -> ProofResult<Value> {
        let id: [u8; 16] = trace.try_into()?;
        let identity = self
            .accepted
            .lock()
            .map_err(|_| "capture fixture lock failed")?
            .iter()
            .find(|record| record.request.request_id == id)
            .ok_or("retained trace is absent")?
            .binding(0)?
            .identity;
        let future = Self::now()?
            .checked_add(2 * 24 * 60 * 60 * 1_000_000_000)
            .ok_or("retention time overflows")?;
        let store = Arc::clone(&self.store);
        let retained = tokio::task::spawn_blocking(move || {
            EvidenceRetentionOwner::new(&store).retain_trace(&identity, future)
        })
        .await??;
        if retained.removed_records == 0 {
            return Err("retention did not expire the delivered bookmark".into());
        }
        let mut stream = self
            .client
            .watch_trace(proto::WatchTraceRequest {
                trace_id: trace.to_vec(),
                bookmark,
            })
            .await?;
        let frame = tokio::time::timeout(WAIT, stream.message())
            .await??
            .ok_or("expired bookmark has no error frame")?;
        if !matches!(&frame.payload, Some(proto::trace_frame::Payload::Error(error))
            if error.code == "CursorExpired" && error.position.is_some()
                && error.floor.is_some() && !error.last_checkpoint.is_empty())
        {
            return Err("expired bookmark was silently reset".into());
        }
        let status = tokio::time::timeout(WAIT, stream.message())
            .await?
            .err()
            .ok_or("expired bookmark has no failure status")?;
        if status.code() != tonic::Code::OutOfRange {
            return Err("expired bookmark has the wrong failure status".into());
        }
        Ok(
            json!({"frame": frame, "status": "OUT_OF_RANGE", "removed_records": retained.removed_records}),
        )
    }

    async fn native(&mut self, executable: &Path) -> ProofResult<Value> {
        let window = self.window(executable).await?;
        let mut sql =
            CliProcess::spawn(executable, &self.profile, &self.root, "sql", &["sql", SQL])?;
        let rows = sql.until("query_replace").await?;
        if rows["frame"]["operation"] != proto::QueryOperation::Replace as i32
            || CliProcess::count(&rows)? != self.query_rows().await?[0][0]
        {
            return Err("CLI one-shot query did not declare replacement".into());
        }
        sql.until("query_terminal").await?;
        if sql.end().await? != Some(0) {
            return Err("CLI one-shot query failed".into());
        }

        let original = fs::read(&self.source)?;
        let source = self
            .source
            .to_str()
            .ok_or("source path is not UTF-8")?
            .to_owned();
        let mut trace = CliProcess::spawn(
            executable,
            &self.profile,
            &self.root,
            "trace",
            &[
                "trace",
                "--file",
                &source,
                "--target",
                &self.target.target,
                "--cluster",
                &self.target.cluster,
                "--container",
                &self.target.container,
                "--duration",
                "30s",
            ],
        )?;
        let printed = match trace.until("trace_receipt").await {
            Ok(printed) => printed,
            Err(error) => {
                let probe = self
                    .client
                    .submit_trace(proto::SubmitTraceRequest {
                        idempotency_key: uuid::Uuid::new_v4().as_bytes().to_vec(),
                        selection: Some(self.target.clone()),
                        source: Some(proto::submit_trace_request::Source::Script(
                            original.clone(),
                        )),
                        collection_seconds: 30,
                        finding_reference: String::new(),
                    })
                    .await;
                let detail: String = format!("{probe:?}").chars().take(4096).collect();
                fs::write(self.root.join("submit-diagnostic.stderr"), detail)?;
                return Err(error);
            }
        };
        let trace_id: Vec<u8> = serde_json::from_value(printed["frame"]["trace_id"].clone())?;
        if trace_id.len() != 16 {
            return Err("CLI receipt has an invalid trace identity".into());
        }
        fs::write(&self.source, b"source changed after submission")?;
        let detail = self
            .client
            .get_trace(proto::GetTraceRequest { trace_id })
            .await?;
        let receipt = detail
            .receipt
            .as_ref()
            .ok_or("native trace has no receipt")?
            .clone();
        if detail.source != original
            || serde_json::to_value(&receipt)? != printed["frame"]
            || detail.targets.len() != 1
        {
            return Err("local source edit changed the accepted trace".into());
        }
        let retry = self
            .client
            .submit_trace(proto::SubmitTraceRequest {
                idempotency_key: receipt.trace_id.clone(),
                selection: Some(self.target.clone()),
                source: Some(proto::submit_trace_request::Source::Script(
                    original.clone(),
                )),
                collection_seconds: 30,
                finding_reference: String::new(),
            })
            .await?;
        if retry != receipt {
            return Err("exact submit retry changed its receipt".into());
        }
        trace.until("trace_output").await?;
        let id = uuid::Uuid::from_slice(&receipt.trace_id)?.to_string();
        let mut viewer = CliProcess::spawn(
            executable,
            &self.profile,
            &self.root,
            "viewer",
            &["trace", "--resume", &id],
        )?;
        let checkpoint = viewer.until("trace_checkpoint").await?;
        let bookmark: Vec<u8> = serde_json::from_value(checkpoint["frame"]["bookmark"].clone())?;
        if bookmark.is_empty() || bookmark.len() > 2048 {
            return Err("viewer did not deliver a bounded bookmark".into());
        }
        viewer.interrupt()?;
        if viewer.end().await? != Some(130) {
            return Err("read-only viewer interruption failed".into());
        }
        let detail = self
            .client
            .get_trace(proto::GetTraceRequest {
                trace_id: receipt.trace_id.clone(),
            })
            .await?;
        if detail
            .receipt
            .as_ref()
            .is_none_or(|value| value.cancel_requested)
        {
            return Err("read-only viewer cancelled the trace".into());
        }
        let mut follow = CliProcess::spawn(
            executable,
            &self.profile,
            &self.root,
            "follow",
            &["sql", SQL, "--follow", "--duration", "30s"],
        )?;
        let initial = follow.until("query_replace").await?;
        follow.until("query_checkpoint").await?;
        self.restart().await?;
        let committed = self.commit().await?;
        let expected: u64 = committed["expected_rows"][0][0]
            .as_str()
            .ok_or("native aggregate text is absent")?
            .parse()?;
        if self.query_count(Some(self.target.clone())).await? != vec![vec![expected]] {
            return Err("selected native query differs from committed trace output".into());
        }
        let replacement = tokio::time::timeout(WAIT, async {
            for _ in 0..16 {
                let replacement = follow.until("query_replace").await?;
                if CliProcess::count(&replacement)? == expected {
                    return Ok::<_, Box<dyn std::error::Error>>(replacement);
                }
                if CliProcess::count(&replacement)? != CliProcess::count(&initial)? {
                    return Err("CLI replay returned an unexpected aggregate".into());
                }
            }
            Err("CLI replay exceeded its replacement bound".into())
        })
        .await??;
        if replacement["frame"]["operation"] != proto::QueryOperation::Replace as i32
            || CliProcess::count(&replacement)? != expected
            || replacement["frame"]["store_uuid"] != initial["frame"]["store_uuid"]
            || replacement["frame"]["recovery_epoch"] != initial["frame"]["recovery_epoch"]
            || replacement["frame"]["read_revision"].as_u64()
                <= initial["frame"]["read_revision"].as_u64()
            || follow.child.try_wait()?.is_some()
        {
            return Err("CLI follow did not replace its aggregate".into());
        }
        follow.interrupt()?;
        if follow.end().await? != Some(130) {
            return Err("CLI query interruption failed".into());
        }
        trace.interrupt()?;
        let terminal = trace.until("trace_result").await?;
        let exit = trace.end().await?;
        if exit != Some(130)
            || terminal["frame"]["payload"]["Result"]["complete"] != true
            || terminal["frame"]["payload"]["Result"]["cleanup_complete"] != false
            || terminal["frame"]["payload"]["Result"]["output_incomplete"] != true
        {
            return Err(
                "CLI concealed its partial fixture cleanup or missed the final result".into(),
            );
        }
        self.finish().await?;
        let state = self.state(&id).await?;
        if state["cancel_requested"] != true {
            return Err("initiating CLI did not request cancellation".into());
        }
        fs::write(&self.source, &original)?;
        let completed = self.completed(executable).await?;
        let expired = self.expire(&receipt.trace_id, bookmark).await?;
        Ok(
            json!({"schema_version": 1, "case": "query-trace-client", "result": "PASS",
            "physical": false, "performance_claim": false, "sql_execution": "in-process",
            "source_frozen": true, "exact_retry": true, "read_only_interrupt": true,
            "initiator_cancelled": true, "query_replace": true, "trace_id": id,
            "selected_parity": true,
            "terminal": terminal, "trace_exit": exit, "commit": committed,
            "window_expired": true, "connection_restarted": true,
            "normal_completed": true, "cursor_expired": true,
            "window": window, "completed": completed, "expired": expired,
            "proof_boundary": "The built CLI uses production TLS client RPCs, OIDC validation, QueryOwner and TraceOwner. A runtime fixture answers live target resolution. Production NodeTraceOwner supervises an external backend and uploads output through mTLS. Cleanup is Unknown. This case does not prove physical BPF cleanup or performance."}),
        )
    }

    async fn shutdown(mut self) -> ProofResult<()> {
        let _sent = self.commands.try_send(CaptureCommand::Stop);
        let driver = match tokio::time::timeout(WAIT, &mut self.driver).await {
            Ok(result) => result?.map_err(std::io::Error::other),
            Err(error) => {
                self.driver.abort();
                let _joined = self.driver.await;
                Err(std::io::Error::other(error))
            }
        };
        let server = match self.server.take() {
            Some(server) => server.shutdown().await,
            None => Ok(()),
        };
        let node = self.node_server.shutdown().await;
        let provider = self.provider.shutdown().await;
        driver?;
        server?;
        node?;
        provider?;
        Ok(())
    }
}

impl CaptureFixture {
    async fn run(mut self, mut commands: mpsc::Receiver<CaptureCommand>) -> ProofResult<()> {
        let mut resolved = None;
        let mut cursors = BTreeMap::new();
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(CaptureCommand::Seed(tenant, sender)) => {
                        let result = ClientFixture::seed(
                            &mut self.connection,
                            self.path.parent().ok_or("capture target has no parent")?,
                            tenant,
                        ).await;
                        let _sent = sender.send(result.as_ref().map_err(ToString::to_string).copied());
                        result?;
                        continue;
                    }
                    Some(CaptureCommand::Stop) | None => break,
                },
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
            self.node.reap()?;
            let retained = self.node.retained()?;
            let mut output = None;
            for (id, dispatch) in &retained {
                if let Some(batch) = self.node.next_batch(*id, *cursors.get(id).unwrap_or(&0))? {
                    output = Some(TraceUploadV1 {
                        request_id: dispatch.accepted.request.request_id,
                        target_index: dispatch.target_index,
                        original_node_boot_id: [7; 16],
                        batch,
                    });
                    break;
                }
            }
            let reply = self
                .connection
                .exchange_diagnostics(&TraceExchangeV1 {
                    retained: retained.iter().map(|(id, _)| *id).collect(),
                    resolved: resolved.take(),
                    output: output.clone(),
                })
                .await?;
            if let Some(ack) = reply.acknowledgement {
                let upload = output.ok_or("ACK has no submitted output")?;
                let last = upload
                    .batch
                    .frames
                    .last()
                    .map_or(*cursors.get(&ack.execution_id).unwrap_or(&0), |frame| {
                        frame.sequence
                    });
                if ack.execution_id != upload.batch.execution_id
                    || ack.last_sequence != last
                    || ack.terminal != upload.batch.terminal
                {
                    return Err("durable ACK differs from the submitted batch".into());
                }
                cursors.insert(ack.execution_id, ack.last_sequence);
                self.acknowledged
                    .lock()
                    .map_err(|_| "capture ACK lock failed")?
                    .insert(ack.execution_id, ack.last_sequence);
                if let Some(terminal) = ack.terminal {
                    self.node.acknowledge(ack.execution_id, &terminal)?;
                }
            }
            if let Some(request) = reply.resolve {
                resolved = Some(TraceResolvedV1 {
                    resolve_id: request.resolve_id,
                    participants: request
                        .facts
                        .iter()
                        .map(|fact| {
                            Ok(TraceParticipantV1 {
                                fact_digest: DiscoveryDigestV1::of(fact)?,
                                state: if *fact == self.target.fact {
                                    TraceParticipantStateV1::Resolved
                                } else {
                                    TraceParticipantStateV1::Disappeared
                                },
                                target: (*fact == self.target.fact).then(|| self.target.clone()),
                            })
                        })
                        .collect::<ProofResult<Vec<_>>>()?,
                });
            }
            if let Some(dispatch) = reply.dispatch {
                let state = ExecutionSetBindingStateV1 {
                    node_boot_id: self.target.node_boot_id.into(),
                    binding_id: self.target.binding_id.into(),
                    binding_nonce: self.target.binding_nonce.into(),
                    root_cgroup_live_interval_id: self.target.root_cgroup_live_interval_id.into(),
                    root_cgroup_id: self.target.cgroup_id,
                    label_epoch: self.target.label_epoch,
                    container_generation: self.target.container_generation,
                    lifecycle_state: BindingLifecycleStateV1::Active,
                    ..Default::default()
                };
                let lease = TraceTargetLeaseV1::fixture(
                    self.target.clone(),
                    self.path.clone(),
                    move || Ok(Some(state)),
                )?;
                let key = self
                    .trust
                    .policy_signing_key(&dispatch.signing_key_id, dispatch.issuer_epoch)?;
                self.node
                    .admit(dispatch.clone(), Some(lease), &key, ClientFixture::now()?)?;
                let mut accepted = self
                    .accepted
                    .lock()
                    .map_err(|_| "capture fixture lock failed")?;
                if !accepted
                    .iter()
                    .any(|value| value.request.request_id == dispatch.accepted.request.request_id)
                {
                    if accepted.len() >= 4 {
                        return Err("capture fixture trace limit exceeded".into());
                    }
                    accepted.push(dispatch.accepted);
                }
            }
            for id in reply.cancel {
                self.node.cancel(id);
            }
        }
        Ok(())
    }
}

impl CliProcess {
    fn count(record: &Value) -> ProofResult<u64> {
        let data = &record["frame"]["payload"]["Rows"];
        let rows = data["rows"].as_array().ok_or("CLI aggregate has no rows")?;
        if data["limited"].as_bool() != Some(false) || rows.len() != 1 {
            return Err("CLI aggregate changed its bounded shape".into());
        }
        let values = rows[0]["values"]
            .as_array()
            .ok_or("CLI aggregate has no values")?;
        if values.len() != 1 {
            return Err("CLI aggregate changed its bounded shape".into());
        }
        let kind = values[0]["kind"]
            .as_object()
            .ok_or("CLI aggregate has no scalar kind")?;
        if kind.len() != 1 {
            return Err("CLI aggregate has an invalid scalar kind".into());
        }
        if let Some(value) = kind.get("Signed").and_then(Value::as_i64) {
            return Ok(u64::try_from(value)?);
        }
        kind.get("Unsigned")
            .and_then(Value::as_u64)
            .ok_or_else(|| "CLI aggregate is not an integer".into())
    }

    fn spawn(
        executable: &Path,
        profile: &Path,
        root: &Path,
        name: &str,
        args: &[&str],
    ) -> ProofResult<Self> {
        let stderr = File::create(root.join(format!("{name}.stderr")))?;
        let mut child = Command::new(executable)
            .arg("--profile")
            .arg(profile)
            .args(["--output", "jsonl"])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true)
            .spawn()?;
        let id = child.id().ok_or("CLI child has no process identity")?;
        let pid = Pid::from_raw(i32::try_from(id)?).ok_or("CLI PID is invalid")?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty())?;
        let stdout = BufReader::new(child.stdout.take().ok_or("CLI stdout is absent")?);
        Ok(Self {
            child,
            stdout,
            pidfd,
            log: File::create(root.join(format!("{name}.jsonl")))?,
        })
    }

    async fn next(&mut self) -> ProofResult<Option<Value>> {
        let mut bytes = Vec::new();
        let count = tokio::time::timeout(
            WAIT,
            (&mut self.stdout)
                .take(2 * 1024 * 1024 + 1)
                .read_until(b'\n', &mut bytes),
        )
        .await??;
        if count == 0 {
            return Ok(None);
        }
        if count > 2 * 1024 * 1024 || bytes.last() != Some(&b'\n') {
            return Err("CLI output exceeded its line bound".into());
        }
        self.log.write_all(&bytes)?;
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    async fn until(&mut self, kind: &str) -> ProofResult<Value> {
        for _ in 0..128 {
            let value = self
                .next()
                .await?
                .ok_or_else(|| format!("CLI ended before {kind}"))?;
            if value["kind"] == kind {
                return Ok(value);
            }
            if matches!(value["kind"].as_str(), Some("query_error" | "trace_error")) {
                let detail: String = value.to_string().chars().take(4096).collect();
                return Err(format!("CLI failed before {kind}: {detail}").into());
            }
        }
        Err("CLI exceeded its frame bound".into())
    }

    fn interrupt(&self) -> ProofResult<()> {
        pidfd_send_signal(&self.pidfd, Signal::INT)?;
        Ok(())
    }

    async fn end(&mut self) -> ProofResult<Option<i32>> {
        for _ in 0..128 {
            if self.next().await?.is_none() {
                return Ok(tokio::time::timeout(WAIT, self.child.wait()).await??.code());
            }
        }
        Err("CLI did not close bounded output".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_cli_count() -> ProofResult<()> {
        for (kind, expected) in [
            (query_value::Kind::Signed(0), Some(0)),
            (query_value::Kind::Unsigned(u64::MAX), Some(u64::MAX)),
            (query_value::Kind::Signed(-1), None),
            (query_value::Kind::Text("1".into()), None),
        ] {
            let frame = proto::QueryFrame {
                payload: Some(query_frame::Payload::Rows(proto::QueryRows {
                    rows: vec![proto::QueryRow {
                        values: vec![proto::QueryValue { kind: Some(kind) }],
                    }],
                    ..Default::default()
                })),
                ..Default::default()
            };
            let record = json!({"kind": "query_replace", "frame": frame});
            match expected {
                Some(value) => assert_eq!(CliProcess::count(&record)?, value),
                None => assert!(CliProcess::count(&record).is_err()),
            }
        }
        assert!(CliProcess::count(&json!({})).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "Requires the built araphor CLI through ARAPHOR_CLI"]
    fn observability_cli_client() -> ProofResult<()> {
        let directory = tempfile::tempdir()?;
        let executable = std::env::var_os("ARAPHOR_CLI").ok_or("ARAPHOR_CLI is required")?;
        let owner = ObservabilityQualification::new(directory.path().join("client"));
        if let Err(error) = owner.query_trace_client(Some(PathBuf::from(executable)), None, false) {
            let root = directory.keep();
            return Err(format!(
                "client fixture failed; artifacts {}: {error}",
                root.display()
            )
            .into());
        }
        let record: Value = serde_json::from_slice(&fs::read(owner.output.join("result.json"))?)?;
        assert_eq!(record["result"], "PASS");
        for field in [
            "source_frozen",
            "exact_retry",
            "read_only_interrupt",
            "initiator_cancelled",
            "query_replace",
            "selected_parity",
            "window_expired",
            "connection_restarted",
            "normal_completed",
            "cursor_expired",
        ] {
            assert_eq!(record[field], true, "{field}");
        }
        assert_eq!(record["sql_execution"], "in-process");
        assert_eq!(record["physical"], false);
        assert_eq!(record["trace_exit"], 130);
        Ok(())
    }
}
