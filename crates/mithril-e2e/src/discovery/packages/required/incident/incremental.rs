use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use araphor_analysis_builtins::causal::{model::*, Causal};
use araphor_data::{
    AnalysisReadControl, AnalysisStore, DiscoveryRecordIdV1, EvidenceIntakeIdentityV1,
    FindingStateV1, ManagedDestination, NotificationFindingRefV1, StorePositionV1,
};
use erebor_interceptor_abi::{
    EffectObservationHealthV1, EffectObservationV1, KernelEffectFamilyV1, KernelEffectOperationV1,
};
use erebor_runtime_client::AraphorClient;
use erebor_runtime_ipc::araphor::{self as wire, query_frame::Payload};
use erebor_telemetry::tracing::{
    field::{Field, Visit},
    instrument::WithSubscriber as _,
    Event, Subscriber,
};
use erebor_telemetry::tracing_subscriber::{layer::Context, prelude::*, Layer, Registry};
use mithril_control::{CausalRole, CollectedAction, EvidenceIdV1};
use mithril_node::{
    ControlConnection, EffectObservationStore, EvidenceWalLimits, NodeControlConnector,
    NodeControlMessage, ObservationCanonicalizer, TrustCache,
};
use zerocopy::IntoBytes as _;

use super::super::super::*;
use super::super::input::{configuration, event};
use super::Incident;
use crate::control_fixture::OutagePolicyFixture;

const INSTANCE: &str = "mithril-control-causal";

#[derive(Default)]
struct Sample(BTreeMap<String, String>);

impl Visit for Sample {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().into(), value.to_string());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
}

#[derive(Clone, Default)]
struct Work {
    samples: Arc<Mutex<Vec<Sample>>>,
    changed: Arc<tokio::sync::Notify>,
}

impl<S: Subscriber> Layer<S> for Work {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        if event.metadata().fields().field("cut_revision").is_none() {
            return;
        }
        let mut sample = Sample::default();
        event.record(&mut sample);
        self.samples
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(sample);
        self.changed.notify_waiters();
    }
}

impl Work {
    async fn committed(&self, cut: u64) -> Result<u64> {
        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if let Some(revision) = self
                    .samples
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .iter()
                    .filter(|sample| {
                        sample.0.get("stage").map(String::as_str) == Some("managed_commit_timing")
                            && sample.0.get("instance_id").map(String::as_str) == Some(INSTANCE)
                            && sample
                                .0
                                .get("cut_revision")
                                .and_then(|value| value.parse::<u64>().ok())
                                .is_some_and(|value| value >= cut)
                    })
                    .filter_map(|sample| {
                        sample
                            .0
                            .get("publication_revision")
                            .and_then(|value| value.parse::<u64>().ok())
                    })
                    .min()
                {
                    return Ok(revision);
                }
                changed.await;
            }
        })
        .await
        .map_err(|_| format!("causal package did not commit input cut {cut}"))?
    }
}

struct Source {
    wal: EffectObservationStore,
    identity: EvidenceIntakeIdentityV1,
    cursor: u64,
}

impl Source {
    fn open(tls: &MtlsFixture, seed: u8, node: &str, boot: [u8; 16]) -> Result<Self> {
        let root = tls.path().join(format!("causal-{seed}"));
        fs::create_dir(&root)?;
        let wal = EffectObservationStore::durable(
            8,
            root.join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                [seed; 16].into(),
                1,
                boot.into(),
            )?,
        )?;
        wal.sample_coverage_health([EffectObservationHealthV1::default(); 4].as_bytes())?;
        let source = wal
            .coverage_snapshot()
            .ok_or("source coverage")?
            .current_intervals()
            .into_iter()
            .find(|interval| interval.cpu_id == 3)
            .ok_or("CPU source")?
            .source_id
            .to_be_bytes();
        Ok(Self {
            wal,
            cursor: 0,
            identity: EvidenceIntakeIdentityV1 {
                tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
                node_id: node.into(),
                node_boot_id: boot,
                label_epoch: 1,
                source_id: source,
                source_epoch: 1,
            },
        })
    }

    fn prepare(&mut self, mut record: EffectObservationV1) -> EffectObservationV1 {
        self.cursor += 1;
        record.source_cpu_id = 3;
        record.source_sequence = self.cursor;
        record.observed_boottime_ns = if self.identity.node_id == "node-b" {
            self.cursor
        } else {
            100_000 + self.cursor
        };
        record
    }

    fn append(&mut self, record: EffectObservationV1) -> DiscoveryRecordIdV1 {
        let record = self.prepare(record);
        self.wal.record_bytes(record.as_bytes());
        DiscoveryRecordIdV1 {
            stream: self.identity.clone(),
            cpu_id: 3,
            durable_cursor: self.cursor,
        }
    }

    fn background(&mut self, count: usize) -> Result<()> {
        assert_eq!(self.wal.pending_evidence_records(), 0);
        let (ingress, worker) = self.wal.ingestion_queue(None, count)?;
        let rows = u64::try_from(count)?;
        for cursor in 0..rows {
            let mut record = event(cursor + 1, false);
            record.task_cookie = 1_000_000 + cursor;
            record.process_instance_id = EvidenceIdV1::new(50, cursor + 1).to_be_bytes().into();
            ingress.record_bytes(self.prepare(record).as_bytes());
        }
        drop(ingress);
        worker.run();
        assert_eq!(self.wal.evidence_errors(), 0);
        assert_eq!(self.wal.pending_evidence_records(), rows);
        Ok(())
    }

    async fn flush(&self, node: &mut ControlConnection) -> Result<()> {
        while let Some(batch) = self.wal.next_evidence_batch() {
            node.send_evidence_batch(batch.clone()).await?;
            let ack = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let NodeControlMessage::EvidenceAck(ack) = node.next_message().await? {
                        return Ok::<_, mithril_node::Error>(ack);
                    }
                }
            })
            .await??;
            assert_eq!(ack.contiguous_cursor, batch.last_cursor);
            self.wal.acknowledge_evidence(ack)?;
        }
        let mut health = [EffectObservationHealthV1::default(); 4];
        health[3] = EffectObservationHealthV1 {
            attempted: self.cursor,
            requested: self.cursor,
            emitted: self.cursor,
            next_sequence: self.cursor,
            ..Default::default()
        };
        self.wal.sample_coverage_health(health.as_bytes())?;
        let snapshot = self.wal.coverage_snapshot().ok_or("coverage snapshot")?;
        let interval = snapshot
            .current_intervals()
            .into_iter()
            .find(|interval| interval.cpu_id == 3)
            .ok_or("coverage interval")?;
        assert!(interval.supports_negative_claim());
        let expected = node.send_coverage_report(&snapshot, &interval).await?;
        let actual = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let NodeControlMessage::CoverageAck(ack) = node.next_message().await? {
                    return Ok::<_, mithril_node::Error>(ack);
                }
            }
        })
        .await??;
        assert_eq!(actual, expected);
        Ok(())
    }
}

struct Episode {
    actions: Vec<(usize, CausalRole, CollectedAction)>,
    records: Vec<DiscoveryRecordIdV1>,
    creation: DiscoveryRecordIdV1,
}

impl Episode {
    fn create(sources: &mut [Source], serial: u64) -> Self {
        let task = 7 + serial;
        let process = EvidenceIdV1::new(8, serial).to_be_bytes();
        let credential = Credential {
            authority: "aws-imds-node-role".into(),
            lease: format!("node-session-{serial}"),
            principal: "system:node:worker-a".into(),
        };
        let issued = Credential {
            authority: "kubernetes-token-request".into(),
            lease: format!("csi-token-{serial}"),
            principal: "system:serviceaccount:kube-system:ebs-csi-controller-sa".into(),
        };
        let pod = Pod {
            cluster: "hf-evaluation".into(),
            uid: format!("privileged-pod-{serial}"),
            created_revision: format!("create-{serial}"),
        };
        let binding = format!("scheduling-{serial}");
        let mut actions = Vec::new();
        let mut records = Vec::new();
        let raw =
            |operation: KernelEffectOperationV1, family: KernelEffectFamilyV1, denied: bool| {
                let mut raw = event(1, denied);
                raw.task_cookie = task;
                raw.process_instance_id = process.into();
                raw.operation = operation as u16;
                raw.effect_family = family as u16;
                raw.exact_object_key_id = 20 + serial;
                raw
            };
        let object = |raw: &EffectObservationV1| {
            mithril_control::EvidenceFileObjectV1::from(raw.file_object)
                .observation_id(raw.exact_object_key_id)
                .to_be_bytes()
        };
        let mut add = |source: usize,
                       role: CausalRole,
                       raw: EffectObservationV1,
                       outcome: Outcome,
                       status,
                       action| {
            let record = sources[source].append(raw);
            records.push(record.clone());
            actions.push((
                source,
                role,
                CollectedAction {
                    record: record.clone(),
                    revision: 1,
                    task: raw.task_cookie,
                    process: raw.process_instance_id.to_be_bytes(),
                    outcome,
                    status_code: status,
                    action,
                },
            ));
            record
        };
        let denied = raw(
            KernelEffectOperationV1::OpenRead,
            KernelEffectFamilyV1::File,
            true,
        );
        add(
            0,
            CausalRole::Completion,
            denied,
            Outcome::Denied,
            None,
            Action::CredentialAccess {
                credential: credential.clone(),
                object: object(&denied),
                completion: format!("synthetic-denied-read-{serial}"),
                result: -13,
                bytes: 0,
            },
        );
        let read = raw(
            KernelEffectOperationV1::Receive,
            KernelEffectFamilyV1::Network,
            false,
        );
        let acquisition = add(
            0,
            CausalRole::Completion,
            read,
            Outcome::Succeeded,
            None,
            Action::CredentialAccess {
                credential: credential.clone(),
                object: object(&read),
                completion: format!("imds-response-{serial}"),
                result: 2048,
                bytes: 2048,
            },
        );
        let network = raw(
            KernelEffectOperationV1::Send,
            KernelEffectFamilyV1::Network,
            false,
        );
        let issue = add(
            1,
            CausalRole::ApiAudit,
            network,
            Outcome::Succeeded,
            Some(201),
            Action::TokenRequest {
                request: Request {
                    cluster: pod.cluster.clone(),
                    audit: format!("token-audit-{serial}"),
                    carried: format!("token-request-{serial}"),
                    credential,
                    socket: object(&network),
                    credential_origin: Origin {
                        record: acquisition,
                        proof: format!("imds-response-{serial}"),
                    },
                },
                issued: Some(issued.clone()),
            },
        );
        let creation = add(
            1,
            CausalRole::ApiAudit,
            network,
            Outcome::Succeeded,
            Some(201),
            Action::PodCreate {
                request: Request {
                    cluster: pod.cluster.clone(),
                    audit: format!("create-audit-{serial}"),
                    carried: format!("create-request-{serial}"),
                    credential: issued,
                    socket: object(&network),
                    credential_origin: Origin {
                        record: issue,
                        proof: format!("token-audit-{serial}"),
                    },
                },
                pod: Some(pod.clone()),
                containers: vec![Container {
                    name: "host-reader".into(),
                    privileged: true,
                    host_mounts: vec![HostMount {
                        host_path: "/".into(),
                        container_path: "/host".into(),
                        read_only: false,
                    }],
                }],
            },
        );
        let scheduling = add(
            2,
            CausalRole::Scheduler,
            network,
            Outcome::Succeeded,
            None,
            Action::PodScheduled {
                pod: pod.clone(),
                created_by: Origin {
                    record: creation.clone(),
                    proof: format!("create-audit-{serial}"),
                },
                binding: binding.clone(),
                node: "node-b".into(),
            },
        );
        let admitted = raw(
            KernelEffectOperationV1::Execute,
            KernelEffectFamilyV1::Exec,
            false,
        );
        add(
            3,
            CausalRole::Runtime,
            admitted,
            Outcome::Succeeded,
            None,
            Action::ContainerAdmitted {
                runtime: Runtime {
                    pod,
                    binding: binding.clone(),
                    node: "node-b".into(),
                    boot: [17; 16],
                    label_epoch: 1,
                    container: format!("containerd://{serial:064x}"),
                    container_name: "host-reader".into(),
                    cgroup: 10_000 + serial,
                    admission: format!("runtime-admission-{serial}"),
                    task,
                    process,
                    scheduled_by: Origin {
                        record: scheduling,
                        proof: binding,
                    },
                },
            },
        );
        Self {
            actions,
            records,
            creation,
        }
    }

    fn submit(&mut self, fixture: &Fixture, skip: Option<usize>) -> Result<u64> {
        let mut cut = 0;
        for (index, (_, role, action)) in std::mem::take(&mut self.actions).into_iter().enumerate()
        {
            if skip == Some(index) {
                self.actions.push((3, role, action));
                continue;
            }
            let collector = fixture.control.causal_collector(
                action.record.stream.tenant_id,
                &action.record.stream.node_id,
                role,
            )?;
            for reference in collector.submit(vec![action], &AnalysisReadControl::default())? {
                cut = cut.max(reference.commit_revision);
            }
        }
        Ok(cut)
    }
}

struct Flow {
    streams: [tonic::Streaming<wire::QueryFrame>; 4],
    events: BTreeMap<Vec<u8>, (u64, StorePositionV1)>,
    graph: u64,
    findings: BTreeMap<String, (String, String, u64)>,
    notices: BTreeMap<String, (String, u64)>,
    revisions: [u64; 4],
    exhausted: [bool; 4],
}

impl Flow {
    async fn subscribe(client: &AraphorClient) -> Result<Self> {
        let mut streams = Vec::new();
        for sql in [
            "SELECT source_id, source_cursor, commit_revision, ordinal FROM events",
            "SELECT graph_result_id, commit_revision FROM graph_manifest QUALIFY ROW_NUMBER() OVER (ORDER BY commit_revision DESC)=1",
            "SELECT finding_id, graph_result_id, state, finding_value_id FROM findings WHERE package_id='HF-CAUSAL-001'",
            "SELECT finding_id, finding_result_id, finding_value_id FROM notifications WHERE package_id='HF-CAUSAL-001' AND route_id='primary'",
        ] { streams.push(client.query(wire::QueryRequest { sql: sql.into(), follow: true, ..Default::default() }).await?); }
        Ok(Self {
            streams: streams.try_into().map_err(|_| "stream count")?,
            events: BTreeMap::new(),
            graph: 0,
            findings: BTreeMap::new(),
            notices: BTreeMap::new(),
            revisions: [0; 4],
            exhausted: [false; 4],
        })
    }

    async fn next(&mut self) -> Result<()> {
        let (source, frame) = {
            let [events, graphs, findings, notices] = &mut self.streams;
            tokio::select! { frame=events.message() => (0,frame?), frame=graphs.message() => (1,frame?),
            frame=findings.message() => (2,frame?), frame=notices.message() => (3,frame?) }
        };
        let frame = frame.ok_or("causal subscription closed")?;
        match frame.payload {
            Some(Payload::Rows(rows)) => {
                self.revisions[source] = 0;
                self.exhausted[source] = !rows.limited;
                if frame.operation == wire::QueryOperation::Replace as i32 {
                    match source {
                        0 => assert!(self.events.is_empty(), "immutable events replaced"),
                        1 => self.graph = 0,
                        2 => self.findings.clear(),
                        3 => self.notices.clear(),
                        _ => unreachable!(),
                    }
                }
                for row in rows.rows {
                    match source {
                        0 => {
                            let key = Incident::binary(&row, 0)?.to_vec();
                            let cursor = Incident::number(&row, 1)?;
                            let previous = self.events.entry(key).or_insert((
                                0,
                                StorePositionV1 {
                                    commit_revision: 0,
                                    ordinal: 0,
                                },
                            ));
                            assert_eq!(cursor, previous.0 + 1, "event replay, gap, or duplicate");
                            *previous = (
                                cursor,
                                StorePositionV1 {
                                    commit_revision: Incident::number(&row, 2)?,
                                    ordinal: Incident::number(&row, 3)?.try_into()?,
                                },
                            );
                        }
                        1 => self.graph = self.graph.max(Incident::number(&row, 1)?),
                        2 => {
                            self.findings.insert(
                                Incident::text(&row, 0)?.into(),
                                (
                                    Incident::text(&row, 1)?.into(),
                                    Incident::text(&row, 2)?.into(),
                                    Incident::number(&row, 3)?,
                                ),
                            );
                        }
                        3 => {
                            self.notices.insert(
                                Incident::text(&row, 0)?.into(),
                                (Incident::text(&row, 1)?.into(), Incident::number(&row, 2)?),
                            );
                        }
                        _ => unreachable!(),
                    }
                }
            }
            Some(Payload::Checkpoint(_)) if self.exhausted[source] => {
                self.revisions[source] = frame.read_revision
            }
            Some(Payload::Error(error)) => {
                return Err(format!("causal stream {source}: {error:?}").into())
            }
            Some(Payload::Terminal(terminal)) => {
                return Err(format!("causal stream {source}: {terminal:?}").into())
            }
            _ => {}
        }
        Ok(())
    }

    async fn wait(&mut self, ready: impl Fn(&Self) -> bool) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(90), async {
            while !ready(self) {
                self.next().await?;
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await
        .map_err(|_| {
            format!(
                "causal progress: Graph {}, findings {}, notices {}, checkpoints {:?}",
                self.graph,
                self.findings.len(),
                self.notices.len(),
                self.revisions
            )
        })?
    }

    async fn caught_up(&mut self, work: &Work, cut: u64) -> Result<u64> {
        let revision = work.committed(cut).await?;
        self.wait(|flow| {
            flow.graph >= revision && flow.revisions[1..3].iter().all(|cut| *cut >= revision)
        })
        .await?;
        Ok(revision)
    }

    async fn finding(
        &mut self,
        data: &AnalysisStore,
        episode: &Episode,
        count: usize,
    ) -> Result<(String, Instant)> {
        self.wait(|flow| {
            flow.findings.len() == count
                && flow.notices.len() == count
                && flow.findings.iter().all(|(id, (_, state, value))| {
                    state == "confirmed"
                        && flow
                            .notices
                            .get(id)
                            .is_some_and(|(_, notice)| value == notice)
                })
        })
        .await?;
        let arrived = Instant::now();
        let mut found = None;
        for (id, (result, _, _)) in &self.findings {
            let (finding, revision) = data
                .graph_finding(episode.creation.stream.tenant_id, result, id)?
                .ok_or("finding value")?;
            if finding.evidence.contains(&episode.creation) {
                assert_eq!(finding.state, FindingStateV1::Confirmed);
                assert!(episode
                    .records
                    .iter()
                    .all(|record| finding.evidence.contains(record)));
                assert_eq!(finding.evidence.len(), 6);
                assert_eq!(
                    revision
                        .evidence
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>(),
                    episode
                        .records
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                );
                assert_eq!(
                    revision
                        .evidence
                        .iter()
                        .map(|record| record.stream.node_id.as_str())
                        .collect::<std::collections::BTreeSet<_>>(),
                    std::collections::BTreeSet::from(["node-a", "node-b"])
                );
                assert_eq!(
                    revision
                        .coverage
                        .iter()
                        .map(|key| &key.source)
                        .collect::<std::collections::BTreeSet<_>>()
                        .len(),
                    4
                );
                assert!(revision.missing_ranges.is_empty());
                let reference = NotificationFindingRefV1 {
                    finding_id: id.clone(),
                    result_id: self
                        .notices
                        .get(id)
                        .ok_or("notification reference")?
                        .0
                        .clone(),
                };
                assert_eq!(
                    data.notification_finding(finding.tenant_id, &reference)?.0,
                    finding
                );
                assert_eq!(
                    data.graph_revision_finding(finding.tenant_id, id, &revision)?,
                    Some(finding)
                );
                found = Some(id.clone());
            }
        }
        found
            .map(|id| (id, arrived))
            .ok_or_else(|| "cross-node finding absent".into())
    }
}

#[tokio::test]
async fn follows_incremental_sources() -> Result<()> {
    let work = Work::default();
    let output = erebor_telemetry::tracing_subscriber::fmt::layer()
        .with_test_writer()
        .with_ansi(false)
        .with_filter(erebor_telemetry::tracing_subscriber::EnvFilter::from_default_env());
    let dispatch = erebor_telemetry::tracing::Dispatch::new(
        Registry::default().with(work.clone()).with(output),
    );
    async move {
        let tls = MtlsFixture::new(false)?;
        let oidc = OidcFixture::start(&tls.files, "causal-operator").await?;
        let result: Result<()> = async {
            let (mut config, _, authority) = configuration(&tls, &oidc).await?;
            config.data_retention.raw_max_age_ns = None;
            let (peer, digest) = tls.peer("node-b")?;
            let mut allowed = config.allowed_nodes[0].clone();
            allowed.node_id = "node-b".into();
            allowed.certificate_sha256 = digest;
            config.allowed_nodes.push(allowed);
            for route in &mut config.notifications.routes {
                if route.route_id == "primary" {
                    route.package_ids = vec![Causal::ID.into()];
                }
            }
            let auth = config.client.as_ref().ok_or("client config")?.auth.clone();
            let fixture = Fixture::configured(config, authority)?;
            let (fixture, server) = fixture.listening(&tls).await?;
            let credential = tls.path().join("causal-token");
            fs::write(&credential, b"fixture-access")?;
            let (client, query) = fixture
                .client(
                    &tls,
                    &auth,
                    &credential,
                    EvidenceIdV1::new(1, 2).to_be_bytes(),
                )
                .await?;
            let tested: Result<()> = async {
                let data = fixture.control.analysis_store().ok_or("Data owner")?;
                let current = data
                    .managed_instance(
                        EvidenceIdV1::new(1, 2).to_be_bytes(),
                        INSTANCE,
                        &AnalysisReadControl::default(),
                    )?
                    .ok_or("causal instance")?;
                assert_eq!(current.spec.destination, ManagedDestination::Selected);
                assert!(current.running && !current.removed);
                assert_eq!(current.spec.manifest.calls.len(), 2);
                assert!(current
                    .spec
                    .manifest
                    .calls
                    .values()
                    .all(|call| call.package.package_id == Causal::ID));
                assert_eq!(current.grant.selection.nodes.len(), 2);
                let mut flow = Flow::subscribe(&client).await?;
                let mut first_trust = TrustCache::load(&tls.path().join("trust-a"))?;
                let mut second_trust = TrustCache::load(&tls.path().join("trust-b"))?;
                let mut first = OutagePolicyFixture::registration([7; 16], false);
                first.effect_prevention_claims_enabled = false;
                let mut second = OutagePolicyFixture::registration([17; 16], false);
                second.effect_prevention_claims_enabled = false;
                second.kubernetes_node_name = "worker-b".into();
                second.startup_absence_proof_digest = mithril_control::startup_absence_proof_digest(
                    "node-b", &[17; 16], 1, true, true,
                );
                let mut node = tls
                    .connector(&server, "node-a", [7; 16])
                    .connect(first, false, &mut first_trust)
                    .await?;
                let mut remote = NodeControlConnector::new(
                    peer.node_config(server.address()),
                    "node-b".into(),
                    [17; 16],
                )
                .connect(second, false, &mut second_trust)
                .await?;
                let mut sources = vec![
                    Source::open(&tls, 33, "node-a", [7; 16])?,
                    Source::open(&tls, 34, "node-a", [7; 16])?,
                    Source::open(&tls, 35, "node-a", [7; 16])?,
                    Source::open(&tls, 36, "node-b", [17; 16])?,
                ];
                let mut episode = Episode::create(&mut sources, 1);
                for source in &sources[..3] {
                    source.flush(&mut node).await?;
                }
                sources[3].flush(&mut remote).await?;
                let cut = episode.submit(&fixture, Some(5))?;
                flow.caught_up(&work, cut).await?;
                assert!(
                    flow.findings.is_empty() && flow.notices.is_empty(),
                    "partial chain produced a finding"
                );
                let started = Instant::now();
                let cut = episode.submit(&fixture, None)?;
                let (_, arrived) = flow.finding(&data, &episode, 1).await?;
                let publication = flow.caught_up(&work, cut).await?;
                erebor_telemetry::info!(
                    stage = "causal_latency",
                    section = "initial",
                    elapsed_s = arrived.duration_since(started).as_secs_f64(),
                    input_revision = cut,
                    publication_revision = publication,
                    "Trusted audit ingestion reached notification subscription"
                );
                let bulk = Instant::now();
                for source in &mut sources {
                    source.background(4096)?;
                }
                for source in &sources[..3] {
                    source.flush(&mut node).await?;
                }
                sources[3].flush(&mut remote).await?;
                flow.wait(|flow| {
                    sources.iter().all(|source| {
                        flow.events
                            .get(source.identity.source_id.as_slice())
                            .is_some_and(|(cursor, _)| *cursor == source.cursor)
                    })
                })
                .await?;
                let cut = flow
                    .events
                    .values()
                    .map(|(_, position)| position.commit_revision)
                    .max()
                    .ok_or("bulk event revision")?;
                flow.caught_up(&work, cut).await?;
                assert_eq!(flow.findings.len(), 1);
                assert_eq!(flow.notices.len(), 1);
                erebor_telemetry::info!(
                    stage = "causal_latency",
                    section = "bulk",
                    elapsed_s = bulk.elapsed().as_secs_f64(),
                    rows = 16_384,
                    "Background workload reached package publication"
                );
                for serial in 2..=3 {
                    let mut episode = Episode::create(&mut sources, serial);
                    for source in &sources[..3] {
                        source.flush(&mut node).await?;
                    }
                    sources[3].flush(&mut remote).await?;
                    let started = Instant::now();
                    let cut = episode.submit(&fixture, None)?;
                    let (_, arrived) = flow.finding(&data, &episode, serial as usize).await?;
                    flow.caught_up(&work, cut).await?;
                    erebor_telemetry::info!(
                        stage = "causal_latency",
                        section = "warm",
                        elapsed_s = arrived.duration_since(started).as_secs_f64(),
                        input_revision = cut,
                        "Trusted audit ingestion reached notification subscription"
                    );
                }
                let history = data.managed_history(
                    &current.grant.selection,
                    INSTANCE,
                    &AnalysisReadControl::default(),
                )?;
                assert!(!history.is_empty());
                for receipt in history {
                    assert!(receipt
                        .results
                        .values()
                        .all(|call| call.commit_revision == receipt.selected.commit_revision));
                }
                flow.wait(|flow| {
                    sources.iter().all(|source| {
                        flow.events
                            .get(source.identity.source_id.as_slice())
                            .is_some_and(|(cursor, _)| *cursor == source.cursor)
                    })
                })
                .await?;
                assert_eq!(
                    flow.events.values().map(|(cursor, _)| cursor).sum::<u64>(),
                    16_402
                );
                Ok(())
            }
            .await;
            drop(client);
            query.shutdown().await?;
            let (network, stopped) = tokio::join!(server.shutdown(), fixture.shutdown());
            network?;
            stopped?;
            tested
        }
        .await;
        oidc.shutdown().await?;
        result
    }
    .with_subscriber(dispatch)
    .await
}
