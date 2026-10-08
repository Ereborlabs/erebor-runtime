use std::{
    collections::BTreeMap,
    error::Error as StdError,
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use araphor_data::*;
use erebor_interceptor_abi::{
    EffectObservationHealthV1, EffectObservationReasonV1, EffectObservationV1,
    EffectPhysicalResultV1, KernelEffectFamilyV1, KernelEffectOperationV1,
};
use mithril_control::{
    AuthenticatedEvidenceNodeV1, ConfiguredNotificationAuthority, ControlStore, CoverageCounters,
    CoverageInterval, CoverageReport, EvidenceIntakeOwner, IntakeClock,
};
use mithril_node::{
    EffectObservationStore, EvidenceIdV1, EvidenceWalLimits, NodeControlMessage,
    ObservationCanonicalizer, TrustCache,
};
use serde_json::json;
use zerocopy::IntoBytes as _;

use crate::control_fixture::{MtlsFixture, OutagePolicyFixture};

#[cfg(test)]
mod physical;
mod replay;

pub struct GraphNotificationQualification {
    output: PathBuf,
}

pub(super) struct GraphInputs {
    facts: RwLock<BTreeMap<DiscoveryRecordIdV1, Vec<AnalysisContextVersionV1>>>,
    revision: AtomicU64,
}

impl Default for GraphInputs {
    fn default() -> Self {
        Self {
            facts: RwLock::new(BTreeMap::new()),
            revision: AtomicU64::new(1),
        }
    }
}

impl GraphInputs {
    pub(super) fn insert(
        &self,
        fact: GraphFactV1,
        name: &str,
        revision: u64,
    ) -> Result<AnalysisContextKeyV1> {
        fact.validate()?;
        let stream = &fact.record_id.stream;
        let mut lifetime = stream.tenant_id.to_vec();
        lifetime.extend_from_slice(&(stream.node_id.len() as u32).to_be_bytes());
        lifetime.extend_from_slice(stream.node_id.as_bytes());
        lifetime.extend_from_slice(&stream.node_boot_id);
        lifetime.extend_from_slice(&stream.label_epoch.to_be_bytes());
        lifetime.extend_from_slice(&stream.source_id);
        lifetime.extend_from_slice(&stream.source_epoch.to_be_bytes());
        lifetime.extend_from_slice(&fact.record_id.cpu_id.to_be_bytes());
        lifetime.extend_from_slice(&fact.record_id.durable_cursor.to_be_bytes());
        let context = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: fact.record_id.stream.tenant_id,
                owner_id: "qualification-input-v1".into(),
                entity_key: name.as_bytes().to_vec(),
                lifetime_key: lifetime,
                owner_revision: revision,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: serde_json::to_vec(&fact).map_err(|source| Error::GraphEncoding {
                source,
                location: snafu::Location::default(),
            })?,
        };
        let key = context.key.clone();
        self.facts
            .write()
            .map_err(|_| Error::GraphInvalid {
                field: "qualification facts lock",
                location: snafu::Location::default(),
            })?
            .entry(fact.record_id)
            .or_default()
            .push(context);
        self.revision.fetch_add(1, Ordering::Release);
        Ok(key)
    }
}

impl GraphContextProvider for GraphInputs {
    fn facts(&self, record: &DiscoveryRecordV1) -> Result<Vec<AnalysisContextVersionV1>> {
        self.facts
            .read()
            .map(|facts| facts.get(&record.id).cloned().unwrap_or_default())
            .map_err(|_| Error::GraphInvalid {
                field: "qualification facts lock",
                location: snafu::Location::default(),
            })
    }

    fn revision(&self, _source: &EvidenceIntakeIdentityV1) -> Result<u64> {
        Ok(self.revision.load(Ordering::Acquire))
    }
}

struct Clock(SystemTime);

impl IntakeClock for Clock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

pub(super) struct IncidentSink {
    failed: AtomicBool,
    finding_id: String,
}

impl IncidentSink {
    fn new(finding_id: String) -> Self {
        Self {
            failed: AtomicBool::new(false),
            finding_id,
        }
    }
}

impl NotificationSink for IncidentSink {
    fn deliver(&self, delivery: &NotificationDeliveryV1) -> NotificationSinkResultV1 {
        if delivery.kind == NotificationDeliveryKindV1::Finding
            && delivery
                .finding
                .as_ref()
                .is_some_and(|finding| finding.finding_id == self.finding_id)
            && !self.failed.swap(true, Ordering::AcqRel)
        {
            NotificationSinkResultV1::Failed {
                reason: NotificationFailureV1::TransportFailed,
            }
        } else {
            NotificationSinkResultV1::AgentReceived {
                receipt: format!("sink-{:?}-{}", delivery.kind, delivery.attempt),
            }
        }
    }
}

impl GraphNotificationQualification {
    pub fn new(output: PathBuf) -> Self {
        Self { output }
    }

    pub async fn run(&self) -> std::result::Result<(), Box<dyn StdError>> {
        if self.output.exists() {
            return Err("the qualification output already exists".into());
        }
        let tls = MtlsFixture::new(false)?;
        let root = tls.path().join("control-store");
        let data_root = tls.path().join("analysis");
        let store = ControlStore::open(&root)?;
        let data = Arc::new(AnalysisStore::open(&data_root)?);
        let now = 1_791_400_000_000_000_000;
        let intake = EvidenceIntakeOwner::new(
            store.clone(),
            data.clone(),
            Arc::new(Clock(UNIX_EPOCH + Duration::from_nanos(now))),
        )?;
        let control = tls.control_from_intake(intake.clone(), 1)?;
        let server = tls.start(control).await?;
        let boot = [7; 16];
        let wal = EffectObservationStore::durable(
            8,
            tls.path().join("wal"),
            EvidenceWalLimits {
                maximum_batch_records: 1,
                ..Default::default()
            },
            ObservationCanonicalizer::new(EvidenceIdV1::new(1, 2), [3; 16].into(), 1, boot.into())?,
        )?;
        wal.sample_coverage_health([EffectObservationHealthV1::default(); 4].as_bytes())?;
        wal.record_bytes(Self::native(1, true).as_bytes());
        wal.record_bytes(Self::native(2, false).as_bytes());
        let batches = wal.next_evidence_batches();
        if batches.len() != 2 {
            return Err("the Node WAL did not keep two bounded batches".into());
        }
        let original: Vec<_> = batches
            .iter()
            .map(|batch| batch.decode_records())
            .collect::<std::result::Result<_, _>>()?;
        let mut trust = TrustCache::load(&tls.path().join("trust"))?;
        let mut registration = OutagePolicyFixture::registration(boot, false);
        registration.effect_prevention_claims_enabled = false;
        let connector = tls.connector(&server, "node-a", boot);
        let mut connection = connector
            .connect(registration.clone(), false, &mut trust)
            .await?;
        let mut acknowledgements = Vec::new();
        let mut cursors = Vec::new();
        for index in [1, 1, 0, 0] {
            connection
                .send_evidence_batch(batches[index].clone())
                .await?;
            let response = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let NodeControlMessage::EvidenceAck(ack) = connection.next_message().await? {
                        return Ok::<_, mithril_node::Error>(ack);
                    }
                }
            })
            .await?;
            if index == 1 {
                let mithril_node::Error::ControlRpc { source, .. } = response.unwrap_err() else {
                    return Err("pending upload did not return a Control RPC error".into());
                };
                assert_eq!(source.code(), tonic::Code::Unavailable);
                assert_eq!(
                    source.message(),
                    "evidence batch is durable but waits for an earlier cursor range"
                );
                acknowledgements.push(None);
                connection = connector
                    .connect(registration.clone(), false, &mut trust)
                    .await?;
            } else {
                acknowledgements.push(Some(response?.contiguous_cursor));
            }
            let pending_source = data
                .source_page(EvidenceIdV1::new(1, 2).to_be_bytes(), None)?
                .into_iter()
                .next()
                .ok_or("accepted source absent")?;
            cursors.push(intake.contiguous_cursor(&pending_source)?);
        }
        assert_eq!(acknowledgements, [None, None, Some(2), Some(2)]);
        assert_eq!(cursors, [0, 0, 2, 2]);
        let source = data
            .source_page(EvidenceIdV1::new(1, 2).to_be_bytes(), None)?
            .into_iter()
            .next()
            .ok_or("accepted source absent")?;
        let records = data.read_page(&source, 1)?.records;
        assert_eq!(records.len(), 2);
        for (retained, original) in records.iter().zip(original.iter().flatten()) {
            assert_eq!(
                EvidenceRecord::try_from(retained.framed_record.as_slice())?,
                *original
            );
        }
        let report = Self::coverage(
            &source,
            &records,
            data.source_receipt(&source)?
                .ok_or("source receipt absent")?
                .cpu_id,
            "HEALTHY",
            1,
        )?;
        let authenticated = AuthenticatedEvidenceNodeV1 {
            tenant_id: source.tenant_id,
            node_id: source.node_id.clone(),
            node_boot_id: source.node_boot_id,
            label_epoch: source.label_epoch,
        };
        intake.receive_coverage(&authenticated, &report)?;
        let inputs = Arc::new(GraphInputs::default());
        let graph = GraphAndFindingOwner::new(data.clone(), inputs.clone())?;
        assert!(!data.discovery_enabled());
        data.set_commit_hook(AnalysisCommitStage::BeforeResultCommit, || {
            Err(Error::AnalysisConflict {
                location: snafu::Location::default(),
            })
        })?;
        assert!(graph.process(now).is_err());
        assert!(graph.snapshot(&source)?.is_none());
        for _ in 0..4 {
            if graph.process(now)? == 1 {
                break;
            }
        }
        let snapshot = graph.snapshot(&source)?.ok_or("graph result absent")?;
        assert_eq!(snapshot.findings.len(), 1);
        let finding = snapshot.findings[0].clone();
        assert_eq!(finding.state, FindingStateV1::Confirmed);
        assert_eq!(
            finding.effects[0].physical_result,
            GraphPhysicalResultV1::Prevented
        );
        let replay = Self::replay(&data, &source, &snapshot)?;
        Self::check_replay(&replay, &snapshot)?;
        let acceptance = replay::run(now)?;
        drop(connection);
        server.shutdown().await?;
        drop(intake);
        let mut result = Self::notify(&store, data.clone(), &graph, &finding, now)?;
        drop(graph);
        drop(data);
        drop(store);
        let store = ControlStore::open(&root)?;
        let data = Arc::new(AnalysisStore::open(&data_root)?);
        let graph = GraphAndFindingOwner::new(data.clone(), inputs)?;
        assert_eq!(graph.snapshot(&source)?, Some(snapshot.clone()));
        assert_eq!(graph.process(now + 11)?, 0);
        Self::resume(&store, &data, &graph, &finding, now, &mut result)?;
        fs::create_dir(&self.output)?;
        super::write_json(&self.output.join("graph.json"), &snapshot)?;
        super::write_json(
            &self.output.join("result.json"),
            &json!({
                "schema_version": 1, "case": "graph-notification", "result": "PASS",
                "qualification": "LIGHTWEIGHT", "discovery_enabled": false,
                "acknowledgements": acknowledgements, "accepted_cursors": cursors,
                "pending_upload_status": "UNAVAILABLE", "graph_id": snapshot.scope,
                "graph_revision": snapshot.input_manifest, "finding_id": finding.finding_id,
                "finding_revision": finding.revision, "evidence_digests": records.iter().map(|record|
                    crate::DigestV1::of(&record.framed_record).to_string()).collect::<Vec<_>>(),
                "source_coverage": snapshot.input_manifest.coverage, "notification": result, "acceptance": acceptance,
                "graph_decision": Self::decision(&finding),
                "transaction_failure_kept_progress": true, "reordered_duplicate_intake": true,
                "canonical_replay_equal": true, "physical_action_attempted": false,
                "performance_claim": false, "cross_node_qualified": false,
                "provider_issuance_qualified": false,
            }),
        )?;
        Ok(())
    }

    pub(super) fn decision(finding: &FindingV1) -> serde_json::Value {
        json!({
            "package_id": finding.package_id, "state": finding.state, "reason": finding.reason,
            "limits": finding.limits, "severity": finding.severity,
            "required_action": finding.required_action,
            "effects": finding.effects.iter().map(|effect| json!({
                "family": effect.effect_family, "operation": effect.operation,
                "decision": effect.source_decision, "reason": effect.source_reason,
                "configured_errno": effect.configured_errno, "kernel_result": effect.kernel_result,
                "physical_result": effect.physical_result, "proof_quality": effect.proof_quality,
            })).collect::<Vec<_>>(),
            "policy_states": finding.policy_provenance.iter().map(|policy| policy.state).collect::<Vec<_>>(),
            "policy_limits": finding.policy_provenance.iter().map(|policy| &policy.limits).collect::<Vec<_>>(),
        })
    }

    pub(super) fn native(cursor: u64, denied: bool) -> EffectObservationV1 {
        EffectObservationV1 {
            observed_boottime_ns: 100 + cursor,
            source_sequence: cursor,
            source_cpu_id: 3,
            task_cookie: 7,
            process_instance_id: [8; 16].into(),
            entry_instance_id: [9; 16].into(),
            binding_id: [10; 16].into(),
            execution_set_id: [11; 16].into(),
            authority_domain_id: [12; 16].into(),
            profile_generation_ref_id: 1,
            active_role_id: 1,
            process_state_vector_id: 1,
            admitted_entry_rule_id: 1,
            exact_object_key_id: if denied { 20 } else { 21 },
            composite_atom_id: if denied { 22 } else { 23 },
            reason: if denied {
                EffectObservationReasonV1::ExactPolicyDeny as u8
            } else {
                EffectObservationReasonV1::ExactPolicyAllow as u8
            },
            physical_result: if denied {
                EffectPhysicalResultV1::DeniedBeforeEffect as u8
            } else {
                EffectPhysicalResultV1::UnknownAfterPreEffect as u8
            },
            effect_family: KernelEffectFamilyV1::File as u16,
            operation: KernelEffectOperationV1::OpenRead as u16,
            configured_errno: if denied { -13 } else { 0 },
            kernel_result: if denied { -libc::EACCES } else { 0 },
            ..Default::default()
        }
    }

    pub(super) fn coverage(
        source: &EvidenceIntakeIdentityV1,
        records: &[AnalysisRecordV1],
        cpu_id: u32,
        state: &str,
        revision: u64,
    ) -> std::result::Result<CoverageReport, Box<dyn StdError>> {
        let record = EvidenceRecord::try_from(records[0].framed_record.as_slice())?;
        let first_sequence = record
            .decision_context
            .as_ref()
            .ok_or("coverage start context absent")?
            .original_kernel_sequence;
        let last_sequence = EvidenceRecord::try_from(
            records
                .last()
                .ok_or("coverage end absent")?
                .framed_record
                .as_slice(),
        )?
        .decision_context
        .ok_or("coverage end context absent")?
        .original_kernel_sequence;
        let count = u64::try_from(records.len())?;
        Ok(CoverageReport {
            source_id: source.source_id.to_vec(),
            cpu_id,
            source_epoch: source.source_epoch,
            revision,
            intervals: vec![CoverageInterval {
                current: true,
                interval_id: record.coverage_interval_id.to_vec(),
                source_epoch: source.source_epoch,
                revision,
                state: state.into(),
                first_sequence,
                last_sequence: Some(last_sequence),
                opening_counters: Some(CoverageCounters {
                    next_sequence: first_sequence
                        .checked_sub(1)
                        .ok_or("zero coverage sequence")?,
                    ..Default::default()
                }),
                closing_counters: Some(CoverageCounters {
                    attempted: count,
                    requested: count,
                    emitted: count,
                    next_sequence: last_sequence
                        .checked_add(1)
                        .ok_or("coverage sequence overflow")?,
                    ..Default::default()
                }),
                gap_reasons: if state == "GAPPED" {
                    vec!["RING_LOSS".into()]
                } else {
                    vec![]
                },
            }],
        })
    }

    pub(super) fn replay(
        data: &AnalysisStore,
        source: &EvidenceIntakeIdentityV1,
        snapshot: &GraphSnapshotV1,
    ) -> std::result::Result<GraphReplayInputV1, Box<dyn StdError>> {
        let receipt = data
            .source_receipt(source)?
            .ok_or("source receipt absent")?;
        let records = data
            .read_page(source, snapshot.first_cursor)?
            .records
            .into_iter()
            .take_while(|record| record.cursor <= snapshot.last_cursor)
            .map(|record| DiscoveryRecordV1::try_from((source, receipt.cpu_id, &record)))
            .collect::<Result<Vec<_>>>()?;
        let mut coverage = Vec::new();
        for key in &snapshot.input_manifest.coverage {
            let mut matching = Vec::new();
            for record in &records {
                if record.decode()?.coverage_interval_id.as_ref() == key.interval_id {
                    matching.push(record);
                }
            }
            coverage.push(DiscoveryCoverageV1 {
                stream: source.clone(),
                cpu_id: key.cpu_id,
                first_cursor: matching
                    .first()
                    .ok_or("coverage fixture start absent")?
                    .id
                    .durable_cursor,
                last_cursor: matching
                    .last()
                    .ok_or("coverage fixture end absent")?
                    .id
                    .durable_cursor,
                expected_records: u64::try_from(matching.len())?,
                coverage_revision: key.report_revision,
                coverage_interval_id: key.interval_id,
                state: key.state,
                gap_reasons: key.gap_reasons.clone(),
            });
        }
        Ok(GraphReplayInputV1 {
            source: source.clone(),
            coverage,
            records,
            coverage_keys: snapshot.input_manifest.coverage.clone(),
            facts: snapshot
                .input_manifest
                .context
                .iter()
                .map(|key| {
                    data.context_version(key)?
                        .ok_or_else(|| "retained graph fact absent".into())
                })
                .collect::<std::result::Result<_, Box<dyn StdError>>>()?,
            missing_ranges: snapshot.missing_ranges.clone(),
        })
    }

    pub(super) fn check_replay(
        input: &GraphReplayInputV1,
        snapshot: &GraphSnapshotV1,
    ) -> std::result::Result<(), Box<dyn StdError>> {
        let mut reordered = input.clone();
        reordered.records.reverse();
        reordered.records.extend(input.records.clone());
        reordered.facts.reverse();
        reordered.facts.extend(input.facts.clone());
        let replay = GraphAndFindingOwner::derive(&reordered)?;
        assert_eq!(replay.graph, snapshot.graph);
        assert_eq!(replay.findings, snapshot.findings);
        assert_eq!(
            serde_json::to_vec(&replay.findings)?,
            serde_json::to_vec(&snapshot.findings)?
        );
        let mut foreign = input.clone();
        foreign.source.tenant_id = [99; 16];
        assert!(GraphAndFindingOwner::derive(&foreign).is_err());
        let mut conflict = input.clone();
        let mut changed = conflict.records[0].clone();
        changed.original_kernel_sequence = Some(999);
        conflict.records.push(changed);
        assert!(GraphAndFindingOwner::derive(&conflict).is_err());
        Ok(())
    }

    fn grants(tenant: [u8; 16], now: u64) -> Vec<NotificationGrantV1> {
        [
            NotificationPrincipalV1::Service,
            NotificationPrincipalV1::Human,
            NotificationPrincipalV1::Agent,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, principal)| NotificationGrantV1 {
            tenant_id: tenant,
            principal_id: [u8::try_from(index + 1).unwrap_or(1); 16],
            principal,
            authorization_revision: 1,
            routes: vec!["human".into(), "primary".into()],
            operations: vec![
                NotificationOperationV1::Configure,
                NotificationOperationV1::Read,
                NotificationOperationV1::Acknowledge,
                NotificationOperationV1::RecordAgent,
            ],
            max_sensitivity: ContextSensitivityV1::HostRestricted,
            expires_utc_ns: now + 1_000_000,
        })
        .collect()
    }

    pub(super) fn notify(
        store: &ControlStore,
        data: Arc<AnalysisStore>,
        graph: &GraphAndFindingOwner,
        finding: &FindingV1,
        now: u64,
    ) -> std::result::Result<serde_json::Value, Box<dyn StdError>> {
        let grants = Self::grants(finding.tenant_id, now);
        let authority = Arc::new(ConfiguredNotificationAuthority::new(
            store.clone(),
            &grants,
        )?);
        let router = NotificationRouter::new(data, authority)?;
        router.route(graph, now)?;
        for (route, package) in [("human", "unused-package"), ("primary", "HF-PROC-001")] {
            router.configure(
                &grants[0],
                NotificationPolicyV1 {
                    tenant_id: finding.tenant_id,
                    route_id: route.into(),
                    revision: 1,
                    package_ids: vec![package.into()],
                    minimum_priority: NotificationPriorityV1::Critical,
                    acknowledgement_ns: 100,
                    retry_limit: 3,
                    retry_delay_ns: 10,
                    escalation_route_id: "human".into(),
                    max_sensitivity: ContextSensitivityV1::Tenant,
                    allow_concerns: false,
                },
                now + 1,
            )?;
        }
        router.route(graph, now + 1)?;
        let state = Self::one(&router, &grants[1], finding, now + 1)?;
        assert_eq!(state.deadline_utc_ns, Some(now + 100));
        assert_eq!(state.priority(), NotificationPriorityV1::Critical);
        let benign = router.record_agent(
            &grants[2],
            state.key,
            [4; 16],
            Some(NotificationAdvisoryV1 {
                suggested_priority: NotificationPriorityV1::Info,
                model_label: "benign-refused-to-investigate".into(),
            }),
            now + 1,
        )?;
        assert_eq!(benign.priority(), NotificationPriorityV1::Critical);
        assert!(benign.human_acknowledgement.is_none());
        assert!(router
            .acknowledge(&grants[2], state.key, [5; 16], now + 1)
            .is_err());
        router.deliver(
            graph,
            &IncidentSink::new(finding.finding_id.clone()),
            now + 1,
        )?;
        let failed = Self::one(&router, &grants[1], finding, now + 1)?;
        assert_eq!(
            failed
                .attempts
                .iter()
                .filter(|attempt| attempt.kind == NotificationDeliveryKindV1::Finding)
                .count(),
            1
        );
        assert_eq!(failed.failure, Some(NotificationFailureV1::TransportFailed));
        assert_eq!(failed.deadline_utc_ns, state.deadline_utc_ns);
        assert!(failed.human_acknowledgement.is_none());
        router.route(graph, now + 2)?;
        assert_eq!(Self::one(&router, &grants[1], finding, now + 2)?, failed);
        Ok(
            json!({"before_restart": failed, "deadline": state.deadline_utc_ns,
            "original_deadline_preserved": true, "single_obligation_per_finding": true}),
        )
    }

    pub(super) fn resume(
        store: &ControlStore,
        data: &Arc<AnalysisStore>,
        graph: &GraphAndFindingOwner,
        finding: &FindingV1,
        now: u64,
        result: &mut serde_json::Value,
    ) -> std::result::Result<(), Box<dyn StdError>> {
        let grants = Self::grants(finding.tenant_id, now);
        let authority = Arc::new(ConfiguredNotificationAuthority::new(
            store.clone(),
            &grants,
        )?);
        let router = NotificationRouter::new(data.clone(), authority)?;
        let before: NotificationObligationV1 =
            serde_json::from_value(result["before_restart"].clone())?;
        assert_eq!(Self::one(&router, &grants[1], finding, now + 11)?, before);
        router.route(graph, now + 11)?;
        let sink = IncidentSink {
            failed: AtomicBool::new(true),
            finding_id: finding.finding_id.clone(),
        };
        router.deliver(graph, &sink, now + 11)?;
        let retried = Self::one(&router, &grants[1], finding, now + 11)?;
        assert!(retried.failure.is_none());
        assert_eq!(
            retried
                .attempts
                .iter()
                .filter(|attempt| attempt.kind == NotificationDeliveryKindV1::Finding)
                .count(),
            2
        );
        assert!(retried.human_acknowledgement.is_none());
        router.deliver(graph, &sink, now + 101)?;
        let overdue = Self::one(&router, &grants[1], finding, now + 101)?;
        assert!(overdue.overdue(now + 101));
        assert_eq!(overdue.overdue_since_utc_ns, Some(now + 100));
        assert!(overdue
            .attempts
            .iter()
            .any(|attempt| attempt.kind == NotificationDeliveryKindV1::AcknowledgementEscalation));
        let mut foreign = grants[1].clone();
        foreign.tenant_id = [99; 16];
        assert!(router
            .acknowledge(&foreign, overdue.key, [6; 16], now + 101)
            .is_err());
        let human = router.acknowledge(&grants[1], overdue.key, [6; 16], now + 102)?;
        assert_eq!(human.deadline_utc_ns, Some(now + 100));
        assert_eq!(
            router.acknowledge(&grants[1], overdue.key, [6; 16], now + 103)?,
            human
        );
        assert!(!human.overdue(now + 103));
        assert_eq!(
            graph.finding(finding.tenant_id, &finding.finding_id, &finding.revision)?,
            Some(finding.clone())
        );
        result["after_restart"] = serde_json::to_value(retried)?;
        result["overdue"] = serde_json::to_value(overdue)?;
        result["human_receipt"] = serde_json::to_value(human.human_acknowledgement)?;
        result["final"] = serde_json::to_value(human)?;
        result["transitions"] = json!([
            "unrouted",
            "required-route",
            "delivery-failed",
            "restart",
            "delivery-retried",
            "human-overdue",
            "human-acknowledged"
        ]);
        Ok(())
    }

    fn one(
        router: &NotificationRouter,
        grant: &NotificationGrantV1,
        finding: &FindingV1,
        now: u64,
    ) -> std::result::Result<NotificationObligationV1, Box<dyn StdError>> {
        let states: Vec<_> = router
            .obligations(grant, now)?
            .into_iter()
            .filter(|state| {
                state
                    .finding
                    .as_ref()
                    .is_some_and(|reference| reference.finding_id == finding.finding_id)
            })
            .collect();
        assert_eq!(states.len(), 1);
        states
            .into_iter()
            .next()
            .ok_or_else(|| "required obligation absent".into())
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn graph_notification_roundtrip() -> crate::platform::TestResult<()> {
        let directory = tempfile::tempdir()?;
        let runner = super::GraphNotificationQualification::new(directory.path().join("proof"));
        runner.run().await?;
        assert!(runner.run().await.is_err());
        Ok(())
    }
}
