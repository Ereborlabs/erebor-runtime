use super::*;
use serde::Deserialize;

mod authority;
mod inputs;
#[cfg(test)]
mod lifetime;
mod window;

#[derive(Deserialize)]
struct Card {
    id: String,
    action: String,
    family: u16,
    operation: u16,
    contexts: Vec<(String, GraphContextActionV1)>,
}

struct ReplayQualification {
    graph: GraphAndFindingOwner,
    intake: EvidenceIntakeOwner,
    data: Arc<AnalysisStore>,
    inputs: Arc<GraphInputs>,
    execution: InstalledAnalysis,
    authenticated: AuthenticatedEvidenceNodeV1,
    now: u64,
    root: tempfile::TempDir,
}

pub(super) async fn run(now: u64) -> std::result::Result<serde_json::Value, Box<dyn StdError>> {
    let started = Instant::now();
    debug!(step = "replay_startup", "graph qualification step started");
    let fixture = ReplayQualification::new(now)?;
    let cards = ReplayQualification::incident_cards()?;
    assert_eq!(cards.len(), 12);
    debug!(
        step = "replay_startup",
        elapsed_ms = %started.elapsed().as_millis(),
        success = true,
        "graph qualification step finished"
    );
    let started = Instant::now();
    debug!(step = "incident_cards", "graph qualification step started");
    let mut results = Vec::new();
    for (index, card) in cards.into_iter().enumerate() {
        assert_eq!(card.id, format!("HF-{:03}", index + 1));
        results.push(fixture.card(&card, u8::try_from(index + 40)?)?);
    }
    debug!(
        step = "incident_cards",
        elapsed_ms = %started.elapsed().as_millis(),
        success = true,
        cards = results.len(),
        "graph qualification step finished"
    );
    let started = Instant::now();
    debug!(
        step = "replay_contracts",
        "graph qualification step started"
    );
    let reads = fixture.read_results()?;
    let sends = fixture.send_results()?;
    let authorization = authority::run(now)?;
    let local = fixture.local_contract()?;
    let nodes = fixture.nodes()?;
    debug!(
        step = "replay_contracts",
        elapsed_ms = %started.elapsed().as_millis(),
        success = true,
        "graph qualification step finished"
    );
    drop(fixture);
    let started = Instant::now();
    debug!(
        step = "notification_density",
        "graph qualification step started"
    );
    let density = ReplayQualification::new(now)?.notification_density().await;
    debug!(
        step = "notification_density",
        elapsed_ms = %started.elapsed().as_millis(),
        success = density.is_ok(),
        "graph qualification step finished"
    );
    let density = density?;
    let started = Instant::now();
    debug!(
        step = "native_window_64",
        "graph qualification step started"
    );
    let window = ReplayQualification::new(now)?.mixed_window().await;
    debug!(
        step = "native_window_64",
        elapsed_ms = %started.elapsed().as_millis(),
        success = window.is_ok(),
        "graph qualification step finished"
    );
    let window = window?;
    let started = Instant::now();
    debug!(
        step = "native_window_185",
        "graph qualification step started"
    );
    let physical_window = ReplayQualification::new(now)?.physical_window().await;
    debug!(
        step = "native_window_185",
        elapsed_ms = %started.elapsed().as_millis(),
        success = physical_window.is_ok(),
        "graph qualification step finished"
    );
    let physical_window = physical_window?;
    Ok(json!({"incident_cards": results, "HF-LOCAL-001": {
        "families": ["exec", "file", "network", "device"],
        "qualification": "RECORDED_GRAPH_REPLAY", "physical_incident_reproduced": false,
        "original_effect_qualification": "UNSUPPORTED",
        "original_effect_limit": "PROJECTED_TOKEN_AND_CONTROLLER_CONTROL_NOT_QUALIFIED",
        "healthy": "confirmed-native-denial", "gapped": "coverage-insufficient",
        "legitimate_control_unflagged": true,
    }, "local_contract": local, "HF-XNODE-001": nodes,
        "NOTIFICATION-DENSITY-001": density,
        "NATIVE-TRAVERSAL-WINDOW-001": window,
        "NATIVE-TRAVERSAL-PHYSICAL-WINDOW-001": physical_window,
        "HF-011-READ-RESULT-001": reads, "HF-004-RESULT-001": sends,
        "AUTHORIZATION-REPLAY-004": authorization,
        "proof_boundary": "Recorded kernel, Control, read-completion, and remote audit inputs check production package contracts. No provider collector, provider issuance, cross-node physical result, or response execution is qualified."}))
}

impl ReplayQualification {
    async fn notification_density(
        self,
    ) -> std::result::Result<serde_json::Value, Box<dyn StdError>> {
        let mut sources = Vec::new();
        for first in (0..257).step_by(8) {
            let raw = (first..(first + 8).min(257))
                .map(|index| {
                    let mut record =
                        GraphNotificationQualification::native(index - first + 1, true);
                    record.task_cookie = index + 1;
                    record.process_instance_id = EvidenceIdV1::new(8, index + 1);
                    record.admitted_entry_rule_id = 0;
                    record
                })
                .collect::<Vec<_>>();
            sources.push(self.accept_node(
                u8::try_from(200 + first / 8)?,
                &raw,
                &self.authenticated,
                false,
            )?);
        }
        let graph = &self.graph;
        for _ in 0..512 {
            graph.process(self.now)?;
            let mut complete = true;
            for source in &sources {
                complete &= graph.snapshot(source)?.is_some();
            }
            if complete {
                break;
            }
        }
        let findings = graph.current_findings(self.authenticated.tenant_id)?;
        assert_eq!(findings.len(), 257);
        assert_eq!(sources.len(), 33);
        let (dense_result_id, first) = findings.first().ok_or("first finding absent")?.clone();
        let dense_snapshot = graph
            .snapshot_result(self.authenticated.tenant_id, &dense_result_id)?
            .ok_or("dense graph result absent")?;
        let dense_traversal = GraphNotificationQualification::traverse(
            self.data.clone(),
            &dense_snapshot,
            &first,
            &dense_result_id,
            self.now,
        )
        .await?;
        let grants = GraphNotificationQualification::grants(self.authenticated.tenant_id, self.now);
        let store = ControlStore::open(self.root.path().join("notification-control"))?;
        let authority = Arc::new(ConfiguredNotificationAuthority::new(
            store.clone(),
            &grants,
        )?);
        let router = NotificationRouter::new(self.data.clone(), authority)?;
        assert_eq!(router.route(graph, self.now)?, 256);
        let health = router.health(&grants[1], self.now)?;
        assert_eq!(health.obligations, 256);
        assert_eq!(health.unrouted, 256);
        assert!(!health.routing_available);
        let prefix = router.obligations(&grants[1], self.now)?;
        let (_, tail) = findings.last().ok_or("tail finding absent")?.clone();
        assert!(prefix.iter().all(|state| {
            state
                .finding
                .as_ref()
                .is_none_or(|reference| reference.finding_id != tail.finding_id)
        }));
        drop(router);
        drop(store);
        let Self {
            root,
            graph,
            intake,
            data,
            inputs,
            execution,
            authenticated,
            now,
        } = self;
        drop(graph);
        drop(intake);
        drop(execution);
        drop(data);
        let data = Arc::new(AnalysisStore::open(root.path().join("analysis"))?);
        let store = ControlStore::open(root.path().join("notification-control"))?;
        let graph = GraphAndFindingOwner::new(
            data.clone(),
            inputs.clone(),
            InstalledAnalysis::testing(Some(data.clone()), authenticated.tenant_id)?,
        )?;
        assert_eq!(data.source_page(authenticated.tenant_id, None)?.len(), 33);
        assert_eq!(graph.current_findings(authenticated.tenant_id)?.len(), 257);
        assert_eq!(
            graph.snapshot_result(authenticated.tenant_id, &dense_result_id)?,
            Some(dense_snapshot.clone())
        );
        assert_eq!(
            GraphNotificationQualification::traverse(
                data.clone(),
                &dense_snapshot,
                &first,
                &dense_result_id,
                now,
            )
            .await?,
            dense_traversal
        );
        let authority = Arc::new(ConfiguredNotificationAuthority::new(
            store.clone(),
            &grants,
        )?);
        let router = NotificationRouter::new(data.clone(), authority)?;
        assert_eq!(router.obligations(&grants[1], now)?, prefix);
        assert_eq!(router.route(&graph, now)?, 0);
        assert_eq!(router.route(&graph, now)?, 1);
        let dense = router.health(&grants[1], now)?;
        assert_eq!(dense.obligations, 257);
        assert_eq!(dense.unrouted, 257);
        assert!(matches!(
            router.obligations(&grants[1], now),
            Err(araphor_analysis_back::Error::Data {
                source: Error::Notification {
                    code: NotificationErrorCodeV1::Limit,
                    field: "notification read count",
                    ..
                }
            })
        ));
        let mut after = None;
        let mut retained = Vec::new();
        loop {
            let (page, next) = router.obligations_page(&grants[1], after, now)?;
            assert!(page.len() <= 256);
            retained.extend(page);
            let Some(next) = next else {
                break;
            };
            after = Some(next);
        }
        assert_eq!(retained.len(), 257);
        for state in &prefix {
            assert!(retained.contains(state));
        }
        assert!(retained.iter().any(|state| {
            state
                .finding
                .as_ref()
                .is_some_and(|reference| reference.finding_id == tail.finding_id)
        }));
        drop(router);
        let mut lifecycle =
            GraphNotificationQualification::notify(&store, data.clone(), &graph, &first, now)?;
        assert_eq!(lifecycle["unrouted_health"]["obligations"], 257);
        assert_eq!(
            lifecycle["ambient_heads"].as_array().map(Vec::len),
            Some(256)
        );
        drop(graph);
        drop(data);
        drop(store);
        let data = Arc::new(AnalysisStore::open(root.path().join("analysis"))?);
        let store = ControlStore::open(root.path().join("notification-control"))?;
        let graph = GraphAndFindingOwner::new(
            data.clone(),
            inputs.clone(),
            InstalledAnalysis::testing(Some(data.clone()), authenticated.tenant_id)?,
        )?;
        GraphNotificationQualification::resume(&store, &data, &graph, &first, now, &mut lifecycle)?;
        assert_eq!(lifecycle["final_health"]["obligations"], 257);
        assert_eq!(lifecycle["final_health"]["unrouted"], 256);
        let authority = Arc::new(ConfiguredNotificationAuthority::new(
            store.clone(),
            &grants,
        )?);
        let router = NotificationRouter::new(data.clone(), authority)?;
        let before = GraphNotificationQualification::one(&router, &grants[1], &first, now + 103)?;
        assert_eq!(router.route(&graph, now + 103)?, 255);
        let old = GraphNotificationQualification::finding_ref(&graph, &first)?;
        let record = first
            .effects
            .first()
            .ok_or("first effect absent")?
            .evidence
            .clone();
        inputs.insert(
            GraphFactV1 {
                record_id: record.clone(),
                value: GraphFactValueV1::Baseline {
                    role_id: 1,
                    state_id: 1,
                    outside_reviewed_baseline: true,
                    reviewed_policy_revision: "recorded-reviewed-source".into(),
                },
            },
            "late-dense-baseline",
            1,
        )?;
        assert!(graph.refresh(&record.stream, now + 104)?);
        let (result_id, revised) = graph
            .current_finding(authenticated.tenant_id, &first.finding_id)?
            .ok_or("revised first finding absent")?;
        assert_ne!(revised.revision, first.revision);
        assert_eq!(revised.required_action, first.required_action);
        assert_eq!(
            graph.finding_result(first.tenant_id, &old.result_id, &old.finding_id)?,
            Some(first)
        );
        assert!(matches!(
            router.route_finding(&graph, authenticated.tenant_id, &old, now + 104),
            Err(araphor_analysis_back::Error::Data {
                source: Error::Notification {
                    code: NotificationErrorCodeV1::Conflict,
                    field: "current finding reference",
                    ..
                }
            })
        ));
        router.configure(
            &grants[0],
            NotificationPolicyV1 {
                tenant_id: authenticated.tenant_id,
                route_id: "primary".into(),
                revision: 2,
                package_ids: vec!["HF-PROC-001".into()],
                minimum_priority: NotificationPriorityV1::High,
                acknowledgement_ns: 1_000,
                retry_limit: 3,
                retry_delay_ns: 10,
                escalation_route_id: "human".into(),
                max_sensitivity: ContextSensitivityV1::Tenant,
                allow_concerns: false,
            },
            now + 104,
        )?;
        assert_eq!(router.route(&graph, now + 104)?, 1);
        assert_eq!(router.route(&graph, now + 104)?, 256);
        let updated =
            GraphNotificationQualification::one(&router, &grants[1], &revised, now + 104)?;
        assert_eq!(updated.key, before.key);
        assert_eq!(updated.first_seen_utc_ns, before.first_seen_utc_ns);
        assert_eq!(updated.deadline_utc_ns, before.deadline_utc_ns);
        assert_eq!(updated.attempts, before.attempts);
        assert_eq!(updated.minimum_priority, before.minimum_priority);
        assert!(updated.source_priority >= before.source_priority);
        assert_ne!(updated.finding_revision, before.finding_revision);
        assert_eq!(updated.route.as_ref().map(|route| route.revision), Some(2));
        assert_eq!(
            updated
                .finding
                .as_ref()
                .map(|reference| &reference.result_id),
            Some(&result_id)
        );
        assert!(updated.overdue(now + 104));
        let sink = IncidentSink {
            failed: AtomicBool::new(true),
            finding_id: revised.finding_id.clone(),
        };
        let mut capacity = None;
        for _ in 0..4 {
            match router.deliver(&graph, &sink, now + 104) {
                Ok(_) => {}
                Err(araphor_analysis_back::Error::Data {
                    source: Error::StorageCapacity { resource, .. },
                }) => {
                    capacity = Some(resource);
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        assert_eq!(capacity, Some("tenant retained revisions"));
        let pressure = router.health(&grants[1], now + 104)?;
        assert_eq!(pressure.obligations, 257);
        assert_eq!(pressure.unrouted, 0);
        assert_eq!(graph.current_findings(authenticated.tenant_id)?.len(), 257);
        Ok(json!({
            "qualification": "RECORDED_GRAPH_REPLAY",
            "input": "257-denied-effects-before-route-configuration",
            "current_findings": findings.len(),
            "native_traversal": {
                "retained_findings": findings.len(), "retained_source_windows": sources.len(),
                "fresh_query_owner": true, "before_notification_routing": true,
                "reopen_equal": true, "query": dense_traversal,
            },
            "persisted_obligations": dense.obligations,
            "result": "PASS", "work_bound": 256, "page_bound": 256,
            "analysis_store_reopened": true, "restart_prefix_unchanged": true,
            "tail_progress_after_restart": true, "earlier_key_revisited": true,
            "route_revision": 2, "original_deadline_preserved": true,
            "priority_floors_preserved": true, "attempts_preserved": true,
            "point_notification": lifecycle,
            "capacity_error": {"code": "STORAGE_CAPACITY", "resource": capacity},
            "storage_quotas": {"tenant_retained_revisions": 1024, "global_retained_revisions": 4096},
            "backpressure_health": pressure,
            "empty_configuration_healthy": false,
            "findings_retained": true, "bound_disabled": false,
        }))
    }

    fn new(now: u64) -> std::result::Result<Self, Box<dyn StdError>> {
        let root = tempfile::tempdir()?;
        let store = ControlStore::open(root.path().join("control"))?;
        let data = Arc::new(AnalysisStore::open(root.path().join("analysis"))?);
        let execution = InstalledAnalysis::testing_tenants(
            Some(data.clone()),
            &[EvidenceIdV1::new(1, 2).to_be_bytes(), [201; 16]],
        )?;
        let intake = EvidenceIntakeOwner::new(
            store,
            data.clone(),
            Arc::new(Clock(UNIX_EPOCH + Duration::from_nanos(now))),
        )?;
        let inputs = Arc::new(GraphInputs::default());
        let graph = GraphAndFindingOwner::new(data.clone(), inputs.clone(), execution.clone())?;
        Ok(Self {
            graph,
            intake,
            data,
            inputs,
            execution,
            now,
            authenticated: AuthenticatedEvidenceNodeV1 {
                tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
                node_id: "node-a".into(),
                node_boot_id: [7; 16],
                label_epoch: 1,
            },
            root,
        })
    }

    fn accept(
        &self,
        source: u8,
        raw: &[EffectObservationV1],
    ) -> std::result::Result<EvidenceIntakeIdentityV1, Box<dyn StdError>> {
        self.accept_node(source, raw, &self.authenticated, true)
    }

    fn accept_node(
        &self,
        source: u8,
        raw: &[EffectObservationV1],
        authenticated: &AuthenticatedEvidenceNodeV1,
        health: bool,
    ) -> std::result::Result<EvidenceIntakeIdentityV1, Box<dyn StdError>> {
        let wal = EffectObservationStore::durable(
            8,
            self.root.path().join(format!("node-{source}")).join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(
                authenticated.tenant_id.into(),
                [source; 16].into(),
                1,
                authenticated.node_boot_id.into(),
            )?,
        )?;
        if health {
            wal.sample_coverage_health([EffectObservationHealthV1::default(); 4].as_bytes())?;
        }
        for event in raw {
            wal.record_bytes(event.as_bytes());
        }
        let batch = wal.next_evidence_batch().ok_or("recorded batch absent")?;
        let batch: mithril_control::EvidenceBatch = batch.into();
        let source = EvidenceIntakeIdentityV1 {
            tenant_id: authenticated.tenant_id,
            node_id: authenticated.node_id.clone(),
            node_boot_id: authenticated.node_boot_id,
            label_epoch: 1,
            source_id: batch.source_id.as_slice().try_into()?,
            source_epoch: batch.source_epoch,
        };
        let ack = self.intake.receive(authenticated, batch.clone())?;
        assert_eq!(ack.contiguous_cursor, raw.len() as u64);
        assert_eq!(
            self.intake
                .receive(authenticated, batch.clone())?
                .contiguous_cursor,
            ack.contiguous_cursor
        );
        let mut foreign = source.clone();
        foreign.tenant_id = [99; 16];
        assert!(self.data.source_receipt(&foreign)?.is_none());
        assert_eq!(self.intake.contiguous_cursor(&foreign)?, 0);
        let records = self.data.read_page(&source, 1)?.records;
        self.intake.receive_coverage(
            authenticated,
            &GraphNotificationQualification::coverage(
                &source,
                &records,
                self.data
                    .source_receipt(&source)?
                    .ok_or("source receipt absent")?
                    .cpu_id,
                "HEALTHY",
                1,
            )?,
        )?;
        Ok(source)
    }

    fn snapshot(
        &self,
        source: &EvidenceIntakeIdentityV1,
    ) -> std::result::Result<GraphSnapshotV1, Box<dyn StdError>> {
        let graph = &self.graph;
        for _ in 0..32 {
            let started = Instant::now();
            debug!(step = "graph_process", "graph qualification step started");
            let processed = graph.process(self.now);
            debug!(
                step = "graph_process",
                elapsed_ms = %started.elapsed().as_millis(),
                success = processed.is_ok(),
                "graph qualification step finished"
            );
            processed?;
            let started = Instant::now();
            debug!(step = "graph_snapshot", "graph qualification step started");
            let snapshot = graph.snapshot(source);
            debug!(
                step = "graph_snapshot",
                elapsed_ms = %started.elapsed().as_millis(),
                success = snapshot.is_ok(),
                "graph qualification step finished"
            );
            if let Some(snapshot) = snapshot? {
                return Ok(snapshot);
            }
        }
        Err("graph source did not reach its accepted cursor".into())
    }

    fn record(
        &self,
        source: &EvidenceIntakeIdentityV1,
        cursor: u64,
    ) -> std::result::Result<DiscoveryRecordV1, Box<dyn StdError>> {
        let receipt = self.data.source_receipt(source)?.ok_or("receipt absent")?;
        let record = self
            .data
            .read_page(source, cursor)?
            .records
            .into_iter()
            .next()
            .ok_or("record absent")?;
        Ok(DiscoveryRecordV1::try_from((
            source,
            receipt.cpu_id,
            &record,
        ))?)
    }

    fn result_snapshot(
        &self,
        graph: &GraphAndFindingOwner,
        source: &EvidenceIntakeIdentityV1,
        package: &str,
    ) -> std::result::Result<GraphSnapshotV1, Box<dyn StdError>> {
        assert!(graph.current_findings([99; 16])?.is_empty());
        let (result_id, finding) = graph
            .current_findings(source.tenant_id)?
            .into_iter()
            .find(|(_, finding)| {
                finding.package_id == package
                    && finding.evidence.iter().any(|id| &id.stream == source)
            })
            .ok_or("current package finding absent")?;
        let snapshot = graph
            .snapshot_result(source.tenant_id, &result_id)?
            .ok_or("current package graph absent")?;
        assert!(snapshot.findings.contains(&finding));
        Ok(snapshot)
    }

    fn card(
        &self,
        card: &Card,
        source_id: u8,
    ) -> std::result::Result<serde_json::Value, Box<dyn StdError>> {
        let source = self.card_input(card, source_id)?;
        let anchor = self.record(&source, 2)?;
        let snapshot = self.snapshot(&source)?;
        let native = snapshot
            .findings
            .iter()
            .find(|finding| {
                finding
                    .effects
                    .iter()
                    .any(|effect| effect.evidence.durable_cursor == 1)
            })
            .ok_or("native finding absent")?;
        assert_eq!(native.state, FindingStateV1::Confirmed);
        assert_eq!(
            native.effects[0].physical_result,
            GraphPhysicalResultV1::Prevented
        );
        assert!(snapshot
            .findings
            .iter()
            .filter(|finding| finding.subject_id.kind != GraphSubjectKindV1::External)
            .all(|finding| !finding.evidence.iter().any(|id| id.durable_cursor == 2)));
        let mut contexts = Vec::new();
        for (action, classification) in &card.contexts {
            let context = snapshot
                .findings
                .iter()
                .find(|finding| finding.subject_id.identity == action.as_bytes())
                .ok_or("context finding absent")?;
            assert!(context.effects.is_empty());
            assert!(context.policy_provenance.is_empty());
            if *classification == GraphContextActionV1::OutsideAuthority {
                assert!(snapshot
                    .graph
                    .branches
                    .iter()
                    .any(|branch| branch.seed == context.subject_id
                        && branch.state == GraphBranchStateV1::OutsideAuthority));
            }
            contexts.push(json!({
                "action": action, "input_classification": classification,
                "state": context.state, "reason": context.reason, "limits": context.limits,
                "physical_result": null, "native_effects": context.effects.len(),
                "local_authority": false,
            }));
        }
        let input = GraphNotificationQualification::replay(&self.data, &source, &snapshot)?;
        GraphNotificationQualification::check_replay(&input, &snapshot)?;
        let mut gap = input.clone();
        gap.coverage[0].state = DiscoveryCoverageStateV1::Gapped;
        gap.coverage[0].gap_reasons = vec!["RING_LOSS".into()];
        gap.coverage_keys[0].state = DiscoveryCoverageStateV1::Gapped;
        gap.coverage_keys[0].gap_reasons = vec!["RING_LOSS".into()];
        let gapped = GraphAndFindingOwner::derive(&gap, &self.execution)?;
        assert!(gapped
            .findings
            .iter()
            .filter(|finding| !finding.effects.is_empty())
            .all(|finding| finding.state == FindingStateV1::CoverageInsufficient));
        let mut reversed = gap.clone();
        reversed.records.reverse();
        reversed.facts.reverse();
        assert_eq!(
            gapped.findings,
            GraphAndFindingOwner::derive(&reversed, &self.execution)?.findings
        );
        let late = self.late_card(&source, native)?;
        let mut device = GraphNotificationQualification::native(1, true);
        device.effect_family = KernelEffectFamilyV1::Device as u16;
        device.operation = KernelEffectOperationV1::OpenRead as u16;
        if source_id == 40 {
            let device_source = self.accept(90, &[device])?;
            assert_eq!(
                self.snapshot(&device_source)?.findings[0].effects[0].physical_result,
                GraphPhysicalResultV1::Prevented
            );
        }
        Ok(
            json!({"id": card.id, "action": card.action, "result": "PASS",
            "qualification": "RECORDED_GRAPH_REPLAY", "physical_incident_reproduced": false,
            "accepted_inputs": {"source": source, "denied_record": self.record(&source, 1)?.id,
                "allowed_control_record": anchor.id, "native_source": "SYNTHETIC_NODE_WAL",
                "context_source": "RECORDED_EXTERNAL_FACTS"},
            "graph_revision": snapshot.input_manifest,
            "finding_ids": snapshot.findings.iter().map(|finding| &finding.finding_id).collect::<Vec<_>>(),
            "managed_effect": GraphNotificationQualification::decision(native),
            "allowed_control": {"family": card.family, "operation": card.operation,
                "decision": "allowed-admission", "kernel_result": 0, "bytes_read_proven": false},
            "contexts": contexts, "legitimate_control_unflagged": true,
            "duplicate_reordered_equal": true, "gapped_state": "COVERAGE_INSUFFICIENT", "late": late}),
        )
    }

    fn late_card(
        &self,
        source: &EvidenceIntakeIdentityV1,
        original: &FindingV1,
    ) -> std::result::Result<serde_json::Value, Box<dyn StdError>> {
        let record = self.record(source, 1)?;
        self.policy(&record)?;
        let graph = &self.graph;
        assert!(graph.refresh(source, self.now + 300_000_000_000)?);
        let late = self.result_snapshot(graph, source, &original.package_id)?;
        let finding = late
            .findings
            .iter()
            .find(|finding| finding.finding_id == original.finding_id)
            .ok_or("late finding absent")?;
        assert_ne!(finding.revision, original.revision);
        assert_eq!(finding.state, FindingStateV1::Confirmed);
        assert!(finding
            .policy_provenance
            .iter()
            .all(|policy| policy.state == PolicyProvenanceStateV1::Exact));
        assert_eq!(
            graph.finding(original.tenant_id, &original.finding_id, &original.revision)?,
            Some(original.clone())
        );
        let mut contradiction = finding
            .policy_provenance
            .first()
            .ok_or("late policy absent")?
            .clone();
        contradiction.state = PolicyProvenanceStateV1::Contradicted;
        contradiction.limits = vec!["RECORDED_ACTIVATION_CONTRADICTION".into()];
        self.contradiction_input(&record, contradiction)?;
        assert!(graph.refresh(source, self.now + 300_000_000_001)?);
        let contradicted = self.result_snapshot(graph, source, &original.package_id)?;
        let conflict = contradicted
            .findings
            .iter()
            .find(|finding| finding.finding_id == original.finding_id)
            .ok_or("contradicted finding absent")?;
        assert_eq!(conflict.reason, FindingReasonV1::Contradiction);
        assert_eq!(conflict.state, FindingStateV1::CoverageInsufficient);
        assert_eq!(
            conflict.effects[0].physical_result,
            GraphPhysicalResultV1::Prevented
        );
        assert_ne!(conflict.revision, finding.revision);
        assert_eq!(
            graph.finding(finding.tenant_id, &finding.finding_id, &finding.revision)?,
            Some(finding.clone())
        );
        let input = GraphNotificationQualification::replay(&self.data, source, &contradicted)?;
        GraphNotificationQualification::check_replay(&input, &contradicted)?;
        Ok(json!({
            "operation": "PRODUCTION_GRAPH_REFRESH", "accepted_cursor_unchanged": true,
            "late_revision": finding.revision, "late_decision": GraphNotificationQualification::decision(finding),
            "contradictory_revision": conflict.revision, "contradictory_decision": GraphNotificationQualification::decision(conflict),
            "earlier_revision_unchanged": true, "contradiction_retained": true,
        }))
    }

    fn local_contract(&self) -> std::result::Result<Vec<serde_json::Value>, Box<dyn StdError>> {
        let mut results = Vec::new();
        for (offset, name) in [
            "activation-missing",
            "activation-exact",
            "entry-rule-missing",
            "initial-health-missing",
        ]
        .into_iter()
        .enumerate()
        {
            let mut denied = GraphNotificationQualification::native(1, true);
            if name == "entry-rule-missing" {
                denied.admitted_entry_rule_id = 0;
            }
            let source = self.accept_node(
                u8::try_from(91 + offset)?,
                &[denied],
                &self.authenticated,
                name != "initial-health-missing",
            )?;
            if name == "activation-exact" {
                self.policy(&self.record(&source, 1)?)?;
            }
            let snapshot = self.snapshot(&source)?;
            let finding = snapshot.findings.first().ok_or("local finding absent")?;
            if matches!(name, "entry-rule-missing" | "initial-health-missing") {
                assert_eq!(finding.state, FindingStateV1::CoverageInsufficient);
            } else {
                assert_eq!(finding.state, FindingStateV1::Confirmed);
            }
            results.push(
                json!({"input": name, "accepted_record": self.record(&source, 1)?.id,
                "decision": GraphNotificationQualification::decision(finding)}),
            );
        }
        Ok(results)
    }

    fn nodes(&self) -> std::result::Result<serde_json::Value, Box<dyn StdError>> {
        let remote = AuthenticatedEvidenceNodeV1 {
            tenant_id: self.authenticated.tenant_id,
            node_id: "node-b".into(),
            node_boot_id: [14; 16],
            label_epoch: 1,
        };
        let raw = GraphNotificationQualification::native(1, true);
        let local = self.accept(130, &[raw])?;
        let remote = self.accept_node(131, &[raw], &remote, true)?;
        let first = self.snapshot(&local)?;
        let second = self.snapshot(&remote)?;
        assert_ne!(first.findings[0].subject_id, second.findings[0].subject_id);
        assert_eq!(first.findings[0].state, FindingStateV1::Confirmed);
        assert_eq!(second.findings[0].state, FindingStateV1::Confirmed);
        let mut mixed = GraphNotificationQualification::replay(&self.data, &local, &first)?;
        mixed.records.push(self.record(&remote, 1)?);
        assert!(matches!(
            GraphAndFindingOwner::derive(&mixed, &self.execution),
            Err(araphor_analysis_back::Error::Data {
                source: Error::GraphInvalid {
                    field: "replay record identity",
                    ..
                }
            })
        ));
        self.partial_node_input(&local, &remote)?;
        let graph = &self.graph;
        assert!(graph.refresh(&local, self.now + 1)?);
        let partial = self.result_snapshot(graph, &local, "HF-XNODE-001")?;
        let finding = partial
            .findings
            .iter()
            .find(|finding| finding.package_id == "HF-XNODE-001")
            .ok_or("cross-node partial finding absent")?;
        assert_eq!(finding.state, FindingStateV1::CoverageInsufficient);
        assert!(finding
            .limits
            .contains(&"REMOTE_RUNTIME_ADMISSION_MISSING".into()));
        assert!(finding
            .limits
            .contains(&"CROSS_NODE_CAUSALITY_UNQUALIFIED".into()));
        assert!(partial
            .graph
            .edges
            .iter()
            .all(|edge| edge.key.edge_type != GraphEdgeTypeV1::NativeParent));
        GraphNotificationQualification::check_replay(
            &GraphNotificationQualification::replay(&self.data, &local, &partial)?,
            &partial,
        )?;
        Ok(json!({"qualification": "RECORDED_TWO_NODE_OWNER_REPLAY",
            "sources": [local, remote], "native_subjects": [first.findings[0].subject_id.clone(), second.findings[0].subject_id.clone()],
            "local_findings": [first.findings[0].revision.clone(), second.findings[0].revision.clone()],
            "mixed_source_rejected": true, "partial_cross_node_decision": GraphNotificationQualification::decision(finding),
            "remote_runtime_admission": "MISSING", "cross_node_causality": "UNQUALIFIED",
            "physical_multi_node_qualified": false, "kubernetes_collector_qualified": false}))
    }

    fn proof() -> ProofQualityV1 {
        ProofQualityV1 {
            source_authority: SourceAuthorityV1::AuthoritativeProvider,
            local_subject_binding: LocalSubjectBindingV1::ExactProcess,
            remote_subject_binding: RemoteSubjectBindingV1::ExactRequest,
            operation_result_authority: OperationResultAuthorityV1::AuthoritativeSucceeded,
            temporal_coverage: TemporalCoverageV1::Complete,
            integrity: ProofIntegrityV1::Signed,
        }
    }

    fn policy(&self, record: &DiscoveryRecordV1) -> std::result::Result<(), Box<dyn StdError>> {
        let activation = self.inputs.insert(
            GraphFactV1 {
                record_id: record.id.clone(),
                value: GraphFactValueV1::Activation(GraphPolicyActivationV1 {
                    tenant_id: uuid::Uuid::from_bytes(record.id.stream.tenant_id).to_string(),
                    node_id: record.id.stream.node_id.clone(),
                    node_boot_id: record.id.stream.node_boot_id.to_vec(),
                    label_epoch: record.id.stream.label_epoch,
                    candidate_content_id: "recorded-candidate".into(),
                    policy_source_revision_id: "recorded-reviewed-source".into(),
                    target_snapshot_digest: "recorded-target".into(),
                    state: "ACTIVE".into(),
                    node_bound_generation_digest: Some("recorded-generation".into()),
                    profile_generation_ref_id: Some(1),
                    readback_digest: Some("recorded-readback".into()),
                    probe_result_digest: Some("recorded-probe".into()),
                    reason_code: None,
                    observed_utc_ns: i64::try_from(self.now)?,
                }),
            },
            "activation",
            1,
        )?;
        self.inputs.insert(
            GraphFactV1 {
                record_id: record.id.clone(),
                value: GraphFactValueV1::Policy(PolicyObservationProvenanceV1 {
                    source: record.id.stream.clone(),
                    profile_generation_ref_id: 1,
                    observations: vec![record.id.clone()],
                    policy_source_revision_id: Some("recorded-reviewed-source".into()),
                    candidate_content_id: Some("recorded-candidate".into()),
                    target_snapshot_digest: Some("recorded-target".into()),
                    node_bound_generation_digest: Some("recorded-generation".into()),
                    activation_acknowledgement: Some(activation),
                    state: PolicyProvenanceStateV1::Exact,
                    limits: vec![],
                }),
            },
            "policy",
            1,
        )?;
        Ok(())
    }

    fn read_results(&self) -> std::result::Result<Vec<serde_json::Value>, Box<dyn StdError>> {
        let mut results = Vec::new();
        for (index, (name, path, result, bytes)) in [
            ("open-admission", GraphReadPathV1::Read, 0, 0),
            ("zero-read", GraphReadPathV1::Read, 0, 0),
            ("eof", GraphReadPathV1::Read, 0, 0),
            ("EIO", GraphReadPathV1::Read, -5, 0),
            ("partial-positive", GraphReadPathV1::Read, 1, 1),
            ("mmap-admission-address", GraphReadPathV1::Mmap, 4096, 0),
            ("inherited-fd", GraphReadPathV1::InheritedFd, 1, 1),
            ("io-uring", GraphReadPathV1::IoUring, 1, 1),
            ("resident-memory", GraphReadPathV1::Memory, 1, 1),
        ]
        .into_iter()
        .enumerate()
        {
            let operation = if name == "open-admission" {
                KernelEffectOperationV1::OpenRead
            } else if path == GraphReadPathV1::Mmap {
                KernelEffectOperationV1::MmapRead
            } else {
                KernelEffectOperationV1::Read
            };
            let completion = if name == "open-admission" || path == GraphReadPathV1::Mmap {
                None
            } else {
                Some((result, bytes))
            };
            let (read, network, authority) = self.completion_inputs(
                u8::try_from(index + 100)?,
                name,
                path,
                operation,
                completion,
            )?;
            let source = read.id.stream.clone();
            let earlier = self.snapshot(&source)?;
            self.inputs.insert(authority.clone(), "late-authority", 1)?;
            let graph = &self.graph;
            assert!(graph.refresh(&source, self.now + 300_000_000_000)?);
            let snapshot = self.result_snapshot(graph, &source, "HF-DW-001")?;
            assert_ne!(snapshot.input_manifest, earlier.input_manifest);
            let finding = snapshot
                .findings
                .iter()
                .find(|finding| finding.package_id == "HF-DW-001")
                .ok_or("credential finding absent")?;
            let proved = result > 0
                && !matches!(path, GraphReadPathV1::Memory | GraphReadPathV1::Mmap)
                && name != "open-admission";
            assert_eq!(
                finding.state,
                if proved {
                    FindingStateV1::Confirmed
                } else {
                    FindingStateV1::CoverageInsufficient
                }
            );
            assert!(finding.limits.contains(&"TLS_PAYLOAD_UNOBSERVABLE".into()));
            assert!(finding
                .effects
                .iter()
                .all(|effect| effect.physical_result == GraphPhysicalResultV1::Unknown));
            for old in &earlier.findings {
                assert_eq!(
                    graph.finding(source.tenant_id, &old.finding_id, &old.revision)?,
                    Some(old.clone())
                );
            }
            let input = GraphNotificationQualification::replay(&self.data, &source, &snapshot)?;
            GraphNotificationQualification::check_replay(&input, &snapshot)?;
            let mut borrowed_completions = Vec::new();
            if matches!(
                path,
                GraphReadPathV1::InheritedFd | GraphReadPathV1::IoUring
            ) {
                for name in ["other-admission", "other-process"] {
                    let borrowed = if name == "other-admission" {
                        Self::borrowed_completion(&input, &network.id, [8; 16])?
                    } else {
                        Self::borrowed_completion(&input, &read.id, [88; 16])?
                    };
                    if name == "other-admission" {
                        assert!(matches!(
                            GraphAndFindingOwner::derive(&borrowed, &self.execution),
                            Err(araphor_analysis_back::Error::Data {
                                source: Error::GraphInvalid {
                                    field: "credential read completion",
                                    ..
                                }
                            })
                        ));
                    } else {
                        let unbound = GraphAndFindingOwner::derive(&borrowed, &self.execution)?;
                        assert!(unbound
                            .findings
                            .iter()
                            .any(|finding| finding.package_id == "HF-DW-001"
                                && finding.state == FindingStateV1::CoverageInsufficient));
                    }
                    borrowed_completions
                        .push(json!({"input": name, "credential_bytes_proven": false}));
                }
            }
            let mut contradicted = input.clone();
            let mut authority = authority;
            if let GraphFactValueV1::AuthorityUse { proof_quality, .. } = &mut authority.value {
                proof_quality.operation_result_authority =
                    OperationResultAuthorityV1::AuthoritativeDenied;
            }
            self.inputs.insert(authority, "contradicted-authority", 1)?;
            contradicted.facts = self
                .inputs
                .facts(&read)?
                .into_iter()
                .chain(self.inputs.facts(&network)?)
                .collect();
            let contradiction = GraphAndFindingOwner::derive(&contradicted, &self.execution)?;
            assert!(contradiction
                .findings
                .iter()
                .any(|finding| finding.package_id == "HF-DW-001"
                    && finding.reason == FindingReasonV1::Contradiction));
            results.push(json!({"path": name, "read_result": result, "byte_count": bytes,
                "credential_bytes_proven": proved, "state": finding.state,
                "borrowed_completions": borrowed_completions,
                "late_revision_appended": true, "earlier_revision_unchanged": true,
                "contradiction_preserved": true, "payload": "PAYLOAD_UNOBSERVABLE",
                "graph_revision": snapshot.input_manifest, "finding_id": finding.finding_id,
                "completion_limit": if path == GraphReadPathV1::Mmap { Some("MAPPING_ADMISSION_HAS_NO_PAGE_ACCESS_PROOF") } else { None }}));
        }
        Ok(results)
    }

    fn send_results(&self) -> std::result::Result<Vec<serde_json::Value>, Box<dyn StdError>> {
        let mut results = Vec::new();
        for (index, (name, denied)) in [
            ("failed-send", true),
            ("send-admission", false),
            ("packet-emitted", false),
            ("provider-write", false),
            ("content-oracle-absent", false),
        ]
        .into_iter()
        .enumerate()
        {
            let (record, provider) = self.send_input(u8::try_from(120 + index)?, name, denied)?;
            let source = record.id.stream.clone();
            let snapshot = self.snapshot(&source)?;
            let finding = snapshot
                .findings
                .iter()
                .find(|finding| finding.package_id == "HF-PROC-001")
                .ok_or("network finding absent")?;
            if let Some(provider) = &provider {
                assert!(snapshot.graph.facts.contains(provider));
                assert!(snapshot
                    .graph
                    .edges
                    .iter()
                    .all(|edge| { edge.key.edge_type != GraphEdgeTypeV1::CredentialAuthority }));
                let input = GraphNotificationQualification::replay(&self.data, &source, &snapshot)?;
                let decoded = input
                    .facts
                    .iter()
                    .map(GraphFactV1::try_from)
                    .collect::<Result<Vec<_>>>()?;
                assert!(decoded.contains(provider));
                GraphNotificationQualification::check_replay(&input, &snapshot)?;
            }
            assert!(finding.limits.contains(&"TLS_PAYLOAD_UNOBSERVABLE".into()));
            assert!(finding.limits.contains(&"REMOTE_OPERATION_UNPROVEN".into()));
            assert_eq!(
                finding.effects[0].physical_result,
                if denied {
                    GraphPhysicalResultV1::Prevented
                } else {
                    GraphPhysicalResultV1::Unknown
                }
            );
            let limits: Vec<&str> = match name {
                "failed-send" => vec!["NO_PACKET_OR_PROVIDER_RESULT_PROOF"],
                "send-admission" => vec!["POST_SYSCALL_RESULT_SCHEMA_UNAVAILABLE"],
                "packet-emitted" => vec!["PACKET_RESULT_SCHEMA_UNAVAILABLE"],
                "provider-write" => vec![
                    "LOCAL_PROCESS_REQUEST_BRIDGE_MISSING",
                    "PAYLOAD_UNOBSERVABLE",
                ],
                _ => vec!["CONTENT_ORACLE_UNAVAILABLE", "PAYLOAD_UNOBSERVABLE"],
            };
            results.push(json!({"stage": name,
                "qualification": "RECORDED_GRAPH_REPLAY",
                "accepted_native_record": record.id,
                "decision": finding.effects[0].source_decision,
                "physical_result": finding.effects[0].physical_result,
                "provider_input": provider,
                "provider_result": if provider.is_some() { Some("AUTHORITATIVE_SUCCEEDED") } else { None },
                "packet_emission_observed": false, "provider_write_observed": false,
                "recorded_provider_result_retained": provider.is_some(),
                "post_syscall_result": "UNSUPPORTED", "packet_result": "UNSUPPORTED",
                "limits": limits, "local_cause_proven": false, "confirmed_exfiltration": false,
                "content_proof": "UNSUPPORTED", "payload": "PAYLOAD_UNOBSERVABLE",
                "finding_revision": finding.revision}));
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    mod commit;
    mod context;
    mod history;
    mod local;
    mod nodes;
    mod notifications;
    mod provider;
    mod reads;
    mod transport;

    #[tokio::test]
    async fn graph_notification_dense_progress_and_capacity() -> crate::platform::TestResult<()> {
        super::ReplayQualification::new(1_791_400_000_000_000_000)?
            .notification_density()
            .await?;
        Ok(())
    }
}
