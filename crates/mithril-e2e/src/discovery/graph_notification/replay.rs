use super::*;
use serde::Deserialize;

mod authority;

#[derive(Deserialize)]
struct Card {
    id: String,
    action: String,
    family: u16,
    operation: u16,
    contexts: Vec<(String, GraphContextActionV1)>,
}

struct ReplayQualification {
    root: tempfile::TempDir,
    intake: EvidenceIntakeOwner,
    data: Arc<AnalysisStore>,
    inputs: Arc<GraphInputs>,
    authenticated: AuthenticatedEvidenceNodeV1,
    now: u64,
}

pub(super) fn run(now: u64) -> std::result::Result<serde_json::Value, Box<dyn StdError>> {
    let fixture = ReplayQualification::new(now)?;
    let cards: Vec<Card> = serde_json::from_slice(include_bytes!(
        "../../../fixtures/discovery/incident-cards-v1.json"
    ))?;
    assert_eq!(cards.len(), 12);
    let mut results = Vec::new();
    for (index, card) in cards.into_iter().enumerate() {
        assert_eq!(card.id, format!("HF-{:03}", index + 1));
        results.push(fixture.card(&card, u8::try_from(index + 40)?)?);
    }
    let reads = fixture.read_results()?;
    let sends = fixture.send_results()?;
    let authorization = authority::run(now)?;
    let local = fixture.local_contract()?;
    let nodes = fixture.nodes()?;
    Ok(json!({"incident_cards": results, "HF-LOCAL-001": {
        "families": ["exec", "file", "network", "device"],
        "qualification": "RECORDED_GRAPH_REPLAY", "physical_incident_reproduced": false,
        "original_effect_qualification": "UNSUPPORTED",
        "original_effect_limit": "PROJECTED_TOKEN_AND_CONTROLLER_CONTROL_NOT_QUALIFIED",
        "healthy": "confirmed-native-denial", "gapped": "coverage-insufficient",
        "legitimate_control_unflagged": true,
    }, "local_contract": local, "HF-XNODE-001": nodes,
        "HF-011-READ-RESULT-001": reads, "HF-004-RESULT-001": sends,
        "AUTHORIZATION-REPLAY-004": authorization,
        "proof_boundary": "Recorded kernel, Control, read-completion, and remote audit inputs check production package contracts. No provider collector, provider issuance, cross-node physical result, or response execution is qualified."}))
}

impl ReplayQualification {
    fn new(now: u64) -> std::result::Result<Self, Box<dyn StdError>> {
        let root = tempfile::tempdir()?;
        let store = ControlStore::open(root.path().join("control"))?;
        let data = Arc::new(AnalysisStore::open(root.path().join("analysis"))?);
        let intake = EvidenceIntakeOwner::new(
            store,
            data.clone(),
            Arc::new(Clock(UNIX_EPOCH + Duration::from_nanos(now))),
        )?;
        Ok(Self {
            root,
            intake,
            data,
            inputs: Arc::new(GraphInputs::default()),
            now,
            authenticated: AuthenticatedEvidenceNodeV1 {
                tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
                node_id: "node-a".into(),
                node_boot_id: [7; 16],
                label_epoch: 1,
            },
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
        let graph = GraphAndFindingOwner::new(self.data.clone(), self.inputs.clone())?;
        for _ in 0..32 {
            graph.process(self.now)?;
            if let Some(snapshot) = graph.snapshot(source)? {
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
        let mut raw = GraphNotificationQualification::native(1, true);
        raw.effect_family = card.family;
        raw.operation = card.operation;
        let mut control = GraphNotificationQualification::native(2, false);
        control.effect_family = card.family;
        control.operation = card.operation;
        let source = self.accept(source_id, &[raw, control])?;
        let anchor = self.record(&source, 2)?;
        for (index, (action, classification)) in card.contexts.iter().enumerate() {
            self.inputs.insert(
                GraphFactV1 {
                    record_id: anchor.id.clone(),
                    value: GraphFactValueV1::Context {
                        subject: GraphSubjectKeyV1 {
                            tenant_id: source.tenant_id,
                            authority: GraphSubjectAuthorityV1::External {
                                authority_id: format!("{}-context", card.id),
                            },
                            kind: GraphSubjectKindV1::External,
                            identity: action.as_bytes().to_vec(),
                        },
                        action_id: action.clone(),
                        classification: *classification,
                        proof_quality: ProofQualityV1 {
                            source_authority: SourceAuthorityV1::AuthenticatedMeasurement,
                            local_subject_binding: LocalSubjectBindingV1::None,
                            remote_subject_binding: RemoteSubjectBindingV1::Contextual,
                            operation_result_authority: OperationResultAuthorityV1::Contextual,
                            temporal_coverage: TemporalCoverageV1::Unknown,
                            integrity: ProofIntegrityV1::AuthenticatedChannel,
                        },
                    },
                },
                &format!("context-{source_id}-{index}"),
                1,
            )?;
        }
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
        let gapped = GraphAndFindingOwner::derive(&gap)?;
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
            GraphAndFindingOwner::derive(&reversed)?.findings
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
        let graph = GraphAndFindingOwner::new(self.data.clone(), self.inputs.clone())?;
        assert!(graph.refresh(source, self.now + 300_000_000_000)?);
        let late = self.result_snapshot(&graph, source, &original.package_id)?;
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
        self.inputs.insert(
            GraphFactV1 {
                record_id: record.id,
                value: GraphFactValueV1::Policy(contradiction),
            },
            "contradictory-policy",
            1,
        )?;
        assert!(graph.refresh(source, self.now + 300_000_000_001)?);
        let contradicted = self.result_snapshot(&graph, source, &original.package_id)?;
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
            GraphAndFindingOwner::derive(&mixed),
            Err(Error::GraphInvalid {
                field: "replay record identity",
                ..
            })
        ));
        let record = self.record(&local, 1)?;
        self.inputs.insert(
            GraphFactV1 {
                record_id: record.id,
                value: GraphFactValueV1::Kubernetes(KubernetesStageProofV1 {
                    cluster_id: "recorded-cluster".into(),
                    carried_request_id: Some("recorded-cross-node-request".into()),
                    audit_id: Some("recorded-cross-node-audit".into()),
                    object_uid: Some("recorded-object".into()),
                    resource_version: Some("recorded-version".into()),
                    owner_uid: Some("recorded-owner".into()),
                    pod_uid: Some("recorded-pod".into()),
                    node_id: Some(remote.node_id.clone()),
                    full_container_id: None,
                    remote_admission_id: None,
                    proof_quality: Self::proof(),
                }),
            },
            "cross-node-scheduled",
            1,
        )?;
        let graph = GraphAndFindingOwner::new(self.data.clone(), self.inputs.clone())?;
        assert!(graph.refresh(&local, self.now + 1)?);
        let partial = self.result_snapshot(&graph, &local, "HF-XNODE-001")?;
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
            let mut raw = GraphNotificationQualification::native(1, false);
            raw.operation = if name == "open-admission" {
                KernelEffectOperationV1::OpenRead as u16
            } else if path == GraphReadPathV1::Mmap {
                KernelEffectOperationV1::MmapRead as u16
            } else {
                KernelEffectOperationV1::Read as u16
            };
            let mut channel = GraphNotificationQualification::native(2, false);
            channel.effect_family = KernelEffectFamilyV1::Network as u16;
            channel.operation = KernelEffectOperationV1::Send as u16;
            let source = self.accept(u8::try_from(index + 100)?, &[raw, channel])?;
            let read = self.record(&source, 1)?;
            let network = self.record(&source, 2)?;
            let object: [u8; 16] = read.decode()?.exact_object_id.as_ref().try_into()?;
            let socket: [u8; 16] = network.decode()?.exact_object_id.as_ref().try_into()?;
            self.policy(&read)?;
            self.policy(&network)?;
            self.inputs.insert(
                GraphFactV1 {
                    record_id: read.id.clone(),
                    value: GraphFactValueV1::Credential {
                        object_id: object,
                        expected_access: false,
                        reviewed_policy_revision: "recorded-reviewed-source".into(),
                        completion: if name == "open-admission" || path == GraphReadPathV1::Mmap {
                            None
                        } else {
                            Some(GraphReadCompletionV1 {
                                admission_record: read.id.clone(),
                                owner: "recorded-read-completion".into(),
                                completion_id: name.into(),
                                task_cookie: 7,
                                process_instance_id: [8; 16],
                                object_id: object,
                                file_description_id: "fd-lifetime".into(),
                                path,
                                result,
                                byte_count: bytes,
                                credential_lease_id: Some("recorded-lease".into()),
                                principal_id: Some("principal".into()),
                            })
                        },
                        proof_quality: Self::proof(),
                        principal_id: Some("principal".into()),
                    },
                },
                "credential",
                1,
            )?;
            self.inputs.insert(
                GraphFactV1 {
                    record_id: network.id.clone(),
                    value: GraphFactValueV1::Channel {
                        task_cookie: 7,
                        process_instance_id: [8; 16],
                        socket_object_id: socket,
                        authority_id: "recorded-provider".into(),
                        carried_request_id: "request".into(),
                        credential_lease_id: "recorded-lease".into(),
                        principal_id: "principal".into(),
                        operation_id: "write".into(),
                        proof_quality: Self::proof(),
                    },
                },
                "channel",
                1,
            )?;
            let earlier = self.snapshot(&source)?;
            let authority = GraphFactValueV1::AuthorityUse {
                authority_id: "recorded-provider".into(),
                process_instance_id: Some([8; 16]),
                task_cookie: Some(7),
                credential_object_id: Some(object),
                socket_object_id: Some(socket),
                request_id: Some("request".into()),
                credential_lease_id: Some("recorded-lease".into()),
                principal_id: "principal".into(),
                operation_id: "write".into(),
                outside_reviewed_behavior: true,
                proof_quality: Self::proof(),
                workload_binding: None,
            };
            self.inputs.insert(
                GraphFactV1 {
                    record_id: network.id.clone(),
                    value: authority.clone(),
                },
                "late-authority",
                1,
            )?;
            let graph = GraphAndFindingOwner::new(self.data.clone(), self.inputs.clone())?;
            assert!(graph.refresh(&source, self.now + 300_000_000_000)?);
            let snapshot = self.result_snapshot(&graph, &source, "HF-DW-001")?;
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
                    let mut borrowed = input.clone();
                    for context in &mut borrowed.facts {
                        let mut fact = GraphFactV1::try_from(&*context)?;
                        if let GraphFactValueV1::Credential {
                            completion: Some(completion),
                            ..
                        } = &mut fact.value
                        {
                            if name == "other-admission" {
                                completion.admission_record = network.id.clone();
                            } else {
                                completion.process_instance_id = [88; 16];
                            }
                            context.body = serde_json::to_vec(&fact)?;
                        }
                    }
                    if name == "other-admission" {
                        assert!(matches!(
                            GraphAndFindingOwner::derive(&borrowed),
                            Err(Error::GraphInvalid {
                                field: "credential read completion",
                                ..
                            })
                        ));
                    } else {
                        let unbound = GraphAndFindingOwner::derive(&borrowed)?;
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
            if let GraphFactValueV1::AuthorityUse { proof_quality, .. } = &mut authority {
                proof_quality.operation_result_authority =
                    OperationResultAuthorityV1::AuthoritativeDenied;
            }
            self.inputs.insert(
                GraphFactV1 {
                    record_id: network.id.clone(),
                    value: authority,
                },
                "contradicted-authority",
                1,
            )?;
            contradicted.facts = self
                .inputs
                .facts(&read)?
                .into_iter()
                .chain(self.inputs.facts(&network)?)
                .collect();
            let contradiction = GraphAndFindingOwner::derive(&contradicted)?;
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
            let mut raw = GraphNotificationQualification::native(1, denied);
            raw.effect_family = KernelEffectFamilyV1::Network as u16;
            raw.operation = KernelEffectOperationV1::Send as u16;
            let source = self.accept(u8::try_from(120 + index)?, &[raw])?;
            let record = self.record(&source, 1)?;
            if !denied {
                self.policy(&record)?;
                self.inputs.insert(
                    GraphFactV1 {
                        record_id: record.id.clone(),
                        value: GraphFactValueV1::Baseline {
                            role_id: 1,
                            state_id: 1,
                            outside_reviewed_baseline: true,
                            reviewed_policy_revision: "recorded-reviewed-source".into(),
                        },
                    },
                    "network-baseline",
                    1,
                )?;
            }
            let provider = if name == "provider-write" {
                let fact = GraphFactV1 {
                    record_id: record.id.clone(),
                    value: GraphFactValueV1::AuthorityUse {
                        authority_id: "recorded-provider".into(),
                        process_instance_id: None,
                        task_cookie: None,
                        credential_object_id: None,
                        socket_object_id: None,
                        request_id: Some("recorded-publication-43".into()),
                        credential_lease_id: None,
                        principal_id: "recorded-publisher".into(),
                        operation_id: "publication.write".into(),
                        outside_reviewed_behavior: true,
                        proof_quality: ProofQualityV1 {
                            source_authority: SourceAuthorityV1::AuthoritativeProvider,
                            local_subject_binding: LocalSubjectBindingV1::None,
                            remote_subject_binding: RemoteSubjectBindingV1::ExactRequest,
                            operation_result_authority:
                                OperationResultAuthorityV1::AuthoritativeSucceeded,
                            temporal_coverage: TemporalCoverageV1::Complete,
                            integrity: ProofIntegrityV1::Signed,
                        },
                        workload_binding: None,
                    },
                };
                self.inputs
                    .insert(fact.clone(), "provider-publication-result", 1)?;
                Some(fact)
            } else {
                None
            };
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
