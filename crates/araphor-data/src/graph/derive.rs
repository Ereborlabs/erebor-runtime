use std::collections::{BTreeMap, BTreeSet};

use erebor_interceptor_abi::{
    KernelEffectFamilyV1, KernelEffectOperationV1, PhysicalDecisionKindV1,
};
use snafu::ResultExt as _;

use super::*;
use crate::{
    ContextSensitivityV1, DiscoveryCoverageStateV1, DiscoveryRecordIdV1, DiscoveryRecordV1,
    EvidenceRecord, GraphEncodingSnafu, GraphInvalidSnafu, ProcessorScopeV1, Result,
};

struct GraphDerivation<'a> {
    input: &'a GraphReplayInputV1,
    revision: GraphRevisionV1,
    subjects: BTreeSet<GraphSubjectKeyV1>,
    edges: BTreeMap<GraphEdgeKeyV1, GraphEdgeV1>,
    branches: Vec<GraphBranchV1>,
    findings: BTreeMap<String, FindingV1>,
    facts: Vec<GraphFactV1>,
    states: [GraphPackageStateV1; 3],
}

impl GraphAndFindingOwner {
    pub fn derive(input: &GraphReplayInputV1) -> Result<GraphSnapshotV1> {
        let mut records = BTreeMap::new();
        for record in &input.records {
            if records
                .insert(record.id.clone(), record.clone())
                .is_some_and(|previous| previous != *record)
            {
                return GraphInvalidSnafu {
                    field: "conflicting observation",
                }
                .fail();
            }
        }
        let mut facts = BTreeMap::new();
        for fact in &input.facts {
            if facts
                .insert(fact.key.clone(), fact.clone())
                .is_some_and(|previous| previous != *fact)
            {
                return GraphInvalidSnafu {
                    field: "conflicting context version",
                }
                .fail();
            }
        }
        let mut coverage = input.coverage.clone();
        coverage.sort();
        coverage.dedup();
        let mut coverage_keys = input.coverage_keys.clone();
        coverage_keys.sort();
        coverage_keys.dedup();
        let mut gaps = input.missing_ranges.clone();
        gaps.sort();
        gaps.dedup();
        let input = GraphReplayInputV1 {
            source: input.source.clone(),
            records: records.into_values().collect(),
            coverage,
            coverage_keys,
            facts: facts.into_values().collect(),
            missing_ranges: gaps,
        };
        input.validate()?;
        let revision = GraphRevisionV1 {
            evidence: input
                .records
                .iter()
                .map(|record| record.id.clone())
                .collect(),
            coverage: input.coverage_keys.clone(),
            context: input.facts.iter().map(|fact| fact.key.clone()).collect(),
            missing_ranges: input.missing_ranges.clone(),
        };
        let facts = input
            .facts
            .iter()
            .map(GraphFactV1::try_from)
            .collect::<Result<Vec<_>>>()?;
        let mut owner = GraphDerivation {
            input: &input,
            revision,
            subjects: BTreeSet::new(),
            edges: BTreeMap::new(),
            branches: Vec::new(),
            findings: BTreeMap::new(),
            facts,
            states: [
                GraphPackageStateV1::Waiting,
                GraphPackageStateV1::Waiting,
                GraphPackageStateV1::KubernetesProofMissing,
            ],
        };
        for record in &input.records {
            owner.native(record)?;
        }
        owner.credentials()?;
        owner.cross_node()?;
        owner.context_actions()?;
        owner.finish()
    }
}

impl GraphDerivation<'_> {
    fn subject(&mut self, kind: GraphSubjectKindV1, identity: Vec<u8>) -> GraphSubjectKeyV1 {
        let key = GraphSubjectKeyV1::native(&self.input.source, kind, identity);
        self.subjects.insert(key.clone());
        key
    }

    fn task(&mut self, record: &DiscoveryRecordV1, wire: &EvidenceRecord) -> GraphSubjectKeyV1 {
        if wire.task_cookie > 0 {
            self.subject(
                GraphSubjectKindV1::Task,
                wire.task_cookie.to_be_bytes().to_vec(),
            )
        } else {
            let key = GraphSubjectKeyV1 {
                tenant_id: record.id.stream.tenant_id,
                authority: GraphSubjectAuthorityV1::External {
                    authority_id: "unresolved-native-observation".into(),
                },
                kind: GraphSubjectKindV1::External,
                identity: record
                    .id
                    .stream
                    .key()
                    .into_iter()
                    .chain(record.id.durable_cursor.to_be_bytes())
                    .collect(),
            };
            self.subjects.insert(key.clone());
            key
        }
    }

    fn proof(&self, record: &DiscoveryRecordV1) -> ProofQualityV1 {
        let range = self
            .input
            .coverage
            .iter()
            .filter(|range| {
                range.stream == record.id.stream
                    && range.cpu_id == record.id.cpu_id
                    && (range.first_cursor..=range.last_cursor).contains(&record.id.durable_cursor)
            })
            .max_by_key(|range| range.coverage_revision);
        let has_gap = self.input.coverage.iter().any(|range| {
            range.stream == record.id.stream
                && range.cpu_id == record.id.cpu_id
                && (range.first_cursor..=range.last_cursor).contains(&record.id.durable_cursor)
                && range.state == DiscoveryCoverageStateV1::Gapped
        });
        let temporal = if !self.input.missing_ranges.is_empty() || has_gap {
            TemporalCoverageV1::Gapped
        } else {
            match range.map(|range| range.state) {
                Some(DiscoveryCoverageStateV1::Healthy | DiscoveryCoverageStateV1::Closed) => {
                    TemporalCoverageV1::Complete
                }
                Some(DiscoveryCoverageStateV1::Gapped) => TemporalCoverageV1::Gapped,
                _ => TemporalCoverageV1::Unknown,
            }
        };
        let mut proof = ProofQualityV1::kernel_decision(temporal);
        proof.integrity = ProofIntegrityV1::AuthenticatedChannel;
        if record.decode().is_ok_and(|wire| wire.task_cookie == 0) {
            proof.local_subject_binding = LocalSubjectBindingV1::None;
        }
        proof
    }

    fn edge(
        &mut self,
        mut key: GraphEdgeKeyV1,
        proof: ProofQualityV1,
        wire: &EvidenceRecord,
    ) -> Result<()> {
        key.evidence.sort();
        key.evidence.dedup();
        let coverage = <[u8; 16]>::try_from(wire.coverage_interval_id.as_ref()).map_err(|_| {
            GraphInvalidSnafu {
                field: "edge coverage interval",
            }
            .build()
        })?;
        let edge = GraphEdgeV1 {
            key: key.clone(),
            proof_quality: proof,
            required_coverage_interval_ids: vec![coverage],
            first_boottime_ns: wire.observed_boottime_ns,
            last_boottime_ns: wire.observed_boottime_ns,
        };
        if let Some(previous) = self.edges.get_mut(&key) {
            if *previous != edge {
                if key.cause != GraphCauseV1::Contradicted {
                    return GraphInvalidSnafu {
                        field: "conflicting edge value",
                    }
                    .fail();
                }
                previous.proof_quality.operation_result_authority =
                    OperationResultAuthorityV1::Unknown;
            }
        } else {
            self.edges.insert(key, edge);
        }
        Ok(())
    }

    fn facts(&self, record: &DiscoveryRecordV1) -> Vec<GraphFactV1> {
        self.facts
            .iter()
            .filter(|fact| fact.record_id == record.id)
            .cloned()
            .collect()
    }

    fn policies(&self, record: &DiscoveryRecordV1) -> Vec<PolicyObservationProvenanceV1> {
        let generation = record
            .decode()
            .ok()
            .and_then(|wire| wire.profile_generation_ref_id)
            .unwrap_or_default();
        let policies: Vec<_> = self
            .facts(record)
            .into_iter()
            .filter_map(|fact| match fact.value {
                GraphFactValueV1::Policy(policy)
                    if policy.profile_generation_ref_id == generation =>
                {
                    Some(policy)
                }
                _ => None,
            })
            .collect();
        let exact_chains: BTreeSet<_> = policies
            .iter()
            .filter(|policy| policy.state == PolicyProvenanceStateV1::Exact)
            .map(|policy| {
                (
                    policy.policy_source_revision_id.clone(),
                    policy.candidate_content_id.clone(),
                    policy.target_snapshot_digest.clone(),
                )
            })
            .collect();
        policies
            .into_iter()
            .filter(|policy| {
                policy.state != PolicyProvenanceStateV1::Missing
                    || !exact_chains.contains(&(
                        policy.policy_source_revision_id.clone(),
                        policy.candidate_content_id.clone(),
                        policy.target_snapshot_digest.clone(),
                    ))
            })
            .collect()
    }

    fn reviewed_policy(&self, record: &DiscoveryRecordV1, revision: &str) -> bool {
        let policies: Vec<_> = self
            .policies(record)
            .into_iter()
            .filter(|policy| policy.policy_source_revision_id.as_deref() == Some(revision))
            .collect();
        let exact: BTreeSet<_> = policies
            .iter()
            .filter(|policy| policy.state == PolicyProvenanceStateV1::Exact)
            .map(|policy| {
                (
                    &policy.candidate_content_id,
                    &policy.target_snapshot_digest,
                    &policy.node_bound_generation_digest,
                )
            })
            .collect();
        exact.len() == 1
            && policies
                .iter()
                .all(|policy| policy.state != PolicyProvenanceStateV1::Contradicted)
    }

    fn policy_conflict(&self, record: &DiscoveryRecordV1) -> bool {
        let policies = self.policies(record);
        let exact: BTreeSet<_> = policies
            .iter()
            .filter(|policy| policy.state == PolicyProvenanceStateV1::Exact)
            .map(|policy| {
                (
                    &policy.policy_source_revision_id,
                    &policy.candidate_content_id,
                    &policy.target_snapshot_digest,
                    &policy.node_bound_generation_digest,
                )
            })
            .collect();
        exact.len() > 1
            || policies
                .iter()
                .any(|policy| policy.state == PolicyProvenanceStateV1::Contradicted)
    }

    fn effect(&self, record: &DiscoveryRecordV1, wire: &EvidenceRecord) -> GraphEffectV1 {
        let context = wire.decision_context.as_ref();
        GraphEffectV1 {
            evidence: record.id.clone(),
            process_instance_id: context
                .and_then(|context| context.process_instance_id.as_slice().try_into().ok())
                .filter(|id| *id != [0; 16]),
            entry_instance_id: context
                .and_then(|context| context.entry_instance_id.as_slice().try_into().ok())
                .filter(|id| *id != [0; 16]),
            binding_id: context
                .and_then(|context| context.binding_id.as_slice().try_into().ok())
                .filter(|id| *id != [0; 16]),
            role_id: context
                .map(|context| context.role_id)
                .filter(|role| *role > 0),
            state_id: context
                .map(|context| context.state_id)
                .filter(|state| *state > 0),
            entry_rule_id: context
                .map(|context| context.entry_rule_id)
                .filter(|rule| *rule > 0),
            profile_generation_ref_id: wire.profile_generation_ref_id,
            original_kernel_sequence: record.original_kernel_sequence,
            effect_family: wire.effect_family,
            operation: wire.operation,
            source_decision: wire.decision,
            source_reason: wire.reason,
            configured_errno: wire.configured_errno,
            kernel_result: wire.kernel_result,
            physical_result: if wire.decision == PhysicalDecisionKindV1::Deny as u32
                && wire.kernel_result < 0
            {
                GraphPhysicalResultV1::Prevented
            } else {
                GraphPhysicalResultV1::Unknown
            },
            proof_quality: self.proof(record),
        }
    }

    fn finding(
        &mut self,
        package: &str,
        seed: &DiscoveryRecordV1,
        subject: GraphSubjectKeyV1,
        reason: FindingReasonV1,
        state: FindingStateV1,
        evidence: Vec<DiscoveryRecordIdV1>,
        mut limits: Vec<String>,
    ) -> Result<()> {
        let mut evidence = evidence;
        evidence.sort();
        evidence.dedup();
        let mut provenance = Vec::new();
        let mut effects = Vec::new();
        let mut coverage = BTreeSet::new();
        let mut timestamps = Vec::new();
        for id in &evidence {
            let record = self
                .input
                .records
                .iter()
                .find(|record| &record.id == id)
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "finding evidence",
                    }
                    .build()
                })?;
            let wire = record.decode()?;
            coverage.insert(
                <[u8; 16]>::try_from(wire.coverage_interval_id.as_ref()).map_err(|_| {
                    GraphInvalidSnafu {
                        field: "finding coverage",
                    }
                    .build()
                })?,
            );
            timestamps.push(wire.ingested_utc_ns);
            if matches!(
                reason,
                FindingReasonV1::OutsideAuthority
                    | FindingReasonV1::InMemoryOnly
                    | FindingReasonV1::PayloadUnobservable
            ) {
                continue;
            }
            effects.push(self.effect(record, &wire));
            let mut joined = false;
            for policy in self.policies(record) {
                limits.extend(policy.limits.iter().cloned());
                match policy.state {
                    PolicyProvenanceStateV1::Missing => {
                        limits.push("POLICY_PROVENANCE_MISSING".into())
                    }
                    PolicyProvenanceStateV1::Contradicted => {
                        limits.push("POLICY_PROVENANCE_CONTRADICTED".into())
                    }
                    PolicyProvenanceStateV1::Exact => {}
                }
                provenance.push(policy);
                joined = true;
            }
            if !joined {
                limits.push("POLICY_PROVENANCE_MISSING".into());
                provenance.push(PolicyObservationProvenanceV1 {
                    source: record.id.stream.clone(),
                    profile_generation_ref_id: wire.profile_generation_ref_id.unwrap_or_default(),
                    observations: vec![record.id.clone()],
                    policy_source_revision_id: None,
                    candidate_content_id: None,
                    target_snapshot_digest: None,
                    node_bound_generation_digest: None,
                    activation_acknowledgement: None,
                    state: PolicyProvenanceStateV1::Missing,
                    limits: vec!["ACTIVATION_ACKNOWLEDGEMENT_MISSING".into()],
                });
            }
        }
        provenance.sort();
        provenance.dedup();
        limits.sort();
        limits.dedup();
        let finding_id =
            serde_json::to_string(&(package, &seed.id, &subject)).context(GraphEncodingSnafu)?;
        let finding = FindingV1 {
            tenant_id: self.input.source.tenant_id,
            finding_id: finding_id.clone(),
            revision: self.revision.clone(),
            package_id: package.into(),
            package_version: 1,
            subject_id: subject,
            state,
            window_start_utc_ns: timestamps.iter().copied().min().unwrap_or(0),
            window_end_utc_ns: timestamps.iter().copied().max().unwrap_or(0),
            evidence,
            required_coverage_interval_ids: coverage.into_iter().collect(),
            policy_provenance: provenance,
            effects,
            reason,
            severity: if matches!(
                reason,
                FindingReasonV1::UnexpectedEffect | FindingReasonV1::CredentialPivot
            ) {
                FindingSeverityV1::Critical
            } else {
                FindingSeverityV1::High
            },
            sensitivity: if self
                .input
                .facts
                .iter()
                .any(|fact| fact.sensitivity == ContextSensitivityV1::HostRestricted)
            {
                ContextSensitivityV1::HostRestricted
            } else {
                ContextSensitivityV1::Tenant
            },
            required_action: Some(
                match reason {
                    FindingReasonV1::UnexpectedEffect => "inspect-denied-effect",
                    FindingReasonV1::AuditedRoleDeviation => "review-role-deviation",
                    FindingReasonV1::CredentialPivot => "investigate-credential-pivot",
                    FindingReasonV1::ContextualCredentialPivot => {
                        "review-contextual-authority-hypothesis"
                    }
                    FindingReasonV1::Contradiction => "resolve-contradiction",
                    _ => "resolve-missing-proof",
                }
                .into(),
            ),
            limits,
        };
        finding.validate()?;
        if let Some(previous) = self.findings.get(&finding_id) {
            if previous.reason == FindingReasonV1::Contradiction
                || (previous.state == FindingStateV1::Confirmed
                    && finding.state != FindingStateV1::Confirmed)
            {
                return Ok(());
            }
        }
        self.findings.insert(finding_id, finding);
        Ok(())
    }

    fn native(&mut self, record: &DiscoveryRecordV1) -> Result<()> {
        let wire = record.decode()?;
        let task = self.task(record, &wire);
        let detail = self.effect(record, &wire);
        let identity = wire.task_cookie > 0
            && detail.process_instance_id.is_some()
            && detail.entry_instance_id.is_some()
            && detail.binding_id.is_some()
            && detail.role_id.is_some()
            && detail.state_id.is_some()
            && detail.entry_rule_id.is_some();
        let proof = detail.proof_quality;
        if let Some(process) = detail.process_instance_id {
            let process = self.subject(GraphSubjectKindV1::Process, process.to_vec());
            self.edge(
                GraphEdgeKeyV1 {
                    from: task.clone(),
                    to: process,
                    edge_type: GraphEdgeTypeV1::TaskInProcess,
                    package_id: "HF-PROC-001".into(),
                    evidence: vec![record.id.clone()],
                    cause: if identity {
                        GraphCauseV1::Direct
                    } else {
                        GraphCauseV1::Contextual
                    },
                },
                proof,
                &wire,
            )?;
        }
        if wire.execution_set_id.iter().any(|byte| *byte != 0) {
            let set = self.subject(
                GraphSubjectKindV1::ExecutionSet,
                wire.execution_set_id.to_vec(),
            );
            self.edge(
                GraphEdgeKeyV1 {
                    from: task.clone(),
                    to: set,
                    edge_type: GraphEdgeTypeV1::TaskInExecutionSet,
                    package_id: "HF-PROC-001".into(),
                    evidence: vec![record.id.clone()],
                    cause: if identity {
                        GraphCauseV1::Direct
                    } else {
                        GraphCauseV1::Contextual
                    },
                },
                proof,
                &wire,
            )?;
        }
        if wire.exact_object_id.iter().any(|byte| *byte != 0) {
            let mut object = wire.exact_object_id.to_vec();
            object.extend_from_slice(
                &wire
                    .profile_generation_ref_id
                    .unwrap_or_default()
                    .to_be_bytes(),
            );
            let kind = if wire.effect_family == KernelEffectFamilyV1::Network as u32 {
                GraphSubjectKindV1::Socket
            } else {
                GraphSubjectKindV1::Artifact
            };
            let object = self.subject(kind, object);
            self.edge(
                GraphEdgeKeyV1 {
                    from: task.clone(),
                    to: object,
                    edge_type: GraphEdgeTypeV1::NativeEffect,
                    package_id: "HF-PROC-001".into(),
                    evidence: vec![record.id.clone()],
                    cause: if identity {
                        GraphCauseV1::Direct
                    } else {
                        GraphCauseV1::Contextual
                    },
                },
                proof,
                &wire,
            )?;
        }
        let mut ancestry = false;
        let mut deviations = BTreeSet::new();
        let mut baseline_unproved = false;
        for fact in self.facts(record) {
            match fact.value {
                GraphFactValueV1::NativeParent {
                    parent,
                    child,
                    proof_quality,
                } => {
                    let child_matches = child.authority == task.authority
                        && child.tenant_id == task.tenant_id
                        && ((child.kind == GraphSubjectKindV1::Task
                            && wire.task_cookie > 0
                            && child.identity == wire.task_cookie.to_be_bytes())
                            || (child.kind == GraphSubjectKindV1::Process
                                && detail
                                    .process_instance_id
                                    .is_some_and(|id| child.identity == id)));
                    if !child_matches
                        || proof_quality.temporal_coverage != TemporalCoverageV1::Complete
                        || !matches!(
                            proof_quality.integrity,
                            ProofIntegrityV1::Signed
                                | ProofIntegrityV1::AuthenticatedChannel
                                | ProofIntegrityV1::LocalAttested
                        )
                    {
                        continue;
                    }
                    self.subjects.insert(parent.clone());
                    self.subjects.insert(child.clone());
                    self.edge(
                        GraphEdgeKeyV1 {
                            from: parent,
                            to: child,
                            edge_type: GraphEdgeTypeV1::NativeParent,
                            package_id: "HF-PROC-001".into(),
                            evidence: vec![record.id.clone()],
                            cause: GraphCauseV1::Direct,
                        },
                        proof_quality,
                        &wire,
                    )?;
                    ancestry = true;
                }
                GraphFactValueV1::Baseline {
                    role_id,
                    state_id,
                    outside_reviewed_baseline,
                    reviewed_policy_revision,
                } if detail.role_id == Some(role_id) && detail.state_id == Some(state_id) => {
                    let exact_policy = self.reviewed_policy(record, &reviewed_policy_revision);
                    if exact_policy {
                        deviations.insert(outside_reviewed_baseline);
                    } else if outside_reviewed_baseline {
                        baseline_unproved = true;
                    }
                }
                _ => {}
            }
        }
        let mut limits = Vec::new();
        if baseline_unproved {
            limits.push("REVIEWED_BASELINE_PROVENANCE_MISSING".into());
        }
        if !ancestry {
            limits.push("NATIVE_ANCESTRY_UNAVAILABLE".into());
        }
        if proof.temporal_coverage != TemporalCoverageV1::Complete {
            limits.push("SOURCE_COVERAGE_INSUFFICIENT".into());
        }
        if wire.effect_family == KernelEffectFamilyV1::Network as u32 {
            limits.push("TLS_PAYLOAD_UNOBSERVABLE".into());
            limits.push("REMOTE_OPERATION_UNPROVEN".into());
        }
        if detail.physical_result == GraphPhysicalResultV1::Unknown {
            limits.push("PHYSICAL_EFFECT_UNPROVEN".into());
        }
        if deviations.len() > 1 || self.policy_conflict(record) {
            self.states[0] = GraphPackageStateV1::Contradicted;
            self.finding(
                "HF-PROC-001",
                record,
                task,
                FindingReasonV1::Contradiction,
                FindingStateV1::CoverageInsufficient,
                vec![record.id.clone()],
                limits,
            )?;
        } else if !identity
            || wire.decision == PhysicalDecisionKindV1::Deny as u32
            || deviations.contains(&true)
            || baseline_unproved
        {
            self.states[0] = GraphPackageStateV1::NativeEffect;
            let reason = if !identity {
                FindingReasonV1::LineageCoverageGap
            } else if wire.decision == PhysicalDecisionKindV1::Deny as u32 {
                FindingReasonV1::UnexpectedEffect
            } else {
                FindingReasonV1::AuditedRoleDeviation
            };
            let state = if identity
                && !baseline_unproved
                && proof.temporal_coverage == TemporalCoverageV1::Complete
            {
                FindingStateV1::Confirmed
            } else {
                FindingStateV1::CoverageInsufficient
            };
            self.finding(
                "HF-PROC-001",
                record,
                task,
                reason,
                state,
                vec![record.id.clone()],
                limits,
            )?;
        }
        Ok(())
    }

    fn qualified_result(proof: ProofQualityV1) -> bool {
        matches!(
            proof.source_authority,
            SourceAuthorityV1::KernelDecision
                | SourceAuthorityV1::AuthoritativeProvider
                | SourceAuthorityV1::SignedCoordinator
                | SourceAuthorityV1::AuthenticatedMeasurement
        ) && matches!(
            proof.local_subject_binding,
            LocalSubjectBindingV1::ExactTask | LocalSubjectBindingV1::ExactProcess
        ) && proof.temporal_coverage == TemporalCoverageV1::Complete
            && matches!(
                proof.integrity,
                ProofIntegrityV1::Signed
                    | ProofIntegrityV1::AuthenticatedChannel
                    | ProofIntegrityV1::LocalAttested
            )
    }

    fn credentials(&mut self) -> Result<()> {
        for record in &self.input.records {
            let wire = record.decode()?;
            let credentials: Vec<_> = self.facts(record).into_iter().filter(|fact| matches!(&fact.value, GraphFactValueV1::Credential { object_id, .. } if wire.exact_object_id.as_ref() == object_id)).collect();
            let classifications: BTreeSet<_> = credentials
                .iter()
                .filter_map(|fact| match &fact.value {
                    GraphFactValueV1::Credential {
                        expected_access, ..
                    } => Some(*expected_access),
                    _ => None,
                })
                .collect();
            let mut completions = BTreeMap::new();
            let mut contradicted = classifications.len() > 1
                || (!credentials.is_empty() && self.policy_conflict(record));
            for fact in &credentials {
                if let GraphFactValueV1::Credential {
                    completion: Some(completion),
                    ..
                } = &fact.value
                {
                    let key = (&completion.owner, &completion.completion_id);
                    if completions
                        .insert(key, completion)
                        .is_some_and(|previous| previous != completion)
                    {
                        contradicted = true;
                    }
                }
            }
            if contradicted {
                self.states[1] = GraphPackageStateV1::Contradicted;
                let task = self.task(record, &wire);
                self.finding(
                    "HF-DW-001",
                    record,
                    task,
                    FindingReasonV1::Contradiction,
                    FindingStateV1::CoverageInsufficient,
                    vec![record.id.clone()],
                    vec!["CREDENTIAL_FACTS_CONTRADICTED".into()],
                )?;
                continue;
            }
            for fact in credentials {
                let GraphFactValueV1::Credential {
                    object_id,
                    expected_access,
                    completion,
                    proof_quality,
                    reviewed_policy_revision,
                    principal_id: credential_principal,
                } = fact.value
                else {
                    continue;
                };
                if expected_access
                    || wire.exact_object_id.as_ref() != object_id
                    || !matches!(wire.operation, operation if operation == KernelEffectOperationV1::OpenRead as u32 || operation == KernelEffectOperationV1::Read as u32 || operation == KernelEffectOperationV1::MmapRead as u32)
                {
                    continue;
                }
                self.states[1] = GraphPackageStateV1::CredentialObserved;
                let task = self.task(record, &wire);
                let process = self.effect(record, &wire).process_instance_id;
                let policy_proven = self.reviewed_policy(record, &reviewed_policy_revision);
                let bytes_proven = wire.decision != PhysicalDecisionKindV1::Deny as u32
                    && policy_proven
                    && Self::qualified_result(proof_quality)
                    && proof_quality.operation_result_authority
                        == OperationResultAuthorityV1::AuthoritativeSucceeded
                    && completion.as_ref().is_some_and(|completion| {
                        completion.byte_count > 0
                            && completion.result > 0
                            && completion.task_cookie == wire.task_cookie
                            && Some(completion.process_instance_id) == process
                            && completion.object_id == object_id
                            && match completion.path {
                                GraphReadPathV1::Read
                                | GraphReadPathV1::InheritedFd
                                | GraphReadPathV1::IoUring => {
                                    wire.operation == KernelEffectOperationV1::Read as u32
                                }
                                GraphReadPathV1::Mmap | GraphReadPathV1::Memory => false,
                            }
                    });
                let mut evidence = vec![record.id.clone()];
                let mut limits = vec!["TLS_PAYLOAD_UNOBSERVABLE".into()];
                if !bytes_proven {
                    limits.push("CREDENTIAL_BYTES_UNPROVEN".into());
                }
                if !policy_proven {
                    limits.push("REVIEWED_CREDENTIAL_PROVENANCE_MISSING".into());
                }
                let mut matched = Vec::new();
                for channel_record in &self.input.records {
                    let channel_wire = channel_record.decode()?;
                    let channel_process = self
                        .effect(channel_record, &channel_wire)
                        .process_instance_id;
                    if channel_record.id.stream.node_id != record.id.stream.node_id
                        || channel_record.id.stream.node_boot_id != record.id.stream.node_boot_id
                        || channel_record.id.stream.label_epoch != record.id.stream.label_epoch
                        || channel_wire.observed_boottime_ns < wire.observed_boottime_ns
                        || channel_wire.observed_boottime_ns - wire.observed_boottime_ns
                            > GRAPH_WINDOW_NS
                        || channel_wire.effect_family != KernelEffectFamilyV1::Network as u32
                        || !((channel_wire.task_cookie == wire.task_cookie && wire.task_cookie > 0)
                            || (process.is_some() && channel_process == process))
                    {
                        continue;
                    }
                    for authority in &self.facts {
                        let GraphFactValueV1::AuthorityUse {
                            authority_id,
                            process_instance_id,
                            task_cookie,
                            credential_object_id,
                            socket_object_id,
                            request_id,
                            credential_lease_id,
                            principal_id,
                            operation_id,
                            outside_reviewed_behavior,
                            proof_quality,
                            workload_binding,
                        } = &authority.value
                        else {
                            continue;
                        };
                        let authority_record = self
                            .input
                            .records
                            .iter()
                            .find(|candidate| candidate.id == authority.record_id)
                            .ok_or_else(|| {
                                GraphInvalidSnafu {
                                    field: "authority record",
                                }
                                .build()
                            })?;
                        let authority_wire = authority_record.decode()?;
                        let local = (*task_cookie == Some(wire.task_cookie)
                            && wire.task_cookie > 0)
                            || (process.is_some() && *process_instance_id == process);
                        let socket = socket_object_id
                            .is_some_and(|socket| channel_wire.exact_object_id.as_ref() == socket);
                        let bounded = authority_wire.observed_boottime_ns
                            >= wire.observed_boottime_ns
                            && authority_wire.observed_boottime_ns - wire.observed_boottime_ns
                                <= GRAPH_WINDOW_NS;
                        let workload = wire.execution_set_id.iter().any(|byte| *byte != 0)
                            && workload_binding.as_ref()
                                == Some(&GraphSubjectKeyV1::native(
                                    &record.id.stream,
                                    GraphSubjectKindV1::ExecutionSet,
                                    wire.execution_set_id.to_vec(),
                                ));
                        let contextual = workload
                            && credential_principal.as_ref() == Some(principal_id)
                            && matches!(
                                proof_quality.source_authority,
                                SourceAuthorityV1::AuthoritativeProvider
                                    | SourceAuthorityV1::SignedCoordinator
                            )
                            && matches!(
                                proof_quality.integrity,
                                ProofIntegrityV1::Signed | ProofIntegrityV1::AuthenticatedChannel
                            );
                        if !outside_reviewed_behavior
                            || !bounded
                            || (!(local && socket && *credential_object_id == Some(object_id))
                                && !contextual)
                        {
                            continue;
                        }
                        let carried =
                            self.facts(channel_record)
                                .iter()
                                .any(|fact| match &fact.value {
                                    GraphFactValueV1::Channel {
                                        task_cookie,
                                        process_instance_id,
                                        socket_object_id,
                                        authority_id: channel_authority,
                                        carried_request_id,
                                        credential_lease_id: channel_lease,
                                        principal_id: channel_principal,
                                        operation_id: channel_operation,
                                        proof_quality: channel_proof,
                                    } => *task_cookie == channel_wire.task_cookie
                                        && Some(*process_instance_id) == channel_process
                                        && channel_wire.exact_object_id.as_ref()
                                            == *socket_object_id
                                        && channel_authority == authority_id
                                        && Some(carried_request_id) == request_id.as_ref()
                                        && Some(channel_lease) == credential_lease_id.as_ref()
                                        && channel_principal == principal_id
                                        && channel_operation == operation_id
                                        && Self::qualified_result(*channel_proof)
                                        && channel_proof.operation_result_authority
                                            == OperationResultAuthorityV1::AuthoritativeSucceeded,
                                    _ => false,
                                });
                        let direct = bytes_proven
                            && local
                            && socket
                            && *credential_object_id == Some(object_id)
                            && completion.as_ref().is_some_and(|completion| {
                                completion.credential_lease_id.as_ref()
                                    == credential_lease_id.as_ref()
                                    && completion.credential_lease_id.is_some()
                                    && completion.principal_id.as_ref() == Some(principal_id)
                            })
                            && carried
                            && channel_wire.decision != PhysicalDecisionKindV1::Deny as u32
                            && self.proof(channel_record).temporal_coverage
                                == TemporalCoverageV1::Complete
                            && proof_quality.source_authority
                                == SourceAuthorityV1::AuthoritativeProvider
                            && matches!(
                                proof_quality.remote_subject_binding,
                                RemoteSubjectBindingV1::ExactRequest
                                    | RemoteSubjectBindingV1::ExactSession
                            )
                            && matches!(
                                proof_quality.operation_result_authority,
                                OperationResultAuthorityV1::AuthoritativeSucceeded
                                    | OperationResultAuthorityV1::AuthoritativeDenied
                            )
                            && Self::qualified_result(*proof_quality);
                        evidence.push(channel_record.id.clone());
                        matched.push((authority.clone(), direct));
                    }
                }
                for authority in &self.facts {
                    let GraphFactValueV1::AuthorityUse {
                        principal_id,
                        outside_reviewed_behavior,
                        proof_quality,
                        workload_binding,
                        ..
                    } = &authority.value
                    else {
                        continue;
                    };
                    let authority_record = self
                        .input
                        .records
                        .iter()
                        .find(|candidate| candidate.id == authority.record_id)
                        .ok_or_else(|| {
                            GraphInvalidSnafu {
                                field: "contextual authority record",
                            }
                            .build()
                        })?;
                    let authority_wire = authority_record.decode()?;
                    let workload = wire.execution_set_id.iter().any(|byte| *byte != 0)
                        && workload_binding.as_ref()
                            == Some(&GraphSubjectKeyV1::native(
                                &record.id.stream,
                                GraphSubjectKindV1::ExecutionSet,
                                wire.execution_set_id.to_vec(),
                            ));
                    let bounded = authority_wire.observed_boottime_ns >= wire.observed_boottime_ns
                        && authority_wire.observed_boottime_ns - wire.observed_boottime_ns
                            <= GRAPH_WINDOW_NS;
                    if *outside_reviewed_behavior
                        && workload
                        && bounded
                        && credential_principal.as_ref() == Some(principal_id)
                        && matches!(
                            proof_quality.source_authority,
                            SourceAuthorityV1::AuthoritativeProvider
                                | SourceAuthorityV1::SignedCoordinator
                        )
                        && matches!(
                            proof_quality.integrity,
                            ProofIntegrityV1::Signed | ProofIntegrityV1::AuthenticatedChannel
                        )
                        && !matched.iter().any(|(fact, _)| fact == authority)
                    {
                        matched.push((authority.clone(), false));
                    }
                }
                let mut qualified: Vec<(GraphFactV1, bool)> = Vec::new();
                for (fact, direct) in matched {
                    if let Some((_, existing)) =
                        qualified.iter_mut().find(|(existing, _)| existing == &fact)
                    {
                        *existing |= direct;
                    } else {
                        qualified.push((fact, direct));
                    }
                }
                qualified.sort_by(|left, right| left.0.record_id.cmp(&right.0.record_id));
                let matched = qualified;
                let mut results = BTreeMap::<
                    (String, Option<String>, Option<String>, String, String),
                    BTreeSet<OperationResultAuthorityV1>,
                >::new();
                for (fact, _) in &matched {
                    if let GraphFactValueV1::AuthorityUse {
                        authority_id,
                        request_id,
                        credential_lease_id,
                        principal_id,
                        operation_id,
                        proof_quality,
                        ..
                    } = &fact.value
                    {
                        if request_id.is_some() {
                            results
                                .entry((
                                    authority_id.clone(),
                                    request_id.clone(),
                                    credential_lease_id.clone(),
                                    principal_id.clone(),
                                    operation_id.clone(),
                                ))
                                .or_default()
                                .insert(proof_quality.operation_result_authority);
                        }
                    }
                }
                let contradicted = results.values().any(|results| {
                    results.contains(&OperationResultAuthorityV1::AuthoritativeSucceeded)
                        && results.contains(&OperationResultAuthorityV1::AuthoritativeDenied)
                });
                let direct = !matched.is_empty() && matched.iter().all(|(_, direct)| *direct);
                let reason = if matched.is_empty() {
                    FindingReasonV1::MissingAuthorityProof
                } else if contradicted {
                    FindingReasonV1::Contradiction
                } else if direct {
                    FindingReasonV1::CredentialPivot
                } else {
                    FindingReasonV1::ContextualCredentialPivot
                };
                let state = if direct
                    && !contradicted
                    && self.proof(record).temporal_coverage == TemporalCoverageV1::Complete
                {
                    FindingStateV1::Confirmed
                } else {
                    FindingStateV1::CoverageInsufficient
                };
                self.states[1] = if contradicted {
                    GraphPackageStateV1::Contradicted
                } else if direct {
                    GraphPackageStateV1::DirectPivot
                } else if matched.is_empty() {
                    GraphPackageStateV1::CoverageInsufficient
                } else {
                    GraphPackageStateV1::ContextualPivot
                };
                if matched.is_empty() {
                    limits.push("AUTHORITATIVE_REMOTE_RESULT_MISSING".into());
                    if self.input.records.len() == GRAPH_WINDOW_RECORDS as usize {
                        limits.push("JOIN_WINDOW_RECORD_LIMIT".into());
                    }
                }
                if !direct {
                    limits.push("CREDENTIAL_SPECIFIC_RESPONSE_UNPROVEN".into());
                    limits.push("CARRIED_REQUEST_OR_COMPLETION_MISSING".into());
                    limits.push("EXACT_TASK_SOCKET_REQUEST_PROOF_INSUFFICIENT".into());
                }
                for (authority, exact) in matched {
                    evidence.push(authority.record_id.clone());
                    if let GraphFactValueV1::AuthorityUse {
                        authority_id,
                        request_id,
                        principal_id,
                        operation_id,
                        proof_quality,
                        ..
                    } = authority.value
                    {
                        let remote = GraphSubjectKeyV1 {
                            tenant_id: self.input.source.tenant_id,
                            authority: GraphSubjectAuthorityV1::Provider { authority_id },
                            kind: if request_id.is_some() {
                                GraphSubjectKindV1::Request
                            } else {
                                GraphSubjectKindV1::ProviderObject
                            },
                            identity: serde_json::to_vec(&(request_id, principal_id, operation_id))
                                .context(GraphEncodingSnafu)?,
                        };
                        self.subjects.insert(remote.clone());
                        self.edge(
                            GraphEdgeKeyV1 {
                                from: task.clone(),
                                to: remote,
                                edge_type: GraphEdgeTypeV1::CredentialAuthority,
                                package_id: "HF-DW-001".into(),
                                evidence: evidence.clone(),
                                cause: if contradicted {
                                    GraphCauseV1::Contradicted
                                } else if exact {
                                    GraphCauseV1::Direct
                                } else {
                                    GraphCauseV1::Contextual
                                },
                            },
                            proof_quality,
                            &wire,
                        )?;
                    }
                }
                self.finding("HF-DW-001", record, task, reason, state, evidence, limits)?;
            }
        }
        Ok(())
    }

    fn cross_node(&mut self) -> Result<()> {
        let facts: Vec<_> = self
            .facts
            .iter()
            .filter(|fact| matches!(fact.value, GraphFactValueV1::Kubernetes(_)))
            .cloned()
            .collect();
        for fact in facts {
            let GraphFactValueV1::Kubernetes(stage) = fact.value else {
                continue;
            };
            let record = self
                .input
                .records
                .iter()
                .find(|record| record.id == fact.record_id)
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "Kubernetes evidence",
                    }
                    .build()
                })?;
            let wire = record.decode()?;
            let task = self.task(record, &wire);
            let qualified = stage.proof_quality.source_authority
                == SourceAuthorityV1::AuthoritativeProvider
                && stage.proof_quality.temporal_coverage == TemporalCoverageV1::Complete
                && matches!(
                    stage.proof_quality.integrity,
                    ProofIntegrityV1::Signed | ProofIntegrityV1::AuthenticatedChannel
                );
            let mut missing = Vec::new();
            for (proved, name) in [
                (
                    stage.carried_request_id.is_some(),
                    "CARRIED_REQUEST_MISSING",
                ),
                (stage.audit_id.is_some(), "KUBERNETES_AUDIT_MISSING"),
                (
                    stage.object_uid.is_some() && stage.resource_version.is_some(),
                    "OBJECT_VERSION_MISSING",
                ),
                (
                    stage.owner_uid.is_some() && stage.pod_uid.is_some(),
                    "OWNER_POD_BRIDGE_MISSING",
                ),
                (stage.node_id.is_some(), "SCHEDULER_NODE_MISSING"),
                (
                    stage.full_container_id.is_some() && stage.remote_admission_id.is_some(),
                    "REMOTE_RUNTIME_ADMISSION_MISSING",
                ),
                (qualified, "KUBERNETES_SOURCE_QUALIFICATION_MISSING"),
            ] {
                if !proved {
                    missing.push(name.to_owned());
                }
            }
            self.states[2] = if !qualified {
                GraphPackageStateV1::KubernetesProofMissing
            } else if stage.full_container_id.is_some() && stage.remote_admission_id.is_some() {
                GraphPackageStateV1::RemoteAdmission
            } else if stage.node_id.is_some() {
                GraphPackageStateV1::KubernetesScheduled
            } else if stage.object_uid.is_some() && stage.resource_version.is_some() {
                GraphPackageStateV1::KubernetesObject
            } else if stage.audit_id.is_some() {
                GraphPackageStateV1::KubernetesAudit
            } else if stage.carried_request_id.is_some() {
                GraphPackageStateV1::KubernetesRequest
            } else {
                GraphPackageStateV1::KubernetesProofMissing
            };
            if let Some(uid) = &stage.object_uid {
                let object = GraphSubjectKeyV1 {
                    tenant_id: self.input.source.tenant_id,
                    authority: GraphSubjectAuthorityV1::Kubernetes {
                        cluster_id: stage.cluster_id.clone(),
                    },
                    kind: GraphSubjectKindV1::KubernetesObject,
                    identity: serde_json::to_vec(&(uid, &stage.resource_version))
                        .context(GraphEncodingSnafu)?,
                };
                self.subjects.insert(object.clone());
                self.edge(
                    GraphEdgeKeyV1 {
                        from: task.clone(),
                        to: object,
                        edge_type: GraphEdgeTypeV1::KubernetesExpansion,
                        package_id: "HF-XNODE-001".into(),
                        evidence: vec![record.id.clone()],
                        cause: GraphCauseV1::Contextual,
                    },
                    stage.proof_quality,
                    &wire,
                )?;
            }
            missing.push("CROSS_NODE_CAUSALITY_UNQUALIFIED".into());
            missing.sort();
            self.finding(
                "HF-XNODE-001",
                record,
                task,
                FindingReasonV1::KubernetesProofMissing,
                FindingStateV1::CoverageInsufficient,
                vec![record.id.clone()],
                missing,
            )?;
        }
        Ok(())
    }

    fn context_actions(&mut self) -> Result<()> {
        for fact in self.facts.clone() {
            let GraphFactValueV1::Context {
                subject,
                classification,
                ..
            } = fact.value
            else {
                continue;
            };
            let record = self
                .input
                .records
                .iter()
                .find(|record| record.id == fact.record_id)
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "context anchor",
                    }
                    .build()
                })?;
            self.subjects.insert(subject.clone());
            let reason = match classification {
                GraphContextActionV1::OutsideAuthority => FindingReasonV1::OutsideAuthority,
                GraphContextActionV1::InMemory => FindingReasonV1::InMemoryOnly,
                GraphContextActionV1::PayloadUnobservable => FindingReasonV1::PayloadUnobservable,
            };
            self.finding(
                "HF-PROC-001",
                record,
                subject,
                reason,
                FindingStateV1::CoverageInsufficient,
                vec![record.id.clone()],
                vec!["CONTEXT_ANCHOR_HAS_NO_PHYSICAL_ACTION_PROOF".into()],
            )?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<GraphSnapshotV1> {
        for finding in self.findings.values() {
            self.branches.push(GraphBranchV1 {
                package_id: finding.package_id.clone(),
                seed: finding.subject_id.clone(),
                evidence: finding.evidence.clone(),
                state: if finding.reason == FindingReasonV1::OutsideAuthority {
                    GraphBranchStateV1::OutsideAuthority
                } else if finding.limits.iter().any(|limit| {
                    limit.contains("COVERAGE")
                        || limit.contains("MISSING")
                        || limit.contains("UNAVAILABLE")
                }) {
                    GraphBranchStateV1::CoverageUnknown
                } else if finding.reason == FindingReasonV1::ContextualCredentialPivot {
                    GraphBranchStateV1::ContextualOnly
                } else {
                    GraphBranchStateV1::Open
                },
                missing_fields: finding.limits.clone(),
            });
        }
        self.branches.sort_by(|left, right| {
            (
                &left.package_id,
                &left.seed,
                &left.evidence,
                &left.missing_fields,
            )
                .cmp(&(
                    &right.package_id,
                    &right.seed,
                    &right.evidence,
                    &right.missing_fields,
                ))
        });
        self.branches.dedup();
        let first = self
            .input
            .records
            .first()
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph first record",
                }
                .build()
            })?
            .id
            .durable_cursor;
        let last = self
            .input
            .records
            .last()
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph last record",
                }
                .build()
            })?
            .id
            .durable_cursor;
        let packages = [
            (
                "HF-PROC-001",
                vec!["exact-task-entry-role", "kernel-effect", "source-coverage"],
            ),
            (
                "HF-DW-001",
                vec![
                    "reviewed-credential",
                    "exact-local-channel",
                    "authoritative-operation",
                    "source-coverage",
                ],
            ),
            (
                "HF-XNODE-001",
                vec![
                    "carried-request-proof",
                    "Kubernetes-audit",
                    "object-owner-scheduler",
                    "remote-runtime-admission",
                ],
            ),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (id, inputs))| GraphPackageCheckpointV1 {
            package_id: id.into(),
            package_version: 1,
            required_inputs: inputs.into_iter().map(str::to_owned).collect(),
            state: self.states[index],
            maximum_lateness_ns: GRAPH_WITNESS_TTL_NS,
            retention_ttl_ns: GRAPH_WITNESS_TTL_NS,
            clock_uncertainty_ns: None,
            late_action: "append-exact-revision-or-report-expired-input".into(),
            window_ns: GRAPH_WINDOW_NS,
            window_records: GRAPH_WINDOW_RECORDS,
            window_bytes: GRAPH_WINDOW_BYTES,
            coverage_predicate:
                "complete-required-source-intervals-and-qualified-operation-results".into(),
            replay_contract_id: format!("{id}/v1"),
            result_states: vec![
                FindingStateV1::Provisional,
                FindingStateV1::Confirmed,
                FindingStateV1::Superseded,
                FindingStateV1::Retracted,
                FindingStateV1::CoverageInsufficient,
            ],
            accepted_cursor_watermark: last,
            observed_boottime_watermark_ns: self
                .input
                .records
                .iter()
                .filter_map(|record| record.decode().ok().map(|wire| wire.observed_boottime_ns))
                .max()
                .unwrap_or(0),
        })
        .collect();
        let snapshot = GraphSnapshotV1 {
            schema_version: GRAPH_SCHEMA_VERSION,
            scope: ProcessorScopeV1 {
                processor_id: GRAPH_PROCESSOR.into(),
                method_version: GRAPH_SCHEMA_VERSION as u64,
                identity: self.input.source.clone(),
            },
            first_cursor: first,
            last_cursor: last,
            input_manifest: self.revision.clone(),
            graph: GraphVersionV1 {
                revision: self.revision,
                subjects: self.subjects.into_iter().collect(),
                edges: self.edges.into_values().collect(),
                branches: self.branches,
                facts: self.facts,
            },
            findings: self.findings.into_values().collect(),
            packages,
            missing_ranges: self.input.missing_ranges.clone(),
            input_positions: Vec::new(),
            previous_result_id: None,
            context_notice_revision: 0,
            witness_deadline_utc_ns: 0,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }
}
