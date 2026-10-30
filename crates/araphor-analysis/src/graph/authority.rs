use super::*;

impl Graph<'_> {
    pub(super) fn require(valid: bool, field: &'static str) -> Result<()> {
        if valid {
            Ok(())
        } else {
            GraphInvalidSnafu { field }.fail()
        }
    }

    fn record(&self, index: u32) -> Result<&DiscoveryRecordV1> {
        self.input.records.get(index as usize).ok_or_else(|| {
            GraphInvalidSnafu {
                field: "graph output record",
            }
            .build()
        })
    }

    fn fact(&self, index: Option<u32>) -> Result<&GraphFactV1> {
        index
            .and_then(|index| self.facts.get(index as usize))
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph output fact",
                }
                .build()
            })
    }

    fn exact(value: &algorithm::Observation) -> bool {
        value.effect.task_cookie > 0
            && value.process_instance_id.is_some()
            && value.entry_instance_id.is_some()
            && value.binding_id.is_some()
            && value.role_id.is_some()
            && value.state_id.is_some()
            && value.entry_rule_id.is_some()
    }

    fn native_key(&self, key: &GraphSubjectKeyV1) -> bool {
        key.tenant_id == self.input.source.tenant_id
            && matches!(&key.authority,
            GraphSubjectAuthorityV1::Native { node_id, node_boot_id, label_epoch }
            if node_id == &self.input.source.node_id && node_boot_id == &self.input.source.node_boot_id && *label_epoch == self.input.source.label_epoch)
    }

    fn task_matches(&self, value: &algorithm::Observation, key: &GraphSubjectKeyV1) -> bool {
        if value.effect.task_cookie > 0 {
            self.native_key(key)
                && key.kind == GraphSubjectKindV1::Task
                && key.identity == value.effect.task_cookie.to_be_bytes()
        } else {
            key.tenant_id == value.id.stream.tenant_id
                && matches!(&key.authority, GraphSubjectAuthorityV1::External { authority_id } if authority_id == "unresolved-native-observation")
                && key.kind == GraphSubjectKindV1::External
                && key.identity
                    == value
                        .id
                        .stream
                        .key()
                        .into_iter()
                        .chain(value.id.durable_cursor.to_be_bytes())
                        .collect::<Vec<_>>()
        }
    }

    fn raw_subject(&self, value: &algorithm::Observation, key: &GraphSubjectKeyV1) -> bool {
        if self.task_matches(value, key) {
            return true;
        }
        if !self.native_key(key) {
            return false;
        }
        match key.kind {
            GraphSubjectKindV1::Process => value
                .process_instance_id
                .is_some_and(|id| key.identity == id),
            GraphSubjectKindV1::ExecutionSet => key.identity == value.effect.execution_set_id,
            GraphSubjectKindV1::Socket | GraphSubjectKindV1::Artifact => {
                let kind = if value.effect.effect_family == KernelEffectFamilyV1::Network as u32 {
                    GraphSubjectKindV1::Socket
                } else {
                    GraphSubjectKindV1::Artifact
                };
                key.kind == kind
                    && key.identity
                        == value
                            .effect
                            .exact_object_id
                            .iter()
                            .copied()
                            .chain(
                                value
                                    .profile_generation_ref_id
                                    .unwrap_or_default()
                                    .to_be_bytes(),
                            )
                            .collect::<Vec<_>>()
            }
            _ => false,
        }
    }

    fn authority_matches(&self, fact: &GraphFactV1, key: &GraphSubjectKeyV1) -> Result<bool> {
        let GraphFactValueV1::AuthorityUse {
            authority_id,
            request_id,
            principal_id,
            operation_id,
            ..
        } = &fact.value
        else {
            return Ok(false);
        };
        Ok(key.tenant_id == self.input.source.tenant_id
            && matches!(&key.authority, GraphSubjectAuthorityV1::Provider { authority_id: actual } if actual == authority_id)
            && key.kind
                == if request_id.is_some() {
                    GraphSubjectKindV1::Request
                } else {
                    GraphSubjectKindV1::ProviderObject
                }
            && key.identity
                == GraphSubjectKeyV1::provider_identity(request_id, principal_id, operation_id)
                    .context(AnalysisContractSnafu)?)
    }

    fn kubernetes_matches(&self, fact: &GraphFactV1, key: &GraphSubjectKeyV1) -> Result<bool> {
        let GraphFactValueV1::Kubernetes(stage) = &fact.value else {
            return Ok(false);
        };
        let Some(uid) = &stage.object_uid else {
            return Ok(false);
        };
        Ok(key.tenant_id == self.input.source.tenant_id
            && matches!(&key.authority, GraphSubjectAuthorityV1::Kubernetes { cluster_id } if cluster_id == &stage.cluster_id)
            && key.kind == GraphSubjectKindV1::KubernetesObject
            && key.identity
                == GraphSubjectKeyV1::kubernetes_identity(uid, &stage.resource_version)
                    .context(AnalysisContractSnafu)?)
    }

    pub(super) fn validate_subject(&self, row: &algorithm::Subject) -> Result<()> {
        row.key.validate()?;
        let record = self.record(row.record)?;
        let valid = match row.context {
            Some(index) => {
                let fact = self.fact(Some(index))?;
                fact.record_id == record.id
                    && match &fact.value {
                        GraphFactValueV1::Context { subject, .. } => subject == &row.key,
                        GraphFactValueV1::NativeParent { parent, child, .. } => {
                            parent == &row.key || child == &row.key
                        }
                        GraphFactValueV1::AuthorityUse { .. } => {
                            self.authority_matches(fact, &row.key)?
                        }
                        GraphFactValueV1::Kubernetes(_) => {
                            self.kubernetes_matches(fact, &row.key)?
                        }
                        _ => false,
                    }
            }
            None => self.raw_subject(self.observation(record)?, &row.key),
        };
        Self::require(valid, "graph subject authority")
    }

    pub(super) fn validate_edge(
        &self,
        row: &algorithm::Relationship,
        subjects: &[algorithm::Subject],
    ) -> Result<()> {
        let record = self.record(row.record)?;
        let value = self.observation(record)?;
        let edge = &row.edge;
        Self::require(
            edge.key.evidence.contains(&row.record)
                && edge.key.evidence.windows(2).all(|pair| pair[0] < pair[1])
                && edge
                    .key
                    .evidence
                    .iter()
                    .all(|index| (*index as usize) < self.input.records.len()),
            "graph edge evidence",
        )?;
        let from = subjects.get(edge.key.from as usize).ok_or_else(|| {
            GraphInvalidSnafu {
                field: "graph edge endpoint",
            }
            .build()
        })?;
        let to = subjects.get(edge.key.to as usize).ok_or_else(|| {
            GraphInvalidSnafu {
                field: "graph edge endpoint",
            }
            .build()
        })?;
        let interval: [u8; 16] =
            value
                .coverage_interval_id
                .as_slice()
                .try_into()
                .map_err(|_| {
                    GraphInvalidSnafu {
                        field: "edge coverage interval",
                    }
                    .build()
                })?;
        Self::require(
            edge.required_coverage_interval_ids == [interval]
                && edge.first_boottime_ns == value.observed_boottime_ns
                && edge.last_boottime_ns == value.observed_boottime_ns,
            "graph edge input fields",
        )?;
        let (valid, mut ceiling, direct) = match edge.key.edge_type {
            GraphEdgeTypeV1::TaskInProcess => (
                self.task_matches(value, &from.key)
                    && self.native_key(&to.key)
                    && to.key.kind == GraphSubjectKindV1::Process
                    && value
                        .process_instance_id
                        .is_some_and(|id| to.key.identity == id),
                value.proof_quality,
                Self::exact(value),
            ),
            GraphEdgeTypeV1::TaskInExecutionSet => (
                self.task_matches(value, &from.key)
                    && self.native_key(&to.key)
                    && to.key.kind == GraphSubjectKindV1::ExecutionSet
                    && to.key.identity == value.effect.execution_set_id,
                value.proof_quality,
                Self::exact(value),
            ),
            GraphEdgeTypeV1::NativeEffect => (
                self.task_matches(value, &from.key)
                    && matches!(
                        to.key.kind,
                        GraphSubjectKindV1::Socket | GraphSubjectKindV1::Artifact
                    )
                    && self.raw_subject(value, &to.key),
                value.proof_quality,
                Self::exact(value),
            ),
            GraphEdgeTypeV1::NativeParent => {
                let fact = self.fact(row.fact)?;
                let GraphFactValueV1::NativeParent {
                    parent,
                    child,
                    proof_quality,
                } = &fact.value
                else {
                    return GraphInvalidSnafu {
                        field: "graph parent selection",
                    }
                    .fail();
                };
                (
                    fact.record_id == record.id && &from.key == parent && &to.key == child,
                    *proof_quality,
                    proof_quality.parent_qualified()
                        && child.matches_local(value.effect.task_cookie, value.process_instance_id),
                )
            }
            GraphEdgeTypeV1::CredentialAuthority => {
                let fact = self.fact(row.fact)?;
                let GraphFactValueV1::AuthorityUse {
                    task_cookie,
                    process_instance_id,
                    credential_object_id,
                    proof_quality,
                    ..
                } = &fact.value
                else {
                    return GraphInvalidSnafu {
                        field: "graph AuthorityUse input",
                    }
                    .fail();
                };
                let direct = Self::exact(value)
                    && proof_quality.authority_direct()
                    && ((value.effect.task_cookie > 0
                        && *task_cookie == Some(value.effect.task_cookie))
                        || (value.process_instance_id.is_some()
                            && *process_instance_id == value.process_instance_id))
                    && credential_object_id.is_some_and(|id| value.effect.exact_object_id == id)
                    && edge
                        .key
                        .evidence
                        .iter()
                        .any(|index| self.input.records[*index as usize].id == fact.record_id);
                (
                    self.task_matches(value, &from.key) && self.authority_matches(fact, &to.key)?,
                    *proof_quality,
                    direct,
                )
            }
            GraphEdgeTypeV1::KubernetesExpansion => {
                let fact = self.fact(row.fact)?;
                let GraphFactValueV1::Kubernetes(stage) = &fact.value else {
                    return GraphInvalidSnafu {
                        field: "graph Kubernetes selection",
                    }
                    .fail();
                };
                (
                    fact.record_id == record.id
                        && self.task_matches(value, &from.key)
                        && self.kubernetes_matches(fact, &to.key)?,
                    stage.proof_quality,
                    false,
                )
            }
        };
        Self::require(valid, "graph edge endpoint authority")?;
        if edge.key.cause == GraphCauseV1::Contradicted
            && edge.proof_quality.operation_result_authority == OperationResultAuthorityV1::Unknown
        {
            ceiling.operation_result_authority = OperationResultAuthorityV1::Unknown;
        }
        Self::require(edge.proof_quality == ceiling, "graph edge proof ceiling")?;
        Self::require(
            edge.key.cause != GraphCauseV1::Superseded
                && (edge.key.cause != GraphCauseV1::Direct || direct),
            "graph direct cause proof",
        )
    }

    fn validate_effect(&self, effect: &GraphEffectV1) -> Result<()> {
        let index = self
            .input
            .records
            .binary_search_by(|row| row.id.cmp(&effect.evidence))
            .map_err(|_| {
                GraphInvalidSnafu {
                    field: "finding evidence",
                }
                .build()
            })?;
        let value = self.observation(&self.input.records[index])?;
        let physical = match value.effect.decision {
            code if code == EffectPhysicalResultV1::DeniedBeforeEffect as u32
                && value.effect.kernel_result < 0 =>
            {
                GraphPhysicalResultV1::Prevented
            }
            code if code == EffectPhysicalResultV1::PacketDroppedAfterRewrite as u32 => {
                GraphPhysicalResultV1::PacketDropped
            }
            code if code == EffectPhysicalResultV1::TerminationQueuedBeforeUserMode as u32 => {
                GraphPhysicalResultV1::TerminationQueued
            }
            _ => GraphPhysicalResultV1::Unknown,
        };
        Self::require(
            effect.process_instance_id == value.process_instance_id
                && effect.entry_instance_id == value.entry_instance_id
                && effect.binding_id == value.binding_id
                && effect.role_id == value.role_id
                && effect.state_id == value.state_id
                && effect.entry_rule_id == value.entry_rule_id
                && effect.profile_generation_ref_id == value.profile_generation_ref_id
                && effect.original_kernel_sequence == value.original_kernel_sequence
                && effect.effect_family == value.effect.effect_family
                && effect.operation == value.effect.operation
                && effect.source_decision == value.effect.decision
                && effect.source_reason == value.effect.reason
                && effect.configured_errno == value.effect.configured_errno
                && effect.kernel_result == value.effect.kernel_result
                && effect.physical_result == physical
                && effect.proof_quality == value.proof_quality,
            "graph effect authority",
        )
    }

    fn missing_policy(
        policy: &PolicyObservationProvenanceV1,
        id: &DiscoveryRecordIdV1,
        generation: u64,
    ) -> bool {
        policy.state == PolicyProvenanceStateV1::Missing
            && policy.source == id.stream
            && policy.profile_generation_ref_id == generation
            && policy.observations.as_slice() == std::slice::from_ref(id)
            && policy.policy_source_revision_id.is_none()
            && policy.candidate_content_id.is_none()
            && policy.target_snapshot_digest.is_none()
            && policy.node_bound_generation_digest.is_none()
            && policy.activation_acknowledgement.is_none()
            && policy.limits == ["ACTIVATION_ACKNOWLEDGEMENT_MISSING"]
    }

    fn validate_provenance(&self, finding: &FindingV1) -> Result<()> {
        if matches!(
            finding.reason,
            FindingReasonV1::OutsideAuthority
                | FindingReasonV1::InMemoryOnly
                | FindingReasonV1::PayloadUnobservable
        ) {
            return Self::require(
                finding.policy_provenance.is_empty(),
                "graph policy provenance authority",
            );
        }
        let mut required = BTreeSet::new();
        let mut missing = Vec::new();
        for id in &finding.evidence {
            let index = self
                .input
                .records
                .binary_search_by(|row| row.id.cmp(id))
                .map_err(|_| {
                    GraphInvalidSnafu {
                        field: "finding evidence",
                    }
                    .build()
                })?;
            let generation = self.input.records[index]
                .decode()?
                .profile_generation_ref_id
                .unwrap_or_default();
            let policies = self
                .facts
                .iter()
                .filter(|fact| &fact.record_id == id)
                .filter_map(|fact| match &fact.value {
                    GraphFactValueV1::Policy(policy)
                        if policy.profile_generation_ref_id == generation =>
                    {
                        Some(policy)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            let exact = policies
                .iter()
                .filter(|policy| policy.state == PolicyProvenanceStateV1::Exact)
                .map(|policy| {
                    (
                        &policy.policy_source_revision_id,
                        &policy.candidate_content_id,
                        &policy.target_snapshot_digest,
                    )
                })
                .collect::<BTreeSet<_>>();
            let mut joined = false;
            for policy in policies {
                if policy.state == PolicyProvenanceStateV1::Missing
                    && exact.contains(&(
                        &policy.policy_source_revision_id,
                        &policy.candidate_content_id,
                        &policy.target_snapshot_digest,
                    ))
                {
                    continue;
                }
                required.insert(policy);
                joined = true;
            }
            if !joined {
                missing.push((id, generation));
            }
        }
        Self::require(
            finding
                .policy_provenance
                .windows(2)
                .all(|pair| pair[0] < pair[1])
                && finding.policy_provenance.iter().all(|policy| {
                    required.contains(policy)
                        || missing
                            .iter()
                            .any(|(id, generation)| Self::missing_policy(policy, id, *generation))
                })
                && required
                    .iter()
                    .all(|policy| finding.policy_provenance.contains(policy))
                && missing.iter().all(|(id, generation)| {
                    finding
                        .policy_provenance
                        .iter()
                        .any(|policy| Self::missing_policy(policy, id, *generation))
                }),
            "graph policy provenance authority",
        )?;
        Self::require(
            required.iter().all(|policy| {
                policy
                    .limits
                    .iter()
                    .all(|limit| finding.limits.contains(limit))
                    && match policy.state {
                        PolicyProvenanceStateV1::Exact => true,
                        PolicyProvenanceStateV1::Missing => finding
                            .limits
                            .iter()
                            .any(|limit| limit == "POLICY_PROVENANCE_MISSING"),
                        PolicyProvenanceStateV1::Contradicted => finding
                            .limits
                            .iter()
                            .any(|limit| limit == "POLICY_PROVENANCE_CONTRADICTED"),
                    }
            }) && (missing.is_empty()
                || finding
                    .limits
                    .iter()
                    .any(|limit| limit == "POLICY_PROVENANCE_MISSING")),
            "graph policy provenance limits",
        )
    }

    pub(super) fn validate_finding(
        &self,
        record: u32,
        context: Option<u32>,
        finding: &FindingV1,
    ) -> Result<()> {
        let record = self.record(record)?;
        Self::require(
            finding.evidence.contains(&record.id),
            "graph finding evidence",
        )?;
        let value = self.observation(record)?;
        let subject = match context {
            Some(index) => {
                let fact = self.fact(Some(index))?;
                fact.record_id == record.id
                    && matches!(&fact.value, GraphFactValueV1::Context { subject, .. } if subject == &finding.subject_id)
            }
            None => self.task_matches(value, &finding.subject_id),
        };
        Self::require(subject, "graph context selection")?;
        if finding.state == FindingStateV1::Confirmed {
            Self::require(
                context.is_none()
                    && Self::exact(value)
                    && value.proof_quality.temporal_coverage == TemporalCoverageV1::Complete,
                "graph confirmed finding proof",
            )?;
        }
        let mut intervals = BTreeSet::new();
        let mut times = Vec::new();
        for id in &finding.evidence {
            let index = self
                .input
                .records
                .binary_search_by(|row| row.id.cmp(id))
                .map_err(|_| {
                    GraphInvalidSnafu {
                        field: "finding evidence",
                    }
                    .build()
                })?;
            let value = self.observation(&self.input.records[index])?;
            if finding.state == FindingStateV1::Confirmed {
                Self::require(
                    value.proof_quality.temporal_coverage == TemporalCoverageV1::Complete,
                    "graph finding coverage",
                )?;
            }
            intervals.insert(
                <[u8; 16]>::try_from(value.coverage_interval_id.as_slice()).map_err(|_| {
                    GraphInvalidSnafu {
                        field: "finding coverage",
                    }
                    .build()
                })?,
            );
            times.push(value.ingested_utc_ns);
        }
        Self::require(
            finding.window_start_utc_ns == times.iter().copied().min().unwrap_or(0)
                && finding.window_end_utc_ns == times.iter().copied().max().unwrap_or(0)
                && finding.required_coverage_interval_ids
                    == intervals.into_iter().collect::<Vec<_>>(),
            "graph finding input fields",
        )?;
        let floor = if self
            .input
            .facts
            .iter()
            .any(|fact| fact.sensitivity == ContextSensitivityV1::HostRestricted)
        {
            ContextSensitivityV1::HostRestricted
        } else {
            ContextSensitivityV1::Tenant
        };
        Self::require(finding.sensitivity == floor, "graph finding disclosure")?;
        Self::require(
            finding.finding_id
                == FindingV1::identity(&finding.package_id, &record.id, &finding.subject_id)
                    .context(AnalysisContractSnafu)?,
            "graph finding identity",
        )?;
        let context_only = matches!(
            finding.reason,
            FindingReasonV1::OutsideAuthority
                | FindingReasonV1::InMemoryOnly
                | FindingReasonV1::PayloadUnobservable
        );
        Self::require(
            if context_only {
                finding.effects.is_empty()
            } else {
                finding
                    .effects
                    .iter()
                    .map(|effect| &effect.evidence)
                    .eq(finding.evidence.iter())
            },
            "graph effect evidence",
        )?;
        for effect in &finding.effects {
            self.validate_effect(effect)?;
        }
        self.validate_provenance(finding)?;
        self.revision.validate_finding(finding)
    }
}
