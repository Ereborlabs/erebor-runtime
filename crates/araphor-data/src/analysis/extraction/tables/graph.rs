use super::*;
use crate::{
    ContextSensitivityV1, FindingSeverityV1, FindingStateV1, GraphBranchStateV1, GraphCauseV1,
    GraphEdgeTypeV1, GraphPackageStateV1, GraphSnapshotV1, GraphSubjectKeyV1, GraphSubjectKindV1,
    PolicyProvenanceStateV1,
};
use serde_arrow::schema::{SchemaLike as _, TracingOptions};
use std::sync::LazyLock;

#[derive(serde::Serialize)]
struct ManifestRow<'a> {
    tenant_id: &'a serde_bytes::Bytes,
    source_key: &'a serde_bytes::Bytes,
    graph_result_id: &'a str,
    commit_revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    graph_revision: Option<&'a crate::GraphRevisionV1>,
    graph_sensitivity: &'a str,
    first_cursor: u64,
    last_cursor: u64,
    previous_result_id: Option<&'a str>,
    context_notice_revision: u64,
    notice_context_revision: u64,
    notice_coverage_revision: u64,
    witness_deadline_utc_ns: u64,
    retained_input_expired: bool,
    subject_count: u64,
    relationship_count: u64,
    max_hops: u32,
    hop_boundary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot: Option<&'a serde_bytes::Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<&'a serde_bytes::Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context_refs: Option<&'a [crate::AnalysisContextRefV1]>,
}

fn context_ref_field() -> sdk::Field {
    #[derive(serde::Serialize)]
    struct Sample<'a> {
        context_refs: &'a [crate::AnalysisContextRefV1],
    }

    #[expect(
        clippy::expect_used,
        reason = "The schema comes from one complete internal typed sample."
    )]
    static FIELD: LazyLock<sdk::Field> = LazyLock::new(|| {
        let reference = crate::AnalysisContextRefV1 {
            key: crate::AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "owner".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: 1,
            },
            commit_revision: 1,
        };
        let fields = Vec::<Arc<sdk::Field>>::from_samples(
            [Sample {
                context_refs: &[reference],
            }],
            TracingOptions::default()
                .strings_as_large_utf8(false)
                .sequence_as_large_list(false)
                .bytes_as_large_binary(false),
        )
        .expect("the context reference has a native Arrow schema");
        fields[0].as_ref().clone()
    });
    FIELD.clone()
}

#[derive(serde::Serialize)]
struct RelationshipRow<'a> {
    tenant_id: &'a serde_bytes::Bytes,
    source_key: &'a serde_bytes::Bytes,
    graph_result_id: &'a str,
    commit_revision: u64,
    graph_sensitivity: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    relationship_key: Option<&'a serde_bytes::Bytes>,
    from_subject_id: u32,
    to_subject_id: u32,
    edge_type: &'a str,
    package_id: &'a str,
    cause: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<&'a [u32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_quality: Option<&'a serde_bytes::Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required_coverage_interval_ids: Option<&'a serde_bytes::Bytes>,
    first_boottime_ns: u64,
    last_boottime_ns: u64,
}

macro_rules! graph_row {
    (
        $append:ident, $schema:ident, $relation:literal;
        $capture:ident, $budget:ident, $graph:ident, $result:ident,
        $revision:ident, $sensitivity:ident, $source:ident;
        $( $arg:ident: $arg_type:ty ),* $(,)?;
        $( $name:ident => $kind:ident($nullable:literal): $value:expr ),* $(,)?
    ) => {
        table_row! {
            #[allow(clippy::too_many_arguments)]
            fn $append(
                &mut $capture,
                $graph: &GraphSnapshotV1,
                $result: &str,
                $revision: u64,
                $sensitivity: ContextSensitivityV1,
                $source: &[u8],
                $( $arg: $arg_type, )*
                $budget: &mut ReadBudget<'_>,
            );
            schema $schema;
            row($capture, $relation, $budget);
            setup {}
            fields {
                tenant_id => Binary(false): Some($graph.scope.identity.tenant_id.as_slice()),
                source_key => Binary(false): Some($source),
                graph_result_id => Utf8(false): Some($result),
                commit_revision => UInt64(false): Some($revision),
                graph_sensitivity => Utf8(false): Some(<&str>::from($sensitivity)),
                $( $name => $kind($nullable): $value, )*
            }
        }
    };
}

impl Capture<'_> {
    pub(in crate::analysis::extraction) fn graph_witnesses(&self) -> bool {
        !self.graph_expiry
            && (self.read.projects_field("graph_manifest", "metadata")
                || self.read.projects_field("graph_manifest", "snapshot")
                || [
                    "findings",
                    "relationships",
                    "graph_subjects",
                    "graph_branches",
                    "correlation_packages",
                    "policy_observations",
                ]
                .iter()
                .any(|name| self.read.projected(name).is_some()))
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::analysis::extraction) fn graph(
        &mut self,
        result_id: &str,
        graph: &GraphSnapshotV1,
        subject_count: usize,
        relationship_count: usize,
        commit_revision: u64,
        sensitivity: ContextSensitivityV1,
        traversal_depths: Option<&[(GraphSubjectKeyV1, u32)]>,
        subject_ids: Option<&[u32]>,
        contexts: &[crate::AnalysisContextRefV1],
        notice: (u64, u64),
        expired: bool,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        if !self.scope.permits_graph(graph) {
            return Ok(true);
        }
        if subject_ids.is_some_and(|ids| ids.len() != graph.graph.subjects.len()) {
            return Err(invalid("the Graph subject ordinal map differs"));
        }
        let deadline = graph.witness_deadline_utc_ns;
        if deadline > self.read.now {
            self.next_change = Some(self.next_change.map_or(deadline, |old| old.min(deadline)));
        }
        if self.read.requests.contains_key("graph_coverage") {
            for key in &graph.input_manifest.coverage {
                if !self
                    .graph_coverage
                    .contains(&(key.source.clone(), key.report_revision))
                {
                    budget.charge(
                        size_of::<(crate::EvidenceIntakeIdentityV1, u64)>()
                            + key.source.node_id.len(),
                    )?;
                    self.graph_coverage
                        .insert((key.source.clone(), key.report_revision));
                }
            }
        }
        if self.graph_witnesses() {
            for evidence in &graph.input_manifest.evidence {
                budget.grow(&mut self.witnesses)?;
                budget.charge(evidence.stream.node_id.len())?;
                self.witnesses.push(crate::AnalysisWitnessV1 {
                    identity: evidence.stream.clone().into(),
                    cursor: evidence.durable_cursor,
                    expires_utc_ns: graph.witness_deadline_utc_ns,
                });
            }
        }
        let source_key = graph.scope.identity.key();
        budget.charge(source_key.len())?;
        for finding in &graph.findings {
            let row = self
                .tables
                .get("findings")
                .map_or(0, |table| table.total_rows);
            if !self.finding_row(
                graph,
                result_id,
                commit_revision,
                sensitivity,
                &source_key,
                finding,
                budget,
            )? {
                return Ok(false);
            }
            if self.read.projected("findings").is_some() {
                let key = (finding.tenant_id, finding.finding_id.clone());
                if !self.latest.contains_key(&key) {
                    budget.charge(size_of::<([u8; 16], String)>() + key.1.capacity())?;
                }
                if self
                    .latest
                    .get(&key)
                    .is_none_or(|(revision, _)| *revision <= commit_revision)
                {
                    self.latest.insert(key, (commit_revision, row));
                }
            }
            for observation in &finding.policy_provenance {
                if !self.observation_row(
                    graph,
                    result_id,
                    commit_revision,
                    sensitivity,
                    &source_key,
                    finding,
                    observation,
                    budget,
                )? {
                    return Ok(false);
                }
            }
        }
        for edge in &graph.graph.edges {
            let from = subject_ids
                .map_or(Some(edge.key.from), |ids| {
                    ids.get(edge.key.from as usize).copied()
                })
                .ok_or_else(|| invalid("the Graph edge source ordinal is absent"))?;
            let to = subject_ids
                .map_or(Some(edge.key.to), |ids| {
                    ids.get(edge.key.to as usize).copied()
                })
                .ok_or_else(|| invalid("the Graph edge target ordinal is absent"))?;
            if !self.relationship_row(
                graph,
                result_id,
                commit_revision,
                sensitivity,
                &source_key,
                edge,
                from,
                to,
                budget,
            )? {
                return Ok(false);
            }
        }
        for (index, subject) in graph.graph.subjects.iter().enumerate() {
            let subject_id = match subject_ids {
                Some(ids) => ids[index],
                None => u32::try_from(index).map_err(|_| overflow())?,
            };
            let depth = traversal_depths.and_then(|depths| {
                depths
                    .iter()
                    .find(|(key, _)| key == subject)
                    .map(|(_, depth)| *depth)
            });
            if !self.subject_row(
                graph,
                result_id,
                commit_revision,
                sensitivity,
                &source_key,
                subject_id,
                subject,
                depth,
                budget,
            )? {
                return Ok(false);
            }
        }
        for branch in &graph.graph.branches {
            if !self.branch_row(
                graph,
                result_id,
                commit_revision,
                sensitivity,
                &source_key,
                branch,
                budget,
            )? {
                return Ok(false);
            }
        }
        for package in &graph.packages {
            if !self.package_row(
                graph,
                result_id,
                commit_revision,
                sensitivity,
                &source_key,
                package,
                budget,
            )? {
                return Ok(false);
            }
        }
        self.graph_manifest(
            graph,
            result_id,
            commit_revision,
            sensitivity,
            &source_key,
            subject_count,
            relationship_count,
            contexts,
            notice,
            expired,
            budget,
        )
    }

    graph_row! {
        finding_row, finding_fields, "findings";
        self, budget, graph, result_id, commit_revision, sensitivity, source_key;
        finding: &crate::FindingV1;
        finding_id => Utf8(false): Some(finding.finding_id.as_str()),
        package_id => Utf8(false): Some(finding.package_id.as_str()),
        package_version => UInt64(false): Some(finding.package_version),
        subject_id => Json(false): Some(&finding.subject_id),
        state => Utf8(false): Some(match finding.state {
            FindingStateV1::Provisional => "provisional",
            FindingStateV1::Confirmed => "confirmed",
            FindingStateV1::Superseded => "superseded",
            FindingStateV1::Retracted => "retracted",
            FindingStateV1::CoverageInsufficient => "coverage_insufficient",
        }),
        window_start_utc_ns => Int64(false): Some(finding.window_start_utc_ns),
        window_end_utc_ns => Int64(false): Some(finding.window_end_utc_ns),
        evidence => Json(false): Some(&finding.evidence),
        required_coverage_interval_ids => Json(false): Some(&finding.required_coverage_interval_ids),
        policy_provenance => Json(false): Some(&finding.policy_provenance),
        effects => Json(false): Some(&finding.effects),
        reason => Utf8(false): { budget.charge(4096)?; Some(araphor_graph::FindingRows::reason_label(&finding.reason)?) },
        severity => Utf8(false): Some(match finding.severity {
            FindingSeverityV1::Info => "info",
            FindingSeverityV1::Warning => "warning",
            FindingSeverityV1::High => "high",
            FindingSeverityV1::Critical => "critical",
        }),
        sensitivity => Utf8(false): Some(<&str>::from(finding.sensitivity)),
        required_action => Utf8(true): finding.required_action.as_deref(),
        limits => Json(false): Some(&finding.limits),
    }

    graph_row! {
        observation_row, observation_fields, "policy_observations";
        self, budget, graph, result_id, commit_revision, sensitivity, source_key;
        finding: &crate::FindingV1, observation: &crate::PolicyObservationProvenanceV1;
        finding_id => Utf8(false): Some(finding.finding_id.as_str()),
        profile_generation_ref_id => UInt64(false): Some(observation.profile_generation_ref_id),
        observations => Json(false): Some(&observation.observations),
        policy_source_revision_id => Utf8(true): observation.policy_source_revision_id.as_deref(),
        candidate_content_id => Utf8(true): observation.candidate_content_id.as_deref(),
        target_snapshot_digest => Utf8(true): observation.target_snapshot_digest.as_deref(),
        node_bound_generation_digest => Utf8(true): observation.node_bound_generation_digest.as_deref(),
        activation_acknowledgement => Json(true): observation.activation_acknowledgement.as_ref(),
        state => Utf8(false): Some(match observation.state {
            PolicyProvenanceStateV1::Exact => "exact",
            PolicyProvenanceStateV1::Missing => "missing",
            PolicyProvenanceStateV1::Contradicted => "contradicted",
        }),
        limits => Json(false): Some(&observation.limits),
    }

    #[allow(clippy::too_many_arguments)]
    fn relationship_row(
        &mut self,
        graph: &GraphSnapshotV1,
        result_id: &str,
        commit_revision: u64,
        sensitivity: ContextSensitivityV1,
        source_key: &[u8],
        edge: &crate::GraphEdgeV1,
        from: u32,
        to: u32,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        if self.read.projected("relationships").is_none() {
            return Ok(true);
        }
        budget.check()?;
        const NAMES: &[&str] = &[
            "tenant_id",
            "source_key",
            "graph_result_id",
            "commit_revision",
            "graph_sensitivity",
            "relationship_key",
            "from_subject_id",
            "to_subject_id",
            "edge_type",
            "package_id",
            "cause",
            "evidence",
            "proof_quality",
            "required_coverage_interval_ids",
            "first_boottime_ns",
            "last_boottime_ns",
        ];
        let schema = Arc::clone(&self.table("relationships", NAMES, budget)?.schema);
        let key = if self
            .read
            .projects_field("relationships", "relationship_key")
        {
            if edge.key.from != from || edge.key.to != to {
                budget.charge(
                    edge.key
                        .evidence
                        .len()
                        .checked_mul(size_of::<u32>())
                        .and_then(|bytes| bytes.checked_add(edge.key.package_id.len()))
                        .ok_or_else(overflow)?,
                )?;
                let mut key = edge.key.clone();
                key.from = from;
                key.to = to;
                json(Some(&key), budget)?
            } else {
                json(Some(&edge.key), budget)?
            }
        } else {
            None
        };
        let proof = if self.read.projects_field("relationships", "proof_quality") {
            json(Some(&edge.proof_quality), budget)?
        } else {
            None
        };
        let coverage = if self
            .read
            .projects_field("relationships", "required_coverage_interval_ids")
        {
            json(Some(&edge.required_coverage_interval_ids), budget)?
        } else {
            None
        };
        let evidence = self
            .read
            .projects_field("relationships", "evidence")
            .then_some(edge.key.evidence.as_slice());
        let kind = match edge.key.edge_type {
            GraphEdgeTypeV1::TaskInProcess => "task_in_process",
            GraphEdgeTypeV1::TaskInExecutionSet => "task_in_execution_set",
            GraphEdgeTypeV1::NativeParent => "native_parent",
            GraphEdgeTypeV1::NativeEffect => "native_effect",
            GraphEdgeTypeV1::CredentialAuthority => "credential_authority",
            GraphEdgeTypeV1::KubernetesExpansion => "kubernetes_expansion",
        };
        let cause = match edge.key.cause {
            GraphCauseV1::Direct => "direct",
            GraphCauseV1::Contextual => "contextual",
            GraphCauseV1::Contradicted => "contradicted",
            GraphCauseV1::Superseded => "superseded",
        };
        budget.check()?;
        let row = RelationshipRow {
            tenant_id: serde_bytes::Bytes::new(&graph.scope.identity.tenant_id),
            source_key: serde_bytes::Bytes::new(source_key),
            graph_result_id: result_id,
            commit_revision,
            graph_sensitivity: <&str>::from(sensitivity),
            relationship_key: key.as_deref().map(serde_bytes::Bytes::new),
            from_subject_id: from,
            to_subject_id: to,
            edge_type: kind,
            package_id: &edge.key.package_id,
            cause,
            evidence,
            proof_quality: proof.as_deref().map(serde_bytes::Bytes::new),
            required_coverage_interval_ids: coverage.as_deref().map(serde_bytes::Bytes::new),
            first_boottime_ns: edge.first_boottime_ns,
            last_boottime_ns: edge.last_boottime_ns,
        };
        let batch = if schema.fields().is_empty() {
            RecordBatch::try_new_with_options(
                schema,
                Vec::new(),
                &sdk::arrow_array::RecordBatchOptions::new().with_row_count(Some(1)),
            )
            .map_err(arrow_error)?
        } else {
            serde_arrow::to_record_batch(schema.fields(), &[row]).map_err(|source| {
                crate::Error::DiscoveryContext {
                    source: Box::new(source),
                    location: snafu::location!(),
                }
            })?
        };
        self.table("relationships", NAMES, budget)?
            .append_native(batch, budget)
    }

    pub(super) fn relationship_fields() -> Vec<sdk::Field> {
        use sdk::DataType::*;
        vec![
            sdk::Field::new("tenant_id", Binary, false),
            sdk::Field::new("source_key", Binary, false),
            sdk::Field::new("graph_result_id", Utf8, false),
            sdk::Field::new("commit_revision", UInt64, false),
            sdk::Field::new("graph_sensitivity", Utf8, false),
            sdk::Field::new("relationship_key", Binary, false),
            sdk::Field::new("from_subject_id", UInt32, false),
            sdk::Field::new("to_subject_id", UInt32, false),
            sdk::Field::new("edge_type", Utf8, false),
            sdk::Field::new("package_id", Utf8, false),
            sdk::Field::new("cause", Utf8, false),
            sdk::Field::new(
                "evidence",
                List(Arc::new(sdk::Field::new("element", UInt32, false))),
                false,
            ),
            sdk::Field::new("proof_quality", Binary, false),
            sdk::Field::new("required_coverage_interval_ids", Binary, false),
            sdk::Field::new("first_boottime_ns", UInt64, false),
            sdk::Field::new("last_boottime_ns", UInt64, false),
        ]
    }

    graph_row! {
        subject_row, subject_fields, "graph_subjects";
        self, budget, graph, result_id, commit_revision, sensitivity, source_key;
        subject_id: u32, subject: &GraphSubjectKeyV1, depth: Option<u32>;
        subject_id => UInt32(false): Some(subject_id),
        subject_kind => Utf8(false): Some(match subject.kind {
            GraphSubjectKindV1::Task => "task",
            GraphSubjectKindV1::Process => "process",
            GraphSubjectKindV1::ExecutionSet => "execution_set",
            GraphSubjectKindV1::Socket => "socket",
            GraphSubjectKindV1::Artifact => "artifact",
            GraphSubjectKindV1::Request => "request",
            GraphSubjectKindV1::CredentialLease => "credential_lease",
            GraphSubjectKindV1::KubernetesObject => "kubernetes_object",
            GraphSubjectKindV1::ProviderObject => "provider_object",
            GraphSubjectKindV1::External => "external",
        }),
        authority => Json(false): Some(&subject.authority),
        identity => Binary(false): Some(subject.identity.as_slice()),
        traversal_depth => UInt32(true): depth,
    }

    graph_row! {
        branch_row, branch_fields, "graph_branches";
        self, budget, graph, result_id, commit_revision, sensitivity, source_key;
        branch: &crate::GraphBranchV1;
        package_id => Utf8(false): Some(branch.package_id.as_str()),
        seed_subject_id => Json(false): Some(&branch.seed),
        evidence => Json(false): Some(&branch.evidence),
        state => Utf8(false): Some(match branch.state {
            GraphBranchStateV1::Open => "open",
            GraphBranchStateV1::TerminalVerified => "terminal_verified",
            GraphBranchStateV1::ContextualOnly => "contextual_only",
            GraphBranchStateV1::OutsideAuthority => "outside_authority",
            GraphBranchStateV1::CoverageUnknown => "coverage_unknown",
        }),
        missing_fields => Json(false): Some(&branch.missing_fields),
    }

    graph_row! {
        package_row, package_fields, "correlation_packages";
        self, budget, graph, result_id, commit_revision, sensitivity, source_key;
        package: &crate::GraphPackageCheckpointV1;
        package_id => Utf8(false): Some(package.package_id.as_str()),
        package_version => UInt64(false): Some(package.package_version),
        required_inputs => Json(false): Some(&package.required_inputs),
        state => Utf8(false): Some(match &package.state {
            GraphPackageStateV1::Waiting => "waiting",
            GraphPackageStateV1::NativeEffect => "native_effect",
            GraphPackageStateV1::CredentialObserved => "credential_observed",
            GraphPackageStateV1::AuthorityChannel => "authority_channel",
            GraphPackageStateV1::DirectPivot => "direct_pivot",
            GraphPackageStateV1::ContextualPivot => "contextual_pivot",
            GraphPackageStateV1::Contradicted => "contradicted",
            GraphPackageStateV1::CoverageInsufficient => "coverage_insufficient",
            GraphPackageStateV1::KubernetesProofMissing => "kubernetes_proof_missing",
            GraphPackageStateV1::KubernetesRequest => "kubernetes_request",
            GraphPackageStateV1::KubernetesAudit => "kubernetes_audit",
            GraphPackageStateV1::KubernetesObject => "kubernetes_object",
            GraphPackageStateV1::KubernetesScheduled => "kubernetes_scheduled",
            GraphPackageStateV1::RemoteAdmission => "remote_admission",
            GraphPackageStateV1::Declared(value) => value.as_str(),
        }),
        maximum_lateness_ns => UInt64(false): Some(package.maximum_lateness_ns),
        retention_ttl_ns => UInt64(false): Some(package.retention_ttl_ns),
        clock_uncertainty_ns => UInt64(true): package.clock_uncertainty_ns,
        late_action => Utf8(false): Some(package.late_action.as_str()),
        window_ns => UInt64(false): Some(package.window_ns),
        coverage_predicate => Utf8(false): Some(package.coverage_predicate.as_str()),
        replay_contract_id => Utf8(false): Some(package.replay_contract_id.as_str()),
        result_states => Json(false): Some(&package.result_states),
        accepted_cursor_watermark => UInt64(false): Some(package.accepted_cursor_watermark),
        observed_boottime_watermark_ns => UInt64(false): Some(package.observed_boottime_watermark_ns),
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::analysis::extraction) fn graph_manifest(
        &mut self,
        graph: &GraphSnapshotV1,
        result_id: &str,
        commit_revision: u64,
        sensitivity: ContextSensitivityV1,
        source_key: &[u8],
        subject_count: usize,
        relationship_count: usize,
        contexts: &[crate::AnalysisContextRefV1],
        notice: (u64, u64),
        expired: bool,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        budget.check()?;
        if !self.needs_manifest(result_id) {
            return Ok(true);
        }
        const NAMES: &[&str] = &[
            "tenant_id",
            "source_key",
            "graph_result_id",
            "commit_revision",
            "graph_revision",
            "graph_sensitivity",
            "first_cursor",
            "last_cursor",
            "previous_result_id",
            "context_notice_revision",
            "notice_context_revision",
            "notice_coverage_revision",
            "witness_deadline_utc_ns",
            "retained_input_expired",
            "subject_count",
            "relationship_count",
            "max_hops",
            "hop_boundary",
            "snapshot",
            "metadata",
            "context_refs",
        ];
        let schema = Arc::clone(&self.table("graph_manifest", NAMES, budget)?.schema);
        let revision = self
            .read
            .projects_field("graph_manifest", "graph_revision")
            .then_some(&graph.input_manifest);
        let snapshot = if self.read.projects_field("graph_manifest", "snapshot") {
            let bytes = graph.encode_native()?;
            budget.charge(bytes.len())?;
            Some(bytes)
        } else {
            None
        };
        let metadata = if self.read.projects_field("graph_manifest", "metadata") {
            let bytes = crate::GraphManifest::from_snapshot(graph).encode()?;
            budget.charge(bytes.len())?;
            Some(bytes)
        } else {
            None
        };
        let contexts = if self.read.projects_field("graph_manifest", "context_refs") {
            Some(contexts)
        } else {
            None
        };
        budget.charge(
            result_id
                .len()
                .checked_add(size_of::<String>())
                .ok_or_else(overflow)?,
        )?;
        budget.check()?;
        let row = ManifestRow {
            tenant_id: serde_bytes::Bytes::new(&graph.scope.identity.tenant_id),
            source_key: serde_bytes::Bytes::new(source_key),
            graph_result_id: result_id,
            commit_revision,
            graph_revision: revision,
            graph_sensitivity: <&str>::from(sensitivity),
            first_cursor: graph.first_cursor,
            last_cursor: graph.last_cursor,
            previous_result_id: graph.previous_result_id.as_deref(),
            context_notice_revision: graph.context_notice_revision,
            notice_context_revision: notice.0,
            notice_coverage_revision: notice.1,
            witness_deadline_utc_ns: graph.witness_deadline_utc_ns,
            retained_input_expired: expired,
            subject_count: subject_count.try_into().map_err(|_| overflow())?,
            relationship_count: relationship_count.try_into().map_err(|_| overflow())?,
            max_hops: 0,
            hop_boundary: false,
            snapshot: snapshot.as_deref().map(serde_bytes::Bytes::new),
            metadata: metadata.as_deref().map(serde_bytes::Bytes::new),
            context_refs: contexts,
        };
        let batch = if schema.fields().is_empty() {
            RecordBatch::try_new_with_options(
                schema,
                Vec::new(),
                &sdk::arrow_array::RecordBatchOptions::new().with_row_count(Some(1)),
            )
            .map_err(arrow_error)?
        } else {
            serde_arrow::to_record_batch(schema.fields(), &[row]).map_err(|source| {
                crate::Error::DiscoveryContext {
                    source: Box::new(source),
                    location: snafu::location!(),
                }
            })?
        };
        let admitted = self
            .table("graph_manifest", NAMES, budget)?
            .append_native(batch, budget)?;
        if admitted {
            self.graph_manifests.insert(result_id.to_owned());
        }
        Ok(admitted)
    }

    pub(super) fn graph_fields() -> Vec<sdk::Field> {
        use sdk::DataType::*;
        vec![
            sdk::Field::new("tenant_id", Binary, false),
            sdk::Field::new("source_key", Binary, false),
            sdk::Field::new("graph_result_id", Utf8, false),
            sdk::Field::new("commit_revision", UInt64, false),
            sdk::Field::new(
                "graph_revision",
                Struct(crate::GraphRevisionV1::arrow_schema().fields().clone()),
                false,
            ),
            sdk::Field::new("graph_sensitivity", Utf8, false),
            sdk::Field::new("first_cursor", UInt64, false),
            sdk::Field::new("last_cursor", UInt64, false),
            sdk::Field::new("previous_result_id", Utf8, true),
            sdk::Field::new("context_notice_revision", UInt64, false),
            sdk::Field::new("notice_context_revision", UInt64, false),
            sdk::Field::new("notice_coverage_revision", UInt64, false),
            sdk::Field::new("witness_deadline_utc_ns", UInt64, false),
            sdk::Field::new("retained_input_expired", Boolean, false),
            sdk::Field::new("subject_count", UInt64, false),
            sdk::Field::new("relationship_count", UInt64, false),
            sdk::Field::new("max_hops", UInt32, false),
            sdk::Field::new("hop_boundary", Boolean, false),
            sdk::Field::new("snapshot", Binary, false),
            sdk::Field::new("metadata", Binary, false),
            context_ref_field(),
        ]
    }
}
