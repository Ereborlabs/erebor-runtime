use super::*;
use crate::{
    ContextSensitivityV1, FindingSeverityV1, FindingStateV1, GraphBranchStateV1, GraphCauseV1,
    GraphEdgeTypeV1, GraphPackageStateV1, GraphSnapshotV1, GraphSubjectKeyV1, GraphSubjectKindV1,
    PolicyProvenanceStateV1,
};

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
                graph_revision => Json(false): Some(&$graph.input_manifest),
                graph_sensitivity => Utf8(false): Some(<&str>::from($sensitivity)),
                $( $name => $kind($nullable): $value, )*
            }
        }
    };
}

impl Capture<'_> {
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
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        if !self.scope.permits_graph(graph) {
            return Ok(true);
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
        for evidence in &graph.input_manifest.evidence {
            budget.grow(&mut self.witnesses)?;
            budget.charge(evidence.stream.node_id.len())?;
            self.witnesses.push(crate::AnalysisWitnessV1 {
                identity: evidence.stream.clone().into(),
                cursor: evidence.durable_cursor,
                expires_utc_ns: graph.witness_deadline_utc_ns,
            });
        }
        budget.charge(crate::EvidenceIntakeIdentityV1::MAX_KEY_BYTES)?;
        let source_key = graph.scope.identity.key();
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
                    budget.charge(finding.finding_id.len() + 128)?;
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
            if !self.relationship_row(
                graph,
                result_id,
                commit_revision,
                sensitivity,
                &source_key,
                edge,
                budget,
            )? {
                return Ok(false);
            }
        }
        for subject in &graph.graph.subjects {
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
        self.graph_row(
            graph,
            result_id,
            commit_revision,
            sensitivity,
            &source_key,
            subject_count,
            relationship_count,
            budget,
        )
    }

    graph_row! {
        finding_row, finding_fields, "findings";
        self, budget, graph, result_id, commit_revision, sensitivity, source_key;
        finding: &crate::FindingV1;
        finding_id => Utf8(false): Some(finding.finding_id.as_str()),
        finding_revision => Json(false): Some(&finding.revision),
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
        reason => Utf8(false): { budget.charge(4096)?; Some(finding.reason.label()?) },
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

    graph_row! {
        relationship_row, relationship_fields, "relationships";
        self, budget, graph, result_id, commit_revision, sensitivity, source_key;
        edge: &crate::GraphEdgeV1;
        relationship_key => Json(false): Some(&edge.key),
        from_subject_id => Json(false): Some(&edge.key.from),
        to_subject_id => Json(false): Some(&edge.key.to),
        edge_type => Utf8(false): Some(match edge.key.edge_type {
            GraphEdgeTypeV1::TaskInProcess => "task_in_process",
            GraphEdgeTypeV1::TaskInExecutionSet => "task_in_execution_set",
            GraphEdgeTypeV1::NativeParent => "native_parent",
            GraphEdgeTypeV1::NativeEffect => "native_effect",
            GraphEdgeTypeV1::CredentialAuthority => "credential_authority",
            GraphEdgeTypeV1::KubernetesExpansion => "kubernetes_expansion",
        }),
        package_id => Utf8(false): Some(edge.key.package_id.as_str()),
        cause => Utf8(false): Some(match edge.key.cause {
            GraphCauseV1::Direct => "direct",
            GraphCauseV1::Contextual => "contextual",
            GraphCauseV1::Contradicted => "contradicted",
            GraphCauseV1::Superseded => "superseded",
        }),
        evidence => Json(false): Some(&edge.key.evidence),
        proof_quality => Json(false): Some(&edge.proof_quality),
        required_coverage_interval_ids => Json(false): Some(&edge.required_coverage_interval_ids),
        first_boottime_ns => UInt64(false): Some(edge.first_boottime_ns),
        last_boottime_ns => UInt64(false): Some(edge.last_boottime_ns),
    }

    graph_row! {
        subject_row, subject_fields, "graph_subjects";
        self, budget, graph, result_id, commit_revision, sensitivity, source_key;
        subject: &GraphSubjectKeyV1, depth: Option<u32>;
        subject_id => Json(false): Some(subject),
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
        window_records => UInt64(false): Some(package.window_records),
        window_bytes => UInt64(false): Some(u64::try_from(package.window_bytes).map_err(|_| overflow())?),
        coverage_predicate => Utf8(false): Some(package.coverage_predicate.as_str()),
        replay_contract_id => Utf8(false): Some(package.replay_contract_id.as_str()),
        result_states => Json(false): Some(&package.result_states),
        accepted_cursor_watermark => UInt64(false): Some(package.accepted_cursor_watermark),
        observed_boottime_watermark_ns => UInt64(false): Some(package.observed_boottime_watermark_ns),
    }

    graph_row! {
        graph_row, graph_fields, "graph_manifest";
        self, budget, graph, result_id, commit_revision, sensitivity, source_key;
        subject_count: usize, relationship_count: usize;
        first_cursor => UInt64(false): Some(graph.first_cursor),
        last_cursor => UInt64(false): Some(graph.last_cursor),
        previous_result_id => Utf8(true): graph.previous_result_id.as_deref(),
        context_notice_revision => UInt64(false): Some(graph.context_notice_revision),
        witness_deadline_utc_ns => UInt64(false): Some(graph.witness_deadline_utc_ns),
        subject_count => UInt64(false): Some(u64::try_from(subject_count).map_err(|_| overflow())?),
        relationship_count => UInt64(false): Some(u64::try_from(relationship_count).map_err(|_| overflow())?),
        max_hops => UInt32(false): Some(0),
        hop_boundary => Boolean(false): Some(false),
    }
}
