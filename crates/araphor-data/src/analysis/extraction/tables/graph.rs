use super::*;
use crate::{
    ContextSensitivityV1, FindingSeverityV1, FindingStateV1, GraphBranchStateV1, GraphCauseV1,
    GraphEdgeTypeV1, GraphPackageStateV1, GraphSnapshotV1, GraphSubjectKeyV1, GraphSubjectKindV1,
    PolicyProvenanceStateV1,
};

macro_rules! graph_row {
    ($capture:ident, $table:literal, $budget:ident, $graph:ident, $result:ident,
     $revision:ident, $sensitivity:ident, $source:ident; $($fields:tt)*) => {
        table_row!($capture, $table, $budget;
            tenant_id => Binary: Some($graph.scope.identity.tenant_id.as_slice()),
            source_key => Binary: Some($source.as_slice()),
            graph_result_id => Utf8: Some($result),
            commit_revision => UInt64: Some($revision),
            graph_revision => Json: Some(&$graph.input_manifest),
            graph_sensitivity => Utf8: Some(<&str>::from($sensitivity)),
            $($fields)*
        )
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
            if !graph_row!(self, "findings", budget, graph, result_id,
                commit_revision, sensitivity, source_key;
                finding_id => Utf8: Some(finding.finding_id.as_str()),
                finding_revision => Json: Some(&finding.revision),
                package_id => Utf8: Some(finding.package_id.as_str()),
                package_version => UInt64: Some(finding.package_version),
                subject_id => Json: Some(&finding.subject_id),
                state => Utf8: Some(match finding.state {
                    FindingStateV1::Provisional => "provisional",
                    FindingStateV1::Confirmed => "confirmed",
                    FindingStateV1::Superseded => "superseded",
                    FindingStateV1::Retracted => "retracted",
                    FindingStateV1::CoverageInsufficient => "coverage_insufficient",
                }),
                window_start_utc_ns => Int64: Some(finding.window_start_utc_ns),
                window_end_utc_ns => Int64: Some(finding.window_end_utc_ns),
                evidence => Json: Some(&finding.evidence),
                required_coverage_interval_ids => Json: Some(&finding.required_coverage_interval_ids),
                policy_provenance => Json: Some(&finding.policy_provenance),
                effects => Json: Some(&finding.effects),
                reason => Utf8: { budget.charge(4096)?; Some(finding.reason.label()?) },
                severity => Utf8: Some(match finding.severity {
                    FindingSeverityV1::Info => "info",
                    FindingSeverityV1::Warning => "warning",
                    FindingSeverityV1::High => "high",
                    FindingSeverityV1::Critical => "critical",
                }),
                sensitivity => Utf8: Some(<&str>::from(finding.sensitivity)),
                required_action => Utf8: finding.required_action.as_deref(),
                limits => Json: Some(&finding.limits),
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
                if !graph_row!(self, "policy_observations", budget, graph, result_id,
                    commit_revision, sensitivity, source_key;
                    finding_id => Utf8: Some(finding.finding_id.as_str()),
                    profile_generation_ref_id => UInt64: Some(observation.profile_generation_ref_id),
                    observations => Json: Some(&observation.observations),
                    policy_source_revision_id => Utf8: observation.policy_source_revision_id.as_deref(),
                    candidate_content_id => Utf8: observation.candidate_content_id.as_deref(),
                    target_snapshot_digest => Utf8: observation.target_snapshot_digest.as_deref(),
                    node_bound_generation_digest => Utf8: observation.node_bound_generation_digest.as_deref(),
                    activation_acknowledgement => Json: observation.activation_acknowledgement.as_ref(),
                    state => Utf8: Some(match observation.state {
                        PolicyProvenanceStateV1::Exact => "exact",
                        PolicyProvenanceStateV1::Missing => "missing",
                        PolicyProvenanceStateV1::Contradicted => "contradicted",
                    }),
                    limits => Json: Some(&observation.limits),
                )? {
                    return Ok(false);
                }
            }
        }
        for edge in &graph.graph.edges {
            if !graph_row!(self, "relationships", budget, graph, result_id,
                commit_revision, sensitivity, source_key;
                relationship_key => Json: Some(&edge.key),
                from_subject_id => Json: Some(&edge.key.from),
                to_subject_id => Json: Some(&edge.key.to),
                edge_type => Utf8: Some(match edge.key.edge_type {
                    GraphEdgeTypeV1::TaskInProcess => "task_in_process",
                    GraphEdgeTypeV1::TaskInExecutionSet => "task_in_execution_set",
                    GraphEdgeTypeV1::NativeParent => "native_parent",
                    GraphEdgeTypeV1::NativeEffect => "native_effect",
                    GraphEdgeTypeV1::CredentialAuthority => "credential_authority",
                    GraphEdgeTypeV1::KubernetesExpansion => "kubernetes_expansion",
                }),
                package_id => Utf8: Some(edge.key.package_id.as_str()),
                cause => Utf8: Some(match edge.key.cause {
                    GraphCauseV1::Direct => "direct",
                    GraphCauseV1::Contextual => "contextual",
                    GraphCauseV1::Contradicted => "contradicted",
                    GraphCauseV1::Superseded => "superseded",
                }),
                evidence => Json: Some(&edge.key.evidence),
                proof_quality => Json: Some(&edge.proof_quality),
                required_coverage_interval_ids => Json: Some(&edge.required_coverage_interval_ids),
                first_boottime_ns => UInt64: Some(edge.first_boottime_ns),
                last_boottime_ns => UInt64: Some(edge.last_boottime_ns),
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
            if !graph_row!(self, "graph_subjects", budget, graph, result_id,
                commit_revision, sensitivity, source_key;
                subject_id => Json: Some(subject),
                subject_kind => Utf8: Some(match subject.kind {
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
                authority => Json: Some(&subject.authority),
                identity => Binary: Some(subject.identity.as_slice()),
                traversal_depth => UInt32: depth,
            )? {
                return Ok(false);
            }
        }
        for branch in &graph.graph.branches {
            if !graph_row!(self, "graph_branches", budget, graph, result_id,
                commit_revision, sensitivity, source_key;
                package_id => Utf8: Some(branch.package_id.as_str()),
                seed_subject_id => Json: Some(&branch.seed),
                evidence => Json: Some(&branch.evidence),
                state => Utf8: Some(match branch.state {
                    GraphBranchStateV1::Open => "open",
                    GraphBranchStateV1::TerminalVerified => "terminal_verified",
                    GraphBranchStateV1::ContextualOnly => "contextual_only",
                    GraphBranchStateV1::OutsideAuthority => "outside_authority",
                    GraphBranchStateV1::CoverageUnknown => "coverage_unknown",
                }),
                missing_fields => Json: Some(&branch.missing_fields),
            )? {
                return Ok(false);
            }
        }
        for package in &graph.packages {
            if !graph_row!(self, "correlation_packages", budget, graph, result_id,
                commit_revision, sensitivity, source_key;
                package_id => Utf8: Some(package.package_id.as_str()),
                package_version => UInt64: Some(package.package_version),
                required_inputs => Json: Some(&package.required_inputs),
                state => Utf8: Some(match &package.state {
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
                maximum_lateness_ns => UInt64: Some(package.maximum_lateness_ns),
                retention_ttl_ns => UInt64: Some(package.retention_ttl_ns),
                clock_uncertainty_ns => UInt64: package.clock_uncertainty_ns,
                late_action => Utf8: Some(package.late_action.as_str()),
                window_ns => UInt64: Some(package.window_ns),
                window_records => UInt64: Some(package.window_records),
                window_bytes => UInt64: Some(u64::try_from(package.window_bytes).map_err(|_| overflow())?),
                coverage_predicate => Utf8: Some(package.coverage_predicate.as_str()),
                replay_contract_id => Utf8: Some(package.replay_contract_id.as_str()),
                result_states => Json: Some(&package.result_states),
                accepted_cursor_watermark => UInt64: Some(package.accepted_cursor_watermark),
                observed_boottime_watermark_ns => UInt64: Some(package.observed_boottime_watermark_ns),
            )? {
                return Ok(false);
            }
        }
        graph_row!(self, "graph_manifest", budget, graph, result_id,
            commit_revision, sensitivity, source_key;
            first_cursor => UInt64: Some(graph.first_cursor),
            last_cursor => UInt64: Some(graph.last_cursor),
            previous_result_id => Utf8: graph.previous_result_id.as_deref(),
            subject_count => UInt64: Some(u64::try_from(subject_count).map_err(|_| overflow())?),
            relationship_count => UInt64: Some(u64::try_from(relationship_count).map_err(|_| overflow())?),
            max_hops => UInt32: Some(0),
            hop_boundary => Boolean: Some(false),
        )
    }
}
