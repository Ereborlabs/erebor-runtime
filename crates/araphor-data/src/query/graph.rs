use super::input::relation;
use super::input::{InputProjection, InputRelations};
use crate::analysis::ProjectionSink;
use crate::Result;
use std::collections::BTreeSet;

pub(super) const RELATIONS: &[&str] = &[
    "findings",
    "relationships",
    "graph_subjects",
    "graph_branches",
    "correlation_packages",
    "policy_observations",
];

pub(super) const REVISION: &str =
    "JSON exact evidence, coverage, context, and missing-range manifest";
pub(super) const SOURCE: &str = "JSON exact accepted source lifetime";
const OWNER: &str = "araphor-data.GraphAndFindingOwner";
const KEY: &str = "tenant_id,graph_result_id,graph_revision. Structured keys contain exact lifetimes. A binding scope requires exact effect proof for each manifest record. Names and time are not causal proof.";

relation! {
    pub(super) FINDINGS, finding(sink; graph: &crate::GraphSnapshotV1, result_id: &str, revision: u64, sensitivity: crate::ContextSensitivityV1, source: &[u8], manifest: &[u8], finding: &crate::FindingV1) {
        name: "findings",
        join_keys: "tenant_id,finding_id,finding_revision. Subject joins use tenant_id,graph_result_id,subject_id. The latest authorized commit supplies one current revision per finding_id. A finding grants no execution authority.",
        owner: OWNER,
        readiness: "conditional",
        description: "Current committed findings across authorized source-window heads. Exact revision values remain unchanged. A binding scope excludes mixed or unproved windows. Sensitivity is an owner label under the existing tenant query permission. Empty findings do not prove complete coverage.",
        setup {
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(graph.scope.identity.tenant_id.as_slice());
            source_key: Binary(SOURCE, "") => Some(source);
            graph_result_id: Utf8("exact immutable result ID", "") => Some(result_id);
            commit_revision: UInt64("store commit revision", "") => Some(revision);
            graph_revision: Binary(REVISION, "") => Some(manifest);
            graph_sensitivity: Utf8("maximum retained input sensitivity; native evidence has a tenant floor", "") =>
                Some(<&str>::from(sensitivity));
            finding_id: Utf8("exact full finding key", "") => Some(finding.finding_id.as_str());
            finding_revision: Binary(REVISION, "") => Some(Self::json(sink, &finding.revision)?);
            package_id: Utf8("qualified package ID", "") => Some(finding.package_id.as_str());
            package_version: UInt64("package version", "") => Some(finding.package_version);
            subject_id: Binary("JSON exact subject authority and lifetime", "") =>
                Some(Self::json(sink, &finding.subject_id)?);
            state: Utf8("unchanged finding state", "") =>
                Some(match &finding.state { crate::FindingStateV1::Provisional => "PROVISIONAL", crate::FindingStateV1::Confirmed => "CONFIRMED", crate::FindingStateV1::Superseded => "SUPERSEDED", crate::FindingStateV1::Retracted => "RETRACTED", crate::FindingStateV1::CoverageInsufficient => "COVERAGE_INSUFFICIENT" });
            window_start_utc_ns: Int64("source UTC nanoseconds", "") => Some(finding.window_start_utc_ns);
            window_end_utc_ns: Int64("source UTC nanoseconds", "") => Some(finding.window_end_utc_ns);
            evidence: Binary("JSON exact accepted record IDs", "") => Some(Self::json(sink, &finding.evidence)?);
            required_coverage_interval_ids: Binary("JSON exact coverage interval IDs", "") =>
                Some(Self::json(sink, &finding.required_coverage_interval_ids)?);
            policy_provenance: Binary("JSON exact policy provenance and limits", "") =>
                Some(Self::json(sink, &finding.policy_provenance)?);
            effects: Binary("JSON unchanged source decisions, physical results, and proof quality", "") =>
                Some(Self::json(sink, &finding.effects)?);
            reason: Utf8("unchanged finding reason", "") => Some(finding.reason.label()?);
            severity: Utf8("source severity", "") =>
                Some(match &finding.severity { crate::FindingSeverityV1::Info => "Info", crate::FindingSeverityV1::Warning => "Warning", crate::FindingSeverityV1::High => "High", crate::FindingSeverityV1::Critical => "Critical" });
            sensitivity: Utf8("public, tenant, or host_restricted", "") => Some(<&str>::from(finding.sensitivity));
            required_action: Utf8("required human action", "The finding has no required action.") =>
                finding.required_action.as_deref();
            limits: Binary("JSON explicit finding limits", "") => Some(Self::json(sink, &finding.limits)?);
        }
    }
}

relation! {
    pub(super) RELATIONSHIPS, relationship(sink; graph: &crate::GraphSnapshotV1, result_id: &str, revision: u64, sensitivity: crate::ContextSensitivityV1, source: &[u8], manifest: &[u8], edge: &crate::GraphEdgeV1) {
        name: "relationships",
        join_keys: "tenant_id,graph_result_id,graph_revision. Join from_subject_id or to_subject_id to graph_subjects.subject_id within the same tenant and graph_result_id. Subject keys retain exact authority and lifetime.",
        owner: OWNER,
        readiness: "conditional",
        description: "Committed relationships from current source-window heads. Contextual and contradictory relationships retain their proof limits. Time and similarity cannot create an exact relationship.",
        setup {
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(graph.scope.identity.tenant_id.as_slice());
            source_key: Binary(SOURCE, "") => Some(source);
            graph_result_id: Utf8("exact immutable result ID", "") => Some(result_id);
            commit_revision: UInt64("store commit revision", "") => Some(revision);
            graph_revision: Binary(REVISION, "") => Some(manifest);
            graph_sensitivity: Utf8("maximum retained input sensitivity; native evidence has a tenant floor", "") =>
                Some(<&str>::from(sensitivity));
            relationship_key: Binary("JSON exact relationship key", "") => Some(Self::json(sink, &edge.key)?);
            from_subject_id: Binary("JSON exact subject authority and lifetime", "") =>
                Some(Self::json(sink, &edge.key.from)?);
            to_subject_id: Binary("JSON exact subject authority and lifetime", "") =>
                Some(Self::json(sink, &edge.key.to)?);
            edge_type: Utf8("unchanged relationship type", "") =>
                Some(match &edge.key.edge_type { crate::GraphEdgeTypeV1::TaskInProcess => "TASK_IN_PROCESS", crate::GraphEdgeTypeV1::TaskInExecutionSet => "TASK_IN_EXECUTION_SET", crate::GraphEdgeTypeV1::NativeParent => "NATIVE_PARENT", crate::GraphEdgeTypeV1::NativeEffect => "NATIVE_EFFECT", crate::GraphEdgeTypeV1::CredentialAuthority => "CREDENTIAL_AUTHORITY", crate::GraphEdgeTypeV1::KubernetesExpansion => "KUBERNETES_EXPANSION" });
            package_id: Utf8("qualified package ID", "") => Some(edge.key.package_id.as_str());
            cause: Utf8("direct, contextual, contradicted, or superseded", "") =>
                Some(match &edge.key.cause { crate::GraphCauseV1::Direct => "DIRECT", crate::GraphCauseV1::Contextual => "CONTEXTUAL", crate::GraphCauseV1::Contradicted => "CONTRADICTED", crate::GraphCauseV1::Superseded => "SUPERSEDED" });
            evidence: Binary("JSON exact accepted record IDs", "") => Some(Self::json(sink, &edge.key.evidence)?);
            proof_quality: Binary("JSON unchanged proof quality", "") =>
                Some(Self::json(sink, &edge.proof_quality)?);
            required_coverage_interval_ids: Binary("JSON exact coverage interval IDs", "") =>
                Some(Self::json(sink, &edge.required_coverage_interval_ids)?);
            first_boottime_ns: UInt64("source boot-relative nanoseconds", "") => Some(edge.first_boottime_ns);
            last_boottime_ns: UInt64("source boot-relative nanoseconds", "") => Some(edge.last_boottime_ns);
        }
    }
}

relation! {
    pub(super) SUBJECTS, subject(sink; graph: &crate::GraphSnapshotV1, result_id: &str, revision: u64, sensitivity: crate::ContextSensitivityV1, source: &[u8], manifest: &[u8], subject: &crate::GraphSubjectKeyV1, depths: Option<&[(crate::GraphSubjectKeyV1, u32)]>) {
        name: "graph_subjects",
        join_keys: KEY,
        owner: OWNER,
        readiness: "conditional",
        description: "Typed subjects from current source-window heads. Provider, Kubernetes, and external identities retain their own authority. A collector lifetime cannot replace a subject lifetime.",
        setup {
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(graph.scope.identity.tenant_id.as_slice());
            source_key: Binary(SOURCE, "") => Some(source);
            graph_result_id: Utf8("exact immutable result ID", "") => Some(result_id);
            commit_revision: UInt64("store commit revision", "") => Some(revision);
            graph_revision: Binary(REVISION, "") => Some(manifest);
            graph_sensitivity: Utf8("maximum retained input sensitivity; native evidence has a tenant floor", "") =>
                Some(<&str>::from(sensitivity));
            subject_id: Binary("JSON exact subject key", "") => Some(Self::json(sink, subject)?);
            subject_kind: Utf8("unchanged subject kind", "") =>
                Some(match &subject.kind { crate::GraphSubjectKindV1::Task => "TASK", crate::GraphSubjectKindV1::Process => "PROCESS", crate::GraphSubjectKindV1::ExecutionSet => "EXECUTION_SET", crate::GraphSubjectKindV1::Socket => "SOCKET", crate::GraphSubjectKindV1::Artifact => "ARTIFACT", crate::GraphSubjectKindV1::Request => "REQUEST", crate::GraphSubjectKindV1::CredentialLease => "CREDENTIAL_LEASE", crate::GraphSubjectKindV1::KubernetesObject => "KUBERNETES_OBJECT", crate::GraphSubjectKindV1::ProviderObject => "PROVIDER_OBJECT", crate::GraphSubjectKindV1::External => "EXTERNAL" });
            authority: Binary("JSON native, provider, Kubernetes, or external authority", "") =>
                Some(Self::json(sink, &subject.authority)?);
            identity: Binary("exact identity within the stated authority", "") => Some(subject.identity.as_slice());
            traversal_depth: UInt32("minimum hops from the selected seeds", "This is not a traversal input.") =>
                depths.and_then(|depths| depths.binary_search_by(|(key, _)| key.cmp(subject)).ok().map(|index| depths[index].1));
        }
    }
}

relation! {
    pub(super) BRANCHES, branch(sink; graph: &crate::GraphSnapshotV1, result_id: &str, revision: u64, sensitivity: crate::ContextSensitivityV1, source: &[u8], manifest: &[u8], branch: &crate::GraphBranchV1) {
        name: "graph_branches",
        join_keys: KEY,
        owner: OWNER,
        readiness: "conditional",
        description: "Committed branch states and missing proof from current source-window heads. An open branch does not prove containment or a response effect.",
        setup {
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(graph.scope.identity.tenant_id.as_slice());
            source_key: Binary(SOURCE, "") => Some(source);
            graph_result_id: Utf8("exact immutable result ID", "") => Some(result_id);
            commit_revision: UInt64("store commit revision", "") => Some(revision);
            graph_revision: Binary(REVISION, "") => Some(manifest);
            graph_sensitivity: Utf8("maximum retained input sensitivity; native evidence has a tenant floor", "") =>
                Some(<&str>::from(sensitivity));
            package_id: Utf8("qualified package ID", "") => Some(branch.package_id.as_str());
            seed_subject_id: Binary("JSON exact subject key", "") => Some(Self::json(sink, &branch.seed)?);
            evidence: Binary("JSON exact accepted record IDs", "") => Some(Self::json(sink, &branch.evidence)?);
            state: Utf8("unchanged branch state", "") =>
                Some(match &branch.state { crate::GraphBranchStateV1::Open => "OPEN", crate::GraphBranchStateV1::TerminalVerified => "TERMINAL_VERIFIED", crate::GraphBranchStateV1::ContextualOnly => "CONTEXTUAL_ONLY", crate::GraphBranchStateV1::OutsideAuthority => "OUTSIDE_AUTHORITY", crate::GraphBranchStateV1::CoverageUnknown => "COVERAGE_UNKNOWN" });
            missing_fields: Binary("JSON explicit missing proof fields", "") =>
                Some(Self::json(sink, &branch.missing_fields)?);
        }
    }
}

relation! {
    pub(super) PACKAGES, package_checkpoint(sink; graph: &crate::GraphSnapshotV1, result_id: &str, revision: u64, sensitivity: crate::ContextSensitivityV1, source: &[u8], manifest: &[u8], package: &crate::GraphPackageCheckpointV1) {
        name: "correlation_packages",
        join_keys: KEY,
        owner: OWNER,
        readiness: "conditional",
        description: "Committed package checkpoints and replay contracts from current source-window heads. Missing Kubernetes or provider proof stays explicit. A checkpoint grants no collector or execution capability.",
        setup {
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(graph.scope.identity.tenant_id.as_slice());
            source_key: Binary(SOURCE, "") => Some(source);
            graph_result_id: Utf8("exact immutable result ID", "") => Some(result_id);
            commit_revision: UInt64("store commit revision", "") => Some(revision);
            graph_revision: Binary(REVISION, "") => Some(manifest);
            graph_sensitivity: Utf8("maximum retained input sensitivity; native evidence has a tenant floor", "") =>
                Some(<&str>::from(sensitivity));
            package_id: Utf8("qualified package ID", "") => Some(package.package_id.as_str());
            package_version: UInt64("package version", "") => Some(package.package_version);
            required_inputs: Binary("JSON exact required inputs", "") =>
                Some(Self::json(sink, &package.required_inputs)?);
            state: Utf8("unchanged package state", "") =>
                Some(match &package.state { crate::GraphPackageStateV1::Waiting => "WAITING", crate::GraphPackageStateV1::NativeEffect => "NATIVE_EFFECT", crate::GraphPackageStateV1::CredentialObserved => "CREDENTIAL_OBSERVED", crate::GraphPackageStateV1::AuthorityChannel => "AUTHORITY_CHANNEL", crate::GraphPackageStateV1::DirectPivot => "DIRECT_PIVOT", crate::GraphPackageStateV1::ContextualPivot => "CONTEXTUAL_PIVOT", crate::GraphPackageStateV1::Contradicted => "CONTRADICTED", crate::GraphPackageStateV1::CoverageInsufficient => "COVERAGE_INSUFFICIENT", crate::GraphPackageStateV1::KubernetesProofMissing => "KUBERNETES_PROOF_MISSING", crate::GraphPackageStateV1::KubernetesRequest => "KUBERNETES_REQUEST", crate::GraphPackageStateV1::KubernetesAudit => "KUBERNETES_AUDIT", crate::GraphPackageStateV1::KubernetesObject => "KUBERNETES_OBJECT", crate::GraphPackageStateV1::KubernetesScheduled => "KUBERNETES_SCHEDULED", crate::GraphPackageStateV1::RemoteAdmission => "REMOTE_ADMISSION", crate::GraphPackageStateV1::Declared(value) => value.as_str() });
            maximum_lateness_ns: UInt64("nanoseconds", "") => Some(package.maximum_lateness_ns);
            retention_ttl_ns: UInt64("nanoseconds", "") => Some(package.retention_ttl_ns);
            clock_uncertainty_ns: UInt64("nanoseconds", "Clock uncertainty is unknown.") =>
                package.clock_uncertainty_ns;
            late_action: Utf8("declared late-input action", "") => Some(package.late_action.as_str());
            window_ns: UInt64("nanoseconds", "") => Some(package.window_ns);
            window_records: UInt64("accepted record limit", "") => Some(package.window_records);
            window_bytes: UInt64("accepted input byte limit", "") => Some(package.window_bytes as u64);
            coverage_predicate: Utf8("required coverage predicate", "") =>
                Some(package.coverage_predicate.as_str());
            replay_contract_id: Utf8("exact replay contract ID", "") => Some(package.replay_contract_id.as_str());
            result_states: Binary("JSON supported finding states", "") =>
                Some(Self::json(sink, &package.result_states)?);
            accepted_cursor_watermark: UInt64("accepted source cursor", "") =>
                Some(package.accepted_cursor_watermark);
            observed_boottime_watermark_ns: UInt64("source boot-relative nanoseconds", "") =>
                Some(package.observed_boottime_watermark_ns);
        }
    }
}

relation! {
    pub(super) POLICY, policy_observation(sink; graph: &crate::GraphSnapshotV1, result_id: &str, revision: u64, sensitivity: crate::ContextSensitivityV1, source: &[u8], manifest: &[u8], finding: &crate::FindingV1, policy: &crate::PolicyObservationProvenanceV1) {
        name: "policy_observations",
        join_keys: KEY,
        owner: OWNER,
        readiness: "conditional",
        description: "Policy provenance retained by each finding revision. Join graph_result_id to findings to read the current finding provenance. Missing, stale, partial, or mixed rollout proof limits the finding. Query cannot change policy or activation.",
        setup {
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(graph.scope.identity.tenant_id.as_slice());
            source_key: Binary(SOURCE, "") => Some(source);
            graph_result_id: Utf8("exact immutable result ID", "") => Some(result_id);
            commit_revision: UInt64("store commit revision", "") => Some(revision);
            graph_revision: Binary(REVISION, "") => Some(manifest);
            graph_sensitivity: Utf8("maximum retained input sensitivity; native evidence has a tenant floor", "") =>
                Some(<&str>::from(sensitivity));
            finding_id: Utf8("exact full finding key", "") => Some(finding.finding_id.as_str());
            profile_generation_ref_id: UInt64("exact Node generation reference", "") =>
                Some(policy.profile_generation_ref_id);
            observations: Binary("JSON exact accepted record IDs", "") =>
                Some(Self::json(sink, &policy.observations)?);
            policy_source_revision_id: Utf8("exact Control source revision", "The source revision is absent.") =>
                policy.policy_source_revision_id.as_deref();
            candidate_content_id: Utf8("exact signed candidate", "The candidate is absent.") =>
                policy.candidate_content_id.as_deref();
            target_snapshot_digest: Utf8("exact signed target snapshot", "The target snapshot is absent.") =>
                policy.target_snapshot_digest.as_deref();
            node_bound_generation_digest: Utf8("exact Node-bound generation", "The generation is absent.") =>
                policy.node_bound_generation_digest.as_deref();
            activation_acknowledgement: Binary("JSON exact activation context key", "The activation acknowledgement is absent.") =>
                policy.activation_acknowledgement.as_ref().map(|value| Self::json(sink, value)).transpose()?;
            state: Utf8("exact, missing, or contradicted", "") =>
                Some(match &policy.state { crate::PolicyProvenanceStateV1::Exact => "EXACT", crate::PolicyProvenanceStateV1::Missing => "MISSING", crate::PolicyProvenanceStateV1::Contradicted => "CONTRADICTED" });
            limits: Binary("JSON explicit policy provenance limits", "") => Some(Self::json(sink, &policy.limits)?);
        }
    }
}
impl InputRelations {
    pub(super) fn graph_prefix<'a>(
        cache: &'a mut (Option<Vec<u8>>, Option<Vec<u8>>),
        graph: &crate::GraphSnapshotV1,
        fields: Option<&BTreeSet<String>>,
        graph_inputs: bool,
        sink: &mut ProjectionSink<'_, ()>,
    ) -> Result<(&'a [u8], &'a [u8])> {
        if cache.0.is_none() && fields.is_none_or(|fields| fields.contains("source_key")) {
            cache.0 = Some(Self::json(sink, &graph.scope.identity)?);
        }
        if cache.1.is_none()
            && !graph_inputs
            && fields.is_none_or(|fields| fields.contains("graph_revision"))
        {
            cache.1 = Some(Self::json(sink, &graph.input_manifest)?);
        }
        Ok((
            cache.0.as_deref().unwrap_or_default(),
            cache.1.as_deref().unwrap_or_default(),
        ))
    }
}

impl InputProjection<'_> {
    pub(super) fn permits_finding(&self, finding: &crate::FindingV1) -> bool {
        self.selection.binding_ids.is_empty()
            || (!finding.effects.is_empty()
                && finding.effects.iter().all(|effect| {
                    effect
                        .binding_id
                        .is_some_and(|binding| self.selection.binding_ids.contains(&binding))
                }))
    }

    fn permits_evidence(
        &self,
        graph: &crate::GraphSnapshotV1,
        evidence: &[crate::DiscoveryRecordIdV1],
    ) -> bool {
        self.selection.binding_ids.is_empty()
            || (!evidence.is_empty()
                && evidence.iter().all(|record| {
                    graph.findings.iter().any(|finding| {
                        self.permits_finding(finding) && finding.evidence.contains(record)
                    })
                }))
    }

    pub(super) fn graph_rows(
        &mut self,
        input: &crate::AnalysisInputV1<'_>,
        cache: &mut (Option<Vec<u8>>, Option<Vec<u8>>),
        sink: &mut ProjectionSink<'_, ()>,
    ) -> Result<bool> {
        let crate::AnalysisInputV1::Graph {
            result_id,
            graph,
            commit_revision,
            sensitivity,
            traversal_depths,
        } = input
        else {
            return Ok(true);
        };
        if !self.selection.permits_graph(graph) {
            return Ok(true);
        }
        let (revision, sensitivity, depths) = (*commit_revision, *sensitivity, *traversal_depths);
        for finding in &graph.findings {
            sink.check()?;
            if !self.permits_finding(finding) {
                continue;
            }
            if self.expands("findings") {
                let fields = self.projections.get("findings");
                let (source, manifest) =
                    InputRelations::graph_prefix(cache, graph, fields, self.graph_inputs, sink)?;
                if !self.inputs.finding(
                    sink,
                    fields,
                    (
                        graph,
                        result_id,
                        revision,
                        sensitivity,
                        source,
                        manifest,
                        finding,
                    ),
                )? {
                    return Ok(false);
                }
            }
            if self.expands("policy_observations") {
                for policy in &finding.policy_provenance {
                    sink.check()?;
                    let fields = self.projections.get("policy_observations");
                    let (source, manifest) = InputRelations::graph_prefix(
                        cache,
                        graph,
                        fields,
                        self.graph_inputs,
                        sink,
                    )?;
                    if !self.inputs.policy_observation(
                        sink,
                        fields,
                        (
                            graph,
                            result_id,
                            revision,
                            sensitivity,
                            source,
                            manifest,
                            finding,
                            policy,
                        ),
                    )? {
                        return Ok(false);
                    }
                }
            }
        }
        if self.expands("relationships") {
            for edge in &graph.graph.edges {
                sink.check()?;
                if !self.permits_evidence(graph, &edge.key.evidence) {
                    continue;
                }
                let fields = self.projections.get("relationships");
                let (source, manifest) =
                    InputRelations::graph_prefix(cache, graph, fields, self.graph_inputs, sink)?;
                if !self.inputs.relationship(
                    sink,
                    fields,
                    (
                        graph,
                        result_id,
                        revision,
                        sensitivity,
                        source,
                        manifest,
                        edge,
                    ),
                )? {
                    return Ok(false);
                }
            }
        }
        if self.expands("graph_subjects") {
            for subject in &graph.graph.subjects {
                sink.check()?;
                if depths.is_none()
                    && !self.selection.binding_ids.is_empty()
                    && !graph.findings.iter().any(|finding| {
                        self.permits_finding(finding) && finding.subject_id == *subject
                    })
                    && !graph.graph.edges.iter().any(|edge| {
                        self.permits_evidence(graph, &edge.key.evidence)
                            && (edge.key.from == *subject || edge.key.to == *subject)
                    })
                {
                    continue;
                }
                let fields = self.projections.get("graph_subjects");
                let (source, manifest) =
                    InputRelations::graph_prefix(cache, graph, fields, self.graph_inputs, sink)?;
                if !self.inputs.subject(
                    sink,
                    fields,
                    (
                        graph,
                        result_id,
                        revision,
                        sensitivity,
                        source,
                        manifest,
                        subject,
                        depths,
                    ),
                )? {
                    return Ok(false);
                }
            }
        }
        if self.expands("graph_branches") {
            for branch in &graph.graph.branches {
                sink.check()?;
                if !self.permits_evidence(graph, &branch.evidence) {
                    continue;
                }
                let fields = self.projections.get("graph_branches");
                let (source, manifest) =
                    InputRelations::graph_prefix(cache, graph, fields, self.graph_inputs, sink)?;
                if !self.inputs.branch(
                    sink,
                    fields,
                    (
                        graph,
                        result_id,
                        revision,
                        sensitivity,
                        source,
                        manifest,
                        branch,
                    ),
                )? {
                    return Ok(false);
                }
            }
        }
        if self.expands("correlation_packages")
            && self.permits_evidence(graph, &graph.input_manifest.evidence)
        {
            for package in &graph.packages {
                sink.check()?;
                let fields = self.projections.get("correlation_packages");
                let (source, manifest) =
                    InputRelations::graph_prefix(cache, graph, fields, self.graph_inputs, sink)?;
                if !self.inputs.package_checkpoint(
                    sink,
                    fields,
                    (
                        graph,
                        result_id,
                        revision,
                        sensitivity,
                        source,
                        manifest,
                        package,
                    ),
                )? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}
