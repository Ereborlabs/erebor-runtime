use duckdb::core::LogicalTypeId::*;
use duckdb::types::Value;
use snafu::IntoError as _;

use super::input::{InputField, InputProjection, InputRow, InputSchema};
use crate::{AnalysisRelationV1, FindingV1, GraphSnapshotV1, Result};

pub(super) const RELATIONS: &[&str] = &[
    "findings",
    "relationships",
    "graph_subjects",
    "graph_branches",
    "correlation_packages",
    "policy_observations",
];

const REVISION: &str = "JSON exact evidence, coverage, context, and missing-range manifest";
const SOURCE: &str = "JSON exact accepted source lifetime";
const OWNER: &str = "araphor-data.GraphAndFindingOwner";
const KEY: &str = "tenant_id,graph_result_id,graph_revision. Structured keys contain exact lifetimes. A binding scope requires exact effect proof for each manifest record. Names and time are not causal proof.";

pub(super) const FINDINGS: InputSchema = InputSchema {
    name: "findings",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("source_key", Blob, SOURCE, ""),
        InputField("graph_result_id", Varchar, "exact immutable result ID", ""),
        InputField("commit_revision", UBigint, "store commit revision", ""),
        InputField("graph_revision", Blob, REVISION, ""),
        InputField("graph_sensitivity", Varchar, "maximum retained input sensitivity; native evidence has a tenant floor", ""),
        InputField("finding_id", Varchar, "exact full finding key", ""),
        InputField("finding_revision", Blob, REVISION, ""),
        InputField("package_id", Varchar, "qualified package ID", ""),
        InputField("package_version", UBigint, "package version", ""),
        InputField("subject_id", Blob, "JSON exact subject authority and lifetime", ""),
        InputField("state", Varchar, "unchanged finding state", ""),
        InputField("window_start_utc_ns", Bigint, "source UTC nanoseconds", ""),
        InputField("window_end_utc_ns", Bigint, "source UTC nanoseconds", ""),
        InputField("evidence", Blob, "JSON exact accepted record IDs", ""),
        InputField("required_coverage_interval_ids", Blob, "JSON exact coverage interval IDs", ""),
        InputField("policy_provenance", Blob, "JSON exact policy provenance and limits", ""),
        InputField("effects", Blob, "JSON unchanged source decisions, physical results, and proof quality", ""),
        InputField("reason", Varchar, "unchanged finding reason", ""),
        InputField("severity", Varchar, "source severity", ""),
        InputField("sensitivity", Varchar, "public, tenant, or host_restricted", ""),
        InputField("required_action", Varchar, "required human action", "The finding has no required action."),
        InputField("limits", Blob, "JSON explicit finding limits", ""),
    ],
    join_keys: "tenant_id,finding_id,finding_revision. The latest authorized commit supplies one current revision per finding_id. A finding grants no execution authority.",
    owner: OWNER,
    readiness: "conditional",
    description: "Current committed findings across authorized source-window heads. Exact revision values remain unchanged. A binding scope excludes mixed or unproved windows. Sensitivity is an owner label under the existing tenant query permission. Empty findings do not prove complete coverage.",
};

pub(super) const RELATIONSHIPS: InputSchema = InputSchema {
    name: "relationships",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("source_key", Blob, SOURCE, ""),
        InputField("graph_result_id", Varchar, "exact immutable result ID", ""),
        InputField("commit_revision", UBigint, "store commit revision", ""),
        InputField("graph_revision", Blob, REVISION, ""),
        InputField("graph_sensitivity", Varchar, "maximum retained input sensitivity; native evidence has a tenant floor", ""),
        InputField("relationship_key", Blob, "JSON exact relationship key", ""),
        InputField("from_subject_id", Blob, "JSON exact subject authority and lifetime", ""),
        InputField("to_subject_id", Blob, "JSON exact subject authority and lifetime", ""),
        InputField("edge_type", Varchar, "unchanged relationship type", ""),
        InputField("package_id", Varchar, "qualified package ID", ""),
        InputField("cause", Varchar, "direct, contextual, contradicted, or superseded", ""),
        InputField("evidence", Blob, "JSON exact accepted record IDs", ""),
        InputField("proof_quality", Blob, "JSON unchanged proof quality", ""),
        InputField("required_coverage_interval_ids", Blob, "JSON exact coverage interval IDs", ""),
        InputField("first_boottime_ns", UBigint, "source boot-relative nanoseconds", ""),
        InputField("last_boottime_ns", UBigint, "source boot-relative nanoseconds", ""),
    ],
    join_keys: KEY,
    owner: OWNER,
    readiness: "conditional",
    description: "Committed relationships from current source-window heads. Contextual and contradictory relationships retain their proof limits. Time and similarity cannot create an exact relationship.",
};

pub(super) const SUBJECTS: InputSchema = InputSchema {
    name: "graph_subjects",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("source_key", Blob, SOURCE, ""),
        InputField("graph_result_id", Varchar, "exact immutable result ID", ""),
        InputField("commit_revision", UBigint, "store commit revision", ""),
        InputField("graph_revision", Blob, REVISION, ""),
        InputField("graph_sensitivity", Varchar, "maximum retained input sensitivity; native evidence has a tenant floor", ""),
        InputField("subject_id", Blob, "JSON exact subject key", ""),
        InputField("subject_kind", Varchar, "unchanged subject kind", ""),
        InputField("authority", Blob, "JSON native, provider, Kubernetes, or external authority", ""),
        InputField("identity", Blob, "exact identity within the stated authority", ""),
    ],
    join_keys: KEY,
    owner: OWNER,
    readiness: "conditional",
    description: "Typed subjects from current source-window heads. Provider, Kubernetes, and external identities retain their own authority. A collector lifetime cannot replace a subject lifetime.",
};

pub(super) const BRANCHES: InputSchema = InputSchema {
    name: "graph_branches",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("source_key", Blob, SOURCE, ""),
        InputField("graph_result_id", Varchar, "exact immutable result ID", ""),
        InputField("commit_revision", UBigint, "store commit revision", ""),
        InputField("graph_revision", Blob, REVISION, ""),
        InputField("graph_sensitivity", Varchar, "maximum retained input sensitivity; native evidence has a tenant floor", ""),
        InputField("package_id", Varchar, "qualified package ID", ""),
        InputField("seed_subject_id", Blob, "JSON exact subject key", ""),
        InputField("evidence", Blob, "JSON exact accepted record IDs", ""),
        InputField("state", Varchar, "unchanged branch state", ""),
        InputField("missing_fields", Blob, "JSON explicit missing proof fields", ""),
    ],
    join_keys: KEY,
    owner: OWNER,
    readiness: "conditional",
    description: "Committed branch states and missing proof from current source-window heads. An open branch does not prove containment or a response effect.",
};

pub(super) const PACKAGES: InputSchema = InputSchema {
    name: "correlation_packages",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("source_key", Blob, SOURCE, ""),
        InputField("graph_result_id", Varchar, "exact immutable result ID", ""),
        InputField("commit_revision", UBigint, "store commit revision", ""),
        InputField("graph_revision", Blob, REVISION, ""),
        InputField("graph_sensitivity", Varchar, "maximum retained input sensitivity; native evidence has a tenant floor", ""),
        InputField("package_id", Varchar, "qualified package ID", ""),
        InputField("package_version", UBigint, "package version", ""),
        InputField("required_inputs", Blob, "JSON exact required inputs", ""),
        InputField("state", Varchar, "unchanged package state", ""),
        InputField("maximum_lateness_ns", UBigint, "nanoseconds", ""),
        InputField("retention_ttl_ns", UBigint, "nanoseconds", ""),
        InputField("clock_uncertainty_ns", UBigint, "nanoseconds", "Clock uncertainty is unknown."),
        InputField("late_action", Varchar, "declared late-input action", ""),
        InputField("window_ns", UBigint, "nanoseconds", ""),
        InputField("window_records", UBigint, "accepted record limit", ""),
        InputField("window_bytes", UBigint, "accepted input byte limit", ""),
        InputField("coverage_predicate", Varchar, "required coverage predicate", ""),
        InputField("replay_contract_id", Varchar, "exact replay contract ID", ""),
        InputField("result_states", Blob, "JSON supported finding states", ""),
        InputField("accepted_cursor_watermark", UBigint, "accepted source cursor", ""),
        InputField("observed_boottime_watermark_ns", UBigint, "source boot-relative nanoseconds", ""),
    ],
    join_keys: KEY,
    owner: OWNER,
    readiness: "conditional",
    description: "Committed package checkpoints and replay contracts from current source-window heads. Missing Kubernetes or provider proof stays explicit. A checkpoint grants no collector or execution capability.",
};

pub(super) const POLICY: InputSchema = InputSchema {
    name: "policy_observations",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("source_key", Blob, SOURCE, ""),
        InputField("graph_result_id", Varchar, "exact immutable result ID", ""),
        InputField("commit_revision", UBigint, "store commit revision", ""),
        InputField("graph_revision", Blob, REVISION, ""),
        InputField("graph_sensitivity", Varchar, "maximum retained input sensitivity; native evidence has a tenant floor", ""),
        InputField("finding_id", Varchar, "exact full finding key", ""),
        InputField("profile_generation_ref_id", UBigint, "exact Node generation reference", ""),
        InputField("observations", Blob, "JSON exact accepted record IDs", ""),
        InputField("policy_source_revision_id", Varchar, "exact Control source revision", "The source revision is absent."),
        InputField("candidate_content_id", Varchar, "exact signed candidate", "The candidate is absent."),
        InputField("target_snapshot_digest", Varchar, "exact signed target snapshot", "The target snapshot is absent."),
        InputField("node_bound_generation_digest", Varchar, "exact Node-bound generation", "The generation is absent."),
        InputField("activation_acknowledgement", Blob, "JSON exact activation context key", "The activation acknowledgement is absent."),
        InputField("state", Varchar, "exact, missing, or contradicted", ""),
        InputField("limits", Blob, "JSON explicit policy provenance limits", ""),
    ],
    join_keys: KEY,
    owner: OWNER,
    readiness: "conditional",
    description: "Policy provenance retained by each finding revision. Join graph_result_id to findings to read the current finding provenance. Missing, stale, partial, or mixed rollout proof limits the finding. Query cannot change policy or activation.",
};

impl InputRow {
    fn graph_base(
        graph: &GraphSnapshotV1,
        result_id: &str,
        commit_revision: u64,
        sensitivity: crate::ContextSensitivityV1,
    ) -> Result<Self> {
        Ok(Self(vec![
            Value::Blob(graph.scope.identity.tenant_id.to_vec()),
            Self::json(&graph.scope.identity)?,
            Value::Text(result_id.into()),
            Value::UBigInt(commit_revision),
            Self::json(&graph.input_manifest)?,
            Value::Text(<&str>::from(sensitivity).into()),
        ]))
    }

    fn json(value: &impl serde::Serialize) -> Result<Value> {
        serde_json::to_vec(value)
            .map(Value::Blob)
            .map_err(|source| crate::QueryEncodingSnafu.into_error(source))
    }

    fn label(value: &impl serde::Serialize) -> Result<Value> {
        match serde_json::to_value(value)
            .map_err(|source| crate::QueryEncodingSnafu.into_error(source))?
        {
            serde_json::Value::String(value) => Ok(Value::Text(value)),
            _ => crate::QueryInvalidSnafu {
                field: "graph enum label",
            }
            .fail(),
        }
    }

    fn finding(
        graph: &GraphSnapshotV1,
        result_id: &str,
        revision: u64,
        finding: &FindingV1,
        sensitivity: crate::ContextSensitivityV1,
    ) -> Result<Self> {
        let mut row = Self::graph_base(graph, result_id, revision, sensitivity)?;
        row.0.extend([
            Value::Text(finding.finding_id.clone()),
            Self::json(&finding.revision)?,
            Value::Text(finding.package_id.clone()),
            Value::UBigInt(finding.package_version),
            Self::json(&finding.subject_id)?,
            Self::label(&finding.state)?,
            Value::BigInt(finding.window_start_utc_ns),
            Value::BigInt(finding.window_end_utc_ns),
            Self::json(&finding.evidence)?,
            Self::json(&finding.required_coverage_interval_ids)?,
            Self::json(&finding.policy_provenance)?,
            Self::json(&finding.effects)?,
            Self::label(&finding.reason)?,
            Self::label(&finding.severity)?,
            Value::Text(<&str>::from(finding.sensitivity).into()),
            finding
                .required_action
                .clone()
                .map_or(Value::Null, Value::Text),
            Self::json(&finding.limits)?,
        ]);
        Ok(row)
    }
}

impl InputProjection<'_> {
    pub(super) fn permits_finding(&self, finding: &FindingV1) -> bool {
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
        graph: &GraphSnapshotV1,
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
        &self,
        graph: &GraphSnapshotV1,
        result_id: &str,
        revision: u64,
        sensitivity: crate::ContextSensitivityV1,
        sink: &mut crate::analysis::ProjectionSink<'_, InputRow>,
    ) -> Result<bool> {
        if !self.selection.permits_graph(graph) {
            return Ok(true);
        }
        for finding in &graph.findings {
            sink.check()?;
            if !self.permits_finding(finding) {
                continue;
            }
            if self.expands("findings") {
                let row = InputRow::finding(graph, result_id, revision, finding, sensitivity)?;
                self.graph_emit(AnalysisRelationV1::Findings, row, sink)?;
            }
            if self.expands("policy_observations") {
                for policy in &finding.policy_provenance {
                    sink.check()?;
                    let mut row = InputRow::graph_base(graph, result_id, revision, sensitivity)?;
                    row.0.extend([
                        Value::Text(finding.finding_id.clone()),
                        Value::UBigInt(policy.profile_generation_ref_id),
                        InputRow::json(&policy.observations)?,
                        policy
                            .policy_source_revision_id
                            .clone()
                            .map_or(Value::Null, Value::Text),
                        policy
                            .candidate_content_id
                            .clone()
                            .map_or(Value::Null, Value::Text),
                        policy
                            .target_snapshot_digest
                            .clone()
                            .map_or(Value::Null, Value::Text),
                        policy
                            .node_bound_generation_digest
                            .clone()
                            .map_or(Value::Null, Value::Text),
                        policy
                            .activation_acknowledgement
                            .as_ref()
                            .map(InputRow::json)
                            .transpose()?
                            .unwrap_or(Value::Null),
                        InputRow::label(&policy.state)?,
                        InputRow::json(&policy.limits)?,
                    ]);
                    self.graph_emit(AnalysisRelationV1::PolicyObservations, row, sink)?;
                }
            }
        }
        if self.expands("relationships") {
            for edge in &graph.graph.edges {
                sink.check()?;
                if !self.permits_evidence(graph, &edge.key.evidence) {
                    continue;
                }
                let mut row = InputRow::graph_base(graph, result_id, revision, sensitivity)?;
                row.0.extend([
                    InputRow::json(&edge.key)?,
                    InputRow::json(&edge.key.from)?,
                    InputRow::json(&edge.key.to)?,
                    InputRow::label(&edge.key.edge_type)?,
                    Value::Text(edge.key.package_id.clone()),
                    InputRow::label(&edge.key.cause)?,
                    InputRow::json(&edge.key.evidence)?,
                    InputRow::json(&edge.proof_quality)?,
                    InputRow::json(&edge.required_coverage_interval_ids)?,
                    Value::UBigInt(edge.first_boottime_ns),
                    Value::UBigInt(edge.last_boottime_ns),
                ]);
                self.graph_emit(AnalysisRelationV1::Relationships, row, sink)?;
            }
        }
        if self.expands("graph_subjects") {
            for subject in &graph.graph.subjects {
                sink.check()?;
                if !self.selection.binding_ids.is_empty()
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
                let mut row = InputRow::graph_base(graph, result_id, revision, sensitivity)?;
                row.0.extend([
                    InputRow::json(subject)?,
                    InputRow::label(&subject.kind)?,
                    InputRow::json(&subject.authority)?,
                    Value::Blob(subject.identity.clone()),
                ]);
                self.graph_emit(AnalysisRelationV1::GraphSubjects, row, sink)?;
            }
        }
        if self.expands("graph_branches") {
            for branch in &graph.graph.branches {
                sink.check()?;
                if !self.permits_evidence(graph, &branch.evidence) {
                    continue;
                }
                let mut row = InputRow::graph_base(graph, result_id, revision, sensitivity)?;
                row.0.extend([
                    Value::Text(branch.package_id.clone()),
                    InputRow::json(&branch.seed)?,
                    InputRow::json(&branch.evidence)?,
                    InputRow::label(&branch.state)?,
                    InputRow::json(&branch.missing_fields)?,
                ]);
                self.graph_emit(AnalysisRelationV1::GraphBranches, row, sink)?;
            }
        }
        if self.expands("correlation_packages")
            && self.permits_evidence(graph, &graph.input_manifest.evidence)
        {
            for package in &graph.packages {
                sink.check()?;
                let mut row = InputRow::graph_base(graph, result_id, revision, sensitivity)?;
                row.0.extend([
                    Value::Text(package.package_id.clone()),
                    Value::UBigInt(package.package_version),
                    InputRow::json(&package.required_inputs)?,
                    InputRow::label(&package.state)?,
                    Value::UBigInt(package.maximum_lateness_ns),
                    Value::UBigInt(package.retention_ttl_ns),
                    package
                        .clock_uncertainty_ns
                        .map_or(Value::Null, Value::UBigInt),
                    Value::Text(package.late_action.clone()),
                    Value::UBigInt(package.window_ns),
                    Value::UBigInt(package.window_records),
                    Value::UBigInt(package.window_bytes as u64),
                    Value::Text(package.coverage_predicate.clone()),
                    Value::Text(package.replay_contract_id.clone()),
                    InputRow::json(&package.result_states)?,
                    Value::UBigInt(package.accepted_cursor_watermark),
                    Value::UBigInt(package.observed_boottime_watermark_ns),
                ]);
                self.graph_emit(AnalysisRelationV1::CorrelationPackages, row, sink)?;
            }
        }
        Ok(true)
    }

    fn graph_emit(
        &self,
        relation: AnalysisRelationV1,
        row: InputRow,
        sink: &mut crate::analysis::ProjectionSink<'_, InputRow>,
    ) -> Result<bool> {
        let bytes = row.allocation_bytes()?;
        sink.emit(relation, (row, bytes))
    }
}
