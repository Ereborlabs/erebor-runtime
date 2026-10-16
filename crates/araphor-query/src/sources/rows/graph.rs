use araphor_data::{
    AnalysisInputV1, AnalysisWitnessV1, ContextSensitivityV1, FindingSeverityV1, FindingStateV1,
    GraphBranchStateV1, GraphCauseV1, GraphEdgeTypeV1, GraphPackageStateV1, GraphSnapshotV1,
    GraphSubjectKindV1, PolicyProvenanceStateV1, ProjectionSink,
};
use datafusion::common::ScalarValue;

use super::{ArrowBatch, Capture};

impl Capture<'_> {
    pub(super) fn graph(
        &mut self,
        input: AnalysisInputV1<'_>,
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<bool> {
        let AnalysisInputV1::Graph {
            result_id,
            graph,
            subject_count,
            relationship_count,
            commit_revision,
            sensitivity,
            traversal_depths,
        } = input
        else {
            return Ok(true);
        };
        if !self.scope.permits_graph(graph) {
            return Ok(true);
        }
        for evidence in &graph.input_manifest.evidence {
            sink.grow(&mut self.witnesses)?;
            sink.charge(evidence.stream.node_id.len())?;
            self.witnesses.push(AnalysisWitnessV1 {
                identity: evidence.stream.clone().into(),
                cursor: evidence.durable_cursor,
                expires_utc_ns: graph.witness_deadline_utc_ns,
            });
        }
        sink.charge(araphor_data::EvidenceIntakeIdentityV1::MAX_KEY_BYTES)?;
        let source_key = graph.scope.identity.key();
        let common = |name: &str, sink: &mut ProjectionSink<'_>| {
            Self::graph_field(
                name,
                graph,
                result_id,
                commit_revision,
                sensitivity,
                &source_key,
                sink,
            )
        };
        for finding in &graph.findings {
            let row = self
                .tables
                .get("findings")
                .map_or(0, |table| table.total_rows);
            if !self.append("findings", sink, |name, _kind, sink| {
                if let Some(value) = common(name, sink)? {
                    return Ok(value);
                }
                Ok(match name {
                    "finding_id" => Self::text(Some(&finding.finding_id), sink)?,
                    "finding_revision" => Self::json(&finding.revision, sink)?,
                    "package_id" => Self::text(Some(&finding.package_id), sink)?,
                    "package_version" => ScalarValue::UInt64(Some(finding.package_version)),
                    "subject_id" => Self::json(&finding.subject_id, sink)?,
                    "state" => Self::text(
                        Some(match finding.state {
                            FindingStateV1::Provisional => "provisional",
                            FindingStateV1::Confirmed => "confirmed",
                            FindingStateV1::Superseded => "superseded",
                            FindingStateV1::Retracted => "retracted",
                            FindingStateV1::CoverageInsufficient => "coverage_insufficient",
                        }),
                        sink,
                    )?,
                    "window_start_utc_ns" => ScalarValue::Int64(Some(finding.window_start_utc_ns)),
                    "window_end_utc_ns" => ScalarValue::Int64(Some(finding.window_end_utc_ns)),
                    "evidence" => Self::json(&finding.evidence, sink)?,
                    "required_coverage_interval_ids" => {
                        Self::json(&finding.required_coverage_interval_ids, sink)?
                    }
                    "policy_provenance" => Self::json(&finding.policy_provenance, sink)?,
                    "effects" => Self::json(&finding.effects, sink)?,
                    "reason" => {
                        sink.charge(4096)?;
                        Self::text(Some(&finding.reason.label()?), sink)?
                    }
                    "severity" => Self::text(
                        Some(match finding.severity {
                            FindingSeverityV1::Info => "info",
                            FindingSeverityV1::Warning => "warning",
                            FindingSeverityV1::High => "high",
                            FindingSeverityV1::Critical => "critical",
                        }),
                        sink,
                    )?,
                    "sensitivity" => Self::text(Some(finding.sensitivity.into()), sink)?,
                    "required_action" => Self::text(finding.required_action.as_deref(), sink)?,
                    "limits" => Self::json(&finding.limits, sink)?,
                    _ => {
                        return Err(ArrowBatch::invalid(
                            "the native source field has no adapter",
                        ));
                    }
                })
            })? {
                return Ok(false);
            }
            if self.requested.contains_key("findings") {
                let key = (finding.tenant_id, finding.finding_id.clone());
                if !self.latest.contains_key(&key) {
                    sink.charge(finding.finding_id.len() + 128)?;
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
                if !self.append("policy_observations", sink, |name, kind, sink| {
                    if let Some(value) = common(name, sink)? {
                        return Ok(value);
                    }
                    Ok(match name {
                        "finding_id" => Self::text(Some(&finding.finding_id), sink)?,
                        "profile_generation_ref_id" => {
                            ScalarValue::UInt64(Some(observation.profile_generation_ref_id))
                        }
                        "observations" => Self::json(&observation.observations, sink)?,
                        "policy_source_revision_id" => {
                            Self::text(observation.policy_source_revision_id.as_deref(), sink)?
                        }
                        "candidate_content_id" => {
                            Self::text(observation.candidate_content_id.as_deref(), sink)?
                        }
                        "target_snapshot_digest" => {
                            Self::text(observation.target_snapshot_digest.as_deref(), sink)?
                        }
                        "node_bound_generation_digest" => {
                            Self::text(observation.node_bound_generation_digest.as_deref(), sink)?
                        }
                        "activation_acknowledgement" => {
                            if let Some(value) = &observation.activation_acknowledgement {
                                Self::json(value, sink)?
                            } else {
                                Self::null(kind)?
                            }
                        }
                        "state" => Self::text(
                            Some(match observation.state {
                                PolicyProvenanceStateV1::Exact => "exact",
                                PolicyProvenanceStateV1::Missing => "missing",
                                PolicyProvenanceStateV1::Contradicted => "contradicted",
                            }),
                            sink,
                        )?,
                        "limits" => Self::json(&observation.limits, sink)?,
                        _ => {
                            return Err(ArrowBatch::invalid(
                                "the native source field has no adapter",
                            ));
                        }
                    })
                })? {
                    return Ok(false);
                }
            }
        }
        for edge in &graph.graph.edges {
            if !self.append("relationships", sink, |name, _kind, sink| {
                if let Some(value) = common(name, sink)? {
                    return Ok(value);
                }
                Ok(match name {
                    "relationship_key" => Self::json(&edge.key, sink)?,
                    "from_subject_id" => Self::json(&edge.key.from, sink)?,
                    "to_subject_id" => Self::json(&edge.key.to, sink)?,
                    "edge_type" => Self::text(
                        Some(match edge.key.edge_type {
                            GraphEdgeTypeV1::TaskInProcess => "task_in_process",
                            GraphEdgeTypeV1::TaskInExecutionSet => "task_in_execution_set",
                            GraphEdgeTypeV1::NativeParent => "native_parent",
                            GraphEdgeTypeV1::NativeEffect => "native_effect",
                            GraphEdgeTypeV1::CredentialAuthority => "credential_authority",
                            GraphEdgeTypeV1::KubernetesExpansion => "kubernetes_expansion",
                        }),
                        sink,
                    )?,
                    "package_id" => Self::text(Some(&edge.key.package_id), sink)?,
                    "cause" => Self::text(
                        Some(match edge.key.cause {
                            GraphCauseV1::Direct => "direct",
                            GraphCauseV1::Contextual => "contextual",
                            GraphCauseV1::Contradicted => "contradicted",
                            GraphCauseV1::Superseded => "superseded",
                        }),
                        sink,
                    )?,
                    "evidence" => Self::json(&edge.key.evidence, sink)?,
                    "proof_quality" => Self::json(&edge.proof_quality, sink)?,
                    "required_coverage_interval_ids" => {
                        Self::json(&edge.required_coverage_interval_ids, sink)?
                    }
                    "first_boottime_ns" => ScalarValue::UInt64(Some(edge.first_boottime_ns)),
                    "last_boottime_ns" => ScalarValue::UInt64(Some(edge.last_boottime_ns)),
                    _ => {
                        return Err(ArrowBatch::invalid(
                            "the native source field has no adapter",
                        ));
                    }
                })
            })? {
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
            if !self.append("graph_subjects", sink, |name, _kind, sink| {
                if let Some(value) = common(name, sink)? {
                    return Ok(value);
                }
                Ok(match name {
                    "subject_id" => Self::json(subject, sink)?,
                    "subject_kind" => Self::text(
                        Some(match subject.kind {
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
                        sink,
                    )?,
                    "authority" => Self::json(&subject.authority, sink)?,
                    "identity" => Self::binary(Some(&subject.identity), sink)?,
                    "traversal_depth" => ScalarValue::UInt32(depth),
                    _ => {
                        return Err(ArrowBatch::invalid(
                            "the native source field has no adapter",
                        ));
                    }
                })
            })? {
                return Ok(false);
            }
        }
        for branch in &graph.graph.branches {
            if !self.append("graph_branches", sink, |name, _kind, sink| {
                if let Some(value) = common(name, sink)? {
                    return Ok(value);
                }
                Ok(match name {
                    "package_id" => Self::text(Some(&branch.package_id), sink)?,
                    "seed_subject_id" => Self::json(&branch.seed, sink)?,
                    "evidence" => Self::json(&branch.evidence, sink)?,
                    "state" => Self::text(
                        Some(match branch.state {
                            GraphBranchStateV1::Open => "open",
                            GraphBranchStateV1::TerminalVerified => "terminal_verified",
                            GraphBranchStateV1::ContextualOnly => "contextual_only",
                            GraphBranchStateV1::OutsideAuthority => "outside_authority",
                            GraphBranchStateV1::CoverageUnknown => "coverage_unknown",
                        }),
                        sink,
                    )?,
                    "missing_fields" => Self::json(&branch.missing_fields, sink)?,
                    _ => {
                        return Err(ArrowBatch::invalid(
                            "the native source field has no adapter",
                        ));
                    }
                })
            })? {
                return Ok(false);
            }
        }
        for package in &graph.packages {
            if !self.append("correlation_packages", sink, |name, _kind, sink| {
                if let Some(value) = common(name, sink)? {
                    return Ok(value);
                }
                Ok(match name {
                    "package_id" => Self::text(Some(&package.package_id), sink)?,
                    "package_version" => ScalarValue::UInt64(Some(package.package_version)),
                    "required_inputs" => Self::json(&package.required_inputs, sink)?,
                    "state" => Self::text(
                        Some(match &package.state {
                            GraphPackageStateV1::Waiting => "waiting",
                            GraphPackageStateV1::NativeEffect => "native_effect",
                            GraphPackageStateV1::CredentialObserved => "credential_observed",
                            GraphPackageStateV1::AuthorityChannel => "authority_channel",
                            GraphPackageStateV1::DirectPivot => "direct_pivot",
                            GraphPackageStateV1::ContextualPivot => "contextual_pivot",
                            GraphPackageStateV1::Contradicted => "contradicted",
                            GraphPackageStateV1::CoverageInsufficient => "coverage_insufficient",
                            GraphPackageStateV1::KubernetesProofMissing => {
                                "kubernetes_proof_missing"
                            }
                            GraphPackageStateV1::KubernetesRequest => "kubernetes_request",
                            GraphPackageStateV1::KubernetesAudit => "kubernetes_audit",
                            GraphPackageStateV1::KubernetesObject => "kubernetes_object",
                            GraphPackageStateV1::KubernetesScheduled => "kubernetes_scheduled",
                            GraphPackageStateV1::RemoteAdmission => "remote_admission",
                            GraphPackageStateV1::Declared(value) => value,
                        }),
                        sink,
                    )?,
                    "maximum_lateness_ns" => ScalarValue::UInt64(Some(package.maximum_lateness_ns)),
                    "retention_ttl_ns" => ScalarValue::UInt64(Some(package.retention_ttl_ns)),
                    "clock_uncertainty_ns" => ScalarValue::UInt64(package.clock_uncertainty_ns),
                    "late_action" => Self::text(Some(&package.late_action), sink)?,
                    "window_ns" => ScalarValue::UInt64(Some(package.window_ns)),
                    "window_records" => ScalarValue::UInt64(Some(package.window_records)),
                    "window_bytes" => ScalarValue::UInt64(Some(
                        u64::try_from(package.window_bytes).map_err(|_| ArrowBatch::overflow())?,
                    )),
                    "coverage_predicate" => Self::text(Some(&package.coverage_predicate), sink)?,
                    "replay_contract_id" => Self::text(Some(&package.replay_contract_id), sink)?,
                    "result_states" => Self::json(&package.result_states, sink)?,
                    "accepted_cursor_watermark" => {
                        ScalarValue::UInt64(Some(package.accepted_cursor_watermark))
                    }
                    "observed_boottime_watermark_ns" => {
                        ScalarValue::UInt64(Some(package.observed_boottime_watermark_ns))
                    }
                    _ => {
                        return Err(ArrowBatch::invalid(
                            "the native source field has no adapter",
                        ));
                    }
                })
            })? {
                return Ok(false);
            }
        }
        self.append("graph_manifest", sink, |name, _kind, sink| {
            if let Some(value) = common(name, sink)? {
                return Ok(value);
            }
            Ok(match name {
                "first_cursor" => ScalarValue::UInt64(Some(graph.first_cursor)),
                "last_cursor" => ScalarValue::UInt64(Some(graph.last_cursor)),
                "previous_result_id" => Self::text(graph.previous_result_id.as_deref(), sink)?,
                "subject_count" => ScalarValue::UInt64(Some(
                    u64::try_from(subject_count).map_err(|_| ArrowBatch::overflow())?,
                )),
                "relationship_count" => ScalarValue::UInt64(Some(
                    u64::try_from(relationship_count).map_err(|_| ArrowBatch::overflow())?,
                )),
                "max_hops" => ScalarValue::UInt32(Some(0)),
                "hop_boundary" => ScalarValue::Boolean(Some(false)),
                _ => {
                    return Err(ArrowBatch::invalid(
                        "the native source field has no adapter",
                    ));
                }
            })
        })
    }

    fn graph_field(
        name: &str,
        graph: &GraphSnapshotV1,
        result_id: &str,
        revision: u64,
        sensitivity: ContextSensitivityV1,
        source_key: &[u8],
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<Option<ScalarValue>> {
        Ok(Some(match name {
            "tenant_id" => Self::binary(Some(&graph.scope.identity.tenant_id), sink)?,
            "source_key" => Self::binary(Some(source_key), sink)?,
            "graph_result_id" => Self::text(Some(result_id), sink)?,
            "commit_revision" => ScalarValue::UInt64(Some(revision)),
            "graph_revision" => Self::json(&graph.input_manifest, sink)?,
            "graph_sensitivity" => Self::text(Some(sensitivity.into()), sink)?,
            _ => return Ok(None),
        }))
    }
}
