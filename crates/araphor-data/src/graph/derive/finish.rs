use super::*;

impl GraphDerivation<'_> {
    pub(super) fn finish(mut self) -> Result<GraphSnapshotV1> {
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
