use super::*;

impl Detector {
    fn required_inputs(self) -> &'static [&'static str] {
        match self {
            Self::Process => &["exact-task-entry-role", "kernel-effect", "source-coverage"],
            Self::Credentials => &[
                "reviewed-credential",
                "exact-local-channel",
                "authoritative-operation",
                "source-coverage",
            ],
            Self::Kubernetes => &[
                "carried-request-proof",
                "Kubernetes-audit",
                "object-owner-scheduler",
                "remote-runtime-admission",
            ],
        }
    }
}

impl GraphPackageCheckpointV1 {
    pub fn from_package(
        package: &sdk::Package,
        model: &sdk::Model,
        state: GraphPackageStateV1,
        accepted: u64,
        observed: u64,
    ) -> Self {
        Self {
            package_id: package.id.clone(),
            package_version: 1,
            required_inputs: Detector::from_id(&package.id).map_or_else(
                |_| {
                    model
                        .inputs
                        .iter()
                        .map(|input| input.port.name.clone())
                        .collect()
                },
                |detector| {
                    detector
                        .required_inputs()
                        .iter()
                        .map(|value| (*value).into())
                        .collect()
                },
            ),
            state,
            maximum_lateness_ns: GRAPH_WITNESS_TTL_NS,
            retention_ttl_ns: GRAPH_WITNESS_TTL_NS,
            clock_uncertainty_ns: None,
            late_action: "append-exact-revision-or-report-expired-input".into(),
            window_ns: GRAPH_WINDOW_NS,
            coverage_predicate:
                "complete-required-source-intervals-and-qualified-operation-results".into(),
            replay_contract_id: format!("{}/v{}", package.id, package.revision),
            result_states: vec![
                FindingStateV1::Provisional,
                FindingStateV1::Confirmed,
                FindingStateV1::Superseded,
                FindingStateV1::Retracted,
                FindingStateV1::CoverageInsufficient,
            ],
            accepted_cursor_watermark: accepted,
            observed_boottime_watermark_ns: observed,
        }
    }
}

impl Computation {
    pub(super) fn output(mut self, package: &sdk::Package) -> sdk::Result<sdk::Output> {
        let mut remap = vec![0; self.subjects.len()];
        self.subjects
            .sort_by(|left, right| left.key.cmp(&right.key));
        for (index, subject) in self.subjects.iter().enumerate() {
            remap[self.subject_indices[&subject.key] as usize] = index as u32;
        }
        let mut edges: Vec<_> = self
            .edges
            .into_values()
            .map(|mut row| {
                row.edge.key.from = remap[row.edge.key.from as usize];
                row.edge.key.to = remap[row.edge.key.to as usize];
                row
            })
            .collect();
        edges.sort_by(|left, right| left.edge.key.cmp(&right.edge.key));
        let sensitivity = if self
            .facts
            .iter()
            .any(|fact| fact.sensitivity == ContextSensitivityV1::HostRestricted)
        {
            ContextSensitivityV1::HostRestricted
        } else {
            ContextSensitivityV1::Tenant
        };
        let findings: Vec<_> = self
            .findings
            .into_values()
            .map(|mut finding| {
                finding.sensitivity = sensitivity;
                finding
            })
            .collect();
        let mut branches: Vec<_> = findings
            .iter()
            .map(|finding| {
                let reason =
                    FindingReasonV1::from_analysis_code(&finding.package_id, &finding.reason_code)?;
                Ok(GraphBranchV1::from_finding(finding, &reason))
            })
            .collect::<sdk::Result<_>>()?;
        branches.sort_by(|left, right| {
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
        branches.dedup();
        let state = GraphPackageStateV1::from_marker(&self.state)?;
        let metadata = Metadata {
            record_ids: self
                .records
                .iter()
                .map(|record| record.id.clone())
                .collect(),
            facts: self.facts,
            package: GraphPackageCheckpointV1::from_package(
                package,
                &package.exports[0],
                state,
                self.records
                    .last()
                    .map_or(0, |record| record.id.durable_cursor),
                self.records
                    .iter()
                    .map(|record| record.observed_boottime_ns)
                    .max()
                    .unwrap_or(0),
            ),
        };
        let mut output = sdk::Output {
            datasets: vec![
                Subject::encode(&self.subjects)?,
                Relationship::encode(&edges)?,
                Finding::encode(&findings)?,
                GraphBranchV1::encode(&branches)?,
                Metadata::encode(std::slice::from_ref(&metadata))?,
            ],
            ..Default::default()
        };
        let record_rows = metadata
            .record_ids
            .iter()
            .enumerate()
            .map(|(row, id)| (id, row as u32))
            .collect();
        for (row, finding) in findings.iter().enumerate() {
            let reference = sdk::RowRef {
                dataset: "findings".into(),
                row: row as u64,
            };
            let details = ReasonDetails::from_finding(finding, &record_rows)?;
            for record in &details.evidence {
                output.evidence.push(sdk::EvidenceLink {
                    output: reference.clone(),
                    input: sdk::RowRef {
                        dataset: "records".into(),
                        row: u64::from(*record),
                    },
                });
            }
            output.reasons.push(sdk::ReasonValue {
                output: reference,
                code: finding.reason_code.clone(),
                details: ReasonDetails::encode(&[details])?.batches.remove(0),
            });
        }
        output.checkpoint = Some(sdk::Checkpoint {
            version: 1,
            datasets: vec![
                GraphPackageStateV1::encode(std::slice::from_ref(&metadata.package.state))?,
                Progress::encode(&self.progress)?,
            ],
        });
        Ok(output)
    }

    pub(super) fn canonical(evidence: &mut Vec<u32>) {
        evidence.sort_unstable();
        evidence.dedup();
    }
}

impl GraphBranchV1 {
    pub fn from_finding(finding: &Finding, reason: &FindingReasonV1) -> Self {
        Self {
            package_id: finding.package_id.clone(),
            seed: finding.subject_id.clone(),
            evidence: finding.evidence.clone(),
            state: if matches!(reason, FindingReasonV1::OutsideAuthority) {
                GraphBranchStateV1::OutsideAuthority
            } else if finding.limits.iter().any(|limit| {
                limit.contains("COVERAGE")
                    || limit.contains("MISSING")
                    || limit.contains("UNAVAILABLE")
            }) {
                GraphBranchStateV1::CoverageUnknown
            } else if matches!(reason, FindingReasonV1::ContextualCredentialPivot) {
                GraphBranchStateV1::ContextualOnly
            } else {
                GraphBranchStateV1::Open
            },
            missing_fields: finding.limits.clone(),
        }
    }
}
