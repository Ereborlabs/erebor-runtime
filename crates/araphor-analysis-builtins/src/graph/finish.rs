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
    pub(super) fn output(mut self) -> sdk::Result<sdk::Output> {
        let record_ids = self
            .records
            .iter()
            .map(|record| record.id.clone())
            .collect::<Vec<_>>();
        let subject_keys = self
            .subjects
            .iter()
            .map(|subject| subject.key.clone())
            .collect::<Vec<_>>();
        let mut subjects = BTreeMap::new();
        for subject in self.subjects {
            let anchor =
                Anchor::from_positions(subject.record, subject.context, &record_ids, &self.facts)?;
            let key = subject.key.clone();
            if subjects
                .insert(key.clone(), SubjectChange { anchor, key })
                .is_some()
            {
                return Err(Self::invalid("graph subject identity"));
            }
        }
        let mut subject_additions = Vec::new();
        let mut subject_removals = Vec::new();
        for (key, current) in subjects {
            match self.prior_subjects.remove(&key) {
                Some(old) if old == current => {}
                Some(_) => {
                    subject_removals.push(SubjectRemoval { key });
                    subject_additions.push(current);
                }
                None => subject_additions.push(current),
            }
        }
        subject_removals.extend(
            self.prior_subjects
                .into_keys()
                .map(|key| SubjectRemoval { key }),
        );
        subject_removals.sort_by(|left, right| left.key.cmp(&right.key));

        let mut edges = BTreeMap::new();
        for row in self.edges.into_values() {
            let key = RelationshipIdentity::from_keys(&row.edge.key, &subject_keys, &record_ids)?;
            let change = RelationshipChange {
                anchor: Anchor::from_positions(row.record, row.fact, &record_ids, &self.facts)?,
                key: key.clone(),
                proof_quality: row.edge.proof_quality,
                required_coverage_interval_ids: row.edge.required_coverage_interval_ids,
                first_boottime_ns: row.edge.first_boottime_ns,
                last_boottime_ns: row.edge.last_boottime_ns,
            };
            if edges.insert(key, change).is_some() {
                return Err(Self::invalid("graph relationship identity"));
            }
        }
        let mut edge_additions = Vec::new();
        let mut edge_removals = Vec::new();
        for (key, current) in edges {
            match self.prior_edges.remove(&key) {
                Some(old) if old == current => {}
                Some(_) => {
                    edge_removals.push(RelationshipRemoval { key });
                    edge_additions.push(current);
                }
                None => edge_additions.push(current),
            }
        }
        edge_removals.extend(
            self.prior_edges
                .into_keys()
                .map(|key| RelationshipRemoval { key }),
        );
        edge_removals.sort_by(|left, right| left.key.cmp(&right.key));

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
        let state = GraphPackageStateV1::from_marker(&self.state)?;
        let mut prior = std::mem::take(&mut self.prior_findings);
        let mut removed = Vec::new();
        let mut changed = Vec::new();
        let mut finding_additions = Vec::new();
        for finding in &findings {
            let reason =
                FindingReasonV1::from_analysis_code(&finding.package_id, &finding.reason_code)?;
            let current = finding.clone().into_finding(reason);
            let anchor =
                Anchor::from_positions(finding.record, finding.context, &record_ids, &self.facts)?;
            match prior.remove(&finding.finding_id) {
                Some(old) if old.0 == current && old.1 == anchor => {}
                Some(_) => {
                    removed.push(FindingRemoval {
                        finding_id: finding.finding_id.clone(),
                    });
                    changed.push(finding.clone());
                    finding_additions.push(FindingChange::from_local(finding.clone(), anchor));
                }
                None => {
                    changed.push(finding.clone());
                    finding_additions.push(FindingChange::from_local(finding.clone(), anchor));
                }
            }
        }
        removed.extend(
            prior
                .into_keys()
                .map(|finding_id| FindingRemoval { finding_id }),
        );
        removed.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
        let mut progress_additions = Vec::new();
        let mut progress_removals = Vec::new();
        for progress in self.progress {
            match self.prior_progress.remove(&progress.record) {
                Some(old) if old == progress => {}
                Some(_) => {
                    progress_removals.push(ProgressRemoval {
                        record: progress.record.clone(),
                    });
                    progress_additions.push(progress);
                }
                None => progress_additions.push(progress),
            }
        }
        progress_removals.extend(
            self.prior_progress
                .into_keys()
                .map(|record| ProgressRemoval { record }),
        );
        progress_additions.sort_by(|left, right| left.record.cmp(&right.record));
        progress_removals.sort_by(|left, right| left.record.cmp(&right.record));
        let mut output = sdk::Output {
            datasets: vec![
                SubjectChange::encode(&subject_additions)?,
                SubjectRemoval::encode(&subject_removals)?,
                RelationshipChange::encode(&edge_additions)?,
                RelationshipRemoval::encode(&edge_removals)?,
                FindingChange::encode(&finding_additions)?,
                FindingRemoval::encode(&removed)?,
                Progress::encode(&progress_additions)?,
                ProgressRemoval::encode(&progress_removals)?,
            ],
            ..Default::default()
        };
        let record_rows = record_ids
            .iter()
            .enumerate()
            .map(|(row, id)| (id, row as u32))
            .collect();
        for (row, finding) in changed.iter().enumerate() {
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
            datasets: vec![GraphPackageStateV1::encode(&[state])?],
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
        Self::from_parts(
            &finding.package_id,
            &finding.subject_id,
            &finding.evidence,
            &finding.limits,
            reason,
        )
    }

    pub fn from_value(finding: &FindingV1) -> Self {
        Self::from_parts(
            &finding.package_id,
            &finding.subject_id,
            &finding.evidence,
            &finding.limits,
            &finding.reason,
        )
    }

    fn from_parts(
        package_id: &str,
        subject_id: &GraphSubjectKeyV1,
        evidence: &[crate::discovery::DiscoveryRecordIdV1],
        limits: &[String],
        reason: &FindingReasonV1,
    ) -> Self {
        Self {
            package_id: package_id.into(),
            seed: subject_id.clone(),
            evidence: evidence.to_vec(),
            state: if matches!(reason, FindingReasonV1::OutsideAuthority) {
                GraphBranchStateV1::OutsideAuthority
            } else if limits.iter().any(|limit| {
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
            missing_fields: limits.to_vec(),
        }
    }
}
