use super::*;

impl GraphDerivation<'_> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finding(
        &mut self,
        package: &str,
        seed: &DiscoveryRecordV1,
        subject: GraphSubjectKeyV1,
        reason: FindingReasonV1,
        state: FindingStateV1,
        evidence: Vec<DiscoveryRecordIdV1>,
        mut limits: Vec<String>,
    ) -> Result<()> {
        let mut evidence = evidence;
        evidence.sort();
        evidence.dedup();
        let mut provenance = Vec::new();
        let mut effects = Vec::new();
        let mut coverage = BTreeSet::new();
        let mut timestamps = Vec::new();
        for id in &evidence {
            let record = self
                .input
                .records
                .iter()
                .find(|record| &record.id == id)
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "finding evidence",
                    }
                    .build()
                })?;
            let wire = record.decode()?;
            coverage.insert(
                <[u8; 16]>::try_from(wire.coverage_interval_id.as_ref()).map_err(|_| {
                    GraphInvalidSnafu {
                        field: "finding coverage",
                    }
                    .build()
                })?,
            );
            timestamps.push(wire.ingested_utc_ns);
            if matches!(
                reason,
                FindingReasonV1::OutsideAuthority
                    | FindingReasonV1::InMemoryOnly
                    | FindingReasonV1::PayloadUnobservable
            ) {
                continue;
            }
            effects.push(self.effect(record, &wire));
            let mut joined = false;
            for policy in self.policies(record) {
                limits.extend(policy.limits.iter().cloned());
                match policy.state {
                    PolicyProvenanceStateV1::Missing => {
                        limits.push("POLICY_PROVENANCE_MISSING".into())
                    }
                    PolicyProvenanceStateV1::Contradicted => {
                        limits.push("POLICY_PROVENANCE_CONTRADICTED".into())
                    }
                    PolicyProvenanceStateV1::Exact => {}
                }
                provenance.push(policy);
                joined = true;
            }
            if !joined {
                limits.push("POLICY_PROVENANCE_MISSING".into());
                provenance.push(PolicyObservationProvenanceV1 {
                    source: record.id.stream.clone(),
                    profile_generation_ref_id: wire.profile_generation_ref_id.unwrap_or_default(),
                    observations: vec![record.id.clone()],
                    policy_source_revision_id: None,
                    candidate_content_id: None,
                    target_snapshot_digest: None,
                    node_bound_generation_digest: None,
                    activation_acknowledgement: None,
                    state: PolicyProvenanceStateV1::Missing,
                    limits: vec!["ACTIVATION_ACKNOWLEDGEMENT_MISSING".into()],
                });
            }
        }
        provenance.sort();
        provenance.dedup();
        limits.sort();
        limits.dedup();
        let finding_id =
            serde_json::to_string(&(package, &seed.id, &subject)).context(GraphEncodingSnafu)?;
        let finding = FindingV1 {
            tenant_id: self.input.source.tenant_id,
            finding_id: finding_id.clone(),
            revision: self.revision.clone(),
            package_id: package.into(),
            package_version: 1,
            subject_id: subject,
            state,
            window_start_utc_ns: timestamps.iter().copied().min().unwrap_or(0),
            window_end_utc_ns: timestamps.iter().copied().max().unwrap_or(0),
            evidence,
            required_coverage_interval_ids: coverage.into_iter().collect(),
            policy_provenance: provenance,
            effects,
            reason,
            severity: if matches!(
                reason,
                FindingReasonV1::UnexpectedEffect | FindingReasonV1::CredentialPivot
            ) {
                FindingSeverityV1::Critical
            } else {
                FindingSeverityV1::High
            },
            sensitivity: if self
                .input
                .facts
                .iter()
                .any(|fact| fact.sensitivity == ContextSensitivityV1::HostRestricted)
            {
                ContextSensitivityV1::HostRestricted
            } else {
                ContextSensitivityV1::Tenant
            },
            required_action: Some(
                match reason {
                    FindingReasonV1::UnexpectedEffect => "inspect-denied-effect",
                    FindingReasonV1::AuditedRoleDeviation => "review-role-deviation",
                    FindingReasonV1::CredentialPivot => "investigate-credential-pivot",
                    FindingReasonV1::ContextualCredentialPivot => {
                        "review-contextual-authority-hypothesis"
                    }
                    FindingReasonV1::Contradiction => "resolve-contradiction",
                    _ => "resolve-missing-proof",
                }
                .into(),
            ),
            limits,
        };
        finding.validate()?;
        if let Some(previous) = self.findings.get(&finding_id) {
            if previous.reason == FindingReasonV1::Contradiction
                || (previous.state == FindingStateV1::Confirmed
                    && finding.state != FindingStateV1::Confirmed)
            {
                return Ok(());
            }
        }
        self.findings.insert(finding_id, finding);
        Ok(())
    }
}
