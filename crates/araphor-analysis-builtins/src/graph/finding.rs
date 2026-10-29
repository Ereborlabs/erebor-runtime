use super::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

impl Computation {
    pub(super) fn finding(
        &mut self,
        row: u32,
        reason: &str,
        confirmed: bool,
        evidence: Vec<u32>,
        limits: Vec<String>,
    ) -> sdk::Result<()> {
        self.context_finding(row, None, reason, confirmed, evidence, limits)
    }

    pub(super) fn context_finding(
        &mut self,
        row: u32,
        context: Option<u32>,
        reason: &str,
        confirmed: bool,
        evidence: Vec<u32>,
        limits: Vec<String>,
    ) -> sdk::Result<()> {
        let package = self.detector.id();
        let reason_code = format!("{package}.{reason}");
        let value = FindingV1::resolve(
            package,
            FindingReasonV1::from_analysis_code(package, &reason_code)?,
            ReasonDetails {
                record: row,
                context,
                reason: reason.into(),
                confirmed,
                evidence,
                limits,
            },
            &self.records,
            &self.facts,
        )?;
        self.subject(row, context)?;
        let finding = Finding::from_finding(row, context, value, reason_code);
        let finding_id = finding.finding_id.clone();
        if let Some(previous) = self.findings.get(&finding_id) {
            if previous.reason_code == format!("{package}.CONTRADICTION")
                || previous.state == FindingStateV1::Confirmed
                    && finding.state != FindingStateV1::Confirmed
            {
                return Ok(());
            }
        }
        self.findings.insert(finding_id, finding);
        Ok(())
    }
}

impl FindingV1 {
    pub fn resolve(
        package: &str,
        reason: FindingReasonV1,
        details: ReasonDetails,
        records: &[Observation],
        facts: &[Fact],
    ) -> sdk::Result<Self> {
        if reason.analysis_code(package)? != format!("{package}.{}", details.reason) {
            return Err(Computation::invalid("graph reason code"));
        }
        let ReasonDetails {
            record: row,
            context,
            confirmed,
            mut evidence,
            mut limits,
            ..
        } = details;
        let seed = records
            .get(row as usize)
            .ok_or_else(|| Computation::invalid("graph finding record"))?;
        let subject = if let Some(index) = context {
            match facts.get(index as usize) {
                Some(Fact {
                    record,
                    value: FactValue::Context { subject, .. },
                    ..
                }) if *record == row => subject.clone(),
                _ => return Err(Computation::invalid("graph finding context")),
            }
        } else {
            seed.task_subject()
        };
        Computation::canonical(&mut evidence);
        for row in &evidence {
            records
                .get(*row as usize)
                .ok_or_else(|| Computation::invalid("graph record reference"))?;
        }
        evidence
            .sort_by(|left, right| records[*left as usize].id.cmp(&records[*right as usize].id));
        let mut provenance = Vec::new();
        let mut effects = Vec::new();
        let mut coverage = BTreeSet::new();
        let mut timestamps = Vec::new();
        let mut ids = Vec::with_capacity(evidence.len());
        for row in evidence {
            let record = &records[row as usize];
            ids.push(record.id.clone());
            coverage.insert(
                <[u8; 16]>::try_from(record.coverage_interval_id.as_slice())
                    .map_err(|_| Computation::invalid("finding coverage"))?,
            );
            timestamps.push(record.ingested_utc_ns);
            if matches!(
                reason,
                FindingReasonV1::OutsideAuthority
                    | FindingReasonV1::InMemoryOnly
                    | FindingReasonV1::PayloadUnobservable
            ) {
                continue;
            }
            effects.push(record.resolved_effect());
            let policies = record.policies(facts.iter().filter(|fact| fact.record == row));
            if policies.is_empty() {
                limits.push("POLICY_PROVENANCE_MISSING".into());
                provenance.push(PolicyObservationProvenanceV1 {
                    source: record.id.stream.clone(),
                    profile_generation_ref_id: record.profile_generation_ref_id.unwrap_or_default(),
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
            for policy in policies {
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
            }
        }
        provenance.sort();
        provenance.dedup();
        limits.sort();
        limits.dedup();
        let finding_id = Self::identity(package, &seed.id, &subject)?;
        Ok(Self {
            tenant_id: seed.id.stream.tenant_id,
            finding_id,
            package_id: package.into(),
            package_version: 1,
            subject_id: subject,
            state: if confirmed {
                FindingStateV1::Confirmed
            } else {
                FindingStateV1::CoverageInsufficient
            },
            window_start_utc_ns: timestamps.iter().copied().min().unwrap_or(0),
            window_end_utc_ns: timestamps.iter().copied().max().unwrap_or(0),
            evidence: ids,
            required_coverage_interval_ids: coverage.into_iter().collect(),
            policy_provenance: provenance,
            effects,
            severity: if matches!(
                reason,
                FindingReasonV1::UnexpectedEffect | FindingReasonV1::CredentialPivot
            ) {
                FindingSeverityV1::Critical
            } else {
                FindingSeverityV1::High
            },
            sensitivity: if facts
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
            reason,
        })
    }

    pub fn identity(
        package: &str,
        record: &crate::discovery::DiscoveryRecordIdV1,
        subject: &GraphSubjectKeyV1,
    ) -> sdk::Result<String> {
        let mut digest = Sha256::new();
        (package, record, subject)
            .serialize(&mut rmp_serde::Serializer::new(&mut digest))
            .map_err(|_| Computation::invalid("graph finding identity"))?;
        Ok(format!("{:x}", digest.finalize()))
    }
}
