use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::managed::Record;
use crate :: { AnalysisContextRefV1 , AnalysisWitnessV1 , DiscoveryRecordIdV1 , GraphRevisionV1 , PackageErrorCodeV1 as Code , Result } ;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::analysis) struct FindingOrigin {
    pub result: String,
    pub revision: u64,
    pub relation: u64,
    pub writer: u64,
    pub owner: Vec<u8>,
    pub key: Vec<u8>,
}

#[derive(Default)]
pub(in crate::analysis) struct FindingBasis {
    visited: BTreeMap<FindingOrigin, BTreeSet<DiscoveryRecordIdV1>>,
    witnesses: BTreeMap<(crate::AnalysisStreamIdentityV1, u64), AnalysisWitnessV1>,
    coverage: BTreeSet<crate::GraphCoverageKeyV1>,
    qualified: BTreeSet<DiscoveryRecordIdV1>,
    gaps: BTreeSet<(u64, u64)>,
    contexts: BTreeMap<crate::AnalysisContextKeyV1, AnalysisContextRefV1>,
}

impl FindingBasis {
    pub fn visit(&mut self, owner: &FindingOrigin, records: &mut BTreeSet<DiscoveryRecordIdV1>) {
        let known = self.visited.entry(owner.clone()).or_default();
        records.retain(|record| known.insert(record.clone()));
    }

    pub fn observe(
        &mut self,
        records: &BTreeSet<DiscoveryRecordIdV1>,
        producer: &Record,
    ) -> BTreeSet<DiscoveryRecordIdV1> {
        if let Some(proof) = &producer.graph_proof {
            for key in &proof.coverage {
                if records
                    .iter()
                    .any(|record| record.stream == key.source && record.cpu_id == key.cpu_id)
                {
                    self.coverage.insert(key.clone());
                }
            }
            for source in &proof.sources {
                if records
                    .iter()
                    .any(|record| record.stream == source.source && record.cpu_id == source.cpu)
                {
                    self.gaps.extend(source.missing.iter().copied());
                    self.qualified.extend(
                        records
                            .iter()
                            .filter(|record| {
                                record.stream == source.source && record.cpu_id == source.cpu
                            })
                            .cloned(),
                    );
                }
            }
        }
        let mut missing = records
            .iter()
            .map(|record| {
                (
                    crate::AnalysisStreamIdentityV1::Evidence(record.stream.clone()),
                    record.durable_cursor,
                )
            })
            .collect::<BTreeSet<_>>();
        for witness in &producer.witnesses {
            let key = (witness.identity.clone(), witness.cursor);
            if !missing.remove(&key) {
                continue;
            }
            let value = self.witnesses.entry(key).or_insert_with(|| witness.clone());
            value.expires_utc_ns = value.expires_utc_ns.min(witness.expires_utc_ns);
        }
        records
            .iter()
            .filter(|record| {
                missing.contains(&(
                    crate::AnalysisStreamIdentityV1::Evidence(record.stream.clone()),
                    record.durable_cursor,
                ))
            })
            .cloned()
            .collect()
    }

    pub fn parents(
        &mut self,
        owners: &mut BTreeMap<FindingOrigin, BTreeSet<DiscoveryRecordIdV1>>,
        mut uncovered: BTreeSet<DiscoveryRecordIdV1>,
        parents: Vec<(FindingOrigin, BTreeSet<DiscoveryRecordIdV1>)>,
    ) -> Result<()> {
        for (parent, records) in parents {
            for record in &records {
                uncovered.remove(record);
            }
            owners.entry(parent).or_default().extend(records);
        }
        if !uncovered.is_empty() {
            return Err(Code::Denied.error("native finding origin witness"));
        }
        Ok(())
    }

    pub fn context(
        &mut self,
        value: &AnalysisContextRefV1,
        records: &BTreeSet<DiscoveryRecordIdV1>,
        proofs: &[(DiscoveryRecordIdV1, AnalysisContextRefV1)],
        mut associated: bool,
        mut matched: bool,
    ) -> Result<()> {
        for (proof, context) in proofs {
            if context == value {
                associated = true;
                matched |= records.contains(proof);
            }
        }
        if associated && !matched {
            return Ok(());
        }
        if self
            .contexts
            .insert(value.key.clone(), value.clone())
            .is_some_and(|prior| prior != *value)
        {
            return Err(Code::Conflict.error("native finding context revision"));
        }
        Ok(())
    }

    pub fn finish(
        self,
        tenant: [u8; 16],
        evidence: Vec<DiscoveryRecordIdV1>,
        require_proof: bool,
    ) -> Result<(
        Vec<AnalysisWitnessV1>,
        Vec<AnalysisContextRefV1>,
        GraphRevisionV1,
    )> {
        if require_proof
            && evidence
                .iter()
                .any(|record| !self.qualified.contains(record))
        {
            return Err(Code::Missing.error("native finding coverage proof"));
        }
        let contexts = self.contexts.into_values().collect::<Vec<_>>();
        let revision = GraphRevisionV1 {
            evidence,
            coverage: self.coverage.into_iter().collect(),
            context: contexts.iter().map(|value| value.key.clone()).collect(),
            missing_ranges: self.gaps.into_iter().collect(),
        };
        revision.validate(tenant)?;
        Ok((self.witnesses.into_values().collect(), contexts, revision))
    }
}
