use super::*;
use crate::AnalysisContextRefV1;

impl SourceEvidence {
    pub(in crate::analysis) fn check_proofs(
        evidence: (
            &[crate::AnalysisWitnessV1],
            &[AnalysisContextRefV1],
            &[(crate::DiscoveryRecordIdV1, AnalysisContextRefV1)],
        ),
        mut receipt: impl FnMut(&crate::DiscoveryRecordIdV1) -> Result<()>,
    ) -> Result<()> {
        let (witnesses, derived, proofs) = evidence;
        let mut seen = BTreeSet::new();
        for (id, reference) in proofs {
            if id.durable_cursor == 0
                || id.stream.tenant_id != reference.key.tenant_id
                || witnesses
                    .binary_search_by(|witness| match &witness.identity {
                        crate::AnalysisStreamIdentityV1::Evidence(source) => {
                            (source, witness.cursor).cmp(&(&id.stream, id.durable_cursor))
                        }
                        crate::AnalysisStreamIdentityV1::Diagnostic(_) => {
                            std::cmp::Ordering::Greater
                        }
                    })
                    .is_err()
                || derived
                    .binary_search_by(|value| value.key.cmp(&reference.key))
                    .ok()
                    .is_none_or(|index| derived[index] != *reference)
            {
                return Err(Code::Invalid.error("source record proof authority"));
            }
            if !seen.insert((id, &reference.key)) {
                return Err(Code::Invalid.error("duplicate source record proof"));
            }
            receipt(id)?;
        }
        Ok(())
    }
}


