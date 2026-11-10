use super::super::model::{Attempt, Record};
use super::*;



impl Record {
    pub(in crate::analysis) fn check_graph_proof(
        &self,
        attempt: &Attempt,
        enabled: bool,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
        mut load: impl FnMut(
            &super::super::model::GraphProofSource,
            &mut dyn FnMut(usize, usize) -> Result<()>,
        ) -> Result<(
            crate::AnalysisSourceReceiptV1,
            Option<crate::CoverageReport>,
        )>,
    ) -> Result<()> {
        let Some(proof) = &self.graph_proof else {
            return Ok(());
        };
        if !enabled
            || proof.sources.is_empty()
            || proof
                .sources
                .windows(2)
                .any(|pair| (&pair[0].source, pair[0].cpu) >= (&pair[1].source, pair[1].cpu))
            || proof.coverage.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Code::Invalid.error("Graph proof order"));
        }
        for source in &proof.sources {
            charge(0, 0)?;
            if !source.source.valid()
                || source.source.tenant_id != attempt.capture.tenant
                || !attempt
                    .capture
                    .grant
                    .selection
                    .includes_source(&source.source)
                || !self.witnesses.iter().any(|witness| {
                    witness.identity
                        == crate::AnalysisStreamIdentityV1::Evidence(source.source.clone())
                })
                || source
                    .missing
                    .iter()
                    .any(|(first, last)| *first == 0 || last < first)
                || source.missing.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(Code::Denied.error("Graph proof source"));
            }
            let (receipt, body) = load(source, charge)?;
            let report = receipt.coverage_revision;
            if receipt.cpu_id != source.cpu || report != source.report {
                return Err(Code::Conflict.error("Graph proof source revision"));
            }
            if report != 0 && body.is_none() {
                return Err(Code::Missing.error("Graph proof coverage report"));
            }
            for key in proof
                .coverage
                .iter()
                .filter(|key| key.source == source.source && key.cpu_id == source.cpu)
            {
                charge(0, 0)?;
                let interval = body
                    .iter()
                    .flat_map(|body| &body.intervals)
                    .find(|interval| {
                        interval.source_epoch == source.source.source_epoch
                            && interval.interval_id.as_slice() == key.interval_id
                    })
                    .ok_or_else(|| Code::Denied.error("Graph proof coverage interval"))?;
                use crate::DiscoveryCoverageStateV1 as State;
                let valid = match key.state {
                    State::Healthy => {
                        interval.is_complete() && !interval.has_gap() && interval.state != "CLOSED"
                    }
                    State::Closed => {
                        interval.is_complete() && !interval.has_gap() && interval.state == "CLOSED"
                    }
                    State::Gapped => interval.has_gap(),
                    State::Unknown => true,
                };
                let mut reasons = if !interval.gap_reasons.is_empty() {
                    interval.gap_reasons.clone()
                } else if interval.has_gap() {
                    vec!["SOURCE_COVERAGE_GAPPED".into()]
                } else if key.state == State::Unknown {
                    vec!["COVERAGE_UNQUALIFIED".into()]
                } else {
                    Vec::new()
                };
                reasons.sort();
                reasons.dedup();
                if key.report_revision != report
                    || key.interval_revision != interval.revision
                    || !valid
                    || key.gap_reasons != reasons
                {
                    return Err(Code::Denied.error("Graph proof coverage authority"));
                }
            }
        }
        if proof.coverage.iter().any(|key| {
            !proof
                .sources
                .iter()
                .any(|source| source.source == key.source && source.cpu == key.cpu_id)
        }) {
            return Err(Code::Denied.error("Graph proof coverage source"));
        }
        Ok(())
    }
}
