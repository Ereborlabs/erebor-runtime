

use super::*;





impl AnalysisExtractionV1 {
    pub(in crate::analysis) fn capture_graph(
        &mut self,
        id: &str,
        graph: &crate::GraphSnapshotV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let mut coverage = sdk::Coverage {
            state: sdk::CoverageState::Complete,
            limits: Vec::new(),
        };
        {
            let mut budget = self.sink(control);
            if graph.input_manifest.coverage.is_empty() {
                coverage.state = sdk::CoverageState::Unknown;
            }
            for range in &graph.input_manifest.coverage {
                budget.check()?;
                match range.state {
                    crate::DiscoveryCoverageStateV1::Gapped => {
                        coverage.state = sdk::CoverageState::Gapped
                    }
                    crate::DiscoveryCoverageStateV1::Unknown
                        if coverage.state != sdk::CoverageState::Gapped =>
                    {
                        coverage.state = sdk::CoverageState::Unknown
                    }
                    _ => {}
                }
                for reason in &range.gap_reasons {
                    if coverage.limits.contains(reason) {
                        continue;
                    }
                    budget.grow(&mut coverage.limits)?;
                    budget.charge(reason.len())?;
                    coverage.limits.push(reason.clone());
                }
            }
            if !graph.missing_ranges.is_empty() {
                coverage.state = sdk::CoverageState::Gapped;
                let reason = "GRAPH_INPUT_GAPS";
                if !coverage.limits.iter().any(|limit| limit == reason) {
                    budget.grow(&mut coverage.limits)?;
                    budget.charge(reason.len())?;
                    coverage.limits.push(reason.into());
                }
            }
        }
        coverage.limits.sort_unstable();
        self.charge(id.len())?;
        let added = Self::grow(
            &mut self.graph_coverage,
            self.input_bytes,
            self.limits.input_bytes,
        )?;
        self.charge(added)?;
        self.graph_coverage.push((id.into(), coverage));
        Ok(())
    }
}




