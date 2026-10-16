use std::collections::BTreeSet;

use prost::Message as _;
use snafu::ResultExt as _;

use super::*;
use crate::{AnalysisSourceStatusV1, CoverageReport};

impl GraphAndFindingOwner {
    pub(super) fn coverage(
        &self,
        status: &AnalysisSourceStatusV1,
        records: &[crate::DiscoveryRecordV1],
        frozen: &[GraphCoverageKeyV1],
    ) -> Result<(Vec<crate::DiscoveryCoverageV1>, Vec<GraphCoverageKeyV1>)> {
        let mut ranges = Vec::new();
        let mut keys = Vec::new();
        let intervals: BTreeSet<_> = records
            .iter()
            .filter_map(|record| {
                record
                    .decode()
                    .ok()
                    .and_then(|wire| <[u8; 16]>::try_from(wire.coverage_interval_id.as_ref()).ok())
            })
            .collect();
        let revisions = frozen
            .iter()
            .filter(|key| {
                key.source == status.receipt.identity && intervals.contains(&key.interval_id)
            })
            .map(|key| key.report_revision)
            .collect();
        for (revision, bytes) in self
            .store
            .graph_coverage_versions(&status.receipt.identity, &revisions)?
        {
            let report =
                CoverageReport::decode(bytes.as_slice()).context(crate::EvidenceDecodeSnafu {
                    frame_bytes: bytes.len(),
                })?;
            if !report.intervals.iter().any(|interval| {
                <[u8; 16]>::try_from(interval.interval_id.as_slice())
                    .is_ok_and(|id| intervals.contains(&id))
            }) {
                continue;
            }
            let mut version = status.clone();
            version.receipt.coverage_revision = revision;
            version.latest_coverage_report = Some(bytes);
            let qualified = crate::DiscoveryOwner::coverage(&version, records)?;
            for range in &qualified {
                let interval_revision = report
                    .intervals
                    .iter()
                    .find(|interval| interval.interval_id.as_ref() == range.coverage_interval_id)
                    .map_or(0, |interval| interval.revision);
                let mut gaps = range.gap_reasons.clone();
                gaps.sort();
                gaps.dedup();
                keys.push(GraphCoverageKeyV1 {
                    source: status.receipt.identity.clone(),
                    cpu_id: range.cpu_id,
                    report_revision: revision,
                    interval_id: range.coverage_interval_id,
                    interval_revision,
                    state: range.state,
                    gap_reasons: gaps,
                });
            }
            ranges.extend(qualified);
        }
        if ranges.is_empty() {
            ranges = crate::DiscoveryOwner::coverage(status, records)?;
        }
        Ok((ranges, keys))
    }
}
