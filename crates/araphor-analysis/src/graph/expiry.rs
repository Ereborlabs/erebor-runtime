use super::*;

impl Graph<'_> {
    pub fn expire(
        previous: &GraphSnapshotV1,
        result_id: &str,
        notice: u64,
    ) -> Result<GraphSnapshotV1> {
        previous.validate()?;
        let mut snapshot = previous.clone();
        snapshot.previous_result_id = Some(result_id.into());
        snapshot.context_notice_revision = notice;
        snapshot
            .missing_ranges
            .push((previous.first_cursor, previous.last_cursor));
        snapshot.missing_ranges.sort();
        snapshot.missing_ranges.dedup();
        snapshot.input_manifest.missing_ranges = snapshot.missing_ranges.clone();
        Self::expire_graph(&mut snapshot);
        Self::expire_findings(&mut snapshot);
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn expire_graph(snapshot: &mut GraphSnapshotV1) {
        for edge in &mut snapshot.graph.edges {
            edge.proof_quality.temporal_coverage = TemporalCoverageV1::Unknown;
            edge.key.cause = GraphCauseV1::Superseded;
        }
        snapshot
            .graph
            .edges
            .sort_by(|left, right| left.key.cmp(&right.key));
        snapshot
            .graph
            .edges
            .dedup_by(|left, right| left.key == right.key);
        for branch in &mut snapshot.graph.branches {
            branch.state = GraphBranchStateV1::CoverageUnknown;
            branch.missing_fields.push("RETAINED_INPUT_EXPIRED".into());
            branch.missing_fields.sort();
            branch.missing_fields.dedup();
        }
    }

    fn expire_findings(snapshot: &mut GraphSnapshotV1) {
        for finding in &mut snapshot.findings {
            finding.state = FindingStateV1::CoverageInsufficient;
            finding.limits.push("RETAINED_INPUT_EXPIRED".into());
            finding
                .limits
                .push("LATE_EVIDENCE_UNSUPPORTED_AFTER_RETENTION".into());
            finding.limits.sort();
            finding.limits.dedup();
            for effect in &mut finding.effects {
                effect.proof_quality.temporal_coverage = TemporalCoverageV1::Unknown;
            }
        }
        for package in &mut snapshot.packages {
            package.state = GraphPackageStateV1::CoverageInsufficient;
        }
    }
}
