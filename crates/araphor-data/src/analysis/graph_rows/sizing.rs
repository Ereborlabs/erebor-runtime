use serde::Serialize;
use snafu::ResultExt as _;

use super::GraphRows;
use crate::{GraphEncodingSnafu, GraphInvalidSnafu, GraphSnapshotV1, Result};

impl GraphRows {
    fn json_bytes(value: &impl Serialize) -> Result<usize> {
        let mut remaining = crate::discovery::InputByteLimit(usize::MAX);
        serde_json::to_writer(&mut remaining, value).context(GraphEncodingSnafu)?;
        Ok(usize::MAX - remaining.0)
    }

    pub(super) fn row_bytes(snapshot: &GraphSnapshotV1) -> Result<usize> {
        let mut bytes = 0usize;
        let mut add = |length: usize| -> Result<()> {
            bytes = bytes.checked_add(length).ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph storage byte bound",
                }
                .build()
            })?;
            Ok(())
        };
        for subject in &snapshot.graph.subjects {
            add(subject.tenant_id.len())?;
            add(Self::label(&subject.kind)?.len())?;
            add(Self::json_bytes(&subject.authority)?)?;
            add(subject.identity.len())?;
        }
        for edge in &snapshot.graph.edges {
            add(Self::label(&edge.key.edge_type)?.len())?;
            add(edge.key.package_id.len())?;
            add(Self::label(&edge.key.cause)?.len())?;
            add(edge
                .key
                .evidence
                .len()
                .checked_mul(size_of::<u32>())
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph storage byte bound",
                    }
                    .build()
                })?)?;
            add(edge
                .required_coverage_interval_ids
                .len()
                .checked_mul(16)
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph storage byte bound",
                    }
                    .build()
                })?)?;
        }
        for finding in &snapshot.findings {
            add(finding.tenant_id.len())?;
            add(finding.finding_id.len())?;
            add(finding.package_id.len())?;
            add(Self::json_bytes(&finding.subject_id)?)?;
            add(Self::label(&finding.state)?.len())?;
            add(Self::json_bytes(&finding.evidence)?)?;
            add(Self::json_bytes(&finding.required_coverage_interval_ids)?)?;
            add(Self::json_bytes(&finding.policy_provenance)?)?;
            add(Self::json_bytes(&finding.effects)?)?;
            add(finding.reason.storage()?.len())?;
            add(Self::label(&finding.severity)?.len())?;
            add(<&str>::from(finding.sensitivity).len())?;
            add(finding.required_action.as_ref().map_or(0, String::len))?;
            add(Self::json_bytes(&finding.limits)?)?;
        }
        Ok(bytes)
    }
}
