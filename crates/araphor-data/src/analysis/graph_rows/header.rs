use minicbor::{Decoder, Encoder};
use serde::{Deserialize, Serialize};

use crate::{
    AnalysisContextKeyV1, GraphBranchV1, GraphCoverageKeyV1, GraphFactV1, GraphInvalidSnafu,
    GraphPackageCheckpointV1, GraphRevisionV1, GraphSnapshotV1, GraphVersionV1, ProcessorScopeV1,
    Result,
};

pub(in crate::analysis) struct GraphHeader {
    pub(in crate::analysis) snapshot: GraphSnapshotV1,
    pub(in crate::analysis) subject_count: usize,
    pub(in crate::analysis) edge_count: usize,
    pub(in crate::analysis) finding_count: usize,
    pub(in crate::analysis) evidence_count: usize,
    pub(in crate::analysis) position_count: usize,
    pub(in crate::analysis) notice: (u64, u64),
}

impl GraphHeader {
    pub(super) fn encode(snapshot: &GraphSnapshotV1) -> Result<Vec<u8>> {
        Self::encode_with_finding_count(snapshot, snapshot.findings.len())
    }

    pub(super) fn encode_with_finding_count(
        snapshot: &GraphSnapshotV1,
        finding_count: usize,
    ) -> Result<Vec<u8>> {
        let subjects = u32::try_from(snapshot.graph.subjects.len()).map_err(Self::error)?;
        let edges = u32::try_from(snapshot.graph.edges.len()).map_err(Self::error)?;
        let findings = u32::try_from(finding_count).map_err(Self::error)?;
        let metadata = HeaderMetadata::try_from(snapshot)?;
        let mut metadata_bytes = Vec::new();
        let mut serializer = rmp_serde::Serializer::new(&mut metadata_bytes)
            .with_struct_map()
            .with_bytes(rmp_serde::config::BytesMode::ForceIterables);
        metadata.serialize(&mut serializer).map_err(Self::error)?;
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .array(5)
            .and_then(|e| e.u32(2))
            .and_then(|e| e.u32(subjects))
            .and_then(|e| e.u32(edges))
            .and_then(|e| e.u32(findings))
            .and_then(|e| e.bytes(&metadata_bytes))
            .map_err(Self::error)?;
        Ok(bytes)
    }

    pub(in crate::analysis) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(Self::error)? != Some(5)
            || decoder.u32().map_err(Self::error)? != 2
        {
            return GraphInvalidSnafu {
                field: "graph header version",
            }
            .fail();
        }
        let subject_count = decoder.u32().map_err(Self::error)? as usize;
        let edge_count = decoder.u32().map_err(Self::error)? as usize;
        let finding_count = decoder.u32().map_err(Self::error)? as usize;
        let metadata = decoder.bytes().map_err(Self::error)?;
        if metadata.is_empty() || decoder.position() != bytes.len() {
            return GraphInvalidSnafu {
                field: "graph header format",
            }
            .fail();
        }
        let mut decoder = rmp_serde::Deserializer::new(std::io::Cursor::new(metadata));
        let decoded = HeaderMetadata::deserialize(&mut decoder).map_err(Self::error)?;
        if decoder.position() != metadata.len() as u64 {
            return Err(Self::error("trailing metadata"));
        }
        let evidence_count = usize::try_from(decoded.evidence_count).map_err(Self::error)?;
        let position_count = usize::try_from(decoded.position_count).map_err(Self::error)?;
        let snapshot = GraphSnapshotV1::from(decoded);
        snapshot.validate()?;
        Ok(Self {
            notice: (
                snapshot.context_notice_revision,
                snapshot
                    .input_manifest
                    .coverage
                    .iter()
                    .map(|key| key.report_revision)
                    .max()
                    .unwrap_or(0),
            ),
            snapshot,
            subject_count,
            edge_count,
            finding_count,
            evidence_count,
            position_count,
        })
    }

    pub(in crate::analysis) fn check_index(
        &self,
        tenant: [u8; 16],
        stream: &[u8],
        method: u64,
        first: u64,
    ) -> Result<()> {
        let graph = &self.snapshot;
        if graph.scope.identity.tenant_id != tenant
            || graph.scope.identity.key() != stream
            || graph.scope.method_version != method
            || graph.first_cursor != first
        {
            return GraphInvalidSnafu {
                field: "graph header index",
            }
            .fail();
        }
        Ok(())
    }

    pub(in crate::analysis) fn check_shape(
        &self,
        subjects: u64,
        edges: u64,
        findings: u64,
    ) -> Result<()> {
        if usize::try_from(subjects).ok() != Some(self.subject_count)
            || usize::try_from(edges).ok() != Some(self.edge_count)
            || usize::try_from(findings).ok() != Some(self.finding_count)
        {
            return GraphInvalidSnafu {
                field: "graph row counts",
            }
            .fail();
        }
        Ok(())
    }

    fn error(_: impl std::fmt::Display) -> crate::Error {
        GraphInvalidSnafu {
            field: "graph header format",
        }
        .build()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HeaderMetadata {
    schema_version: u32,
    scope: ProcessorScopeV1,
    first_cursor: u64,
    last_cursor: u64,
    input_manifest: RevisionMetadata,
    graph: GraphMetadata,
    packages: Vec<GraphPackageCheckpointV1>,
    missing_ranges: Vec<(u64, u64)>,
    evidence_count: u32,
    position_count: u32,
    previous_result_id: Option<String>,
    context_notice_revision: u64,
    witness_deadline_utc_ns: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphMetadata {
    branches: Vec<GraphBranchV1>,
    facts: Vec<GraphFactV1>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RevisionMetadata {
    coverage: Vec<GraphCoverageKeyV1>,
    context: Vec<AnalysisContextKeyV1>,
    missing_ranges: Vec<(u64, u64)>,
}

impl TryFrom<&GraphSnapshotV1> for HeaderMetadata {
    type Error = crate::Error;

    fn try_from(snapshot: &GraphSnapshotV1) -> Result<Self> {
        Ok(Self {
            schema_version: snapshot.schema_version,
            scope: snapshot.scope.clone(),
            first_cursor: snapshot.first_cursor,
            last_cursor: snapshot.last_cursor,
            input_manifest: RevisionMetadata {
                coverage: snapshot.input_manifest.coverage.clone(),
                context: snapshot.input_manifest.context.clone(),
                missing_ranges: snapshot.input_manifest.missing_ranges.clone(),
            },
            graph: GraphMetadata {
                branches: snapshot.graph.branches.clone(),
                facts: snapshot.graph.facts.clone(),
            },
            packages: snapshot.packages.clone(),
            missing_ranges: snapshot.missing_ranges.clone(),
            evidence_count: u32::try_from(snapshot.input_manifest.evidence.len())
                .map_err(GraphHeader::error)?,
            position_count: u32::try_from(snapshot.input_positions.len())
                .map_err(GraphHeader::error)?,
            previous_result_id: snapshot.previous_result_id.clone(),
            context_notice_revision: snapshot.context_notice_revision,
            witness_deadline_utc_ns: snapshot.witness_deadline_utc_ns,
        })
    }
}

impl From<HeaderMetadata> for GraphSnapshotV1 {
    fn from(metadata: HeaderMetadata) -> Self {
        Self {
            schema_version: metadata.schema_version,
            scope: metadata.scope,
            first_cursor: metadata.first_cursor,
            last_cursor: metadata.last_cursor,
            input_manifest: GraphRevisionV1 {
                evidence: Vec::new(),
                coverage: metadata.input_manifest.coverage,
                context: metadata.input_manifest.context,
                missing_ranges: metadata.input_manifest.missing_ranges,
            },
            graph: GraphVersionV1 {
                subjects: Vec::new(),
                edges: Vec::new(),
                branches: metadata.graph.branches,
                facts: metadata.graph.facts,
            },
            findings: Vec::new(),
            packages: metadata.packages,
            missing_ranges: metadata.missing_ranges,
            input_positions: Vec::new(),
            previous_result_id: metadata.previous_result_id,
            context_notice_revision: metadata.context_notice_revision,
            witness_deadline_utc_ns: metadata.witness_deadline_utc_ns,
        }
    }
}
