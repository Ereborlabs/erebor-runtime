use minicbor::{Decoder, Encoder};
use serde::ser::{Serialize, SerializeMap as _, Serializer};
use snafu::ResultExt as _;

use super::GraphRows;
use crate::{GraphInvalidSnafu, GraphSnapshotV1, Result};

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
        let metadata =
            serde_json::to_value(HeaderMetadata(snapshot)).context(crate::GraphEncodingSnafu)?;
        let metadata = GraphRows::json(&metadata)?;
        let subjects = u32::try_from(snapshot.graph.subjects.len()).map_err(Self::error)?;
        let edges = u32::try_from(snapshot.graph.edges.len()).map_err(Self::error)?;
        let findings = u32::try_from(snapshot.findings.len()).map_err(Self::error)?;
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .array(5)
            .and_then(|e| e.u32(2))
            .and_then(|e| e.u32(subjects))
            .and_then(|e| e.u32(edges))
            .and_then(|e| e.u32(findings))
            .and_then(|e| e.bytes(&metadata))
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
        let mut metadata: serde_json::Value = GraphRows::decode(metadata)?;
        let object = metadata
            .as_object_mut()
            .ok_or_else(|| Self::error("snapshot metadata"))?;
        let evidence_count = object
            .remove("evidence_count")
            .and_then(|value| value.as_u64())
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| Self::error("graph evidence count"))?;
        let position_count = object
            .remove("position_count")
            .and_then(|value| value.as_u64())
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| Self::error("graph position count"))?;
        let manifest = object
            .get_mut("input_manifest")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| Self::error("graph input manifest"))?;
        if manifest
            .insert("evidence".to_owned(), serde_json::json!([]))
            .is_some()
            || object
                .insert("input_positions".to_owned(), serde_json::json!([]))
                .is_some()
        {
            return GraphInvalidSnafu {
                field: "duplicate graph inputs",
            }
            .fail();
        }
        let graph = object
            .get_mut("graph")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| Self::error("graph metadata"))?;
        if graph
            .insert("subjects".to_owned(), serde_json::json!([]))
            .is_some()
            || graph
                .insert("edges".to_owned(), serde_json::json!([]))
                .is_some()
            || object
                .insert("findings".to_owned(), serde_json::json!([]))
                .is_some()
        {
            return GraphInvalidSnafu {
                field: "duplicate graph rows",
            }
            .fail();
        }
        let snapshot: GraphSnapshotV1 = GraphRows::decode(&GraphRows::json(&metadata)?)?;
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

struct HeaderMetadata<'a>(&'a GraphSnapshotV1);
struct GraphMetadata<'a>(&'a crate::GraphVersionV1);
struct RevisionMetadata<'a>(&'a crate::GraphRevisionV1);

impl Serialize for HeaderMetadata<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let snapshot = self.0;
        let mut map = serializer.serialize_map(Some(13))?;
        map.serialize_entry("schema_version", &snapshot.schema_version)?;
        map.serialize_entry("scope", &snapshot.scope)?;
        map.serialize_entry("first_cursor", &snapshot.first_cursor)?;
        map.serialize_entry("last_cursor", &snapshot.last_cursor)?;
        map.serialize_entry(
            "input_manifest",
            &RevisionMetadata(&snapshot.input_manifest),
        )?;
        map.serialize_entry("graph", &GraphMetadata(&snapshot.graph))?;
        map.serialize_entry("packages", &snapshot.packages)?;
        map.serialize_entry("missing_ranges", &snapshot.missing_ranges)?;
        map.serialize_entry("evidence_count", &snapshot.input_manifest.evidence.len())?;
        map.serialize_entry("position_count", &snapshot.input_positions.len())?;
        map.serialize_entry("previous_result_id", &snapshot.previous_result_id)?;
        map.serialize_entry("context_notice_revision", &snapshot.context_notice_revision)?;
        map.serialize_entry("witness_deadline_utc_ns", &snapshot.witness_deadline_utc_ns)?;
        map.end()
    }
}

impl Serialize for RevisionMetadata<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("coverage", &self.0.coverage)?;
        map.serialize_entry("context", &self.0.context)?;
        map.serialize_entry("missing_ranges", &self.0.missing_ranges)?;
        map.end()
    }
}

impl Serialize for GraphMetadata<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("branches", &self.0.branches)?;
        map.serialize_entry("facts", &self.0.facts)?;
        map.end()
    }
}
