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
    pub(in crate::analysis) row_bytes: usize,
    pub(in crate::analysis) metadata_allocation_bytes: usize,
    pub(in crate::analysis) notice: (u64, u64),
}

impl GraphHeader {
    pub(in crate::analysis) const MAX_BYTES: usize = (u32::MAX as usize).saturating_add(128);

    pub(super) fn encode(snapshot: &GraphSnapshotV1) -> Result<Vec<u8>> {
        let row_bytes = u64::try_from(GraphRows::row_bytes(snapshot)?).map_err(Self::error)?;
        let metadata =
            serde_json::to_value(HeaderMetadata(snapshot)).context(crate::GraphEncodingSnafu)?;
        let metadata = GraphRows::json(&metadata)?;
        let subjects = u32::try_from(snapshot.graph.subjects.len()).map_err(Self::error)?;
        let edges = u32::try_from(snapshot.graph.edges.len()).map_err(Self::error)?;
        let findings = u32::try_from(snapshot.findings.len()).map_err(Self::error)?;
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .array(6)
            .and_then(|e| e.u32(2))
            .and_then(|e| e.u32(subjects))
            .and_then(|e| e.u32(edges))
            .and_then(|e| e.u32(findings))
            .and_then(|e| e.u64(row_bytes))
            .and_then(|e| e.bytes(&metadata))
            .map_err(Self::error)?;
        if bytes.len() > Self::MAX_BYTES {
            return GraphInvalidSnafu {
                field: "graph header bytes",
            }
            .fail();
        }
        Ok(bytes)
    }

    pub(in crate::analysis) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::MAX_BYTES {
            return GraphInvalidSnafu {
                field: "graph header bytes",
            }
            .fail();
        }
        let metadata_allocation_bytes = bytes
            .len()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(size_of::<GraphSnapshotV1>()))
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph allocation byte bound",
                }
                .build()
            })?;
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(Self::error)? != Some(6)
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
        let row_bytes =
            usize::try_from(decoder.u64().map_err(Self::error)?).map_err(Self::error)?;
        let metadata = decoder.bytes().map_err(Self::error)?;
        if metadata.is_empty() || decoder.position() != bytes.len() {
            return GraphInvalidSnafu {
                field: "graph header format",
            }
            .fail();
        }
        let mut metadata: serde_json::Value = GraphRows::decode(metadata)?;
        let graph = metadata
            .get_mut("graph")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| Self::error("graph metadata"))?;
        if graph
            .insert("subjects".to_owned(), serde_json::json!([]))
            .is_some()
            || graph
                .insert("edges".to_owned(), serde_json::json!([]))
                .is_some()
            || metadata
                .as_object_mut()
                .ok_or_else(|| Self::error("snapshot metadata"))?
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
            row_bytes,
            metadata_allocation_bytes,
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

    pub(in crate::analysis) fn allocation_bytes(&self) -> Result<usize> {
        let bytes = self
            .row_bytes
            .checked_mul(2)
            .and_then(|bytes| {
                self.subject_count
                    .checked_mul(size_of::<crate::GraphSubjectKeyV1>())
                    .and_then(|added| bytes.checked_add(added))
            })
            .and_then(|bytes| {
                self.edge_count
                    .checked_mul(size_of::<crate::GraphEdgeV1>())
                    .and_then(|added| bytes.checked_add(added))
            })
            .and_then(|bytes| {
                self.finding_count
                    .checked_mul(size_of::<crate::FindingV1>())
                    .and_then(|added| bytes.checked_add(added))
            })
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph allocation byte bound",
                }
                .build()
            })?;
        Ok(bytes)
    }

    pub(in crate::analysis) fn check_shape(
        &self,
        result_id: &str,
        stored: u64,
        subjects: u64,
        edges: u64,
        findings: u64,
    ) -> Result<()> {
        if usize::try_from(subjects).ok() != Some(self.subject_count)
            || usize::try_from(edges).ok() != Some(self.edge_count)
            || usize::try_from(findings).ok() != Some(self.finding_count)
        {
            return GraphInvalidSnafu {
                field: "graph row counts or bytes",
            }
            .fail();
        }
        self.check_bytes(result_id, stored)
    }

    pub(in crate::analysis) fn check_bytes(&self, result_id: &str, stored: u64) -> Result<()> {
        let count = self
            .subject_count
            .checked_add(self.edge_count)
            .and_then(|count| count.checked_add(self.finding_count))
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph storage byte bound",
                }
                .build()
            })?;
        let expected = result_id
            .len()
            .checked_add(256)
            .and_then(|width| count.checked_mul(width))
            .and_then(|bytes| bytes.checked_add(self.row_bytes))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph storage byte bound",
                }
                .build()
            })?;
        if stored > expected {
            return GraphInvalidSnafu {
                field: "graph storage byte bound",
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

impl Serialize for HeaderMetadata<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let snapshot = self.0;
        let mut map = serializer.serialize_map(Some(12))?;
        map.serialize_entry("schema_version", &snapshot.schema_version)?;
        map.serialize_entry("scope", &snapshot.scope)?;
        map.serialize_entry("first_cursor", &snapshot.first_cursor)?;
        map.serialize_entry("last_cursor", &snapshot.last_cursor)?;
        map.serialize_entry("input_manifest", &snapshot.input_manifest)?;
        map.serialize_entry("graph", &GraphMetadata(&snapshot.graph))?;
        map.serialize_entry("packages", &snapshot.packages)?;
        map.serialize_entry("missing_ranges", &snapshot.missing_ranges)?;
        map.serialize_entry("input_positions", &snapshot.input_positions)?;
        map.serialize_entry("previous_result_id", &snapshot.previous_result_id)?;
        map.serialize_entry("context_notice_revision", &snapshot.context_notice_revision)?;
        map.serialize_entry("witness_deadline_utc_ns", &snapshot.witness_deadline_utc_ns)?;
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
