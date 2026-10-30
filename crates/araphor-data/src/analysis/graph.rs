use duckdb::{params, Connection, OptionalExt as _};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::*;
use crate::{GraphSnapshotV1, GraphValidate as _, GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION};

mod findings;
mod interest;
pub(super) mod traversal;
mod windows;
pub use interest::GraphLease;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphManifest {
    pub schema_version: u32,
    pub scope: ProcessorScopeV1,
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub input_manifest: crate::GraphRevisionV1,
    pub facts: Vec<crate::GraphFactV1>,
    pub packages: Vec<crate::GraphPackageCheckpointV1>,
    pub missing_ranges: Vec<(u64, u64)>,
    pub input_positions: Vec<(crate::DiscoveryRecordIdV1, crate::StorePositionV1)>,
    pub previous_result_id: Option<String>,
    pub context_notice_revision: u64,
    pub witness_deadline_utc_ns: u64,
}

pub struct GraphCommit {
    pub request: AnalysisResultCommitV1,
    pub metadata: GraphManifest,
    pub contexts: Vec<AnalysisContextVersionV1>,
    pub proofs: Vec<AnalysisContextRefV1>,
    pub sources: Vec<(String, u64)>,
    pub advance: bool,
    pub expire: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(in crate::analysis) struct GraphRequestMeta {
    pub scope: ProcessorScopeV1,
    pub expected_cursor: u64,
    pub consumed_cursor: u64,
    pub coverage_revision: u64,
    pub captured_context_revision: u64,
    pub result_id: String,
    pub created_utc_ns: u64,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub captured_context_refs: Vec<AnalysisContextRefV1>,
    pub context_refs: Vec<AnalysisContextRefV1>,
    pub sources: Vec<(String, u64)>,
    pub advance: bool,
    pub captured_prefix: bool,
}

impl GraphRequestMeta {
    pub fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec(self).context(crate::GraphNativeEncodingSnafu)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = rmp_serde::Deserializer::new(std::io::Cursor::new(bytes));
        let value = Self::deserialize(&mut decoder).context(crate::GraphNativeDecodingSnafu)?;
        if decoder.position() != bytes.len() as u64 {
            return crate::GraphInvalidSnafu {
                field: "graph request metadata trailing bytes",
            }
            .fail();
        }
        Ok(value)
    }
}

impl GraphManifest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.serialize(&mut rmp_serde::Serializer::new(&mut bytes).with_struct_map())
            .map_err(|_| {
                crate::GraphInvalidSnafu {
                    field: "graph metadata encoding",
                }
                .build()
            })?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = rmp_serde::Deserializer::new(std::io::Cursor::new(bytes));
        let value = Self::deserialize(&mut decoder).map_err(|_| {
            crate::GraphInvalidSnafu {
                field: "graph metadata encoding",
            }
            .build()
        })?;
        if decoder.position() != bytes.len() as u64 {
            return crate::GraphInvalidSnafu {
                field: "graph metadata trailing bytes",
            }
            .fail();
        }
        value.validate()?;
        Ok(value)
    }

    pub fn from_snapshot(graph: &GraphSnapshotV1) -> Self {
        Self {
            schema_version: graph.schema_version,
            scope: graph.scope.clone(),
            first_cursor: graph.first_cursor,
            last_cursor: graph.last_cursor,
            input_manifest: graph.input_manifest.clone(),
            facts: graph.graph.facts.clone(),
            packages: graph.packages.clone(),
            missing_ranges: graph.missing_ranges.clone(),
            input_positions: graph.input_positions.clone(),
            previous_result_id: graph.previous_result_id.clone(),
            context_notice_revision: graph.context_notice_revision,
            witness_deadline_utc_ns: graph.witness_deadline_utc_ns,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.snapshot().validate()?;
        for fact in &self.facts {
            fact.validate()?;
            if fact.record_id.stream != self.scope.identity
                || self
                    .input_manifest
                    .evidence
                    .binary_search(&fact.record_id)
                    .is_err()
            {
                return Err(crate::GraphInvalidSnafu {
                    field: "graph fact evidence",
                }
                .build());
            }
        }
        Ok(())
    }

    pub(in crate::analysis) fn snapshot(&self) -> GraphSnapshotV1 {
        GraphSnapshotV1 {
            schema_version: self.schema_version,
            scope: self.scope.clone(),
            first_cursor: self.first_cursor,
            last_cursor: self.last_cursor,
            input_manifest: self.input_manifest.clone(),
            graph: crate::GraphVersionV1 {
                subjects: Vec::new(),
                edges: Vec::new(),
                branches: Vec::new(),
                facts: self.facts.clone(),
            },
            findings: Vec::new(),
            packages: self.packages.clone(),
            missing_ranges: self.missing_ranges.clone(),
            input_positions: self.input_positions.clone(),
            previous_result_id: self.previous_result_id.clone(),
            context_notice_revision: self.context_notice_revision,
            witness_deadline_utc_ns: self.witness_deadline_utc_ns,
        }
    }
}

impl AnalysisStore {
    fn check_graph_read(
        &self,
        tenant: [u8; 16],
        ids: &[Option<&str>],
        field: &'static str,
    ) -> Result<()> {
        if tenant == [0; 16]
            || ids
                .iter()
                .flatten()
                .any(|id| id.is_empty() || id.chars().any(char::is_control))
        {
            return crate::GraphInvalidSnafu { field }.fail();
        }
        Ok(())
    }

    pub fn graph_result(
        &self,
        tenant: [u8; 16],
        result_id: &str,
    ) -> Result<Option<GraphSnapshotV1>> {
        self.check_graph_read(tenant, &[Some(result_id)], "graph result reference")?;
        self.read_snapshot(|reader| {
            super::graph_rows::GraphRows::read_header(reader, tenant, result_id)?
                .map(|header| super::graph_rows::GraphRows::read(reader, result_id, &header))
                .transpose()
        })
    }

    pub fn graph_snapshot(
        &self,
        source: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<GraphSnapshotV1>> {
        if !source.valid() {
            return self.reject("the Graph source is invalid");
        }
        self.read_snapshot(|reader| {
            let id: Option<String> = reader.query_row(
                "SELECT result_id FROM processor_progress WHERE tenant_id = ? AND stream_key = ?
                 AND processor_id = ? AND method_version = ? AND result_id <> ''",
                params![source.tenant_id.as_slice(),source.key(),GRAPH_PROCESSOR,GRAPH_SCHEMA_VERSION], |row|row.get(0),
            ).optional().context(AnalysisDatabaseSnafu {operation:"select Graph head"})?;
            id.map(|id| self.selected_graph_header(reader, source.tenant_id, Some(source), &id)
                .and_then(|header| super::graph_rows::GraphRows::read(reader,&id,&header))).transpose()
        })
    }

    pub fn graph_source(
        &self,
        tenant: [u8; 16],
        result_id: &str,
    ) -> Result<Option<EvidenceIntakeIdentityV1>> {
        self.check_graph_read(tenant, &[Some(result_id)], "graph result reference")?;
        self.read_snapshot(|reader| {
            Ok(
                super::graph_rows::GraphRows::read_header(reader, tenant, result_id)?
                    .map(|header| header.snapshot.scope.identity),
            )
        })
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn graph_snapshots(
        &self,
        tenant: [u8; 16],
        source: Option<&EvidenceIntakeIdentityV1>,
        after: Option<&str>,
        current: bool,
    ) -> Result<Vec<(String, GraphSnapshotV1, u64)>> {
        self.check_graph_read(tenant, &[after], "graph page scope")?;
        self.read_snapshot(|reader| {
            self.graph_page(reader, tenant, source, after, current, None)
                .map(|(rows, _)| rows)
        })
    }

    pub fn graph_coverage_versions(
        &self,
        source: &EvidenceIntakeIdentityV1,
        frozen: &std::collections::BTreeSet<u64>,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        self.read_snapshot(|reader| self.graph_coverage_from(reader, source, frozen, |_, _| Ok(())))
    }

    pub(in crate::analysis) fn graph_coverage_from(
        &self,
        reader: &Connection,
        source: &EvidenceIntakeIdentityV1,
        frozen: &std::collections::BTreeSet<u64>,
        preflight: impl FnOnce(usize, usize) -> Result<()>,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        let placeholders = std::iter::repeat_n("?", frozen.len())
            .collect::<Vec<_>>()
            .join(",");
        let filter = if frozen.is_empty() {
            String::new()
        } else {
            format!(" OR revision IN ({placeholders})")
        };
        let query = format!("SELECT revision,report FROM coverage WHERE tenant_id = ? AND stream_key = ? AND
            (revision = (SELECT max(revision) FROM coverage WHERE tenant_id = ? AND stream_key = ?){filter}) ORDER BY revision");
        let mut values = vec![
            duckdb::types::Value::Blob(source.tenant_id.to_vec()),
            duckdb::types::Value::Blob(source.key()),
            duckdb::types::Value::Blob(source.tenant_id.to_vec()),
            duckdb::types::Value::Blob(source.key()),
        ];
        values.extend(
            frozen
                .iter()
                .map(|&value| duckdb::types::Value::UBigInt(value)),
        );
        let mut statement = reader.prepare(&query).context(AnalysisDatabaseSnafu {
            operation: "prepare Graph coverage",
        })?;
        let rows = statement
            .query_map(duckdb::params_from_iter(values.iter()), |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph coverage",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode Graph coverage",
            })?;
        preflight(rows.len(), rows.iter().map(|(_, bytes)| bytes.len()).sum())?;
        if frozen
            .iter()
            .any(|wanted| !rows.iter().any(|(revision, _)| revision == wanted))
        {
            return self.reject("the frozen Graph coverage is absent");
        }
        Ok(rows)
    }
}
