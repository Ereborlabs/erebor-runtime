use duckdb::{params, Connection, OptionalExt as _};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::*;
use crate::{GraphSnapshotV1, PackageErrorCodeV1, GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION};

mod findings;
mod interest;
pub(super) mod traversal;
mod windows;
pub use interest::GraphLease;

pub use araphor_analysis_types::GraphManifest;

pub struct GraphSourceSummary {
    pub manifest: GraphManifest,
    pub restricted_count: Option<u64>,
    pub expired: bool,
}

pub struct GraphCommit {
    pub input_proof: Option<std::sync::Arc<crate::analysis::graph_rows::store::InputProof>>,
    pub request: AnalysisResultCommitV1,
    pub metadata: GraphManifest,
    pub contexts: Vec<AnalysisContextVersionV1>,
    /// Global proof refs. Exclude fact refs and record proof refs.
    pub proofs: Vec<AnalysisContextRefV1>,
    /// Upstream proof refs for each changed source record.
    pub record_proofs: Vec<(crate::DiscoveryRecordIdV1, AnalysisContextRefV1)>,
    pub sources: Vec<(String, u64)>,
    /// Source records absent from the after set.
    pub removed: Vec<crate::DiscoveryRecordIdV1>,
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

    pub fn graph_frozen_facts(
        &self,
        capture: &ManagedCapture,
        reference: Option<&ManagedAttempt>,
        result: &PackageResultRefV1,
        records: &std::collections::BTreeSet<crate::DiscoveryRecordIdV1>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> Result<(
        GraphSourceSummary,
        Vec<(AnalysisContextVersionV1, AnalysisContextRefV1)>,
        Vec<(crate::DiscoveryRecordIdV1, AnalysisContextRefV1)>,
    )> {
        self.graph_frozen_input(
            capture,
            reference,
            result,
            Some(records),
            limits,
            control,
            |rows, _| Ok(rows),
        )
    }

    pub fn graph_support_facts(
        &self,
        capture: &ManagedCapture,
        reference: Option<&ManagedAttempt>,
        result: &PackageResultRefV1,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> Result<(
        GraphSourceSummary,
        Vec<(AnalysisContextVersionV1, AnalysisContextRefV1)>,
        Vec<(crate::DiscoveryRecordIdV1, AnalysisContextRefV1)>,
    )> {
        self.graph_frozen_input(
            capture,
            reference,
            result,
            None,
            limits,
            control,
            |rows, _| Ok(rows),
        )
    }

    pub fn graph_frozen_source(
        &self,
        capture: &ManagedCapture,
        reference: Option<&ManagedAttempt>,
        result: &PackageResultRefV1,
        records: &std::collections::BTreeSet<crate::DiscoveryRecordIdV1>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> Result<(
        GraphSourceSummary,
        std::sync::Arc<crate::ManagedSourceHistory>,
    )> {
        let frame = capture
            .source()
            .ok_or_else(|| PackageErrorCodeV1::Invalid.error("historical source frame"))?;
        self.graph_frozen_input(
            capture,
            reference,
            result,
            Some(records),
            limits,
            control,
            |(summary, contexts, proofs), charge| {
                frame
                    .seal_history(result.clone(), contexts, proofs, charge)
                    .map(|history| (summary, history))
            },
        )
    }

    fn graph_frozen_input<T>(
        &self,
        capture: &ManagedCapture,
        reference: Option<&ManagedAttempt>,
        result: &PackageResultRefV1,
        records: Option<&std::collections::BTreeSet<crate::DiscoveryRecordIdV1>>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        map: impl FnOnce(
            (
                GraphSourceSummary,
                Vec<(AnalysisContextVersionV1, AnalysisContextRefV1)>,
                Vec<(crate::DiscoveryRecordIdV1, AnalysisContextRefV1)>,
            ),
            &mut dyn FnMut(usize, usize) -> Result<()>,
        ) -> Result<T>,
    ) -> Result<T> {
        let ManagedDestination::Graph { source, .. } = &capture.instance().spec.destination else {
            return Err(PackageErrorCodeV1::Invalid.error("frozen Graph destination"));
        };
        if records.is_some_and(|records| {
            records
                .iter()
                .any(|record| &record.stream != source || record.durable_cursor == 0)
        }) {
            return Err(PackageErrorCodeV1::Denied.error("frozen Graph source"));
        }
        if limits
            .keys
            .is_some_and(|limit| records.is_some_and(|records| records.len() > limit))
        {
            return crate::AnalysisInputTooLargeSnafu {
                resource: "frozen Graph keys",
            }
            .fail();
        }
        self.with_graph_reader(
            capture,
            reference,
            result,
            limits,
            control,
            |reader, charge| {
                for record in records.into_iter().flatten() {
                    charge(
                        0,
                        std::mem::size_of_val(record) + record.stream.node_id.len(),
                    )?;
                }
                let rows = if let Some(rows) = self.native_source_facts(reader,capture,result,records,control,charge)? {
                    rows
                } else { super::graph_rows::GraphRows::frozen_facts(
                    reader,
                    &self.root,
                    capture,
                    result,
                    records,
                    control,
                    &mut |scan, bytes| charge(scan, bytes),
                )? };
                map(rows, charge)
            },
        )
    }

    pub fn graph_record_keys(
        &self,
        capture: &ManagedCapture,
        reference: Option<&ManagedAttempt>,
        result: &PackageResultRefV1,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> Result<Vec<crate::DiscoveryRecordIdV1>> {
        self.with_graph_reader(
            capture,
            reference,
            result,
            limits,
            control,
            |reader, charge| {
                if let Some(records) = self.native_source_records(reader,capture,result,control,charge)? {
                    return Ok(records);
                }
                super::graph_rows::GraphRows::frozen_records(
                    reader,
                    capture,
                    result,
                    control,
                    &mut |scan, bytes| charge(scan, bytes),
                )
            },
        )
    }

    fn with_graph_reader<T>(
        &self,
        capture: &ManagedCapture,
        reference: Option<&ManagedAttempt>,
        result: &PackageResultRefV1,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        read: impl FnOnce(&Connection, &mut dyn FnMut(usize, usize) -> Result<()>) -> Result<T>,
    ) -> Result<T> {
        let started = std::time::Instant::now();
        let ManagedDestination::Graph { source, .. } = &capture.instance().spec.destination else {
            return Err(PackageErrorCodeV1::Invalid.error("frozen Graph destination"));
        };
        if result.result_id.is_empty()
            || result.commit_revision == 0
            || (result.commit_revision > capture.revision()
                && reference
                    .and_then(|reference| reference.receipt())
                    .and_then(|receipt| receipt.graph.as_ref())
                    != Some(result))
            || !capture.instance().grant.selection.includes_source(source)
        {
            return Err(PackageErrorCodeV1::Denied.error("frozen Graph source"));
        }
        if let Some(reference) = reference {
            capture.check_reference(reference)?;
        }
        // The committed Graph reference does not need projection of later journal records.
        let requesting = std::time::Instant::now();
        let mut reader = self.frozen_reader(control)?;
        let acquired = std::time::Instant::now();
        let mut guard_s = 0.0;
        let mut graph_rows_s = 0.0;
        let owner_check = reference.is_some() && result.commit_revision > capture.revision();
        let output = control.run(&mut reader, |reader| {
            let guarding = std::time::Instant::now();
            let guarded = (|| -> Result<()> {
                let actual = Self::read_meta_from(reader, &self.root)?;
                let captured = capture.source_meta();
                if actual.store_uuid != captured.store_uuid
                    || actual.schema_version != captured.schema_version
                    || captured.recovery_epoch == 0
                    || captured.recovery_epoch > actual.recovery_epoch
                    || captured.commit_revision > actual.commit_revision
                {
                    return Err(PackageErrorCodeV1::Conflict.error("frozen Graph store"));
                }
                if let Some(reference) =
                    reference.filter(|_| result.commit_revision > capture.revision())
                {
                    if Self::graph_capture_cut(
                        reader,
                        capture.instance().spec.tenant,
                        result,
                        Some(reference),
                        None,
                    )? != capture.revision()
                    {
                        return Err(
                            PackageErrorCodeV1::Conflict.error("frozen Graph publication source")
                        );
                    }
                }
                Ok(())
            })();
            guard_s = guarding.elapsed().as_secs_f64();
            guarded?;
            let projecting = std::time::Instant::now();
            let mut input = 0usize;
            let mut scanned = 0usize;
            let mut charge = |scan: usize, bytes: usize| {
                scanned = scanned
                    .checked_add(scan)
                    .filter(|total| *total <= limits.scan_bytes)
                    .ok_or_else(|| {
                        crate::AnalysisInputTooLargeSnafu {
                            resource: "scanned Graph bytes",
                        }
                        .build()
                    })?;
                input = input
                    .checked_add(bytes)
                    .filter(|total| *total <= limits.input_bytes)
                    .ok_or_else(|| {
                        crate::AnalysisInputTooLargeSnafu {
                            resource: "frozen Graph bytes",
                        }
                        .build()
                    })?;
                Ok(())
            };
            let output = read(reader, &mut charge);
            graph_rows_s = projecting.elapsed().as_secs_f64();
            output
        });
        let ran = std::time::Instant::now();
        drop(reader);
        let released = std::time::Instant::now();
        erebor_telemetry::debug!(
            stage = "graph_frozen_timing",
            cut_revision = capture.revision(),
            graph_revision = result.commit_revision,
            owner_check,
            preflight_s = requesting.duration_since(started).as_secs_f64(),
            reader_s = acquired.duration_since(requesting).as_secs_f64(),
            guard_s,
            graph_rows_s,
            control_run_s = ran.duration_since(acquired).as_secs_f64(),
            release_s = released.duration_since(ran).as_secs_f64(),
            elapsed_s = released.duration_since(started).as_secs_f64(),
            success = output.is_ok(),
            "Frozen Graph read timing completed"
        );
        output
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
