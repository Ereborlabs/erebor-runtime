use std::sync::atomic::Ordering;

use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::*;
use crate::{AnalysisConflictSnafu, GraphSnapshotV1, GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION};

use super::graph_rows::GraphRows;

mod findings;

impl AnalysisStore {
    pub(crate) fn graph_set_health(
        &self,
        source: &EvidenceIntakeIdentityV1,
        failed: bool,
    ) -> Result<()> {
        if failed {
            self.graph_failures
                .lock()
                .map_err(|_| self.state_error("the graph health lock is poisoned"))?
                .insert(source.clone());
        }
        let (revision, previous) = self.graph_health_context(source)?;
        if previous != failed {
            let context = AnalysisContextVersionV1 {
                key: AnalysisContextKeyV1 {
                    tenant_id: source.tenant_id,
                    owner_id: "graph-health-v1".into(),
                    entity_key: source.key(),
                    lifetime_key: b"graph-findings/v1".to_vec(),
                    owner_revision: revision.checked_add(1).ok_or_else(|| {
                        self.state_error("the graph health revision is exhausted")
                    })?,
                },
                valid_from_utc_ns: None,
                valid_until_utc_ns: None,
                sensitivity: ContextSensitivityV1::Tenant,
                body: serde_json::to_vec(&(source, failed))
                    .map_err(|_| self.state_error("the graph health encoding is invalid"))?,
            };
            self.commit_context_checked(&context, revision)?;
        }
        if !failed {
            self.graph_failures
                .lock()
                .map_err(|_| self.state_error("the graph health lock is poisoned"))?
                .remove(source);
        }
        Ok(())
    }

    pub(super) fn graph_processing_failed(
        &self,
        snapshot: &Connection,
        source: &EvidenceIntakeIdentityV1,
    ) -> Result<bool> {
        if self
            .graph_failures
            .lock()
            .map_err(|_| self.state_error("the graph health lock is poisoned"))?
            .contains(source)
        {
            return Ok(true);
        }
        Ok(self.graph_health_from(snapshot, source)?.1)
    }

    fn graph_health_context(&self, source: &EvidenceIntakeIdentityV1) -> Result<(u64, bool)> {
        self.read_snapshot(|snapshot| self.graph_health_from(snapshot, source))
    }

    fn graph_health_from(
        &self,
        snapshot: &Connection,
        source: &EvidenceIntakeIdentityV1,
    ) -> Result<(u64, bool)> {
        let stored: Option<(u64, Vec<u8>)> = snapshot.query_row(
            "SELECT owner_revision, body FROM context_versions WHERE tenant_id = ? AND owner_id = 'graph-health-v1' AND entity_key = ? AND lifetime_key = ? ORDER BY owner_revision DESC LIMIT 1",
            params![source.tenant_id.as_slice(), source.key().as_slice(), b"graph-findings/v1".as_slice()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().context(AnalysisDatabaseSnafu { operation: "read graph processing health" })?;
        let Some((revision, body)) = stored else {
            return Ok((0, false));
        };
        let (stored_source, failed): (EvidenceIntakeIdentityV1, bool) =
            serde_json::from_slice(&body)
                .map_err(|_| self.state_error("the graph processing health is invalid"))?;
        if &stored_source != source {
            return self.reject("the graph health source differs");
        }
        Ok((revision, failed))
    }

    pub fn graph_enabled(&self) -> bool {
        self.graph_owner.load(Ordering::Acquire)
    }

    pub(crate) fn enable_graph_owner(&self) -> Result<()> {
        let _writer = self.writer_access()?;
        self.graph_owner
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| self.state_error("the graph owner is already active"))?;
        Ok(())
    }

    pub(crate) fn register_graph(&self, identity: &EvidenceIntakeIdentityV1) -> Result<()> {
        let mut writer = self.writer_access()?;
        let floor = Self::read_receipt_from(writer.get()?, &self.root, identity, &identity.key())?
            .map_or(0, |receipt| receipt.retained_floor);
        self.register_graph_locked(writer.get_mut()?, identity, floor)
    }

    pub(super) fn register_graph_locked(
        &self,
        writer: &mut Connection,
        identity: &EvidenceIntakeIdentityV1,
        floor: u64,
    ) -> Result<()> {
        if !self.graph_registration_required(writer, identity)? {
            return Ok(());
        }
        let key = identity.key();
        let start = floor
            .checked_add(1)
            .ok_or_else(|| self.state_error("the graph start cursor is exhausted"))?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin required graph registration",
        })?;
        let revision = Self::read_meta_from(&transaction, &self.root)?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the graph registration revision is exhausted"))?;
        transaction.execute(
            "INSERT INTO processor_progress VALUES (?, ?, ?, ?, 'required', ?, ?, 0, 0, ?, ?, false, '', '', 0, 0, '')",
            params![GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION, identity.tenant_id.as_slice(), key.as_slice(), floor, floor, start, floor],
        ).context(AnalysisDatabaseSnafu { operation: "register required graph processor" })?;
        super::quota::UsageChange::from((256 + key.len() + GRAPH_PROCESSOR.len()) as i64)
            .apply(&transaction, &identity.tenant_id)?;
        self.check_logical(&transaction, identity.tenant_id, false)?;
        Self::record_revision(&transaction, revision, &["processor_progress"])?;
        self.commit_metadata(transaction, "commit required graph registration")?;
        self.revision.send_replace(revision);
        Ok(())
    }

    pub(super) fn graph_registration_required(
        &self,
        writer: &Connection,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<bool> {
        if !identity.valid() {
            return self.reject("the graph source identity is invalid");
        }
        let key = identity.key();
        let existing: Option<(String, bool)> = writer.query_row(
            "SELECT class, retired FROM processor_progress WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
            params![GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION, identity.tenant_id.as_slice(), key.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().context(AnalysisDatabaseSnafu { operation: "read required graph registration" })?;
        if let Some(existing) = existing {
            if existing != ("required".to_owned(), false) {
                return AnalysisConflictSnafu.fail();
            }
            return Ok(false);
        }
        Ok(true)
    }

    pub(crate) fn graph_coverage_versions(
        &self,
        source: &EvidenceIntakeIdentityV1,
        frozen: &std::collections::BTreeSet<u64>,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        self.read_snapshot(|snapshot| {
            let latest: Option<(u64, Vec<u8>)> = snapshot.query_row(
                "SELECT revision, report FROM coverage WHERE tenant_id = ? AND stream_key = ? ORDER BY revision DESC LIMIT 1",
                params![source.tenant_id.as_slice(), source.key().as_slice()], |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional().context(AnalysisDatabaseSnafu { operation: "read current graph coverage" })?;
            let mut versions = std::collections::BTreeMap::new();
            if let Some((revision, report)) = latest { versions.insert(revision, report); }
            for revision in frozen {
                if versions.contains_key(revision) { continue; }
                let report: Option<Vec<u8>> = snapshot.query_row(
                    "SELECT report FROM coverage WHERE tenant_id = ? AND stream_key = ? AND revision = ?",
                    params![source.tenant_id.as_slice(), source.key().as_slice(), revision], |row| row.get(0),
                ).optional().context(AnalysisDatabaseSnafu { operation: "read frozen graph coverage" })?;
                let report = report.ok_or_else(|| self.state_error("the frozen graph coverage is absent"))?;
                versions.insert(*revision, report);
            }
            Ok(versions.into_iter().collect())
        })
    }

    pub(crate) fn graph_snapshot(
        &self,
        source: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<GraphSnapshotV1>> {
        if !source.valid() {
            return self.reject("the graph snapshot source is invalid");
        }
        self.read_snapshot(|snapshot| {
            let id: Option<String> = snapshot
                .query_row(
                    "SELECT r.result_id FROM processor_progress p JOIN analysis_results r
                   ON r.tenant_id = p.tenant_id AND r.result_id = p.result_id
                     AND r.processor_id = p.processor_id
                 WHERE p.processor_id = ? AND p.method_version = ?
                   AND p.tenant_id = ? AND p.stream_key = ?",
                    params![
                        GRAPH_PROCESSOR,
                        GRAPH_SCHEMA_VERSION,
                        source.tenant_id.as_slice(),
                        source.key().as_slice()
                    ],
                    |row| row.get(0),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "read current graph reference",
                })?;
            let Some(id) = id else {
                return Ok(None);
            };
            let header = GraphRows::read_header(snapshot, source.tenant_id, &id)?
                .ok_or_else(|| self.state_error("the current graph header is absent"))?;
            if header.snapshot.scope.identity != *source {
                return self.reject("the current graph source differs from its progress");
            }
            GraphRows::read(snapshot, &id, &header).map(Some)
        })
    }

    pub(crate) fn graph_snapshots(
        &self,
        tenant: [u8; 16],
        source: Option<&EvidenceIntakeIdentityV1>,
        after: Option<&str>,
        current: bool,
    ) -> Result<Vec<(String, GraphSnapshotV1, u64)>> {
        self.read_snapshot(|snapshot| {
            let mut statement = snapshot.prepare(
                "SELECT result_id, commit_revision FROM (
                    SELECT result_id, commit_revision, stream_key,
                    row_number() OVER (PARTITION BY stream_key, first_cursor ORDER BY commit_revision DESC) AS current_rank
                    FROM analysis_results WHERE tenant_id = ? AND processor_id = ? AND method_version = ?
                        AND stream_key IS NOT NULL
                 ) heads WHERE (? IS NULL OR stream_key = ?) AND (? IS NULL OR result_id > ?)
                    AND (NOT ? OR current_rank = 1) ORDER BY result_id LIMIT 1",
            ).context(AnalysisDatabaseSnafu { operation: "prepare committed graph snapshots" })?;
            let key = source.map(EvidenceIntakeIdentityV1::key);
            let rows = statement.query_map(params![tenant.as_slice(), GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION, key.as_deref(), key.as_deref(), after, after, current], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            }).context(AnalysisDatabaseSnafu { operation: "read committed graph snapshots" })?;
            let references = rows.collect::<std::result::Result<Vec<_>, _>>().context(AnalysisDatabaseSnafu { operation: "decode committed graph references" })?;
            drop(statement);
            let mut values = Vec::new();
            for (id, revision) in references {
                let header = GraphRows::read_header(snapshot, tenant, &id)?
                    .ok_or_else(|| self.state_error("the committed graph header is absent"))?;
                let graph = GraphRows::read(snapshot, &id, &header)?;
                if graph.scope.identity.tenant_id != tenant || source.is_some_and(|source| source != &graph.scope.identity) {
                    return self.reject("the committed graph source differs from its index");
                }
                values.push((id, graph, revision));
            }
            Ok(values)
        })
    }

    pub(crate) fn graph_result(
        &self,
        tenant: [u8; 16],
        result_id: &str,
    ) -> Result<Option<GraphSnapshotV1>> {
        if tenant == [0; 16] || result_id.is_empty() || result_id.len() > 256 {
            return self.reject("the graph result reference is invalid");
        }
        self.read_snapshot(|snapshot| {
            let Some(header) = GraphRows::read_header(snapshot, tenant, result_id)? else {
                return Ok(None);
            };
            let graph = GraphRows::read(snapshot, result_id, &header)?;
            Ok(Some(graph))
        })
    }
}
