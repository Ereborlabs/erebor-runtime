use duckdb::{params, OptionalExt as _};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{AnalysisContextKeyV1, AnalysisReadControl, AnalysisStore};
use crate::{
    AnalysisConflictSnafu, AnalysisDatabaseSnafu, AnalysisStreamIdentityV1,
    EvidenceIntakeIdentityV1, JsonSnafu, Result,
};

mod notices;
mod profile;

pub use profile::PreparedProfile;

pub const MAX_RESULT_BYTES: usize = usize::MAX;
pub const MAX_RESULT_REFS: usize = usize::MAX;
const MAX_WITNESS_AGE_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ProcessorClassV1 {
    Optional,
    Required,
}

impl ProcessorClassV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }
}

impl TryFrom<&str> for ProcessorClassV1 {
    type Error = ();

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessorScopeV1 {
    pub processor_id: String,
    pub method_version: u64,
    pub identity: EvidenceIntakeIdentityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnalysisWitnessV1 {
    pub identity: AnalysisStreamIdentityV1,
    pub cursor: u64,
    pub expires_utc_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnalysisContextRefV1 {
    pub key: AnalysisContextKeyV1,
    pub commit_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnalysisResultCommitV1 {
    pub scope: ProcessorScopeV1,
    pub expected_cursor: u64,
    pub consumed_cursor: u64,
    pub coverage_revision: u64,
    pub context_revision: u64,
    pub result_id: String,
    pub body: Vec<u8>,
    pub created_utc_ns: u64,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub context_refs: Vec<AnalysisContextRefV1>,
}

impl AnalysisResultCommitV1 {
    pub(super) fn request_meta(&self) -> std::result::Result<Vec<u8>, serde_json::Error> {
        self.request_meta_refs(self.context_revision, &self.context_refs, &[])
    }

    fn request_meta_refs(
        &self,
        context_revision: u64,
        references: &[AnalysisContextRefV1],
        sources: &[(String, u64)],
    ) -> std::result::Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&(
            &self.scope,
            self.expected_cursor,
            self.consumed_cursor,
            self.coverage_revision,
            context_revision,
            &self.result_id,
            self.created_utc_ns,
            &self.witnesses,
            references,
            sources,
        ))
    }

    pub(super) fn request_refs(
        bytes: &[u8],
    ) -> std::result::Result<(Vec<AnalysisWitnessV1>, Vec<AnalysisContextRefV1>), serde_json::Error>
    {
        type Metadata = (
            ProcessorScopeV1,
            u64,
            u64,
            u64,
            u64,
            String,
            u64,
            Vec<AnalysisWitnessV1>,
            Vec<AnalysisContextRefV1>,
            Vec<(String, u64)>,
        );
        let (_, _, _, _, _, _, _, witnesses, contexts, _sources): Metadata =
            serde_json::from_slice(bytes)?;
        Ok((witnesses, contexts))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisResultReceiptV1 {
    pub commit_revision: u64,
    pub consumed_cursor: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisProcessorResultV1 {
    pub result_id: String,
    pub body: Vec<u8>,
    pub commit_revision: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnalysisGapV1 {
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub commit_revision: u64,
}

#[derive(Default)]
struct ProfileHeader {
    stream_key: Option<Vec<u8>>,
    method_version: Option<u64>,
    interval_id: Option<String>,
    profile_revision: Option<u64>,
    facts_revision: Option<u64>,
    coverage_revision: Option<u64>,
    first_cursor: Option<u64>,
}

impl From<&crate::DiscoveryProfileV1> for ProfileHeader {
    fn from(profile: &crate::DiscoveryProfileV1) -> Self {
        Self {
            stream_key: Some(profile.scope.identity.key()),
            method_version: Some(profile.scope.method_version),
            interval_id: Some(profile.interval_id.clone()),
            profile_revision: Some(profile.revision),
            facts_revision: Some(profile.facts_revision),
            coverage_revision: Some(profile.coverage_revision),
            first_cursor: Some(
                profile
                    .snapshot
                    .coverage
                    .first()
                    .map_or(0, |range| range.first_cursor),
            ),
        }
    }
}

impl ProcessorScopeV1 {
    pub(super) fn valid(&self) -> bool {
        !self.processor_id.is_empty() && self.method_version > 0 && self.identity.valid()
    }
}

impl AnalysisStore {
    pub fn processor_gaps(
        &self,
        scope: &ProcessorScopeV1,
        after_cursor: u64,
    ) -> Result<Vec<AnalysisGapV1>> {
        if !scope.valid() {
            return self.reject("the processor gap scope is invalid");
        }
        self.read_snapshot(|reader| {
            let mut statement = reader
                .prepare(
                    "SELECT first_cursor, last_cursor, commit_revision FROM processor_gaps
                 WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?
                 AND last_cursor > ? ORDER BY first_cursor LIMIT 256",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare processor gaps",
                })?;
            let rows = statement
                .query_map(
                    params![
                        scope.processor_id,
                        scope.method_version,
                        scope.identity.tenant_id.as_slice(),
                        scope.identity.key().as_slice(),
                        after_cursor
                    ],
                    |row| {
                        Ok(AnalysisGapV1 {
                            first_cursor: row.get(0)?,
                            last_cursor: row.get(1)?,
                            commit_revision: row.get(2)?,
                        })
                    },
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read processor gaps",
                })?;
            rows.map(|row| {
                row.context(AnalysisDatabaseSnafu {
                    operation: "decode processor gap",
                })
            })
            .collect()
        })
    }

    pub fn processor_result(
        &self,
        scope: &ProcessorScopeV1,
    ) -> Result<Option<AnalysisProcessorResultV1>> {
        if !scope.valid() {
            return self.reject("the processor result scope is invalid");
        }
        self.read_snapshot(|reader| {
            let mut result = reader
                .query_row(
                    "SELECT r.result_id,
                        CASE WHEN r.processor_id = 'graph-findings' AND r.stream_key IS NOT NULL THEN ''::BLOB
                            ELSE r.body END,
                        r.commit_revision
                     FROM processor_progress p JOIN analysis_results r
                       ON r.tenant_id = p.tenant_id AND r.result_id = p.result_id
                         AND r.processor_id = p.processor_id
                     WHERE p.processor_id = ? AND p.method_version = ?
                       AND p.tenant_id = ? AND p.stream_key = ?",
                    params![
                        scope.processor_id,
                        scope.method_version,
                        scope.identity.tenant_id.as_slice(),
                        scope.identity.key().as_slice(),
                    ],
                    |row| {
                        Ok(AnalysisProcessorResultV1 {
                            result_id: row.get(0)?,
                            body: row.get(1)?,
                            commit_revision: row.get(2)?,
                        })
                    },
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "read processor result",
                })?;
            if scope.processor_id == crate::GRAPH_PROCESSOR {
                if let Some(result) = &mut result {
                    result.body = self
                        .read_result_from(reader, scope.identity.tenant_id, &result.result_id)?
                        .ok_or_else(|| self.state_error("the processor graph result is absent"))?;
                }
            }
            if result.as_ref().is_some_and(|result| result.body.is_empty()) {
                return self.reject("the processor result body is empty");
            }
            Ok(result)
        })
    }

    pub fn read_result(&self, tenant: [u8; 16], result_id: &str) -> Result<Option<Vec<u8>>> {
        self.read_snapshot(|reader| self.read_result_from(reader, tenant, result_id))
    }

    pub(super) fn read_result_from(
        &self,
        connection: &duckdb::Connection,
        tenant: [u8; 16],
        result_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        if tenant == [0; 16] || result_id.is_empty() {
            return self.reject("the analysis result identity is invalid");
        }
        let stored: Option<(bool, Vec<u8>)> = connection
            .query_row(
                "SELECT processor_id = 'graph-findings' AND stream_key IS NOT NULL,
                    CASE WHEN processor_id = 'graph-findings' AND stream_key IS NOT NULL THEN ''::BLOB
                        ELSE body END
                FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
                params![tenant.as_slice(), result_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read retained analysis result",
            })?;
        let Some((native, mut body)) = stored else {
            return Ok(None);
        };
        if native {
            let header = super::graph_rows::GraphRows::read_header(connection, tenant, result_id)?
                .ok_or_else(|| self.state_error("the retained graph result is absent"))?;
            let graph = super::graph_rows::GraphRows::read(connection, result_id, &header)?;
            body = header.body(&graph)?;
        }
        if body.is_empty() {
            return self.reject("the retained analysis result size is invalid");
        }
        Ok(Some(body))
    }

    pub fn register_processor(
        &self,
        scope: &ProcessorScopeV1,
        class: ProcessorClassV1,
        start_cursor: u64,
    ) -> Result<u64> {
        self.register_processor_guarded(scope, class, start_cursor, || Ok(()))
    }

    pub fn register_processor_guarded(
        &self,
        scope: &ProcessorScopeV1,
        class: ProcessorClassV1,
        start_cursor: u64,
        check: impl FnMut() -> Result<()>,
    ) -> Result<u64> {
        self.register_processor_with(scope, class, start_cursor, false, check)
    }

    pub fn ensure_optional_processor_guarded(
        &self,
        scope: &ProcessorScopeV1,
        check: impl FnMut() -> Result<()>,
    ) -> Result<u64> {
        self.register_processor_with(scope, ProcessorClassV1::Optional, 1, true, check)
    }

    fn register_processor_with(
        &self,
        scope: &ProcessorScopeV1,
        class: ProcessorClassV1,
        start_cursor: u64,
        keep_existing: bool,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<u64> {
        if !scope.valid() || start_cursor == 0 {
            return self.reject("the processor scope or start cursor is invalid");
        }
        let key = scope.identity.key();
        let mut writer_guard = self.writer()?;
        let writer = writer_guard.get_mut()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin processor registration",
        })?;
        let existing: Option<(String, u64, bool)> = transaction
            .query_row(
                "SELECT class, start_cursor, retired FROM processor_progress
                 WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                params![
                    scope.processor_id,
                    scope.method_version,
                    scope.identity.tenant_id.as_slice(),
                    key.as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read processor registration",
            })?;
        let meta = Self::read_meta_from(&transaction, &self.root.join("analysis.duckdb"))?;
        if let Some(existing) = existing {
            if existing.2
                || (!keep_existing && existing != (class.as_str().to_owned(), start_cursor, false))
            {
                return AnalysisConflictSnafu.fail();
            }
            check()?;
            return Ok(meta.commit_revision);
        }
        let receipt = Self::read_receipt_from(&transaction, &self.root, &scope.identity, &key)?;
        if receipt.as_ref().is_some_and(|receipt| {
            (start_cursor <= receipt.retained_floor
                && !(class == ProcessorClassV1::Optional && start_cursor == 1))
                || start_cursor > receipt.contiguous_cursor.saturating_add(1)
        }) || (receipt.is_none() && start_cursor != 1)
        {
            return self.reject("the processor start is outside retained source input");
        }
        let revision = meta
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
        transaction
            .execute(
                "INSERT INTO processor_progress VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, false, '', '', 0, 0, '')",
                params![
                    scope.processor_id,
                    scope.method_version,
                    scope.identity.tenant_id.as_slice(),
                    key.as_slice(),
                    class.as_str(),
                    start_cursor - 1,
                    start_cursor - 1,
                    start_cursor,
                    start_cursor - 1,
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "register processor",
            })?;
        self.check_logical(&transaction, scope.identity.tenant_id, false)?;
        Self::record_revision(&transaction, revision, &["processor_progress"])?;
        #[cfg(test)]
        self.crash_at("register.before");
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(super::AnalysisCommitStage::BeforeResultCommit)?;
        check()?;
        self.commit_metadata(transaction, "commit processor registration")?;
        #[cfg(test)]
        self.crash_at("register.after");
        self.revision.send_replace(revision);
        Ok(revision)
    }

    pub fn resume_optional(&self, scope: &ProcessorScopeV1) -> Result<Option<AnalysisGapV1>> {
        self.resume_optional_guarded(scope, || Ok(()))
    }

    pub fn resume_optional_guarded(
        &self,
        scope: &ProcessorScopeV1,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Option<AnalysisGapV1>> {
        if !scope.valid() {
            return self.reject("the optional processor scope is invalid");
        }
        let key = scope.identity.key();
        let mut writer_guard = self.maintenance_writer()?;
        let writer = writer_guard.get_mut()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin optional processor resume",
        })?;
        let progress: Option<(String, u64, u64, bool)> = transaction
            .query_row(
                "SELECT class, consumed_cursor, resume_floor, retired FROM processor_progress
                 WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                params![
                    scope.processor_id,
                    scope.method_version,
                    scope.identity.tenant_id.as_slice(),
                    key.as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read optional processor progress",
            })?;
        let Some((class, consumed, resumed, false)) = progress else {
            return AnalysisConflictSnafu.fail();
        };
        if class != ProcessorClassV1::Optional.as_str() {
            return AnalysisConflictSnafu.fail();
        }
        let first = consumed
            .max(resumed)
            .checked_add(1)
            .ok_or_else(|| self.state_error("the optional cursor is exhausted"))?;
        let last: Option<u64> = transaction
            .query_row(
                "SELECT last_cursor FROM expired_ranges
                 WHERE stream_key = ? AND tenant_id = ? AND first_cursor <= ? AND last_cursor >= ?",
                params![
                    key.as_slice(),
                    scope.identity.tenant_id.as_slice(),
                    first,
                    first
                ],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read optional expired gap",
            })?;
        let Some(last_cursor) = last else {
            check()?;
            return Ok(None);
        };
        let receipt = Self::read_receipt_from(&transaction, &self.root, &scope.identity, &key)?
            .ok_or_else(|| self.state_error("the optional processor source is absent"))?;
        if last_cursor > receipt.contiguous_cursor {
            return self.reject("the expired optional gap exceeds accepted evidence");
        }
        let revision = Self::read_meta_from(&transaction, &self.root.join("analysis.duckdb"))?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
        transaction
            .execute(
                "INSERT INTO processor_gaps VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    scope.processor_id,
                    scope.method_version,
                    scope.identity.tenant_id.as_slice(),
                    key.as_slice(),
                    first,
                    last_cursor,
                    revision,
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "record optional missing range",
            })?;
        transaction
            .execute(
                "UPDATE processor_progress SET resume_floor = ?
                 WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                params![
                    last_cursor,
                    scope.processor_id,
                    scope.method_version,
                    scope.identity.tenant_id.as_slice(),
                    key.as_slice(),
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "advance optional resume floor",
            })?;
        self.check_logical(&transaction, scope.identity.tenant_id, true)?;
        Self::record_revision(
            &transaction,
            revision,
            &["processor_gaps", "processor_progress"],
        )?;
        #[cfg(test)]
        self.crash_at("resume.before");
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(super::AnalysisCommitStage::BeforeResultCommit)?;
        check()?;
        self.commit_metadata(transaction, "commit optional processor gap")?;
        #[cfg(test)]
        self.crash_at("resume.after");
        self.revision.send_replace(revision);
        Ok(Some(AnalysisGapV1 {
            first_cursor: first,
            last_cursor,
            commit_revision: revision,
        }))
    }

    pub fn commit_result(&self, input: &AnalysisResultCommitV1) -> Result<AnalysisResultReceiptV1> {
        if input.scope.processor_id == crate::GRAPH_PROCESSOR {
            return self.reject("the graph result requires a guarded graph commit");
        }
        self.commit_progress(
            input,
            None,
            true,
            None,
            None,
            &[],
            &[],
            &[],
            false,
            &mut || Ok(()),
        )
    }

    pub fn commit_graph(
        &self,
        input: &AnalysisResultCommitV1,
        advance: bool,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<AnalysisResultReceiptV1> {
        if input.scope.processor_id != crate::GRAPH_PROCESSOR {
            return self.reject("the graph result owner is invalid");
        }
        let graph = crate::GraphSnapshotV1::try_from(input.body.as_slice())?;
        self.commit_graph_inner(input, &graph, &[], &[], &[], advance, false, &mut check)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The graph commit includes the exact captured source and context inputs."
    )]
    pub fn commit_graph_snapshot(
        &self,
        mut input: AnalysisResultCommitV1,
        prepared: super::graph_rows::CanonicalGraph,
        contexts: &[super::AnalysisContextVersionV1],
        proofs: &[AnalysisContextRefV1],
        sources: &[(String, u64)],
        advance: bool,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<AnalysisResultReceiptV1> {
        if input.scope.processor_id != crate::GRAPH_PROCESSOR {
            return self.reject("the graph result owner is invalid");
        }
        if !input.body.is_empty() {
            return self.reject("the typed graph commit contains independent body bytes");
        }
        let (graph, body) = prepared.into_parts();
        input.body = body;
        self.commit_graph_inner(
            &input, &graph, contexts, proofs, sources, advance, true, &mut check,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The typed graph commit shares one transaction with its exact context inputs."
    )]
    fn commit_graph_inner(
        &self,
        input: &AnalysisResultCommitV1,
        graph: &crate::GraphSnapshotV1,
        contexts: &[super::AnalysisContextVersionV1],
        proofs: &[AnalysisContextRefV1],
        sources: &[(String, u64)],
        advance: bool,
        canonical: bool,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<AnalysisResultReceiptV1> {
        let expected: Vec<_> = graph
            .input_manifest
            .evidence
            .iter()
            .filter(|id| {
                !graph
                    .missing_ranges
                    .iter()
                    .any(|(first, last)| (*first..=*last).contains(&id.durable_cursor))
            })
            .map(|id| {
                (
                    super::AnalysisStreamIdentityV1::Evidence(id.stream.clone()),
                    id.durable_cursor,
                )
            })
            .collect();
        let actual: Vec<_> = input
            .witnesses
            .iter()
            .map(|witness| (witness.identity.clone(), witness.cursor))
            .collect();
        if graph.scope != input.scope
            || expected != actual
            || input
                .witnesses
                .iter()
                .any(|witness| witness.expires_utc_ns != graph.witness_deadline_utc_ns)
            || (advance && graph.last_cursor != input.consumed_cursor)
            || (!advance && input.expected_cursor != input.consumed_cursor)
        {
            return self.reject("the graph input manifest, witnesses, or progress differ");
        }
        self.commit_progress(
            input,
            None,
            advance,
            None,
            Some(graph),
            contexts,
            proofs,
            sources,
            canonical,
            check,
        )
    }

    #[cfg(test)]
    fn commit_working(
        &self,
        input: &AnalysisResultCommitV1,
        previous: Option<u64>,
    ) -> Result<AnalysisResultReceiptV1> {
        if input.scope.processor_id != crate::DISCOVERY_PROCESSOR {
            return self.reject("the working result owner is invalid");
        }
        let profile = crate::DiscoveryProfileV1::try_from(input.body.as_slice())?;
        self.commit_progress(
            input,
            previous,
            true,
            Some(&profile),
            None,
            &[],
            &[],
            &[],
            false,
            &mut || Ok(()),
        )
    }

    #[cfg(test)]
    fn commit_profile(&self, input: &AnalysisResultCommitV1) -> Result<AnalysisResultReceiptV1> {
        if input.scope.processor_id != crate::DISCOVERY_PROCESSOR
            || input.expected_cursor != input.consumed_cursor
        {
            return self.reject("the historical profile cannot advance progress");
        }
        let profile = crate::DiscoveryProfileV1::try_from(input.body.as_slice())?;
        if !profile.sealed {
            return self.reject("the historical profile is not sealed");
        }
        self.commit_progress(
            input,
            None,
            false,
            Some(&profile),
            None,
            &[],
            &[],
            &[],
            false,
            &mut || Ok(()),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "All result variants share one transaction and final commit guard."
    )]
    fn commit_progress(
        &self,
        input: &AnalysisResultCommitV1,
        previous: Option<u64>,
        advance: bool,
        profile: Option<&crate::DiscoveryProfileV1>,
        graph: Option<&crate::GraphSnapshotV1>,
        contexts: &[super::AnalysisContextVersionV1],
        proofs: &[AnalysisContextRefV1],
        sources: &[(String, u64)],
        canonical: bool,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<AnalysisResultReceiptV1> {
        if profile.is_some_and(|profile| {
            profile.scope != input.scope
                || profile.profile_id != input.result_id
                || profile.coverage_revision != input.coverage_revision
                || profile.context_refs != input.context_refs
        }) {
            return self.reject("the profile header or references differ from its commit");
        }
        if !input.scope.valid()
            || input.result_id.is_empty()
            || input.body.is_empty()
            || input.created_utc_ns == 0
            || input.consumed_cursor < input.expected_cursor
            || input.witnesses.windows(2).any(|pair| {
                (&pair[0].identity, pair[0].cursor) >= (&pair[1].identity, pair[1].cursor)
            })
            || input
                .context_refs
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
            || input.context_refs.iter().any(|reference| {
                !reference.key.valid()
                    || reference.key.tenant_id != input.scope.identity.tenant_id
                    || reference.commit_revision == 0
            })
        {
            return self.reject("the analysis result or progress bounds are invalid");
        }
        if (graph.is_none() && (!contexts.is_empty() || !proofs.is_empty() || !sources.is_empty()))
            || sources.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || sources.iter().any(|(relation, _)| relation.is_empty())
            || contexts.windows(2).any(|pair| pair[0].key >= pair[1].key)
            || contexts.iter().any(|context| {
                !context.valid() || context.key.tenant_id != input.scope.identity.tenant_id
            })
            || proofs.windows(2).any(|pair| pair[0].key >= pair[1].key)
            || proofs.iter().any(|reference| {
                !reference.key.valid()
                    || reference.key.tenant_id != input.scope.identity.tenant_id
                    || reference.commit_revision == 0
            })
        {
            return self.reject("the graph publication contexts are invalid");
        }
        let mut expected_keys = std::collections::BTreeSet::new();
        if let Some(graph) = graph {
            if graph.scope != input.scope {
                return self.reject("the graph manifest differs from its result commit");
            }
            expected_keys.extend(graph.input_manifest.context.iter());
            let package_key =
                crate::GraphSnapshotV1::package_key(&graph.scope.identity, &input.result_id);
            if let Some(reference) = input
                .context_refs
                .iter()
                .find(|reference| reference.key == package_key)
            {
                expected_keys.insert(&reference.key);
            }
            for context in contexts {
                if crate::PackageBundleRef::provenance(context)?.is_some() {
                    expected_keys.insert(&context.key);
                } else {
                    let fact = crate::GraphFactV1::try_from(context)?;
                    if !expected_keys.contains(&context.key) || !graph.graph.facts.contains(&fact) {
                        return self.reject("the proposed fact differs from the graph manifest");
                    }
                }
            }
            expected_keys.extend(proofs.iter().map(|reference| &reference.key));
        }
        let witness_deadline = input
            .created_utc_ns
            .checked_add(MAX_WITNESS_AGE_NS)
            .ok_or_else(|| self.state_error("the witness deadline is exhausted"))?;
        if input.witnesses.iter().any(|witness| {
            witness.identity.tenant() != input.scope.identity.tenant_id
                || !witness.identity.valid()
                || witness.cursor == 0
                || witness.expires_utc_ns < input.created_utc_ns
                || witness.expires_utc_ns > witness_deadline
        }) {
            return self.reject("the result has a foreign or invalid witness");
        }
        let path = self.root.join("analysis.duckdb");
        let graph_header = graph
            .map(|graph| {
                if canonical {
                    super::graph_rows::GraphRows::encode_canonical(graph, &input.body)
                } else {
                    super::graph_rows::GraphRows::encode_body(graph, &input.body)
                }
            })
            .transpose()?;
        let body = graph_header.as_deref().unwrap_or(input.body.as_slice());
        let key = input.scope.identity.key();
        let mut writer_guard = self.maintenance_writer()?;
        let writer = writer_guard.get_mut()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin analysis result",
        })?;
        let existing = transaction
            .query_row(
                "SELECT CASE WHEN octet_length(tenant_id) = 16 THEN tenant_id ELSE NULL END,
                request_meta,
                CASE WHEN processor_id = 'graph-findings' AND stream_key IS NOT NULL THEN ''::BLOB
                    ELSE body END,
                commit_revision FROM analysis_results WHERE result_id = ?",
                params![input.result_id],
                |row| {
                    Ok((
                        row.get::<_, Option<Vec<u8>>>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, u64>(3)?,
                    ))
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read immutable result",
            })?;
        if existing.is_none() {
            let revision = Self::read_meta_from(&transaction, &self.root)?.commit_revision;
            if sources.iter().any(|(_, captured)| *captured > revision)
                || !Self::package_sources_current(
                    &transaction,
                    sources,
                    &AnalysisReadControl::default(),
                )?
            {
                return AnalysisConflictSnafu.fail();
            }
        }
        let mut context_write = None;
        let inserted =
            self.context_rows(&transaction, contexts, false, None, &mut context_write)?;
        let mut references = std::borrow::Cow::Borrowed(input.context_refs.as_slice());
        if !inserted.is_empty() || !proofs.is_empty() {
            references.to_mut().extend(inserted);
            references.to_mut().extend_from_slice(proofs);
            references
                .to_mut()
                .sort_by(|left, right| left.key.cmp(&right.key));
            if references
                .windows(2)
                .any(|pair| pair[0].key == pair[1].key && pair[0] != pair[1])
            {
                return AnalysisConflictSnafu.fail();
            }
            references.to_mut().dedup();
        }
        if graph.is_some_and(|_| {
            !expected_keys
                .iter()
                .copied()
                .eq(references.iter().map(|reference| &reference.key))
        }) {
            return self.reject("the graph manifest differs from its result commit");
        }
        let context_revision = references
            .iter()
            .map(|reference| reference.commit_revision)
            .max()
            .unwrap_or(0);
        if input.context_revision
            != input
                .context_refs
                .iter()
                .map(|reference| reference.commit_revision)
                .max()
                .unwrap_or(0)
        {
            return self.reject("the result context revision differs from its captured references");
        }
        let header = if let Some(graph) = graph {
            ProfileHeader {
                stream_key: Some(input.scope.identity.key()),
                method_version: Some(input.scope.method_version),
                interval_id: Some(graph.first_cursor.to_string()),
                profile_revision: None,
                facts_revision: Some(graph.context_notice_revision),
                coverage_revision: Some(input.coverage_revision),
                first_cursor: Some(graph.first_cursor),
            }
        } else {
            profile.map(ProfileHeader::from).unwrap_or_default()
        };
        let request = if contexts.is_empty() && proofs.is_empty() && sources.is_empty() {
            input.request_meta()
        } else {
            input.request_meta_refs(context_revision, &references, sources)
        }
        .context(JsonSnafu { path: &path })?;

        let replacing = existing.is_some() && previous.is_some();
        if let Some((tenant, stored, retained, revision)) = existing {
            let (Some(tenant), Some(stored), Some(mut retained)) = (tenant, stored, retained)
            else {
                return self.reject("the retained analysis result exceeds its byte bound");
            };
            if tenant == input.scope.identity.tenant_id && stored == request && graph.is_some() {
                retained = self
                    .read_result_from(
                        &transaction,
                        input.scope.identity.tenant_id,
                        &input.result_id,
                    )?
                    .ok_or_else(|| self.state_error("the retry graph result is absent"))?;
            }
            if tenant == input.scope.identity.tenant_id
                && stored == request
                && retained == input.body
            {
                check()?;
                return Ok(AnalysisResultReceiptV1 {
                    commit_revision: revision,
                    consumed_cursor: input.consumed_cursor,
                });
            }
            if tenant != input.scope.identity.tenant_id || previous != Some(revision) {
                return AnalysisConflictSnafu.fail();
            }
            let profile = crate::DiscoveryProfileV1::try_from(retained.as_slice())?;
            if profile.sealed
                || profile.scope != input.scope
                || profile.profile_id != input.result_id
            {
                return AnalysisConflictSnafu.fail();
            }
        } else if previous.is_some() {
            return AnalysisConflictSnafu.fail();
        }
        if let Some(graph) = graph {
            let head: Option<String> = transaction
                .query_row(
                    "SELECT result_id FROM analysis_results WHERE tenant_id = ?
                     AND processor_id = ? AND method_version = ? AND stream_key = ?
                     AND first_cursor = ? ORDER BY commit_revision DESC LIMIT 1",
                    params![
                        input.scope.identity.tenant_id.as_slice(),
                        input.scope.processor_id,
                        input.scope.method_version,
                        key.as_slice(),
                        graph.first_cursor
                    ],
                    |row| row.get(0),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "read expected graph window head",
                })?;
            if head.as_deref() != graph.previous_result_id.as_deref() {
                return AnalysisConflictSnafu.fail();
            }
        }
        let progress: Option<(u64, u64, bool, String)> = transaction
            .query_row(
                "SELECT consumed_cursor, resume_floor, retired, result_id FROM processor_progress
                 WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                params![
                    input.scope.processor_id,
                    input.scope.method_version,
                    input.scope.identity.tenant_id.as_slice(),
                    key.as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read expected progress",
            })?;
        if !progress
            .as_ref()
            .is_some_and(|(consumed, resumed, retired, result)| {
                !retired
                    && (*consumed).max(*resumed) == input.expected_cursor
                    && (!replacing || result == &input.result_id)
            })
        {
            return AnalysisConflictSnafu.fail();
        }
        let receipt =
            Self::read_receipt_from(&transaction, &self.root, &input.scope.identity, &key)?
                .ok_or_else(|| self.state_error("the processor source is absent"))?;
        if input.consumed_cursor > receipt.contiguous_cursor
            || input.coverage_revision > receipt.coverage_revision
        {
            return self.reject("the result claims unavailable source or coverage progress");
        }
        let expected = input.consumed_cursor - input.expected_cursor;
        let revision = Self::read_meta_from(&transaction, &self.root)?.commit_revision;
        let available = self
            .raw
            .lock()
            .map_err(|_| self.state_error("the raw owner lock is poisoned"))?
            .record_count(
                &key,
                input.expected_cursor.saturating_add(1),
                input.consumed_cursor,
                revision,
            );
        if available != expected {
            return self.reject("the processor result skips unavailable raw input");
        }
        let mut checked_context = 0;
        for reference in references.as_ref() {
            let Some((_, revision)) =
                Self::read_context_from(&transaction, &self.root, &reference.key)?
            else {
                return self.reject("the result context version is absent");
            };
            if revision != reference.commit_revision {
                return self.reject("the result context commit revision differs");
            }
            checked_context = checked_context.max(revision);
        }
        if context_revision != checked_context {
            return self.reject("the result context revision differs from its references");
        }
        let witness_segments = self.resolve_witnesses(&input.witnesses, revision)?;
        if !advance {
            if let Some((graph, previous)) = graph.and_then(|graph| {
                graph
                    .previous_result_id
                    .as_deref()
                    .map(|previous| (graph, previous))
            }) {
                let retained = super::graph_rows::GraphRows::read_header(
                    &transaction,
                    input.scope.identity.tenant_id,
                    previous,
                )?
                .ok_or_else(|| self.state_error("the expected graph header is absent"))?;
                let retained =
                    super::graph_rows::GraphRows::read(&transaction, previous, &retained)?;
                let (metadata, retained_revision): (Option<Vec<u8>>, u64) = transaction.query_row(
                    "SELECT CASE WHEN octet_length(request_meta) <= ? THEN request_meta ELSE NULL END,
                        commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
                    params![MAX_RESULT_BYTES as u64, input.scope.identity.tenant_id.as_slice(), previous],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                ).context(AnalysisDatabaseSnafu { operation: "read graph no-op attribution" })?;
                let metadata = metadata
                    .ok_or_else(|| self.state_error("the graph attribution exceeds its bound"))?;
                let (_, retained_refs) = AnalysisResultCommitV1::request_refs(&metadata)
                    .context(JsonSnafu { path: &path })?;
                if retained.last_cursor == graph.last_cursor
                    && retained.input_manifest == graph.input_manifest
                    && retained.graph == graph.graph
                    && retained.findings == graph.findings
                    && retained.packages == graph.packages
                    && retained.input_positions == graph.input_positions
                    && retained.witness_deadline_utc_ns > input.created_utc_ns
                    && retained_refs == references.as_ref()
                {
                    if context_write.is_some() {
                        return self.reject("the unchanged graph added context versions");
                    }
                    self.notice_rows(
                        &transaction,
                        &input.scope,
                        previous,
                        retained_revision,
                        graph.context_notice_revision,
                        input.coverage_revision,
                    )?;
                    #[cfg(any(test, feature = "test-fixtures"))]
                    self.run_commit_hook(super::AnalysisCommitStage::BeforeResultCommit)?;
                    check()?;
                    self.commit_metadata(transaction, "commit unchanged graph notice")?;
                    return Ok(AnalysisResultReceiptV1 {
                        commit_revision: retained_revision,
                        consumed_cursor: input.consumed_cursor,
                    });
                }
            }
        }
        let revision = Self::read_meta_from(&transaction, &path)?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
        if replacing {
            transaction
                .execute(
                    "DELETE FROM evidence_refs WHERE ref_id = ?",
                    params![input.result_id],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "replace working witnesses",
                })?;
            transaction
                .execute(
                    "DELETE FROM context_refs WHERE ref_id = ?",
                    params![input.result_id],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "replace working contexts",
                })?;
            transaction
                .execute(
                    "UPDATE analysis_results SET body = ?, request_meta = ?, commit_revision = ?,
                 stream_key = ?, method_version = ?, interval_id = ?, profile_revision = ?,
                 facts_revision = ?, coverage_revision = ?, first_cursor = ? WHERE result_id = ?",
                    params![
                        body,
                        request.as_slice(),
                        revision,
                        header.stream_key.as_deref(),
                        header.method_version,
                        header.interval_id,
                        header.profile_revision,
                        header.facts_revision,
                        header.coverage_revision,
                        header.first_cursor,
                        input.result_id
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "update working result",
                })?;
        } else {
            transaction
                .execute(
                    "INSERT INTO analysis_results (result_id, tenant_id, processor_id, body,
                        request_meta, commit_revision, stream_key, method_version, interval_id,
                        profile_revision, facts_revision, coverage_revision, first_cursor)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    params![
                        input.result_id,
                        input.scope.identity.tenant_id.as_slice(),
                        input.scope.processor_id,
                        body,
                        request.as_slice(),
                        revision,
                        header.stream_key.as_deref(),
                        header.method_version,
                        header.interval_id,
                        header.profile_revision,
                        header.facts_revision,
                        header.coverage_revision,
                        header.first_cursor,
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert analysis result",
                })?;
        }
        if let Some(graph) = graph {
            super::graph_rows::GraphRows::insert(graph, &transaction, &input.result_id)?;
        }
        Self::insert_references(
            &transaction,
            &input.result_id,
            &input.witnesses,
            &witness_segments,
            &references,
        )?;
        if advance {
            transaction
            .execute(
                "UPDATE processor_progress SET consumed_cursor = ?, coverage_revision = ?,
                 context_revision = ?, required_floor = ?, result_id = ?
                 WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                params![
                    input.consumed_cursor,
                    input.coverage_revision,
                    context_revision,
                    input.consumed_cursor,
                    input.result_id,
                    input.scope.processor_id,
                    input.scope.method_version,
                    input.scope.identity.tenant_id.as_slice(),
                    key.as_slice(),
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "advance processor progress",
            })?;
        }
        let mut relations = vec!["analysis_results"];
        if graph.is_some() {
            relations.extend(["graph_subjects", "graph_relationships", "graph_findings"]);
        }
        if context_write.is_some() {
            relations.push("context_versions");
        }
        if advance {
            relations.push("processor_progress");
        }
        if !input.witnesses.is_empty() {
            relations.push("evidence_refs");
        }
        if !references.is_empty() {
            relations.push("context_refs");
        }
        self.check_logical(
            &transaction,
            input.scope.identity.tenant_id,
            profile.is_none(),
        )?;
        self.check_witnesses(
            &transaction,
            input.scope.identity.tenant_id,
            input.created_utc_ns,
        )?;
        Self::record_revision(&transaction, revision, &relations)?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.crash_at("result.before");
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(super::AnalysisCommitStage::BeforeResultCommit)?;
        check()?;
        self.commit_metadata(transaction, "commit analysis result")?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.crash_at("result.after");
        self.revision.send_replace(revision);
        Ok(AnalysisResultReceiptV1 {
            commit_revision: revision,
            consumed_cursor: input.consumed_cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnalysisContextVersionV1, ContextSensitivityV1, EvidenceStoreOutcomeV1,
        ValidatedEvidenceBatchV1,
    };

    fn identity(tenant: u8) -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: [tenant; 16],
            ..crate::analysis::tests::identity()
        }
    }

    #[test]
    fn registration_guard_rolls_back() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let scope = ProcessorScopeV1 {
            processor_id: "guarded-processor".into(),
            method_version: 1,
            identity: identity(1),
        };
        let before = store.meta()?;
        let mut notices = store.subscribe_revision();
        let control = std::sync::Arc::new(crate::AnalysisReadControl::default());
        control.check()?;
        let cancelled = std::sync::Arc::clone(&control);
        store.set_commit_hook(
            super::super::AnalysisCommitStage::BeforeResultCommit,
            move || cancelled.cancel(),
        )?;
        assert!(matches!(
            store.register_processor_guarded(&scope, ProcessorClassV1::Required, 1, || {
                control.check()
            }),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.meta()?, before);
        assert!(store.processor_health(&scope)?.is_none());
        assert!(!notices.has_changed()?);
        let revision =
            store.register_processor_guarded(&scope, ProcessorClassV1::Optional, 1, || Ok(()))?;
        assert!(revision > before.commit_revision);
        notices.borrow_and_update();
        let committed = store.meta()?;
        assert!(matches!(
            store.register_processor_guarded(&scope, ProcessorClassV1::Optional, 1, || {
                control.check()
            }),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.meta()?, committed);
        assert!(!notices.has_changed()?);
        let health = store.processor_health(&scope)?;
        drop(store);
        let reopened = AnalysisStore::open(root)?;
        assert_eq!(reopened.processor_health(&scope)?, health);
        assert_eq!(
            reopened.register_processor(&scope, ProcessorClassV1::Optional, 1)?,
            revision
        );
        assert_eq!(reopened.meta()?, committed);
        Ok(())
    }

    #[test]
    fn optional_registration_preserves_state() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let scope = ProcessorScopeV1 {
            processor_id: "existing-required".into(),
            method_version: 1,
            identity: identity(1),
        };
        store.accept_validated_batch(
            scope.identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                framed_records: b"frame".to_vec().into(),
                frame_ends: vec![5],
            },
        )?;
        let revision = store.register_processor(&scope, ProcessorClassV1::Required, 2)?;
        let health = store.processor_health(&scope)?;
        let before = store.meta()?;
        let mut notices = store.subscribe_revision();
        assert_eq!(
            store.ensure_optional_processor_guarded(&scope, || Ok(()))?,
            revision
        );
        assert_eq!(store.processor_health(&scope)?, health);
        assert_eq!(store.meta()?, before);
        assert!(!notices.has_changed()?);
        assert_eq!(
            store.register_processor(&scope, ProcessorClassV1::Required, 2)?,
            revision
        );
        assert!(matches!(
            store.register_processor(&scope, ProcessorClassV1::Optional, 1),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        let control = crate::AnalysisReadControl::default();
        control.cancel()?;
        assert!(matches!(
            store.ensure_optional_processor_guarded(&scope, || control.check()),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.processor_health(&scope)?, health);
        assert_eq!(store.meta()?, before);
        assert!(!notices.has_changed()?);
        let missing = ProcessorScopeV1 {
            processor_id: "missing-optional".into(),
            ..scope.clone()
        };
        assert!(matches!(
            store.ensure_optional_processor_guarded(&missing, || control.check()),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert!(store.processor_health(&missing)?.is_none());
        assert_eq!(store.meta()?, before);
        assert!(!notices.has_changed()?);
        let registered = store.ensure_optional_processor_guarded(&missing, || Ok(()))?;
        assert!(registered > revision);
        assert_eq!(
            store
                .processor_health(&missing)?
                .ok_or("optional registration absent")?
                .class,
            ProcessorClassV1::Optional
        );
        let committed = store.meta()?;
        notices.borrow_and_update();
        assert_eq!(
            store.ensure_optional_processor_guarded(&missing, || Ok(()))?,
            registered
        );
        assert_eq!(
            store.register_processor(&missing, ProcessorClassV1::Optional, 1)?,
            registered
        );
        assert_eq!(store.meta()?, committed);
        assert!(!notices.has_changed()?);
        store.retire_required(&crate::ProcessorRetirementV1 {
            scope: scope.clone(),
            change_id: "retire-existing".into(),
            reason: "Stop this required processor.".into(),
            expected_cursor: 1,
            cutoff_cursor: 1,
        })?;
        let retired = store.meta()?;
        let retirement = store.processor_retirement(&scope)?;
        notices.borrow_and_update();
        assert!(matches!(
            store.ensure_optional_processor_guarded(&scope, || Ok(())),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert_eq!(store.meta()?, retired);
        assert_eq!(store.processor_retirement(&scope)?, retirement);
        assert!(!notices.has_changed()?);
        drop(store);
        let reopened = AnalysisStore::open(root)?;
        assert_eq!(reopened.processor_retirement(&scope)?, retirement);
        assert!(matches!(
            reopened.ensure_optional_processor_guarded(&scope, || Ok(())),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        Ok(())
    }

    #[test]
    fn resume_guard_rolls_back() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = crate::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        };
        let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
        let scope = ProcessorScopeV1 {
            processor_id: "guarded-processor".into(),
            method_version: 1,
            identity: identity(1),
        };
        store.accept_validated_batch(
            scope.identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                framed_records: b"frame".to_vec().into(),
                frame_ends: vec![5],
            },
        )?;
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        assert_eq!(
            crate::EvidenceRetentionOwner::new(&store)
                .step(100)?
                .removed_records,
            1
        );
        let before = store.meta()?;
        let health = store.processor_health(&scope)?;
        let mut notices = store.subscribe_revision();
        let control = std::sync::Arc::new(crate::AnalysisReadControl::default());
        control.check()?;
        let cancelled = std::sync::Arc::clone(&control);
        store.set_commit_hook(
            super::super::AnalysisCommitStage::BeforeResultCommit,
            move || cancelled.cancel(),
        )?;
        assert!(matches!(
            store.resume_optional_guarded(&scope, || control.check()),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.meta()?, before);
        assert_eq!(store.processor_health(&scope)?, health);
        assert!(store.processor_gaps(&scope, 0)?.is_empty());
        assert!(!notices.has_changed()?);
        let gap = store
            .resume_optional_guarded(&scope, || Ok(()))?
            .ok_or("resume gap absent")?;
        assert_eq!((gap.first_cursor, gap.last_cursor), (1, 1));
        assert_eq!(store.processor_gaps(&scope, 0)?, [gap]);
        notices.borrow_and_update();
        let committed = store.meta()?;
        assert!(matches!(
            store.resume_optional_guarded(&scope, || control.check()),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.meta()?, committed);
        assert!(!notices.has_changed()?);
        drop(store);
        let reopened = AnalysisStore::open_with_limits(root, limits, Default::default())?;
        assert_eq!(reopened.processor_gaps(&scope, 0)?, [gap]);
        assert_eq!(reopened.resume_optional(&scope)?, None);
        assert_eq!(reopened.meta()?, committed);
        Ok(())
    }

    #[test]
    fn analysis_store_result_progress() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let source = identity(1);
        let scope = ProcessorScopeV1 {
            processor_id: "security-file".into(),
            method_version: 1,
            identity: source.clone(),
        };
        assert_eq!(
            store.register_processor(&scope, ProcessorClassV1::Required, 1)?,
            1
        );
        assert_eq!(
            store.register_processor(&scope, ProcessorClassV1::Required, 1)?,
            1
        );
        assert!(matches!(
            store.register_processor(&scope, ProcessorClassV1::Optional, 1),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert_eq!(
            store.accept_validated_batch(
                source.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: 1,
                    last_cursor: 1,
                    intake_utc_ns: 1_000_000_000,
                    framed_records: b"frame".to_vec().into(),
                    frame_ends: vec![5],
                },
            )?,
            EvidenceStoreOutcomeV1::Accepted
        );
        let context = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: source.tenant_id,
                owner_id: "policy".into(),
                entity_key: b"workload".to_vec(),
                lifetime_key: b"pod".to_vec(),
                owner_revision: 1,
            },
            valid_from_utc_ns: Some(1),
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: b"verified-context".to_vec(),
        };
        let context_revision = store.commit_context(&context)?;
        let mut input = AnalysisResultCommitV1 {
            context_revision,
            body: b"result".to_vec(),
            created_utc_ns: 1_000_000_000,
            witnesses: vec![AnalysisWitnessV1 {
                identity: source.into(),
                cursor: 1,
                expires_utc_ns: 1_000_000_001,
            }],
            context_refs: vec![AnalysisContextRefV1 {
                key: context.key.clone(),
                commit_revision: context_revision,
            }],
            ..crate::analysis::tests::result(scope, "finding-1".into())
        };
        let mut invalid = input.clone();
        assert!(store.processor_result(&input.scope)?.is_none());
        invalid.body.clear();
        assert!(store.commit_result(&invalid).is_err());
        invalid = input.clone();
        invalid.context_refs[0].commit_revision = 0;
        assert!(store.commit_result(&invalid).is_err());
        let receipt = store.commit_result(&input)?;
        assert_eq!(receipt.commit_revision, 4);
        assert_eq!(receipt.consumed_cursor, 1);
        let head = AnalysisProcessorResultV1 {
            result_id: input.result_id.clone(),
            body: input.body.clone(),
            commit_revision: receipt.commit_revision,
        };
        assert_eq!(store.processor_result(&input.scope)?, Some(head.clone()));
        let mut foreign = input.scope.clone();
        foreign.identity.tenant_id = [4; 16];
        assert!(store.processor_result(&foreign)?.is_none());
        assert_eq!(
            store.read_result([1; 16], "finding-1")?,
            Some(b"result".to_vec())
        );
        assert_eq!(store.read_result([4; 16], "finding-1")?, None);
        assert_eq!(store.read_result([1; 16], "missing")?, None);
        assert_eq!(store.commit_result(&input)?, receipt);
        assert_eq!(store.meta()?.commit_revision, 4);
        {
            let reader = store.reader()?;
            let (request, body): (Vec<u8>, Vec<u8>) = reader.get()?.query_row(
                "SELECT request_meta, body FROM analysis_results WHERE result_id = ?",
                params![input.result_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert_eq!(request, input.request_meta()?);
            assert_eq!(body, input.body);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&request)?,
                serde_json::json!([
                    input.scope,
                    input.expected_cursor,
                    input.consumed_cursor,
                    input.coverage_revision,
                    input.context_revision,
                    input.result_id,
                    input.created_utc_ns,
                    input.witnesses,
                    input.context_refs,
                ])
            );
        }
        for change in 0..16 {
            let mut changed = input.clone();
            match change {
                0 => changed.scope.processor_id.push('x'),
                1 => changed.scope.method_version += 1,
                2 => changed.scope.identity.node_id.push('x'),
                3 => changed.expected_cursor += 1,
                4 => changed.consumed_cursor += 1,
                5 => changed.coverage_revision += 1,
                6 => changed.context_revision += 1,
                7 => changed.body.push(0),
                8 => changed.created_utc_ns += 1,
                9 => changed.witnesses[0].expires_utc_ns += 1,
                10 => changed.witnesses[0].cursor += 1,
                11 => changed.witnesses.clear(),
                12 => changed.context_refs[0].commit_revision += 1,
                13 => changed.context_refs[0].key.owner_revision += 1,
                14 => changed.context_refs.clear(),
                _ => {
                    changed.scope.identity.tenant_id = [4; 16];
                    changed.witnesses.clear();
                    changed.context_refs.clear();
                }
            }
            assert!(
                matches!(
                    store.commit_result(&changed),
                    Err(crate::Error::AnalysisConflict { .. })
                ),
                "changed request component {change}"
            );
            assert_eq!(store.meta()?.commit_revision, 4);
        }
        let path = directory.path().join("analysis");
        drop(store);
        let store = AnalysisStore::open(path)?;
        assert_eq!(store.processor_result(&input.scope)?, Some(head));
        assert_eq!(store.commit_result(&input)?, receipt);
        input.result_id = "finding-2".into();
        assert!(matches!(
            store.commit_result(&input),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert_eq!(store.meta()?.commit_revision, 4);
        input.expected_cursor = 1;
        input.context_refs[0].commit_revision += 1;
        assert!(store.commit_result(&input).is_err());
        input.context_refs[0].commit_revision -= 1;
        input.witnesses[0].identity = identity(4).into();
        assert!(store.commit_result(&input).is_err());
        assert_eq!(store.meta()?.commit_revision, 4);
        store.writer()?.get()?.execute(
            "UPDATE analysis_results SET body = ? WHERE result_id = ?",
            params![b"".as_slice(), "finding-1"],
        )?;
        assert!(matches!(
            store.read_result([1; 16], "finding-1"),
            Err(crate::Error::AnalysisState { .. })
        ));
        Ok(())
    }

    #[test]
    fn observability_recovery_mixed_witnesses(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::{
            AnalysisReadControl, EvidenceRetentionOwner, RetentionLimitsV1, TraceBatchV1,
            TraceBindingV1, TraceCleanupV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1,
            TraceIntentV1, TraceSourceV1, TraceTerminalReasonV1, TraceTerminalV1,
        };

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: Some(100),
            raw_max_bytes: Some(64 * 1024 * 1024),
        };
        let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
        let evidence = identity(1);
        store.accept_validated_batch(
            evidence.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 100,
                framed_records: b"event".to_vec().into(),
                frame_ends: vec![5],
            },
        )?;
        let scope = ProcessorScopeV1 {
            processor_id: "mixed-witness".into(),
            method_version: 1,
            identity: evidence.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        let source = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
        let diagnostic = TraceIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            request_id: [7; 16],
            execution_id: [8; 16],
            source_sha256: source.sha256,
        };
        store.accept_trace(&TraceIntentV1 {
            tenant_id: [1; 16],
            request_id: diagnostic.request_id,
            source,
            bindings: vec![TraceBindingV1 {
                binding_id: [9; 16],
                identity: diagnostic.clone(),
                namespace_uid: "namespace-a".into(),
            }],
            authority: b"Control-owned inputs".to_vec(),
            accepted_unix_ns: 100,
            deadline_unix_ns: 1_000_000_000,
            host_sensitive: true,
        })?;
        let frame = TraceFrameV1 {
            execution_id: diagnostic.execution_id,
            sequence: 1,
            kind: TraceFrameKindV1::Data,
            bytes: b"raw\n".to_vec(),
        };
        let terminal = TraceTerminalV1 {
            execution_id: diagnostic.execution_id,
            reason: TraceTerminalReasonV1::Completed,
            last_sequence: 1,
            output_bytes: 4,
            output_incomplete: false,
            kernel_lost_events: None,
            ready_at_unix_ns: None,
            exit_code: Some(0),
            forced_kill: false,
            cleanup: TraceCleanupV1::Unknown,
        };
        store.append_trace(
            &diagnostic,
            &TraceBatchV1 {
                execution_id: diagnostic.execution_id,
                frames: vec![frame.clone()],
                terminal: Some(terminal.clone()),
            },
            100,
        )?;
        let input = AnalysisResultCommitV1 {
            body: b"result".to_vec(),
            created_utc_ns: 101,
            witnesses: vec![
                AnalysisWitnessV1 {
                    identity: evidence.into(),
                    cursor: 1,
                    expires_utc_ns: 300,
                },
                AnalysisWitnessV1 {
                    identity: diagnostic.clone().into(),
                    cursor: 2,
                    expires_utc_ns: 300,
                },
            ],
            ..crate::analysis::tests::result(scope, "mixed-result".into())
        };
        let mut invalid = input.clone();
        invalid.witnesses[1].cursor = 3;
        assert!(store.commit_result(&invalid).is_err());
        invalid.witnesses[1].cursor = 2;
        invalid.witnesses[1].identity = TraceIdentityV1 {
            source_sha256: [9; 32],
            ..diagnostic.clone()
        }
        .into();
        assert!(store.commit_result(&invalid).is_err());
        invalid.witnesses[1].identity = TraceIdentityV1 {
            tenant_id: [9; 16],
            ..diagnostic.clone()
        }
        .into();
        assert!(store.commit_result(&invalid).is_err());
        assert!(store.read_result([1; 16], "mixed-result")?.is_none());
        let receipt = store.commit_result(&input)?;
        let retained = EvidenceRetentionOwner::new(&store).retain_trace(&diagnostic, 201)?;
        assert_eq!(retained.removed_records, 0);
        assert_eq!(retained.retained_floor, 0);
        drop(store);

        let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
        assert_eq!(store.commit_result(&input)?, receipt);
        assert_eq!(
            store.read_result([1; 16], "mixed-result")?,
            Some(b"result".to_vec())
        );
        let output = store.read_trace(&diagnostic, 1, &AnalysisReadControl::default())?;
        assert_eq!(output.frames, vec![frame]);
        assert_eq!(output.terminal, Some(terminal));
        let expired = EvidenceRetentionOwner::new(&store).retain_trace(&diagnostic, 301)?;
        assert_eq!(expired.removed_records, 2);
        assert_eq!(expired.retained_floor, 2);
        assert!(matches!(
            store.read_trace(&diagnostic, 1, &AnalysisReadControl::default()),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        assert_eq!(store.commit_result(&input)?, receipt);
        Ok(())
    }
}
