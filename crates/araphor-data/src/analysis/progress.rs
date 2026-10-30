use duckdb::{params, OptionalExt as _};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{AnalysisContextKeyV1, AnalysisStore};
use crate::{
    AnalysisConflictSnafu, AnalysisDatabaseSnafu, AnalysisStreamIdentityV1,
    EvidenceIntakeIdentityV1, JsonSnafu, Result,
};

mod graph;
mod notices;
mod profile;

pub use profile::{DiscoveryProducer, PreparedProfile, ProfileCommit};

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

#[derive(Clone, Copy)]
pub(in crate::analysis) enum ResultHead<'a> {
    Unchecked,
    Working(u64),
    Current(Option<&'a super::PackageResultRefV1>),
}

pub(in crate::analysis) struct ProgressWrite {
    pub(in crate::analysis) receipt: AnalysisResultReceiptV1,
    pub(in crate::analysis) relations: Vec<&'static str>,
    pub(in crate::analysis) commit: bool,
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
            let result = reader
                .query_row(
                    "SELECT r.result_id, r.body, r.commit_revision
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
        let body: Option<Vec<u8>> = connection
            .query_row(
                "SELECT body FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
                params![tenant.as_slice(), result_id],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read retained analysis result",
            })?;
        let Some(body) = body else {
            return Ok(None);
        };
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
        self.check_revision_limits(&transaction, scope.identity.tenant_id)?;
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
        let gap = AnalysisGapV1 {
            first_cursor: first,
            last_cursor,
            commit_revision: revision,
        };
        Self::insert_processor_gaps(&transaction, scope, std::slice::from_ref(&gap))?;
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
        self.check_revision_limits(&transaction, scope.identity.tenant_id)?;
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
        Ok(Some(gap))
    }

    fn insert_processor_gaps(
        transaction: &duckdb::Transaction<'_>,
        scope: &ProcessorScopeV1,
        gaps: &[AnalysisGapV1],
    ) -> Result<()> {
        let key = scope.identity.key();
        let mut statement = transaction
            .prepare("INSERT INTO processor_gaps VALUES (?, ?, ?, ?, ?, ?, ?)")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare optional missing ranges",
            })?;
        for gap in gaps {
            statement
                .execute(params![
                    scope.processor_id,
                    scope.method_version,
                    scope.identity.tenant_id.as_slice(),
                    key.as_slice(),
                    gap.first_cursor,
                    gap.last_cursor,
                    gap.commit_revision,
                ])
                .context(AnalysisDatabaseSnafu {
                    operation: "record optional missing range",
                })?;
        }
        Ok(())
    }

    pub fn commit_result(&self, input: &AnalysisResultCommitV1) -> Result<AnalysisResultReceiptV1> {
        if input.scope.processor_id == crate::GRAPH_PROCESSOR {
            return self.reject("the graph result requires a guarded graph commit");
        }
        self.commit_progress(input, None, true, None, &[], &mut || Ok(()))
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
        self.commit_progress(input, previous, true, Some(&profile), &[], &mut || Ok(()))
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
        self.commit_progress(input, None, false, Some(&profile), &[], &mut || Ok(()))
    }

    fn commit_progress(
        &self,
        input: &AnalysisResultCommitV1,
        previous: Option<u64>,
        advance: bool,
        profile: Option<&crate::DiscoveryProfileV1>,
        contexts: &[super::AnalysisContextVersionV1],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<AnalysisResultReceiptV1> {
        let mut writer = self.maintenance_writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin analysis result",
            })?;
        let write = self.progress_rows(
            &transaction,
            input,
            previous.map_or(ResultHead::Unchecked, ResultHead::Working),
            advance,
            profile,
            contexts,
        )?;
        if !write.commit {
            check()?;
            return Ok(write.receipt);
        }
        if !write.relations.is_empty() {
            self.check_revision_limits(&transaction, input.scope.identity.tenant_id)?;
            self.check_witnesses(
                &transaction,
                input.scope.identity.tenant_id,
                input.created_utc_ns,
            )?;
            Self::record_revision(
                &transaction,
                write.receipt.commit_revision,
                &write.relations,
            )?;
            #[cfg(any(test, feature = "test-fixtures"))]
            self.crash_at("result.before");
        }
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(super::AnalysisCommitStage::BeforeResultCommit)?;
        check()?;
        self.commit_metadata(transaction, "commit analysis result")?;
        if !write.relations.is_empty() {
            #[cfg(any(test, feature = "test-fixtures"))]
            self.crash_at("result.after");
            self.revision.send_replace(write.receipt.commit_revision);
        }
        Ok(write.receipt)
    }

    pub(in crate::analysis) fn progress_rows(
        &self,
        transaction: &duckdb::Transaction<'_>,
        input: &AnalysisResultCommitV1,
        expected: ResultHead<'_>,
        advance: bool,
        profile: Option<&crate::DiscoveryProfileV1>,
        contexts: &[super::AnalysisContextVersionV1],
    ) -> Result<ProgressWrite> {
        let previous = match expected {
            ResultHead::Working(revision) => Some(revision),
            _ => None,
        };
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
            || (input.body.is_empty() && (profile.is_none() || contexts.is_empty()))
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
        if (profile.is_none() && !contexts.is_empty())
            || contexts.windows(2).any(|pair| pair[0].key >= pair[1].key)
            || contexts.iter().any(|context| {
                !context.valid() || context.key.tenant_id != input.scope.identity.tenant_id
            })
        {
            return self.reject("the result contexts are invalid");
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
        let key = input.scope.identity.key();
        let existing = transaction
            .query_row(
                "SELECT CASE WHEN octet_length(tenant_id) = 16 THEN tenant_id ELSE NULL END,
                request_meta, body, commit_revision FROM analysis_results WHERE result_id = ?",
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
        let mut context_write = None;
        let inserted = self.context_rows(transaction, contexts, false, None, &mut context_write)?;
        let mut references = std::borrow::Cow::Borrowed(input.context_refs.as_slice());
        if !inserted.is_empty() {
            references.to_mut().extend(inserted);
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
            if existing.is_some() && previous.is_none() {
                return AnalysisConflictSnafu.fail();
            }
            return self.reject("the result context revision differs from its captured references");
        }
        let mut encoded = None;
        let mut retained_profile = None;
        if let Some(profile) = profile.filter(|_| !contexts.is_empty()) {
            let mut profile = profile.clone();
            profile.context_refs = references.to_vec();
            profile.validate()?;
            let mut committed = input.clone();
            committed.context_revision = context_revision;
            committed.context_refs = references.to_vec();
            committed.body = PreparedProfile::encode(&profile)?;
            encoded = Some(committed);
            retained_profile = Some(profile);
        }
        let input = encoded.as_ref().unwrap_or(input);
        let profile = retained_profile.as_ref().or(profile);
        let body = input.body.as_slice();
        let header = profile.map(ProfileHeader::from).unwrap_or_default();
        let request = if contexts.is_empty() {
            input.request_meta()
        } else {
            input.request_meta_refs(context_revision, &references, &[])
        }
        .context(JsonSnafu { path: &path })?;

        let replacing = existing.is_some() && previous.is_some();
        if let Some((tenant, stored, retained, revision)) = existing {
            let (Some(tenant), Some(stored), Some(retained)) = (tenant, stored, retained) else {
                return self.reject("the retained analysis result exceeds its byte bound");
            };
            let same = tenant == input.scope.identity.tenant_id
                && stored == request
                && retained == input.body;
            if same {
                return Ok(ProgressWrite {
                    receipt: AnalysisResultReceiptV1 {
                        commit_revision: revision,
                        consumed_cursor: input.consumed_cursor,
                    },
                    relations: Vec::new(),
                    commit: false,
                });
            }
            if tenant != input.scope.identity.tenant_id
                || previous != Some(revision)
                || Self::managed_profile_version(
                    transaction,
                    input.scope.identity.tenant_id,
                    &input.result_id,
                )?
            {
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
        let progress: Option<(u64, u64, bool, String, Option<u64>, String)> = transaction
            .query_row(
                "SELECT p.consumed_cursor, p.resume_floor, p.retired, p.result_id, r.commit_revision, p.class
                 FROM processor_progress p LEFT JOIN analysis_results r
                   ON r.tenant_id = p.tenant_id AND r.result_id = p.result_id AND r.processor_id = p.processor_id
                 WHERE p.processor_id = ? AND p.method_version = ? AND p.tenant_id = ? AND p.stream_key = ?",
                params![
                    input.scope.processor_id,
                    input.scope.method_version,
                    input.scope.identity.tenant_id.as_slice(),
                    key.as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read expected progress",
            })?;
        if !progress
            .as_ref()
            .is_some_and(|(consumed, resumed, retired, result, revision, _)| {
                !retired
                    && (*consumed).max(*resumed) == input.expected_cursor
                    && (!replacing || result == &input.result_id)
                    && match expected {
                        ResultHead::Current(Some(head)) => {
                            result == &head.result_id && *revision == Some(head.commit_revision)
                        }
                        ResultHead::Current(None) => result.is_empty() && revision.is_none(),
                        _ => true,
                    }
            })
        {
            return AnalysisConflictSnafu.fail();
        }
        let receipt =
            Self::read_receipt_from(transaction, &self.root, &input.scope.identity, &key)?
                .ok_or_else(|| self.state_error("the processor source is absent"))?;
        if input.consumed_cursor > receipt.contiguous_cursor
            || input.coverage_revision > receipt.coverage_revision
        {
            return self.reject("the result claims unavailable source or coverage progress");
        }
        let expected = input.consumed_cursor - input.expected_cursor;
        let revision = Self::read_meta_from(transaction, &self.root)?.commit_revision;
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
        let gaps = profile.filter(|_| advance).map_or(&[][..], |profile| {
            &profile.gaps[profile
                .gaps
                .partition_point(|gap| gap.last_cursor <= input.expected_cursor)..]
        });
        let mut missing = 0u64;
        if !gaps.is_empty() {
            if input.scope.processor_id != crate::DISCOVERY_PROCESSOR
                || progress.as_ref().is_none_or(|(_, _, _, _, _, class)| {
                    class != ProcessorClassV1::Optional.as_str()
                })
            {
                return self.reject("only optional Discovery can consume expired input");
            }
            let mut statement = transaction
                .prepare(
                    "SELECT EXISTS(SELECT 1 FROM expired_ranges
                     WHERE stream_key = ? AND tenant_id = ? AND commit_revision = ?
                        AND GREATEST(first_cursor, ?) = ? AND LEAST(last_cursor, ?) = ?)",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare captured expiry proof",
                })?;
            let first = input
                .expected_cursor
                .checked_add(1)
                .ok_or_else(|| self.state_error("the discovery gap cursor is exhausted"))?;
            for gap in gaps {
                if gap.first_cursor < first || gap.last_cursor > input.consumed_cursor {
                    return self.reject("the discovery gap exceeds its captured progress");
                }
                let proven: bool = statement
                    .query_row(
                        params![
                            key.as_slice(),
                            input.scope.identity.tenant_id.as_slice(),
                            gap.commit_revision,
                            first,
                            gap.first_cursor,
                            input.consumed_cursor,
                            gap.last_cursor,
                        ],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "check captured expiry proof",
                    })?;
                if !proven {
                    return self.reject("the discovery gap differs from its captured expiry");
                }
                missing = gap
                    .last_cursor
                    .checked_sub(gap.first_cursor)
                    .and_then(|count| count.checked_add(1))
                    .and_then(|count| missing.checked_add(count))
                    .ok_or_else(|| self.state_error("the discovery gap count is exhausted"))?;
            }
        }
        if available.checked_add(missing) != Some(expected) {
            return self.reject("the processor result skips unavailable raw input");
        }
        let mut checked_context = 0;
        for reference in references.as_ref() {
            let Some((_, revision)) =
                self.read_context_cached_from(transaction, &self.root, &reference.key)?
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
        let revision = Self::read_meta_from(transaction, &path)?
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
        Self::insert_references(
            transaction,
            &input.result_id,
            &input.witnesses,
            &witness_segments,
            &references,
        )?;
        if advance {
            if !gaps.is_empty() {
                Self::insert_processor_gaps(transaction, &input.scope, gaps)?;
            }
            transaction
            .execute(
                "UPDATE processor_progress SET consumed_cursor = ?, coverage_revision = ?,
                 context_revision = ?, required_floor = ?, result_id = ?,
                 resume_floor = GREATEST(resume_floor, ?)
                 WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                params![
                    input.consumed_cursor,
                    input.coverage_revision,
                    context_revision,
                    input.consumed_cursor,
                    input.result_id,
                    gaps.last().map_or(0, |gap| gap.last_cursor),
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
        if context_write.is_some() {
            relations.push("context_versions");
        }
        if advance {
            relations.push("processor_progress");
        }
        if !gaps.is_empty() {
            relations.push("processor_gaps");
        }
        if !input.witnesses.is_empty() {
            relations.push("evidence_refs");
        }
        if !references.is_empty() {
            relations.push("context_refs");
        }
        Ok(ProgressWrite {
            receipt: AnalysisResultReceiptV1 {
                commit_revision: revision,
                consumed_cursor: input.consumed_cursor,
            },
            relations,
            commit: true,
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
        let before = store.meta()?;
        assert!(matches!(
            store.commit_result(&invalid),
            Err(crate::Error::AnalysisState { .. })
        ));
        assert_eq!(store.meta()?, before);
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
                    [],
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
