use duckdb::{params, OptionalExt as _};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{AnalysisContextKeyV1, AnalysisStore};
use crate::{
    AnalysisConflictSnafu, AnalysisDatabaseSnafu, AnalysisStreamIdentityV1,
    EvidenceIntakeIdentityV1, JsonSnafu, Result,
};

pub(crate) const MAX_RESULT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESULT_META_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_RESULT_REFS: usize = 8_192;
const MAX_CONTEXT_REFS: usize = 256;
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
        serde_json::to_vec(&(
            &self.scope,
            self.expected_cursor,
            self.consumed_cursor,
            self.coverage_revision,
            self.context_revision,
            &self.result_id,
            self.created_utc_ns,
            &self.witnesses,
            &self.context_refs,
        ))
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

impl ProfileHeader {
    fn bytes(&self) -> usize {
        self.stream_key.as_ref().map_or(0, Vec::len)
            + self.interval_id.as_ref().map_or(0, String::len)
    }
}

impl ProcessorScopeV1 {
    pub(super) fn valid(&self) -> bool {
        !self.processor_id.is_empty()
            && self.processor_id.len() <= 128
            && self.method_version > 0
            && self.identity.valid()
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
            if result.as_ref().is_some_and(|result| {
                result.body.is_empty() || result.body.len() > MAX_RESULT_BYTES
            }) {
                return self.reject("the processor result exceeds its byte bound");
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
        if tenant == [0; 16] || result_id.is_empty() || result_id.len() > 256 {
            return self.reject("the analysis result identity is invalid");
        }
        let stored: Option<Vec<u8>> = connection
            .query_row(
                "SELECT body FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
                params![tenant.as_slice(), result_id],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read retained analysis result",
            })?;
        let Some(body) = stored else {
            return Ok(None);
        };
        if body.is_empty() || body.len() > MAX_RESULT_BYTES {
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
            if existing != (class.as_str().to_owned(), start_cursor, false) {
                return AnalysisConflictSnafu.fail();
            }
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
        super::quota::UsageChange::from(256 + key.len() as i64 + scope.processor_id.len() as i64)
            .apply(&transaction, &scope.identity.tenant_id)?;
        self.check_logical(&transaction, scope.identity.tenant_id, false)?;
        Self::record_revision(&transaction, revision, &["processor_progress"])?;
        #[cfg(test)]
        self.crash_at("register.before");
        self.commit_metadata(transaction, "commit processor registration")?;
        #[cfg(test)]
        self.crash_at("register.after");
        self.revision.send_replace(revision);
        Ok(revision)
    }

    pub fn resume_optional(&self, scope: &ProcessorScopeV1) -> Result<Option<AnalysisGapV1>> {
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
        super::quota::UsageChange::from(256 + key.len() as i64 + scope.processor_id.len() as i64)
            .apply(&transaction, &scope.identity.tenant_id)?;
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
        self.commit_progress(input, None, true, None)
    }

    pub(crate) fn commit_working(
        &self,
        input: &AnalysisResultCommitV1,
        previous: Option<u64>,
    ) -> Result<AnalysisResultReceiptV1> {
        if input.scope.processor_id != crate::DISCOVERY_PROCESSOR {
            return self.reject("the working result owner is invalid");
        }
        let profile = crate::DiscoveryProfileV1::try_from(input.body.as_slice())?;
        self.commit_progress(input, previous, true, Some(&profile))
    }

    pub(crate) fn commit_profile(
        &self,
        input: &AnalysisResultCommitV1,
    ) -> Result<AnalysisResultReceiptV1> {
        if input.scope.processor_id != crate::DISCOVERY_PROCESSOR
            || input.expected_cursor != input.consumed_cursor
        {
            return self.reject("the historical profile cannot advance progress");
        }
        let profile = crate::DiscoveryProfileV1::try_from(input.body.as_slice())?;
        if !profile.sealed {
            return self.reject("the historical profile is not sealed");
        }
        self.commit_progress(input, None, false, Some(&profile))
    }

    pub(crate) fn mark_notice(
        &self,
        profile: &crate::DiscoveryProfileV1,
        revision: u64,
        facts: u64,
        coverage: u64,
    ) -> Result<()> {
        profile.validate()?;
        let mut writer_guard = self.writer()?;
        let writer = writer_guard.get_mut()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin discovery notice",
        })?;
        let changed = transaction
            .execute(
                "UPDATE analysis_results SET facts_revision = GREATEST(facts_revision, ?),
                coverage_revision = GREATEST(coverage_revision, ?)
             WHERE result_id = ? AND tenant_id = ? AND processor_id = ?
                AND stream_key = ? AND method_version = ? AND commit_revision = ?",
                params![
                    facts,
                    coverage,
                    profile.profile_id,
                    profile.scope.identity.tenant_id.as_slice(),
                    profile.scope.processor_id,
                    profile.scope.identity.key().as_slice(),
                    profile.scope.method_version,
                    revision
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "acknowledge unavailable profile input",
            })?;
        if changed != 1 {
            return AnalysisConflictSnafu.fail();
        }
        self.commit_metadata(transaction, "commit discovery notice")
    }

    fn commit_progress(
        &self,
        input: &AnalysisResultCommitV1,
        previous: Option<u64>,
        advance: bool,
        profile: Option<&crate::DiscoveryProfileV1>,
    ) -> Result<AnalysisResultReceiptV1> {
        if profile.is_some_and(|profile| {
            profile.scope != input.scope
                || profile.profile_id != input.result_id
                || profile.coverage_revision != input.coverage_revision
                || profile.context_refs != input.context_refs
        }) {
            return self.reject("the profile header or references differ from its commit");
        }
        let header = profile.map(ProfileHeader::from).unwrap_or_default();
        if !input.scope.valid()
            || input.result_id.is_empty()
            || input.result_id.len() > 256
            || input.body.is_empty()
            || input.body.len() > MAX_RESULT_BYTES
            || input.created_utc_ns == 0
            || input.witnesses.len() > MAX_RESULT_REFS
            || input.context_refs.len() > MAX_CONTEXT_REFS
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
        let request = input.request_meta().context(JsonSnafu { path: &path })?;
        if request.len() > MAX_RESULT_META_BYTES {
            return self.reject("the analysis result metadata exceeds its byte bound");
        }
        let key = input.scope.identity.key();
        let mut writer_guard = self.maintenance_writer()?;
        let writer = writer_guard.get_mut()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin analysis result",
        })?;
        let existing = transaction
            .query_row(
                "SELECT tenant_id, request_meta, body, commit_revision FROM analysis_results WHERE result_id = ?",
                params![input.result_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, u64>(3)?,
                    ))
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read immutable result",
            })?;
        let replacing = existing.is_some() && previous.is_some();
        let mut removed_bytes = 0;
        if let Some((tenant, stored, body, revision)) = existing {
            if tenant == input.scope.identity.tenant_id && stored == request && body == input.body {
                return Ok(AnalysisResultReceiptV1 {
                    commit_revision: revision,
                    consumed_cursor: input.consumed_cursor,
                });
            }
            if tenant != input.scope.identity.tenant_id || previous != Some(revision) {
                return AnalysisConflictSnafu.fail();
            }
            let profile = crate::DiscoveryProfileV1::try_from(body.as_slice())?;
            if profile.sealed
                || profile.scope != input.scope
                || profile.profile_id != input.result_id
            {
                return AnalysisConflictSnafu.fail();
            }
            removed_bytes = (256
                + input.result_id.len()
                + input.scope.processor_id.len()
                + body.len()
                + stored.len()
                + ProfileHeader::from(&profile).bytes()) as i64;
            removed_bytes += transaction.query_row(
                "SELECT COALESCE(SUM(bytes), 0)::BIGINT FROM (
                    SELECT 256 + octet_length(encode(ref_id)) + octet_length(stream_key) AS bytes
                    FROM evidence_refs WHERE ref_id = ?
                    UNION ALL SELECT 256 + octet_length(encode(ref_id)) + octet_length(encode(owner_id))
                    + octet_length(entity_key) + octet_length(lifetime_key)
                    FROM context_refs WHERE ref_id = ?)",
                params![input.result_id, input.result_id], |row| row.get::<_, i64>(0),
            ).context(AnalysisDatabaseSnafu { operation: "count prior working references" })?;
        } else if previous.is_some() {
            return AnalysisConflictSnafu.fail();
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
        let mut context_revision = 0;
        for reference in &input.context_refs {
            let Some((_, revision)) =
                Self::read_context_from(&transaction, &self.root, &reference.key)?
            else {
                return self.reject("the result context version is absent");
            };
            if revision != reference.commit_revision {
                return self.reject("the result context commit revision differs");
            }
            context_revision = context_revision.max(revision);
        }
        if input.context_revision != context_revision {
            return self.reject("the result context revision differs from its references");
        }
        let mut witness_segments = Vec::<u64>::with_capacity(input.witnesses.len());
        let mut cached = Vec::<super::AnalysisRecordV1>::new();
        let mut source = None;
        let mut segment = 0;
        for witness in &input.witnesses {
            if source != Some(&witness.identity)
                || cached
                    .first()
                    .is_none_or(|record| witness.cursor < record.cursor)
                || cached
                    .last()
                    .is_none_or(|record| witness.cursor > record.cursor)
            {
                let ranges = self
                    .raw
                    .lock()
                    .map_err(|_| self.state_error("the raw owner lock is poisoned"))?
                    .select_ranges(
                        &witness.identity,
                        witness.cursor,
                        witness.cursor,
                        revision,
                        None,
                        2,
                    )?;
                if ranges.len() != 1 {
                    return self.reject("the result witness is not retained exactly once");
                }
                cached = ranges[0].read(&self.root)?;
                segment = ranges[0].segment_id;
                source = Some(&witness.identity);
            }
            cached
                .binary_search_by_key(&witness.cursor, |record| record.cursor)
                .map_err(|_| self.state_error("the result witness is not retained"))?;
            witness_segments.push(segment);
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
                        input.body.as_slice(),
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
                    "INSERT INTO analysis_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    params![
                        input.result_id,
                        input.scope.identity.tenant_id.as_slice(),
                        input.scope.processor_id,
                        input.body.as_slice(),
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
        let mut usage = super::quota::UsageChange {
            bytes: if advance {
                input.result_id.len() as i64 - progress.as_ref().map_or(0, |row| row.3.len()) as i64
            } else {
                0
            } + (256
                + input.result_id.len()
                + input.scope.processor_id.len()
                + input.body.len()
                + request.len()
                + header.bytes()) as i64
                - removed_bytes,
            results: i64::from(!replacing),
            ..Default::default()
        };
        for (witness, segment) in input.witnesses.iter().zip(&witness_segments) {
            transaction
                .execute(
                    "INSERT INTO evidence_refs VALUES (?, ?, ?, ?, ?, ?)",
                    params![
                        input.result_id,
                        witness.identity.tenant().as_slice(),
                        witness.identity.key().as_slice(),
                        witness.cursor,
                        witness.expires_utc_ns,
                        segment,
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert exact witness",
                })?;
            usage.bytes += 256 + witness.identity.key().len() as i64 + input.result_id.len() as i64;
        }
        for reference in &input.context_refs {
            transaction
                .execute(
                    "INSERT INTO context_refs VALUES (?, ?, ?, ?, ?, ?, ?)",
                    params![
                        input.result_id,
                        reference.key.tenant_id.as_slice(),
                        reference.key.owner_id,
                        reference.key.entity_key.as_slice(),
                        reference.key.lifetime_key.as_slice(),
                        reference.key.owner_revision,
                        reference.commit_revision,
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert exact result context",
                })?;
            usage.bytes += (256
                + input.result_id.len()
                + reference.key.owner_id.len()
                + reference.key.entity_key.len()
                + reference.key.lifetime_key.len()) as i64;
        }
        if advance {
            transaction
            .execute(
                "UPDATE processor_progress SET consumed_cursor = ?, coverage_revision = ?,
                 context_revision = ?, required_floor = ?, result_id = ?
                 WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                params![
                    input.consumed_cursor,
                    input.coverage_revision,
                    input.context_revision,
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
        if advance {
            relations.push("processor_progress");
        }
        if !input.witnesses.is_empty() {
            relations.push("evidence_refs");
        }
        if !input.context_refs.is_empty() {
            relations.push("context_refs");
        }
        usage.apply(&transaction, &input.scope.identity.tenant_id)?;
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
        #[cfg(test)]
        self.crash_at("result.before");
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(super::AnalysisCommitStage::BeforeResultCommit)?;
        self.commit_metadata(transaction, "commit analysis result")?;
        #[cfg(test)]
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
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        }
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
            scope,
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 0,
            context_revision,
            result_id: "finding-1".into(),
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
            raw_max_age_ns: 100,
            raw_max_bytes: 64 * 1024 * 1024,
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
            scope,
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "mixed-result".into(),
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
            context_refs: vec![],
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
