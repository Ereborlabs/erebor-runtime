use duckdb::{params, OptionalExt as _};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::{source_key, valid_source_identity, AnalysisContextKeyV1, AnalysisStore};
use crate::{
    AnalysisConflictSnafu, AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, JsonSnafu, Result,
};

const MAX_RESULT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESULT_REFS: usize = 8_192;
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessorScopeV1 {
    pub processor_id: String,
    pub method_version: u64,
    pub identity: EvidenceIntakeIdentityV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnalysisWitnessV1 {
    pub identity: EvidenceIntakeIdentityV1,
    pub cursor: u64,
    pub expires_utc_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnalysisContextRefV1 {
    pub key: AnalysisContextKeyV1,
    pub content_sha256: [u8; 32],
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisResultReceiptV1 {
    pub commit_revision: u64,
    pub consumed_cursor: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisProcessorGapV1 {
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub commit_revision: u64,
}

impl ProcessorScopeV1 {
    fn valid(&self) -> bool {
        !self.processor_id.is_empty()
            && self.processor_id.len() <= 128
            && self.method_version > 0
            && valid_source_identity(&self.identity)
    }
}

impl AnalysisStore {
    pub fn register_processor(
        &self,
        scope: &ProcessorScopeV1,
        class: ProcessorClassV1,
        start_cursor: u64,
    ) -> Result<u64> {
        if !scope.valid() || start_cursor == 0 {
            return self.reject("the processor scope or start cursor is invalid");
        }
        let key = source_key(&scope.identity);
        let mut writer = self.writer()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin processor registration",
        })?;
        let existing: Option<(String, u64)> = transaction
            .query_row(
                "SELECT class, start_cursor FROM processor_progress
                 WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                params![
                    scope.processor_id,
                    scope.method_version,
                    scope.identity.tenant_id.as_slice(),
                    key.as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read processor registration",
            })?;
        let meta = Self::read_meta_from(&transaction, &self.root.join("analysis.duckdb"))?;
        if let Some(existing) = existing {
            if existing != (class.as_str().to_owned(), start_cursor) {
                return AnalysisConflictSnafu.fail();
            }
            return Ok(meta.commit_revision);
        }
        let receipt = Self::read_receipt_from(&transaction, &self.root, &scope.identity, &key)?;
        if receipt.as_ref().is_some_and(|receipt| {
            start_cursor <= receipt.retained_floor
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
                "INSERT INTO processor_progress VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, false)",
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
        Self::record_revision(&transaction, revision, &["processor_progress"])?;
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit processor registration",
        })?;
        self.revision.send_replace(revision);
        Ok(revision)
    }

    pub fn resume_optional(
        &self,
        scope: &ProcessorScopeV1,
    ) -> Result<Option<AnalysisProcessorGapV1>> {
        if !scope.valid() {
            return self.reject("the optional processor scope is invalid");
        }
        let key = source_key(&scope.identity);
        let mut writer = self.writer()?;
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
        Self::record_revision(
            &transaction,
            revision,
            &["processor_gaps", "processor_progress"],
        )?;
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit optional processor gap",
        })?;
        self.revision.send_replace(revision);
        Ok(Some(AnalysisProcessorGapV1 {
            first_cursor: first,
            last_cursor,
            commit_revision: revision,
        }))
    }

    pub fn commit_result(&self, input: &AnalysisResultCommitV1) -> Result<AnalysisResultReceiptV1> {
        if !input.scope.valid()
            || input.result_id.is_empty()
            || input.result_id.len() > 256
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
                !reference.key.valid() || reference.key.tenant_id != input.scope.identity.tenant_id
            })
        {
            return self.reject("the analysis result or progress bounds are invalid");
        }
        let witness_deadline = input
            .created_utc_ns
            .checked_add(MAX_WITNESS_AGE_NS)
            .ok_or_else(|| self.state_error("the witness deadline is exhausted"))?;
        if input.witnesses.iter().any(|witness| {
            witness.identity.tenant_id != input.scope.identity.tenant_id
                || !valid_source_identity(&witness.identity)
                || witness.cursor == 0
                || witness.expires_utc_ns < input.created_utc_ns
                || witness.expires_utc_ns > witness_deadline
        }) {
            return self.reject("the result has a foreign or invalid witness");
        }
        let path = self.root.join("analysis.duckdb");
        let request = serde_json::to_vec(input).context(JsonSnafu { path: &path })?;
        let request_digest: [u8; 32] = Sha256::digest(&request).into();
        let body_digest: [u8; 32] = Sha256::digest(&input.body).into();
        let key = source_key(&input.scope.identity);
        let mut writer = self.writer()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin analysis result",
        })?;
        let existing: Option<(Vec<u8>, Vec<u8>, u64)> = transaction
            .query_row(
                "SELECT tenant_id, request_sha256, commit_revision FROM analysis_results WHERE result_id = ?",
                params![input.result_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read immutable result",
            })?;
        if let Some((tenant, digest, revision)) = existing {
            if tenant != input.scope.identity.tenant_id || digest != request_digest {
                return AnalysisConflictSnafu.fail();
            }
            return Ok(AnalysisResultReceiptV1 {
                commit_revision: revision,
                consumed_cursor: input.consumed_cursor,
            });
        }
        let progress: Option<(u64, u64, bool)> = transaction
            .query_row(
                "SELECT consumed_cursor, resume_floor, retired FROM processor_progress
                 WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                params![
                    input.scope.processor_id,
                    input.scope.method_version,
                    input.scope.identity.tenant_id.as_slice(),
                    key.as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read expected progress",
            })?;
        if !progress.is_some_and(|(consumed, resumed, retired)| {
            !retired && consumed.max(resumed) == input.expected_cursor
        }) {
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
        let available: u64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM events WHERE stream_key = ? AND tenant_id = ?
                 AND durable_cursor > ? AND durable_cursor <= ?",
                params![
                    key.as_slice(),
                    input.scope.identity.tenant_id.as_slice(),
                    input.expected_cursor,
                    input.consumed_cursor,
                ],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check consumed input",
            })?;
        if available != expected {
            return self.reject("the processor result skips unavailable raw input");
        }
        let mut context_revision = 0;
        for reference in &input.context_refs {
            let Some((version, revision)) =
                Self::read_context_from(&transaction, &self.root, &reference.key)?
            else {
                return self.reject("the result context version is absent");
            };
            if version
                .content_digest()
                .context(JsonSnafu { path: &path })?
                != reference.content_sha256
            {
                return self.reject("the result context digest differs");
            }
            context_revision = context_revision.max(revision);
        }
        if input.context_revision != context_revision {
            return self.reject("the result context revision differs from its references");
        }
        for witness in &input.witnesses {
            let witness_key = source_key(&witness.identity);
            let stored: Option<(Vec<u8>, Vec<u8>)> = transaction
                .query_row(
                    "SELECT framed_record, frame_sha256 FROM events
                     WHERE stream_key = ? AND tenant_id = ? AND durable_cursor = ?",
                    params![
                        witness_key.as_slice(),
                        witness.identity.tenant_id.as_slice(),
                        witness.cursor,
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "check exact witness",
                })?;
            let Some((frame, digest)) = stored else {
                return self.reject("the result witness is not retained");
            };
            if Sha256::digest(&frame).as_slice() != digest {
                return self.reject("the result witness digest is invalid");
            }
        }
        let revision = Self::read_meta_from(&transaction, &path)?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
        transaction
            .execute(
                "INSERT INTO analysis_results VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    input.result_id,
                    input.scope.identity.tenant_id.as_slice(),
                    input.scope.processor_id,
                    input.body.as_slice(),
                    body_digest.as_slice(),
                    request_digest.as_slice(),
                    revision,
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert analysis result",
            })?;
        for witness in &input.witnesses {
            transaction
                .execute(
                    "INSERT INTO evidence_refs VALUES (?, ?, ?, ?, ?)",
                    params![
                        input.result_id,
                        witness.identity.tenant_id.as_slice(),
                        source_key(&witness.identity).as_slice(),
                        witness.cursor,
                        witness.expires_utc_ns,
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert exact witness",
                })?;
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
                        reference.content_sha256.as_slice(),
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert exact result context",
                })?;
        }
        transaction
            .execute(
                "UPDATE processor_progress SET consumed_cursor = ?, coverage_revision = ?,
                 context_revision = ?, required_floor = ?
                 WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                params![
                    input.consumed_cursor,
                    input.coverage_revision,
                    input.context_revision,
                    input.consumed_cursor,
                    input.scope.processor_id,
                    input.scope.method_version,
                    input.scope.identity.tenant_id.as_slice(),
                    key.as_slice(),
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "advance processor progress",
            })?;
        let mut relations = vec!["analysis_results", "processor_progress"];
        if !input.witnesses.is_empty() {
            relations.push("evidence_refs");
        }
        if !input.context_refs.is_empty() {
            relations.push("context_refs");
        }
        Self::record_revision(&transaction, revision, &relations)?;
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit analysis result",
        })?;
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
            valid_from_utc_ns: 1,
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
                identity: source,
                cursor: 1,
                expires_utc_ns: 1_000_000_001,
            }],
            context_refs: vec![AnalysisContextRefV1 {
                key: context.key.clone(),
                content_sha256: context.content_digest()?,
            }],
        };
        let receipt = store.commit_result(&input)?;
        assert_eq!(receipt.commit_revision, 4);
        assert_eq!(receipt.consumed_cursor, 1);
        assert_eq!(store.commit_result(&input)?, receipt);
        assert_eq!(store.meta()?.commit_revision, 4);
        input.result_id = "finding-2".into();
        assert!(matches!(
            store.commit_result(&input),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert_eq!(store.meta()?.commit_revision, 4);
        input.expected_cursor = 1;
        input.context_refs[0].content_sha256[0] ^= 1;
        assert!(store.commit_result(&input).is_err());
        input.context_refs[0].content_sha256[0] ^= 1;
        input.witnesses[0].identity = identity(4);
        assert!(store.commit_result(&input).is_err());
        assert_eq!(store.meta()?.commit_revision, 4);
        Ok(())
    }
}
