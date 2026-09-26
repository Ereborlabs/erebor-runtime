use duckdb::{params, OptionalExt as _};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::{source_key, valid_source_identity, AnalysisStore};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, JsonSnafu, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacySourceImportV1 {
    pub identity: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub accepted_cursor: u64,
    pub retained_floor: u64,
    pub coverage_revision: u64,
    pub event_sha256: [u8; 32],
    pub coverage_sha256: Option<[u8; 32]>,
}

impl AnalysisStore {
    pub fn begin_legacy_import(&self, input: &LegacySourceImportV1) -> Result<()> {
        if !valid_source_identity(&input.identity)
            || input.retained_floor > input.accepted_cursor
            || (input.coverage_revision == 0) != input.coverage_sha256.is_none()
        {
            return self.reject("the legacy source import bounds are invalid");
        }
        let identity = &input.identity;
        let key = source_key(identity);
        let mut writer = self.writer()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin legacy source import",
        })?;
        let saved: Option<(u32, u64, u64, u64, Vec<u8>, Option<Vec<u8>>, bool)> = transaction
            .query_row(
                "SELECT cpu_id, accepted_cursor, retained_floor, coverage_revision,
                        event_sha256, coverage_sha256, complete
                 FROM legacy_import_sources WHERE stream_key = ? AND tenant_id = ?",
                params![key.as_slice(), identity.tenant_id.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read legacy import marker",
            })?;
        let receipt = Self::read_receipt_from(&transaction, &self.root, identity, &key)?;
        if let Some((cpu, accepted, floor, coverage, events, report, _complete)) = saved {
            if cpu != input.cpu_id
                || accepted != input.accepted_cursor
                || floor != input.retained_floor
                || coverage != input.coverage_revision
                || events != input.event_sha256
                || report.as_deref() != input.coverage_sha256.as_ref().map(<[u8; 32]>::as_slice)
                || !receipt.as_ref().is_some_and(|receipt| {
                    receipt.cpu_id == cpu
                        && receipt.retained_floor == floor
                        && receipt.contiguous_cursor >= floor
                        && receipt.contiguous_cursor <= accepted
                })
            {
                return self.reject("the legacy import marker or receipt changed");
            }
            return Ok(());
        }
        if receipt.is_some() {
            return self.reject("legacy import cannot replace an existing source");
        }
        let bound = Self::bind_source(&transaction, &self.root, identity)?;
        let revision = Self::read_meta_from(&transaction, &self.root.join("analysis.duckdb"))?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
        let identity_json = serde_json::to_string(identity).context(JsonSnafu {
            path: self.root.join("analysis.duckdb"),
        })?;
        transaction
            .execute(
                "INSERT INTO source_receipts VALUES (?, ?, ?, ?, ?, 0, ?)",
                params![
                    key.as_slice(),
                    identity_json,
                    identity.tenant_id.as_slice(),
                    input.cpu_id,
                    input.retained_floor,
                    input.retained_floor,
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "seed legacy source receipt",
            })?;
        transaction
            .execute(
                "INSERT INTO legacy_import_sources VALUES (?, ?, ?, ?, ?, ?, ?, ?, false)",
                params![
                    key.as_slice(),
                    identity.tenant_id.as_slice(),
                    input.cpu_id,
                    input.accepted_cursor,
                    input.retained_floor,
                    input.coverage_revision,
                    input.event_sha256.as_slice(),
                    input.coverage_sha256.as_ref().map(<[u8; 32]>::as_slice),
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "record legacy import marker",
            })?;
        let mut relations = vec!["source_receipts", "legacy_import_sources"];
        if bound {
            relations.push("source_bindings");
        }
        if input.retained_floor > 0 {
            transaction
                .execute(
                    "INSERT INTO expired_ranges VALUES (?, ?, 1, ?, ?)",
                    params![
                        key.as_slice(),
                        identity.tenant_id.as_slice(),
                        input.retained_floor,
                        revision,
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "record legacy consumed prefix",
                })?;
            relations.push("expired_ranges");
        }
        Self::record_revision(&transaction, revision, &relations)?;
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit legacy import marker",
        })?;
        self.revision.send_replace(revision);
        Ok(())
    }

    pub fn finish_legacy_import(&self, input: &LegacySourceImportV1) -> Result<()> {
        self.begin_legacy_import(input)?;
        let identity = &input.identity;
        let key = source_key(identity);
        let mut writer = self.writer()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "verify legacy source import",
        })?;
        let receipt = Self::read_receipt_from(&transaction, &self.root, identity, &key)?
            .ok_or_else(|| self.state_error("the legacy source receipt is absent"))?;
        if receipt.cpu_id != input.cpu_id
            || receipt.retained_floor != input.retained_floor
            || receipt.contiguous_cursor != input.accepted_cursor
            || receipt.coverage_revision != input.coverage_revision
        {
            return self.reject("the legacy source receipt is incomplete");
        }
        let mut digest = Sha256::new();
        let mut cursor = input.retained_floor;
        {
            let mut statement = transaction
                .prepare(
                    "SELECT durable_cursor, framed_record, frame_sha256 FROM events
                     WHERE stream_key = ? AND tenant_id = ? ORDER BY durable_cursor",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare legacy evidence verification",
                })?;
            let rows = statement
                .query_map(
                    params![key.as_slice(), identity.tenant_id.as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, u64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read imported legacy evidence",
                })?;
            for row in rows {
                let (next, frame, saved) = row.context(AnalysisDatabaseSnafu {
                    operation: "verify imported legacy evidence",
                })?;
                if cursor.checked_add(1) != Some(next)
                    || next > input.accepted_cursor
                    || Sha256::digest(&frame).as_slice() != saved
                {
                    return self
                        .reject("the imported legacy evidence has a gap or bad frame digest");
                }
                digest.update(&frame);
                cursor = next;
            }
        }
        if cursor != input.accepted_cursor || digest.finalize().as_slice() != input.event_sha256 {
            return self.reject("the imported legacy evidence differs from its source digest");
        }
        let coverage_count: u64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM coverage WHERE stream_key = ? AND tenant_id = ?",
                params![key.as_slice(), identity.tenant_id.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "count imported legacy coverage",
            })?;
        if coverage_count != u64::from(input.coverage_revision > 0) {
            return self.reject("the imported legacy coverage count differs");
        }
        if let Some(expected) = input.coverage_sha256 {
            let report: Option<(Vec<u8>, Vec<u8>)> = transaction
                .query_row(
                    "SELECT report, report_sha256 FROM coverage
                     WHERE stream_key = ? AND tenant_id = ? AND revision = ?",
                    params![
                        key.as_slice(),
                        identity.tenant_id.as_slice(),
                        input.coverage_revision,
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "verify imported legacy coverage",
                })?;
            let Some((bytes, digest)) = report else {
                return self.reject("the imported legacy coverage report is absent");
            };
            if Sha256::digest(&bytes).as_slice() != expected || digest != expected {
                return self.reject("the imported legacy coverage digest differs");
            }
        }
        let complete: bool = transaction
            .query_row(
                "SELECT complete FROM legacy_import_sources WHERE stream_key = ?",
                params![key.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read legacy import completion",
            })?;
        if complete {
            return Ok(());
        }
        let revision = Self::read_meta_from(&transaction, &self.root.join("analysis.duckdb"))?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
        transaction
            .execute(
                "UPDATE legacy_import_sources SET complete = true WHERE stream_key = ?",
                params![key.as_slice()],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "complete legacy source import",
            })?;
        Self::record_revision(&transaction, revision, &["legacy_import_sources"])?;
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit legacy source completion",
        })?;
        self.revision.send_replace(revision);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EvidenceStoreOutcomeV1, ValidatedCoverageV1, ValidatedEvidenceBatchV1};

    #[test]
    fn legacy_import_replays_after_restart_and_blocks_live_writes_until_verified(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("analysis");
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        let report = b"legacy coverage";
        let input = LegacySourceImportV1 {
            identity: identity.clone(),
            cpu_id: 7,
            accepted_cursor: 4,
            retained_floor: 2,
            coverage_revision: 3,
            event_sha256: Sha256::digest(b"aabb").into(),
            coverage_sha256: Some(Sha256::digest(report).into()),
        };
        let batch = ValidatedEvidenceBatchV1 {
            cpu_id: 7,
            first_cursor: 3,
            last_cursor: 3,
            intake_utc_ns: 0,
            framed_records: b"aa".to_vec().into(),
            frame_ends: vec![2],
        };
        let store = AnalysisStore::open(&path)?;
        store.begin_legacy_import(&input)?;
        assert!(store
            .accept_validated_batch(
                identity.clone(),
                ValidatedEvidenceBatchV1 {
                    intake_utc_ns: 1,
                    ..batch.clone()
                }
            )
            .is_err());
        assert_eq!(
            store.import_legacy_batch(identity.clone(), batch.clone())?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert!(store.finish_legacy_import(&input).is_err());
        drop(store);
        let store = AnalysisStore::open(&path)?;
        store.begin_legacy_import(&input)?;
        assert_eq!(
            store.import_legacy_batch(identity.clone(), batch)?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert_eq!(
            store.import_legacy_batch(
                identity.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 7,
                    first_cursor: 4,
                    last_cursor: 4,
                    intake_utc_ns: 0,
                    framed_records: b"bb".to_vec().into(),
                    frame_ends: vec![2],
                }
            )?,
            EvidenceStoreOutcomeV1::Accepted
        );
        store.accept_validated_coverage(ValidatedCoverageV1 {
            identity: identity.clone(),
            cpu_id: 7,
            revision: 3,
            encoded_report: report.to_vec(),
        })?;
        store.finish_legacy_import(&input)?;
        store.finish_legacy_import(&input)?;
        assert_eq!(
            store
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .retained_floor,
            2
        );
        assert!(store.read_page(&identity, 1).is_err());
        assert_eq!(store.read_page(&identity, 3)?.records.len(), 2);
        assert_eq!(
            store
                .source_status(&identity)?
                .ok_or("source absent")?
                .retained_event_count,
            2
        );
        Ok(())
    }
}
