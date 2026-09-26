use duckdb::{params, OptionalExt as _};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::{
    source_key, valid_source_identity, AnalysisReadPageV1, AnalysisRecordV1, AnalysisStore,
    StorePositionV1, MAX_ANALYSIS_PAGE_BYTES, MAX_ANALYSIS_PAGE_RECORDS,
};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, Result, RetainedRangeExpiredSnafu};

impl AnalysisStore {
    pub fn source_page(
        &self,
        tenant_id: [u8; 16],
        after: Option<&EvidenceIntakeIdentityV1>,
    ) -> Result<Vec<EvidenceIntakeIdentityV1>> {
        if tenant_id == [0; 16]
            || after.is_some_and(|source| {
                source.tenant_id != tenant_id || !valid_source_identity(source)
            })
        {
            return self.reject("the source page tenant or cursor is invalid");
        }
        let after = after.map(source_key);
        let reader_guard = self.reader()?;
        let reader = reader_guard.get()?;
        let mut statement = reader
            .prepare(
                "SELECT stream_key, identity_json FROM source_receipts
                 WHERE tenant_id = ? AND (CAST(? AS BLOB) IS NULL OR stream_key > ?)
                 ORDER BY stream_key LIMIT ?",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare source page",
            })?;
        let rows = statement
            .query_map(
                params![
                    tenant_id.as_slice(),
                    after.as_ref().map(|key| key.as_slice()),
                    after.as_ref().map(|key| key.as_slice()),
                    MAX_ANALYSIS_PAGE_RECORDS as u32,
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read source page",
            })?;
        let mut sources = Vec::new();
        for row in rows {
            let (key, json) = row.context(AnalysisDatabaseSnafu {
                operation: "decode source page",
            })?;
            let identity: EvidenceIntakeIdentityV1 =
                serde_json::from_str(&json).context(crate::JsonSnafu { path: &self.root })?;
            if identity.tenant_id != tenant_id
                || !valid_source_identity(&identity)
                || source_key(&identity).as_slice() != key
            {
                return self.reject("the source page identity does not match its key or tenant");
            }
            sources.push(identity);
        }
        Ok(sources)
    }

    pub fn read_page(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        first_cursor: u64,
    ) -> Result<AnalysisReadPageV1> {
        let key = source_key(identity);
        let mut reader_guard = self.reader()?;
        let reader = reader_guard.get_mut()?;
        let writer = reader.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin evidence snapshot",
        })?;
        let receipt = Self::read_receipt_from(&writer, &self.root, identity, &key)?
            .ok_or_else(|| self.state_error("the evidence source is absent"))?;
        if first_cursor == 0 || first_cursor > receipt.contiguous_cursor.saturating_add(1) {
            return self.reject("the evidence read cursor is outside the accepted range");
        }
        if first_cursor <= receipt.retained_floor {
            return RetainedRangeExpiredSnafu {
                first_cursor,
                last_cursor: receipt.retained_floor,
            }
            .fail();
        }
        self.check_expired(&writer, &key, identity, first_cursor)?;
        let expiry: Option<u64> = writer
            .query_row(
                "SELECT MIN(first_cursor) FROM expired_ranges
             WHERE stream_key = ? AND tenant_id = ? AND first_cursor > ? AND first_cursor <= ?",
                params![
                    key.as_slice(),
                    identity.tenant_id.as_slice(),
                    first_cursor,
                    receipt.contiguous_cursor
                ],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "bound read before expired input",
            })?;
        let page_end = expiry.map_or(receipt.contiguous_cursor, |cursor| cursor - 1);
        let read_revision =
            Self::read_meta_from(&writer, &self.root.join("analysis.duckdb"))?.commit_revision;
        let mut statement = writer
            .prepare(
                "SELECT durable_cursor, framed_record, frame_sha256, commit_revision, ordinal
                 FROM events WHERE stream_key = ? AND tenant_id = ?
                 AND durable_cursor >= ? AND durable_cursor <= ?
                 ORDER BY durable_cursor LIMIT ?",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare bounded evidence read",
            })?;
        let mut rows = statement
            .query(params![
                key.as_slice(),
                identity.tenant_id.as_slice(),
                first_cursor,
                page_end.min(first_cursor.saturating_add(MAX_ANALYSIS_PAGE_RECORDS as u64)),
                MAX_ANALYSIS_PAGE_RECORDS as u32 + 1,
            ])
            .context(AnalysisDatabaseSnafu {
                operation: "read bounded evidence",
            })?;
        let mut records = Vec::new();
        let mut encoded_bytes = 0;
        let mut bounded = false;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "read bounded evidence",
        })? {
            let cursor: u64 = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "read evidence cursor",
            })?;
            if cursor != first_cursor + records.len() as u64 {
                return self.expired_or_missing(
                    &writer,
                    &key,
                    identity,
                    first_cursor + records.len() as u64,
                );
            }
            if records.len() == MAX_ANALYSIS_PAGE_RECORDS {
                bounded = true;
                break;
            }
            let frame: Vec<u8> = row.get(1).context(AnalysisDatabaseSnafu {
                operation: "read evidence frame",
            })?;
            let digest: Vec<u8> = row.get(2).context(AnalysisDatabaseSnafu {
                operation: "read evidence digest",
            })?;
            if Sha256::digest(&frame).as_slice() != digest {
                return self.reject("the retained evidence digest does not match its frame");
            }
            if encoded_bytes + frame.len() > MAX_ANALYSIS_PAGE_BYTES {
                if records.is_empty() {
                    return self.reject("one evidence frame exceeds the read page bound");
                }
                bounded = true;
                break;
            }
            encoded_bytes += frame.len();
            records.push(AnalysisRecordV1 {
                cursor,
                framed_record: frame,
                position: StorePositionV1 {
                    commit_revision: row.get(3).context(AnalysisDatabaseSnafu {
                        operation: "read evidence commit revision",
                    })?,
                    ordinal: row.get(4).context(AnalysisDatabaseSnafu {
                        operation: "read evidence ordinal",
                    })?,
                },
            });
        }
        let next_cursor = first_cursor + records.len() as u64;
        if next_cursor <= page_end && !bounded {
            return self.expired_or_missing(&writer, &key, identity, next_cursor);
        }
        Ok(AnalysisReadPageV1 {
            first_cursor,
            records,
            encoded_bytes,
            next_cursor: (next_cursor <= receipt.contiguous_cursor).then_some(next_cursor),
            read_revision,
        })
    }

    fn check_expired(
        &self,
        writer: &duckdb::Connection,
        key: &[u8; 32],
        identity: &EvidenceIntakeIdentityV1,
        cursor: u64,
    ) -> Result<()> {
        let last: Option<u64> = writer
            .query_row(
                "SELECT last_cursor FROM expired_ranges
                 WHERE stream_key = ? AND tenant_id = ?
                 AND first_cursor <= ? AND last_cursor >= ? LIMIT 1",
                params![
                    key.as_slice(),
                    identity.tenant_id.as_slice(),
                    cursor,
                    cursor
                ],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "classify missing evidence",
            })?;
        if let Some(last_cursor) = last {
            return RetainedRangeExpiredSnafu {
                first_cursor: cursor,
                last_cursor,
            }
            .fail();
        }
        Ok(())
    }

    fn expired_or_missing<T>(
        &self,
        writer: &duckdb::Connection,
        key: &[u8; 32],
        identity: &EvidenceIntakeIdentityV1,
        cursor: u64,
    ) -> Result<T> {
        self.check_expired(writer, key, identity, cursor)?;
        self.reject("the accepted evidence range has a missing record")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_store_source_pages() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        assert!(store.source_page(identity.tenant_id, None)?.is_empty());
        let mut expected = Vec::new();
        for index in 0..MAX_ANALYSIS_PAGE_RECORDS + 2 {
            let source = EvidenceIntakeIdentityV1 {
                source_epoch: index as u64 + 1,
                ..identity.clone()
            };
            store.accept_validated_coverage(crate::ValidatedCoverageV1 {
                identity: source.clone(),
                cpu_id: 0,
                revision: 1,
                encoded_report: vec![1],
            })?;
            expected.push(source);
        }
        let foreign = EvidenceIntakeIdentityV1 {
            tenant_id: [4; 16],
            ..identity.clone()
        };
        store.accept_validated_coverage(crate::ValidatedCoverageV1 {
            identity: foreign.clone(),
            cpu_id: 0,
            revision: 1,
            encoded_report: vec![2],
        })?;
        expected.sort_by_key(source_key);
        let before = store.meta()?;
        let changed = store.subscribe_revision();
        let first = store.source_page(identity.tenant_id, None)?;
        assert_eq!(first, expected[..MAX_ANALYSIS_PAGE_RECORDS]);
        let second = store.source_page(identity.tenant_id, first.last())?;
        assert_eq!(second, expected[MAX_ANALYSIS_PAGE_RECORDS..]);
        assert!(store
            .source_page(identity.tenant_id, second.last())?
            .is_empty());
        assert_eq!(
            store.source_page(foreign.tenant_id, None)?,
            vec![foreign.clone()]
        );
        assert!(store
            .source_page(identity.tenant_id, Some(&foreign))
            .is_err());
        assert!(store.source_page([0; 16], None).is_err());
        assert_eq!(store.meta()?, before);
        assert!(!changed.has_changed()?);
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.source_page(identity.tenant_id, None)?, first);
        assert_eq!(store.source_page(identity.tenant_id, first.last())?, second);
        Ok(())
    }
}
