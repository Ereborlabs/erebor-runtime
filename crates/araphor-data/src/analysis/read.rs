use duckdb::{params, OptionalExt as _};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::{
    source_key, AnalysisReadPageV1, AnalysisRecordV1, AnalysisStore, StorePositionV1,
    MAX_ANALYSIS_PAGE_BYTES, MAX_ANALYSIS_PAGE_RECORDS,
};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, Result, RetainedRangeExpiredSnafu};

impl AnalysisStore {
    pub fn read_page(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        first_cursor: u64,
    ) -> Result<AnalysisReadPageV1> {
        let key = source_key(identity);
        let writer = self.writer()?;
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
                receipt.contiguous_cursor,
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
        if next_cursor <= receipt.contiguous_cursor && !bounded {
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
