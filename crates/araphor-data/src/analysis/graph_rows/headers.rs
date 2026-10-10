use duckdb::{params_from_iter, Connection};
use snafu::ResultExt as _;

use super::{GraphHeader, GraphRows};
use crate::{
    AnalysisDatabaseSnafu, AnalysisInputTooLargeSnafu, AnalysisReadControl, GraphInvalidSnafu,
    QueryDeniedSnafu, Result,
};

mod sql;

struct HeaderBounds {
    id: String,
    method: u64,
    first: u64,
    revision: u64,
    length: usize,
    stored: u64,
}

impl GraphRows {
    pub(in crate::analysis) fn visit_headers(
        reader: &Connection,
        tenant: [u8; 16],
        ids: &[String],
        header_bytes: usize,
        control: &AnalysisReadControl,
        mut visit: impl FnMut(&str, GraphHeader, u64, Vec<u8>) -> Result<()>,
    ) -> Result<()> {
        for ids in ids.chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS) {
            control.check()?;
            let bounds = Self::header_bounds(reader, tenant, ids, header_bytes, control)?;
            let values = Self::header_values(tenant, ids);
            let mut statement = reader
                .prepare(&Self::header_payload_sql(ids.len()))
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare native graph headers",
                })?;
            let mut rows = statement.query(params_from_iter(values.iter())).context(
                AnalysisDatabaseSnafu {
                    operation: "read native graph headers",
                },
            )?;
            for bound in bounds {
                control.check()?;
                let row = rows
                    .next()
                    .context(AnalysisDatabaseSnafu {
                        operation: "advance native graph headers",
                    })?
                    .ok_or_else(|| QueryDeniedSnafu.build())?;
                let id: String = row.get(0).context(AnalysisDatabaseSnafu {
                    operation: "decode native graph header identity",
                })?;
                if id != bound.id {
                    return QueryDeniedSnafu.fail();
                }
                let bytes: Vec<u8> = row.get(1).context(AnalysisDatabaseSnafu {
                    operation: "decode native graph header bytes",
                })?;
                let stream: Vec<u8> = row.get(2).context(AnalysisDatabaseSnafu {
                    operation: "decode native graph header stream",
                })?;
                if bytes.len() != bound.length {
                    return GraphInvalidSnafu {
                        field: "graph header bytes",
                    }
                    .fail();
                }
                let header = GraphHeader::decode(&bytes)?;
                header.check_index(tenant, &stream, bound.method, bound.first)?;
                header.check_bytes(&id, bound.stored)?;
                visit(&id, header, bound.revision, bytes)?;
            }
            if rows
                .next()
                .context(AnalysisDatabaseSnafu {
                    operation: "check native graph header count",
                })?
                .is_some()
            {
                return QueryDeniedSnafu.fail();
            }
        }
        control.check()?;
        Ok(())
    }

    fn header_bounds(
        reader: &Connection,
        tenant: [u8; 16],
        ids: &[String],
        header_bytes: usize,
        control: &AnalysisReadControl,
    ) -> Result<Vec<HeaderBounds>> {
        let values = Self::header_values(tenant, ids);
        let mut statement = reader
            .prepare(&Self::header_bounds_sql(ids.len()))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare native graph header bounds",
            })?;
        let mut rows =
            statement
                .query(params_from_iter(values.iter()))
                .context(AnalysisDatabaseSnafu {
                    operation: "read native graph header bounds",
                })?;
        let mut expected = ids.iter().map(String::as_str).collect::<Vec<_>>();
        expected.sort_unstable();
        let mut bounds = Vec::new();
        bounds.try_reserve_exact(ids.len()).map_err(|_| {
            AnalysisInputTooLargeSnafu {
                resource: "graph header buffers",
            }
            .build()
        })?;
        let mut bytes = 0usize;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance native graph header bounds",
        })? {
            control.check()?;
            let id: String = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "decode native graph header identity",
            })?;
            if expected.get(bounds.len()).copied() != Some(id.as_str()) {
                return QueryDeniedSnafu.fail();
            }
            let length: u64 = row.get(4).context(AnalysisDatabaseSnafu {
                operation: "decode native graph header length",
            })?;
            let stream: u64 = row.get(5).context(AnalysisDatabaseSnafu {
                operation: "decode native graph stream length",
            })?;
            if length > GraphHeader::MAX_BYTES as u64 {
                return GraphInvalidSnafu {
                    field: "graph header bytes",
                }
                .fail();
            }
            if stream > crate::EvidenceIntakeIdentityV1::MAX_KEY_BYTES as u64 {
                return GraphInvalidSnafu {
                    field: "graph header index",
                }
                .fail();
            }
            bytes = bytes
                .checked_add(256 + id.len() + length as usize + stream as usize)
                .ok_or_else(|| {
                    AnalysisInputTooLargeSnafu {
                        resource: "graph header buffers",
                    }
                    .build()
                })?;
            if bytes > header_bytes {
                return AnalysisInputTooLargeSnafu {
                    resource: "graph header buffers",
                }
                .fail();
            }
            bounds.push(HeaderBounds {
                id,
                length: length as usize,
                method: row.get(1).context(AnalysisDatabaseSnafu {
                    operation: "decode graph method",
                })?,
                first: row.get(2).context(AnalysisDatabaseSnafu {
                    operation: "decode graph first cursor",
                })?,
                revision: row.get(3).context(AnalysisDatabaseSnafu {
                    operation: "decode graph commit revision",
                })?,
                stored: row.get(6).context(AnalysisDatabaseSnafu {
                    operation: "decode native graph charge",
                })?,
            });
        }
        if bounds.len() != expected.len() {
            return QueryDeniedSnafu.fail();
        }
        Ok(bounds)
    }
}
