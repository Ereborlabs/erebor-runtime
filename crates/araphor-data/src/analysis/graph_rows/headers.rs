use duckdb::{params_from_iter, Connection};
use snafu::ResultExt as _;

use super::{GraphHeader, GraphRows};
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisReadDeniedSnafu, GraphInvalidSnafu, Result,
};

mod sql;

impl GraphRows {
    pub(in crate::analysis) fn visit_headers(
        reader: &Connection,
        tenant: [u8; 16],
        ids: &[String],
        control: &AnalysisReadControl,
        mut visit: impl FnMut(&str, GraphHeader, u64, Vec<u8>) -> Result<()>,
    ) -> Result<()> {
        for ids in ids.chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS) {
            control.check()?;
            let values = Self::header_values(tenant, ids);
            let mut statement =
                reader
                    .prepare(&Self::header_sql(ids.len()))
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare native graph headers",
                    })?;
            let mut rows = statement.query(params_from_iter(values.iter())).context(
                AnalysisDatabaseSnafu {
                    operation: "read native graph headers",
                },
            )?;
            let mut expected = ids.iter().map(String::as_str).collect::<Vec<_>>();
            expected.sort_unstable();
            for expected_id in expected {
                control.check()?;
                let row = rows
                    .next()
                    .context(AnalysisDatabaseSnafu {
                        operation: "advance native graph headers",
                    })?
                    .ok_or_else(|| AnalysisReadDeniedSnafu.build())?;
                let id: String = row.get(0).context(AnalysisDatabaseSnafu {
                    operation: "decode native graph header identity",
                })?;
                if id != expected_id {
                    return AnalysisReadDeniedSnafu.fail();
                }
                let bytes: Vec<u8> = row.get(1).context(AnalysisDatabaseSnafu {
                    operation: "decode native graph header bytes",
                })?;
                let stream: Option<Vec<u8>> = row.get(2).context(AnalysisDatabaseSnafu {
                    operation: "decode native graph header stream",
                })?;
                let stream = stream.ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph header index",
                    }
                    .build()
                })?;
                let method: u64 = row.get(3).context(AnalysisDatabaseSnafu {
                    operation: "decode graph method",
                })?;
                let first: u64 = row.get(4).context(AnalysisDatabaseSnafu {
                    operation: "decode graph first cursor",
                })?;
                let revision: u64 = row.get(5).context(AnalysisDatabaseSnafu {
                    operation: "decode graph commit revision",
                })?;
                let mut header = GraphHeader::decode(&bytes)?;
                header.check_index(tenant, &stream, method, first)?;
                let (evidence, positions) = Self::load_inputs(reader, &id, &header, Some(control))?;
                header.snapshot.input_manifest.evidence = evidence;
                header.snapshot.input_positions = positions;
                header.snapshot.validate()?;
                Self::check_shape(reader, &id, &header)?;
                visit(&id, header, revision, bytes)?;
            }
            if rows
                .next()
                .context(AnalysisDatabaseSnafu {
                    operation: "check native graph header count",
                })?
                .is_some()
            {
                return AnalysisReadDeniedSnafu.fail();
            }
        }
        control.check()?;
        Ok(())
    }
}
