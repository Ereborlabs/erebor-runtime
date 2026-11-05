use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::{version_key, AnalysisContextVersionV1};
use crate::{
    AnalysisDatabaseSnafu, AnalysisStore, GraphValidate as _, PackageErrorCodeV1 as Code, Result,
};

#[derive(Eq, PartialEq)]
pub(in crate::analysis) struct FactRecord {
    pub(in crate::analysis) record: Vec<u8>,
    pub(in crate::analysis) stream: Vec<u8>,
    pub(in crate::analysis) cursor: u64,
}

impl AnalysisStore {
    pub(in crate::analysis) fn fact_record(
        input: &AnalysisContextVersionV1,
    ) -> Result<Option<FactRecord>> {
        let Ok(fact) = crate::GraphFactV1::decode_context(&input.body) else {
            return Ok(None);
        };
        fact.validate()?;
        if fact.record_id.stream.tenant_id != input.key.tenant_id {
            return Err(Code::Invalid.error("canonical fact tenant"));
        }
        araphor_analysis_types::DomainRelations::key(&fact.record_id)
            .map(|record| {
                Some(FactRecord {
                    record,
                    stream: fact.record_id.stream.key(),
                    cursor: fact.record_id.durable_cursor,
                })
            })
            .map_err(|source| crate::Error::AnalysisContract {
                source,
                location: snafu::location!(),
            })
    }

    pub(in crate::analysis) fn check_fact_index(
        connection: &Connection,
        input: &AnalysisContextVersionV1,
    ) -> Result<()> {
        let actual: Option<FactRecord> = connection
            .query_row(
                "SELECT record_key,stream_key,source_cursor FROM graph_fact_records WHERE version_key=?",
                params![version_key(&input.key)?],
                |row| Ok(FactRecord { record:row.get(0)?,stream:row.get(1)?,cursor:row.get(2)? }),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read canonical fact index",
            })?;
        if actual != Self::fact_record(input)? {
            return Err(Code::Invalid.error("canonical fact index"));
        }
        Ok(())
    }

    pub(in crate::analysis) fn insert_fact_index(
        connection: &Connection,
        input: &AnalysisContextVersionV1,
    ) -> Result<()> {
        if let Some(record) = Self::fact_record(input)? {
            connection
                .execute(
                    "INSERT INTO graph_fact_records VALUES (?,?,?,?)",
                    params![
                        version_key(&input.key)?,
                        record.record,
                        record.stream,
                        record.cursor
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "index canonical fact record",
                })?;
        }
        Ok(())
    }
}
