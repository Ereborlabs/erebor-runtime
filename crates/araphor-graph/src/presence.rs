use arrow_array::{Array, BinaryArray, RecordBatch};
use duckdb::{params, Connection};
use snafu::ResultExt as _;

use crate::error::{DatabaseSnafu, InvalidSnafu};
use crate::{GraphStore, Result};

impl GraphStore {
    pub fn presence(
        connection: &Connection,
        writer: u64,
        relation: u64,
        revision: u64,
        batch: &RecordBatch,
    ) -> Result<Vec<bool>> {
        let owners = batch
            .column_by_name("owner")
            .and_then(|array| array.as_any().downcast_ref::<BinaryArray>());
        let keys = batch
            .column_by_name("key")
            .and_then(|array| array.as_any().downcast_ref::<BinaryArray>());
        let (Some(owners), Some(keys)) = (owners, keys) else {
            return InvalidSnafu {
                field: "Graph presence shape",
            }
            .fail();
        };
        if writer == 0
            || relation == 0
            || revision == 0
            || owners.null_count() != 0
            || keys.null_count() != 0
        {
            return InvalidSnafu {
                field: "Graph presence identity",
            }
            .fail();
        }
        connection.execute_batch("CREATE TEMP TABLE graph_presence_keys (ordinal UBIGINT PRIMARY KEY,owner_key BLOB,entity_key BLOB)")
            .context(DatabaseSnafu { operation: "create Graph presence keys" })?;
        let result = (|| {
            {
                let mut appender =
                    connection
                        .appender("graph_presence_keys")
                        .context(DatabaseSnafu {
                            operation: "open Graph presence keys",
                        })?;
                for row in 0..batch.num_rows() {
                    appender
                        .append_row(params![row as u64, owners.value(row), keys.value(row)])
                        .context(DatabaseSnafu {
                            operation: "append Graph presence key",
                        })?;
                }
                appender.flush().context(DatabaseSnafu {
                    operation: "flush Graph presence keys",
                })?;
            }
            let mut statement = connection
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM graph_members m JOIN graph_writer_owners o
                    ON o.writer_id=m.writer_id AND o.owner_ref=m.owner_ref
                    WHERE m.writer_id=? AND m.relation_id=? AND o.owner_key=input.owner_key
                        AND m.entity_key=input.entity_key AND m.valid_from<=?
                        AND (m.valid_to IS NULL OR m.valid_to>?))
                 FROM graph_presence_keys input ORDER BY input.ordinal",
                )
                .context(DatabaseSnafu {
                    operation: "prepare Graph presence",
                })?;
            let rows = statement
                .query_map(params![writer, relation, revision, revision], |row| {
                    row.get(0)
                })
                .context(DatabaseSnafu {
                    operation: "read Graph presence",
                })?
                .collect::<duckdb::Result<Vec<bool>>>()
                .context(DatabaseSnafu {
                    operation: "decode Graph presence",
                })?;
            if rows.len() != batch.num_rows() {
                return InvalidSnafu {
                    field: "Graph presence count",
                }
                .fail();
            }
            Ok(rows)
        })();
        let cleanup = connection
            .execute_batch("DROP TABLE graph_presence_keys")
            .context(DatabaseSnafu {
                operation: "release Graph presence keys",
            });
        let rows = result?;
        cleanup?;
        Ok(rows)
    }
}
