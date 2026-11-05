use duckdb::{params, Connection, Transaction};
use snafu::ResultExt as _;

use crate::error::{DatabaseSnafu, InvalidSnafu};
use crate::{GraphStore, Result};

impl GraphStore {
    pub fn intern_owners(
        connection: &Transaction<'_>,
        writer: u64,
        keys: &[Vec<u8>],
    ) -> Result<Vec<u64>> {
        Self::intern_values(connection, writer, keys, true)
    }

    pub fn intern_labels(
        connection: &Transaction<'_>,
        graph: u64,
        keys: &[Vec<u8>],
    ) -> Result<Vec<u64>> {
        Self::intern_values(connection, graph, keys, false)
    }

    fn intern_values(
        connection: &Connection,
        scope: u64,
        keys: &[Vec<u8>],
        owners: bool,
    ) -> Result<Vec<u64>> {
        if scope == 0 {
            return InvalidSnafu {
                field: "Graph dictionary scope",
            }
            .fail();
        }
        if owners {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM graph_writers WHERE writer_id=?)",
                    params![scope],
                    |row| row.get(0),
                )
                .context(DatabaseSnafu {
                    operation: "check Graph owner writer",
                })?;
            if !exists {
                return InvalidSnafu {
                    field: "Graph owner writer",
                }
                .fail();
            }
        }
        connection.execute_batch(
            "CREATE TEMP TABLE graph_dictionary_keys (ordinal UBIGINT PRIMARY KEY,entity_key BLOB NOT NULL)"
        ).context(DatabaseSnafu { operation: "create Graph dictionary keys" })?;
        let result = Self::insert_values(connection, scope, keys, owners);
        let cleanup = connection
            .execute_batch("DROP TABLE graph_dictionary_keys")
            .context(DatabaseSnafu {
                operation: "release Graph dictionary keys",
            });
        let result = result?;
        cleanup?;
        Ok(result)
    }

    fn insert_values(
        connection: &Connection,
        scope: u64,
        keys: &[Vec<u8>],
        owners: bool,
    ) -> Result<Vec<u64>> {
        {
            let mut appender =
                connection
                    .appender("graph_dictionary_keys")
                    .context(DatabaseSnafu {
                        operation: "open Graph dictionary keys",
                    })?;
            for (ordinal, key) in keys.iter().enumerate() {
                appender
                    .append_row(params![ordinal as u64, key])
                    .context(DatabaseSnafu {
                        operation: "append Graph dictionary key",
                    })?;
            }
            appender.flush().context(DatabaseSnafu {
                operation: "flush Graph dictionary keys",
            })?;
        }
        let (table, column, identity, key, sequence) = if owners {
            (
                "graph_writer_owners",
                "writer_id",
                "owner_ref",
                "owner_key",
                "graph_owners_seq",
            )
        } else {
            (
                "graph_labels",
                "graph_id",
                "label_ref",
                "label_key",
                "graph_labels_seq",
            )
        };
        let columns = if owners {
            "writer_id,owner_ref,owner_key"
        } else {
            "graph_id,label_ref,label_key"
        };
        connection
            .execute(
                &format!(
                    "INSERT INTO {table}({columns})
                SELECT ?,nextval('{sequence}'),entity_key FROM (
                    SELECT DISTINCT input.entity_key FROM graph_dictionary_keys input
                    LEFT JOIN {table} stored ON stored.{column}=? AND stored.{key}=input.entity_key
                    WHERE stored.{identity} IS NULL)"
                ),
                params![scope, scope],
            )
            .context(DatabaseSnafu {
                operation: "intern Graph dictionary values",
            })?;
        let mut statement = connection
            .prepare(&format!(
                "SELECT input.ordinal,stored.{identity} FROM graph_dictionary_keys input
             JOIN {table} stored ON stored.{column}=? AND stored.{key}=input.entity_key
             ORDER BY input.ordinal"
            ))
            .context(DatabaseSnafu {
                operation: "prepare Graph dictionary identities",
            })?;
        let mut rows = statement.query(params![scope]).context(DatabaseSnafu {
            operation: "read Graph dictionary identities",
        })?;
        let mut identities = Vec::with_capacity(keys.len());
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance Graph dictionary identities",
        })? {
            let ordinal: u64 = row.get(0).context(DatabaseSnafu {
                operation: "decode Graph dictionary ordinal",
            })?;
            let identity: u64 = row.get(1).context(DatabaseSnafu {
                operation: "decode Graph dictionary identity",
            })?;
            if ordinal != identities.len() as u64 || identity == 0 {
                return InvalidSnafu {
                    field: "Graph dictionary identity",
                }
                .fail();
            }
            identities.push(identity);
        }
        if identities.len() != keys.len() {
            return InvalidSnafu {
                field: "Graph dictionary size",
            }
            .fail();
        }
        Ok(identities)
    }
}
