use arrow_array::{Array, BinaryArray, RecordBatch};
use duckdb::{Connection, OptionalExt as _, params};
use snafu::ResultExt as _;

use crate::error::{DatabaseSnafu, InvalidSnafu};
use crate::{GraphReadView, GraphStore, Result};

impl GraphStore {
    pub fn presence(
        &self,
        connection: &Connection,
        writer: u64,
        relation: u64,
        revision: u64,
        batch: &RecordBatch,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Vec<bool>> {
        GraphReadView::presence_keys(writer, relation, batch)?;
        if writer == 0 || relation == 0 || revision == 0 {
            return InvalidSnafu {
                field: "Graph presence identity",
            }
            .fail();
        }
        let graph: Option<u64> = connection
            .query_row(
                "SELECT graph_id FROM graph_writers WHERE writer_id=?",
                params![writer],
                |row| row.get(0),
            )
            .optional()
            .context(DatabaseSnafu {
                operation: "read Graph presence writer",
            })?;
        let Some(graph) = graph else {
            return Ok(vec![false; batch.num_rows()]);
        };
        self.read_view(connection, graph, revision, &[relation], &mut check, |_| {
            Ok(())
        })?
        .presence(writer, relation, batch, check)
    }
}

impl GraphReadView {
    pub fn presence(
        &self,
        writer: u64,
        relation: u64,
        batch: &RecordBatch,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Vec<bool>> {
        check()?;

        let (owners, keys) = Self::presence_keys(writer, relation, batch)?;
        let wanted = keys
            .iter()
            .flatten()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let selected = self
            .store
            .members(relation, &self.heads, Some(&wanted), &mut check)?;
        let present = selected
            .iter()
            .filter(|row| row.writer == writer)
            .map(|row| (row.owner_key.as_ref(), row.key.as_ref()))
            .collect::<std::collections::BTreeSet<_>>();
        Ok((0..batch.num_rows())
            .map(|row| present.contains(&(owners.value(row), keys.value(row))))
            .collect())
    }
    fn presence_keys(
        writer: u64,
        relation: u64,
        batch: &RecordBatch,
    ) -> Result<(&BinaryArray, &BinaryArray)> {
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
        if writer == 0 || relation == 0 || owners.null_count() != 0 || keys.null_count() != 0 {
            return InvalidSnafu {
                field: "Graph presence identity",
            }
            .fail();
        }
        Ok((owners, keys))
    }
}
