mod base;
mod prepared;
mod scratch;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arrow_array::{Array, BinaryArray, RecordBatch, StructArray, UInt64Array};
use arrow_schema::DataType;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use crate::error::{ConflictSnafu, DatabaseSnafu, InvalidSnafu};
use crate::{
    transaction::Commands, EntityKind, GraphStore, Journal, PendingGraph, Relation, Result, Staged,
};

use base::BaseRows;
use prepared::PreparedRows;
pub use prepared::{PreparedLayers, WriterCut};
use scratch::Scratch;

type Endpoints = Option<(u64, u64, u64)>;
type Selected<'a> = BTreeMap<usize, (&'a RecordBatch, Vec<u64>)>;

impl PendingGraph<'_> {
    pub fn apply_prepared(
        self,
        prepared: PreparedLayers,
        reserve: impl Fn(u64, usize, usize) -> Result<Option<Box<dyn std::any::Any + Send + Sync>>>,
    ) -> Result<BTreeMap<u64, (u64, u64)>> {
        self.check_heads()?;
        if prepared.parents.len() != self.heads.len() {
            return InvalidSnafu {
                field: "Graph prepared writers",
            }
            .fail();
        }
        for (writer, parent) in &prepared.parents {
            let Some(layer) = self.heads.get(writer) else {
                return InvalidSnafu {
                    field: "Graph prepared writer",
                }
                .fail();
            };
            let stored: Option<u64> = self.connection.query_row(
                "SELECT parent_id FROM graph_layers WHERE writer_id=? AND layer_id=? AND revision=?",
                params![writer,layer,self.revision],|row| row.get(0),
            ).context(DatabaseSnafu { operation: "check prepared Graph parent" })?;
            if stored != *parent {
                return ConflictSnafu {
                    resource: "prepared writer parent",
                }
                .fail();
            }
        }
        let scratch = Scratch::new(&reserve);
        let mut counts = prepared.base.close(&self, &scratch)?;
        for rows in prepared.rows {
            scratch.check(rows.writer)?;
            let writer = rows.writer;
            let inserted = self.append_members(rows, &scratch)?;
            counts.entry(writer).or_default().0 += inserted;
        }
        for writer in prepared.parents.keys() {
            scratch.check(*writer)?;
        }
        GraphStore::check_edges(self.connection, self.revision)?;
        for writer in prepared.parents.keys() {
            scratch.check(*writer)?;
        }
        Ok(counts)
    }

    fn append_members(&self, prepared: PreparedRows, scratch: &Scratch<'_>) -> Result<u64> {
        let writer = prepared.writer;
        let relation = prepared.relation;
        let shape = &prepared.shape;
        let owners = GraphStore::intern_owners(self.connection, writer, &prepared.owners)?;
        let entities = GraphStore::intern_entities(self.connection, relation, &prepared.keys)?;
        let properties =
            GraphStore::append_properties(self.connection, relation, shape, prepared.properties)?;
        let endpoints = prepared
            .endpoints
            .zip(prepared.edge_keys)
            .map(
                |((from, to, graph), (sources, targets, labels))| -> Result<_> {
                    Ok((
                        GraphStore::intern_entities(self.connection, from, &sources)?,
                        GraphStore::intern_entities(self.connection, to, &targets)?,
                        GraphStore::intern_labels(self.connection, graph, &labels)?,
                    ))
                },
            )
            .transpose()?;
        let mut rows = self
            .connection
            .appender("graph_members")
            .context(DatabaseSnafu {
                operation: "open final Graph members",
            })?;
        for row in 0..prepared.keys.len() {
            scratch.check(writer)?;
            let (from, to, label) = match &endpoints {
                Some((from, to, label)) => (Some(from[row]), Some(to[row]), Some(label[row])),
                None => (None, None, None),
            };
            rows.append_row(params![
                writer,
                owners[row],
                relation,
                shape.kind as u8,
                prepared.keys[row].as_slice(),
                entities[row],
                properties[row],
                from,
                to,
                label,
                self.revision,
                Option::<u64>::None
            ])
            .context(DatabaseSnafu {
                operation: "append final Graph member",
            })?;
        }
        rows.flush().context(DatabaseSnafu {
            operation: "flush final Graph members",
        })?;
        Ok(prepared.keys.len() as u64)
    }

    fn binary<'a>(batch: &'a RecordBatch, name: &str) -> Result<&'a BinaryArray> {
        batch
            .column_by_name(name)
            .and_then(|array| array.as_any().downcast_ref::<BinaryArray>())
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "Graph journal binary column",
                }
                .build()
            })
    }

    fn keys(batch: &RecordBatch, name: &str) -> Result<Vec<Vec<u8>>> {
        let array = Self::binary(batch, name)?;
        if array.null_count() != 0 {
            return InvalidSnafu {
                field: "Graph journal identity",
            }
            .fail();
        }
        Ok(array.iter().flatten().map(<[u8]>::to_vec).collect())
    }
}
