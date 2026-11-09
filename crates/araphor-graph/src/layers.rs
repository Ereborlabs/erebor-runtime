mod base;
mod keys;
mod prepared;
use crate::scratch;

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
use keys::{LayerKeys, MemberKeys};
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
    ) -> Result<(BTreeMap<u64, (u64, u64)>, crate::PendingLayer)> {
        let started = std::time::Instant::now();
        self.check_heads()?;
        prepared.check_current(&self)?;
        let heads_at = std::time::Instant::now();
        let mut scratch = Scratch::new(&reserve);
        let closed = prepared.base.closures();
        let mut counts = prepared.base.close(&self, &scratch)?;
        let closed_at = std::time::Instant::now();
        let keys = LayerKeys::new(self.connection, &prepared.rows, &mut scratch)?;
        let keys_at = std::time::Instant::now();
        let mut members = Vec::new();
        for (index, rows) in prepared.rows.into_iter().enumerate() {
            scratch.check(rows.writer)?;
            let writer = rows.writer;
            let inserted = self.append_members(rows, keys.batch(index), &scratch)?;
            counts.entry(writer).or_default().0 += inserted.len() as u64;
            members.extend(inserted);
        }
        let members_at = std::time::Instant::now();
        for writer in prepared.parents.keys() {
            scratch.check(*writer)?;
        }
        GraphStore::check_edges(self.connection, self.revision)?;
        let edges_at = std::time::Instant::now();
        for writer in prepared.parents.keys() {
            scratch.check(*writer)?;
        }
        let inserted_rows = members.len();
        let closed_rows = closed.len();
        let layer = self.store.seal(self.revision, members, closed)?;
        erebor_telemetry::debug!(
            stage = "graph_apply_timing",
            revision = self.revision,
            writers = prepared.parents.len(),
            inserted_rows,
            closed_rows,
            heads_s = heads_at.duration_since(started).as_secs_f64(),
            close_s = closed_at.duration_since(heads_at).as_secs_f64(),
            dictionaries_s = keys_at.duration_since(closed_at).as_secs_f64(),
            members_s = members_at.duration_since(keys_at).as_secs_f64(),
            edges_s = edges_at.duration_since(members_at).as_secs_f64(),
            seal_s = edges_at.elapsed().as_secs_f64(),
            elapsed_s = started.elapsed().as_secs_f64(),
            "Graph layer application completed"
        );
        Ok((counts, layer))
    }

    fn append_members(
        &self,
        prepared: PreparedRows,
        keys: MemberKeys<'_>,
        scratch: &Scratch<'_>,
    ) -> Result<Vec<crate::Member>> {
        let started = std::time::Instant::now();
        let writer = prepared.writer;
        let relation = prepared.relation;
        let shape = &prepared.shape;
        let owners = keys.owners;
        let entities = keys.entities;
        let properties = GraphStore::append_properties(
            self.connection,
            relation,
            shape,
            prepared.properties.clone(),
        )?;
        let properties_at = std::time::Instant::now();
        let endpoints = keys.endpoints;
        let endpoints_at = std::time::Instant::now();
        let mut rows = self
            .connection
            .appender("graph_members")
            .context(DatabaseSnafu {
                operation: "open final Graph members",
            })?;
        let properties_batch = Arc::new(prepared.properties.clone());
        let mut members = Vec::with_capacity(prepared.keys.len());
        for row in 0..prepared.keys.len() {
            scratch.check(writer)?;
            let (from, to, label) = match &endpoints {
                Some([from, to, label]) => (Some(from[row]), Some(to[row]), Some(label[row])),
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
            members.push(crate::Member {
                writer,
                owner: owners[row],
                relation,
                kind: shape.kind,
                owner_key: Arc::from(prepared.owners[row].as_slice()),
                key: Arc::from(prepared.keys[row].as_slice()),
                property: properties[row],
                revision: self.revision,
                endpoints: prepared.edge_keys.as_ref().map(|(from, to, label)| {
                    [
                        Arc::from(from[row].as_slice()),
                        Arc::from(to[row].as_slice()),
                        Arc::from(label[row].as_slice()),
                    ]
                }),
                properties: Arc::clone(&properties_batch),
                row,
            });
        }
        rows.flush().context(DatabaseSnafu {
            operation: "flush final Graph members",
        })?;
        erebor_telemetry::debug!(
            stage = "graph_append_timing",
            revision = self.revision,
            writer,
            relation,
            rows = members.len(),
            properties_s = properties_at.duration_since(started).as_secs_f64(),
            endpoints_s = endpoints_at.duration_since(properties_at).as_secs_f64(),
            members_s = endpoints_at.elapsed().as_secs_f64(),
            elapsed_s = started.elapsed().as_secs_f64(),
            "Graph relation append completed"
        );
        Ok(members)
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
