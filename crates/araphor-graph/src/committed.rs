use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use arrow_array::{Array, BinaryArray, RecordBatch, StructArray, UInt64Array};
use arrow_schema::Schema;
use duckdb::{params, Connection};
use snafu::ResultExt as _;

use crate::error::{ConflictSnafu, DatabaseSnafu, InvalidSnafu};
use crate::{GraphStore, Read, Result};

type Identity = (u64, u64, u64, Arc<[u8]>, u64);

pub struct Member {
    pub writer: u64,
    pub owner: u64,
    pub relation: u64,
    pub kind: crate::EntityKind,
    pub owner_key: Arc<[u8]>,
    pub key: Arc<[u8]>,
    pub property: u64,
    pub revision: u64,
    pub(crate) endpoints: Option<[Arc<[u8]>; 3]>,
    pub(crate) properties: Arc<RecordBatch>,
    pub row: usize,
}

impl Member {
    fn identity(&self) -> Identity {
        (
            self.writer,
            self.owner,
            self.relation,
            Arc::clone(&self.key),
            self.revision,
        )
    }

    pub fn properties(&self) -> &RecordBatch {
        &self.properties
    }

    pub fn property_batch(&self) -> Result<RecordBatch> {
        Ok(arrow_select::take::take_record_batch(
            &self.properties,
            &UInt64Array::from(vec![self.row as u64]),
        )?)
    }
}

struct Version {
    member: Arc<Member>,
    closed: Option<u64>,
}

#[derive(Default)]
pub(crate) struct Members {
    rows: BTreeMap<Identity, Version>,
    keys: BTreeMap<(u64, Arc<[u8]>), BTreeSet<Identity>>,
    outgoing: BTreeMap<(u64, Arc<[u8]>), BTreeSet<Identity>>,
    incoming: BTreeMap<(u64, Arc<[u8]>), BTreeSet<Identity>>,
}

pub struct PendingLayer {
    index: Arc<RwLock<Members>>,
    added: Vec<Identity>,
    closed: Vec<Identity>,
    revision: u64,
    committed: bool,
}

impl PendingLayer {
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PendingLayer {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut index = self
            .index
            .write()
            .unwrap_or_else(|error| error.into_inner());
        for id in &self.added {
            index.remove(id);
        }
        for id in &self.closed {
            if let Some(row) = index.rows.get_mut(id) {
                if row.closed == Some(self.revision) {
                    row.closed = None;
                }
            }
        }
    }
}

impl Members {
    fn insert(&mut self, member: Member, closed: Option<u64>) {
        let id = member.identity();
        self.keys
            .entry((member.relation, Arc::clone(&member.key)))
            .or_default()
            .insert(id.clone());
        if let Some([from, to, _]) = &member.endpoints {
            self.outgoing
                .entry((member.relation, Arc::clone(from)))
                .or_default()
                .insert(id.clone());
            self.incoming
                .entry((member.relation, Arc::clone(to)))
                .or_default()
                .insert(id.clone());
        }
        self.rows.insert(
            id,
            Version {
                member: Arc::new(member),
                closed,
            },
        );
    }

    fn remove(&mut self, id: &Identity) {
        if let Some(row) = self.rows.remove(id) {
            let member = row.member;
            Self::remove_posting(&mut self.keys, member.relation, &member.key, id);
            if let Some([from, to, _]) = &member.endpoints {
                Self::remove_posting(&mut self.outgoing, member.relation, from, id);
                Self::remove_posting(&mut self.incoming, member.relation, to, id);
            }
        }
    }

    fn remove_posting(
        index: &mut BTreeMap<(u64, Arc<[u8]>), BTreeSet<Identity>>,
        relation: u64,
        key: &Arc<[u8]>,
        id: &Identity,
    ) {
        let key = (relation, Arc::clone(key));
        if let Some(rows) = index.get_mut(&key) {
            rows.remove(id);
            if rows.is_empty() {
                index.remove(&key);
            }
        }
    }

    fn visible(row: &Version, heads: &BTreeMap<u64, u64>) -> bool {
        heads.get(&row.member.writer).is_some_and(|head| {
            row.member.revision <= *head && row.closed.is_none_or(|closed| closed > *head)
        })
    }
}

impl GraphStore {
    pub(crate) fn seal(
        &self,
        revision: u64,
        added: Vec<Member>,
        closed: Vec<(u64, u64, u64, Vec<u8>, u64)>,
    ) -> Result<PendingLayer> {
        let mut guard = PendingLayer {
            index: Arc::clone(&self.committed),
            added: Vec::with_capacity(added.len()),
            closed: Vec::with_capacity(closed.len()),
            revision,
            committed: false,
        };
        {
            let mut index = self.committed.write().map_err(|_| {
                ConflictSnafu {
                    resource: "Graph layer index",
                }
                .build()
            })?;
            for (writer, owner, relation, key, opened) in closed {
                let id = (writer, owner, relation, Arc::from(key), opened);
                if let Some(row) = index.rows.get_mut(&id) {
                    row.closed = Some(revision);
                }
                guard.closed.push(id);
            }
            for member in added {
                guard.added.push(member.identity());
                index.insert(member, None);
            }
        }
        Ok(guard)
    }

    pub fn view(
        &self,
        heads: &BTreeMap<u64, u64>,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Vec<Arc<Member>>> {
        let index = self.committed.read().map_err(|_| {
            ConflictSnafu {
                resource: "Graph layer index",
            }
            .build()
        })?;
        let mut selected = Vec::new();
        for writer in heads.keys() {
            for (id, row) in index.rows.range((*writer, 0, 0, Arc::from([]), 0)..) {
                check()?;
                if id.0 != *writer {
                    break;
                }
                if Members::visible(row, heads) {
                    selected.push(Arc::clone(&row.member));
                }
            }
        }
        Ok(selected)
    }

    pub fn visit_members(
        &self,
        relation: u64,
        heads: &BTreeMap<u64, u64>,
        keys: Option<&[Vec<u8>]>,
        mut check: impl FnMut() -> Result<()>,
        mut visit: impl FnMut(&Arc<Member>) -> Result<()>,
    ) -> Result<()> {
        let index = self.committed.read().map_err(|_| {
            ConflictSnafu {
                resource: "Graph layer index",
            }
            .build()
        })?;
        let mut rows = |posting: &BTreeSet<Identity>| -> Result<()> {
            for id in posting {
                check()?;
                if let Some(row) = index
                    .rows
                    .get(id)
                    .filter(|row| Members::visible(row, heads))
                {
                    visit(&row.member)?;
                }
            }
            Ok(())
        };
        if let Some(keys) = keys {
            for key in keys.iter().collect::<BTreeSet<_>>() {
                if let Some(posting) = index.keys.get(&(relation, Arc::from(key.as_slice()))) {
                    rows(posting)?;
                }
            }
        } else {
            for ((selected, _), posting) in index.keys.range((relation, Arc::from([]))..) {
                if *selected != relation {
                    break;
                }
                rows(posting)?;
            }
        }
        Ok(())
    }

    pub fn members(
        &self,
        relation: u64,
        heads: &BTreeMap<u64, u64>,
        keys: Option<&[Vec<u8>]>,
        check: impl FnMut() -> Result<()>,
    ) -> Result<Vec<Arc<Member>>> {
        self.select(relation, heads, Read::Nodes, keys, check)
    }

    pub(crate) fn select(
        &self,
        relation: u64,
        heads: &BTreeMap<u64, u64>,
        read: Read,
        keys: Option<&[Vec<u8>]>,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Vec<Arc<Member>>> {
        let index = self.committed.read().map_err(|_| {
            ConflictSnafu {
                resource: "Graph layer index",
            }
            .build()
        })?;
        let mut ids = BTreeSet::new();
        if let Some(keys) = keys {
            let indexes = match read {
                Read::Nodes | Read::Owned(_) => vec![&index.keys],
                Read::Outgoing => vec![&index.outgoing],
                Read::Incoming => vec![&index.incoming],
                Read::Neighbors => vec![&index.outgoing, &index.incoming],
            };
            for key in keys {
                check()?;
                for posting in &indexes {
                    if let Some(found) = posting.get(&(relation, Arc::from(key.as_slice()))) {
                        for id in found {
                            check()?;
                            ids.insert(id.clone());
                        }
                    }
                }
            }
        } else {
            for ((selected, _), rows) in index.keys.range((relation, Arc::from([]))..) {
                if *selected != relation {
                    break;
                }
                for id in rows {
                    check()?;
                    ids.insert(id.clone());
                }
            }
        }
        let mut rows = ids
            .into_iter()
            .filter_map(|id| index.rows.get(&id))
            .filter(|row| Members::visible(row, heads))
            .filter(|row| !matches!(read,Read::Owned(writer) if writer != row.member.writer))
            .map(|row| Arc::clone(&row.member))
            .collect::<Vec<_>>();
        rows.sort_unstable_by(|a, b| {
            (a.writer, &a.owner_key, &a.key).cmp(&(b.writer, &b.owner_key, &b.key))
        });
        Ok(rows)
    }

    pub fn writer_heads(
        connection: &Connection,
        graph: u64,
        revision: u64,
    ) -> Result<BTreeMap<u64, u64>> {
        let mut query = connection
            .prepare_cached(
                "SELECT writer.writer_id,max(layer.revision) FROM graph_writers writer
             JOIN graph_layers layer USING(writer_id) WHERE writer.graph_id=? AND layer.revision<=?
             GROUP BY writer.writer_id",
            )
            .context(DatabaseSnafu {
                operation: "prepare native Graph writer heads",
            })?;
        query
            .query_map(params![graph, revision], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .context(DatabaseSnafu {
                operation: "read native Graph writer heads",
            })?
            .collect::<duckdb::Result<_>>()
            .context(DatabaseSnafu {
                operation: "decode native Graph writer heads",
            })
    }

    pub(crate) fn restore(&self, connection: &Connection) -> Result<()> {
        let mut query = connection
            .prepare("SELECT relation_id,entity_kind FROM graph_relations")
            .context(DatabaseSnafu {
                operation: "prepare retained Graph relations",
            })?;
        let relations = query
            .query_map([], |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u8>(1)?)))
            .context(DatabaseSnafu {
                operation: "read retained Graph relations",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(DatabaseSnafu {
                operation: "decode retained Graph relations",
            })?;
        let mut index = self.committed.write().map_err(|_| {
            ConflictSnafu {
                resource: "Graph layer index",
            }
            .build()
        })?;
        for (relation, kind) in relations {
            let endpoints = if kind == 1 {
                "source.entity_key,target.entity_key,label.label_key"
            } else {
                "NULL::BLOB,NULL::BLOB,NULL::BLOB"
            };
            let joins = if kind == 1 {
                "LEFT JOIN graph_entities source ON source.entity_ref=m.from_ref
                LEFT JOIN graph_entities target ON target.entity_ref=m.to_ref
                LEFT JOIN graph_labels label ON label.label_ref=m.label_ref"
            } else {
                ""
            };
            let mut query = connection.prepare(&format!(
                "SELECT m.writer_id,m.owner_ref,m.entity_key,m.properties_ref,m.valid_from,m.valid_to,
                    owner.owner_key,{endpoints},property.properties
                 FROM graph_members m JOIN graph_writer_owners owner
                    ON owner.writer_id=m.writer_id AND owner.owner_ref=m.owner_ref
                 JOIN graph_properties_{relation} property ON property.property_ref=m.properties_ref
                 {joins} WHERE m.relation_id={relation}"
            )).context(DatabaseSnafu { operation: "prepare retained native Graph members" })?;
            for batch in query.query_arrow([]).context(DatabaseSnafu {
                operation: "restore native Graph members",
            })? {
                let uint = |column: usize| -> Result<&UInt64Array> {
                    batch.column(column).as_any().downcast_ref().ok_or_else(|| {
                        InvalidSnafu {
                            field: "retained Graph integer",
                        }
                        .build()
                    })
                };
                let binary = |column: usize| -> Result<&BinaryArray> {
                    batch.column(column).as_any().downcast_ref().ok_or_else(|| {
                        InvalidSnafu {
                            field: "retained Graph key",
                        }
                        .build()
                    })
                };
                let properties = batch
                    .column(10)
                    .as_any()
                    .downcast_ref::<StructArray>()
                    .ok_or_else(|| {
                        InvalidSnafu {
                            field: "retained Graph properties",
                        }
                        .build()
                    })?;
                let properties = Arc::new(RecordBatch::try_new(
                    Arc::new(Schema::new(properties.fields().clone())),
                    properties.columns().to_vec(),
                )?);
                for row in 0..batch.num_rows() {
                    index.insert(
                        Member {
                            writer: uint(0)?.value(row),
                            owner: uint(1)?.value(row),
                            relation,
                            kind: if kind == 1 {
                                crate::EntityKind::Edge
                            } else {
                                crate::EntityKind::Node
                            },
                            key: Arc::from(binary(2)?.value(row)),
                            property: uint(3)?.value(row),
                            revision: uint(4)?.value(row),
                            owner_key: Arc::from(binary(6)?.value(row)),
                            endpoints: if kind == 1 {
                                Some([
                                    Arc::from(binary(7)?.value(row)),
                                    Arc::from(binary(8)?.value(row)),
                                    Arc::from(binary(9)?.value(row)),
                                ])
                            } else {
                                None
                            },
                            properties: Arc::clone(&properties),
                            row,
                        },
                        (!uint(5)?.is_null(row))
                            .then(|| uint(5).map(|array| array.value(row)))
                            .transpose()?,
                    );
                }
            }
        }
        Ok(())
    }
}
