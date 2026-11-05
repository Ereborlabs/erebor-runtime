use std::sync::Arc;

use arrow_array::{Array, BinaryArray, BooleanArray, RecordBatch, UInt64Array};
use arrow_schema::DataType;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use crate::error::{DatabaseSnafu, InvalidSnafu};
use crate::{EntityKind, GraphStore, Read, Relation, Result};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReadOrigin {
    pub writer: u64,
    pub revision: u64,
}

impl GraphStore {
    pub fn read(
        connection: &Connection,
        graph: u64,
        relation: u64,
        shape: &Relation,
        revision: u64,
        read: Read,
        keys: &RecordBatch,
        mut reserve: impl FnMut(&RecordBatch) -> Result<()>,
        mut visit: impl FnMut(RecordBatch, Vec<ReadOrigin>) -> Result<()>,
    ) -> Result<()> {
        if graph == 0
            || relation == 0
            || revision == 0
            || keys.schema().as_ref() != &if matches!(read,Read::Owned(_)) { arrow_schema::Schema::empty() } else { Relation::key_schema() }
            || matches!(read,Read::Owned(0))
            || matches!(read,Read::Owned(_)) && keys.num_rows()!=0
            || !matches!(
                (shape.kind, read),
                (_,Read::Owned(1..)) | (EntityKind::Node, Read::Nodes)
                    | (
                        EntityKind::Edge,
                        Read::Outgoing | Read::Incoming | Read::Neighbors
                    )
            )
        {
            return InvalidSnafu {
                field: "Graph read declaration",
            }
            .fail();
        }
        let empty = BinaryArray::from_iter_values(std::iter::empty::<&[u8]>());
        let keys = if matches!(read,Read::Owned(_)) { &empty } else {
            keys.column(0).as_any().downcast_ref::<BinaryArray>()
                .filter(|keys| keys.null_count()==0).ok_or_else(|| InvalidSnafu { field:"Graph read keys" }.build())?
        };
        let declared: Option<(u8, Option<u64>, Option<u64>)> = connection
            .query_row(
                "SELECT entity_kind,from_relation,to_relation FROM graph_relations
                 WHERE graph_id=? AND relation_id=?",
                params![graph, relation],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context(DatabaseSnafu {
                operation: "check Graph read relation",
            })?;
        if !declared.is_some_and(|(kind, from, to)| {
            kind == shape.kind as u8
                && matches!(
                    (shape.kind, from, to),
                    (EntityKind::Node, None, None) | (EntityKind::Edge, Some(1..), Some(1..))
                )
        }) {
            return InvalidSnafu {
                field: "Graph stored relation",
            }
            .fail();
        }
        if keys.is_empty() && !matches!(read,Read::Owned(_)) {
            let batch = RecordBatch::new_empty(Arc::new(shape.read_schema()));
            reserve(&batch)?;
            return visit(batch, Default::default());
        }
        connection
            .execute_batch("CREATE TEMP TABLE graph_read_keys (entity_key BLOB PRIMARY KEY)")
            .context(DatabaseSnafu {
                operation: "create Graph read keys",
            })?;
        let result = Self::read_keys(
            connection,
            graph,
            relation,
            shape,
            revision,
            read,
            keys,
            &mut reserve,
            &mut visit,
        );
        let cleanup = connection
            .execute_batch("DROP TABLE graph_read_keys")
            .context(DatabaseSnafu {
                operation: "release Graph read keys",
            });
        result?;
        cleanup
    }

    fn read_keys(
        connection: &Connection,
        graph: u64,
        relation: u64,
        shape: &Relation,
        revision: u64,
        read: Read,
        keys: &BinaryArray,
        reserve: &mut impl FnMut(&RecordBatch) -> Result<()>,
        visit: &mut impl FnMut(RecordBatch, Vec<ReadOrigin>) -> Result<()>,
    ) -> Result<()> {
        let keys = keys
            .iter()
            .flatten()
            .collect::<std::collections::BTreeSet<_>>();
        {
            let mut appender = connection
                .appender("graph_read_keys")
                .context(DatabaseSnafu {
                    operation: "open Graph read keys",
                })?;
            for key in keys {
                appender.append_row(params![key]).context(DatabaseSnafu {
                    operation: "append Graph read key",
                })?;
            }
            appender.flush().context(DatabaseSnafu {
                operation: "flush Graph read keys",
            })?;
        }
        let endpoints = if shape.kind == EntityKind::Edge {
            ", source.entity_key AS \"from\", target.entity_key AS \"to\", label.label_key AS label"
        } else {
            ""
        };
        let joins = if shape.kind == EntityKind::Edge {
            "LEFT JOIN graph_entities source ON source.entity_ref=m.from_ref
                AND source.relation_id=relation.from_relation
             LEFT JOIN graph_relations source_kind ON source_kind.relation_id=source.relation_id
                AND source_kind.graph_id=relation.graph_id AND source_kind.entity_kind=0
             LEFT JOIN graph_entities target ON target.entity_ref=m.to_ref
                AND target.relation_id=relation.to_relation
             LEFT JOIN graph_relations target_kind ON target_kind.relation_id=target.relation_id
                AND target_kind.graph_id=relation.graph_id AND target_kind.entity_kind=0
             LEFT JOIN graph_labels label ON label.label_ref=m.label_ref AND label.graph_id=relation.graph_id"
        } else {
            ""
        };
        let valid = if shape.kind == EntityKind::Edge {
            "AND source_kind.relation_id IS NOT NULL AND target_kind.relation_id IS NOT NULL
             AND label.label_ref IS NOT NULL"
        } else {
            "AND m.from_ref IS NULL AND m.to_ref IS NULL AND m.label_ref IS NULL"
        };
        let predicate = match read {
            Read::Owned(_) => "true",
            Read::Nodes => {
                "EXISTS(SELECT 1 FROM graph_read_keys k WHERE k.entity_key=m.entity_key)"
            }
            Read::Outgoing => {
                "EXISTS(SELECT 1 FROM graph_read_keys k JOIN graph_entities entity
                    ON entity.entity_key=k.entity_key AND entity.relation_id=relation.from_relation
                    WHERE entity.entity_ref=m.from_ref)"
            }
            Read::Incoming => {
                "EXISTS(SELECT 1 FROM graph_read_keys k JOIN graph_entities entity
                    ON entity.entity_key=k.entity_key AND entity.relation_id=relation.to_relation
                    WHERE entity.entity_ref=m.to_ref)"
            }
            Read::Neighbors => {
                "EXISTS(SELECT 1 FROM graph_read_keys k JOIN graph_entities entity
                    ON entity.entity_key=k.entity_key
                    WHERE (entity.relation_id=relation.from_relation AND entity.entity_ref=m.from_ref)
                       OR (entity.relation_id=relation.to_relation AND entity.entity_ref=m.to_ref))"
            }
        };
        let predicate = if let Read::Owned(writer) = read { format!("m.writer_id={writer}") } else { predicate.to_owned() };
        let sql = format!(
            "SELECT (writer.graph_id=relation.graph_id AND m.entity_kind=relation.entity_kind
                AND identity.entity_ref IS NOT NULL AND owner.owner_ref IS NOT NULL
                AND properties.property_ref IS NOT NULL {valid}) IS TRUE AS __valid,
                m.valid_from AS __revision, m.writer_id AS writer, owner.owner_key AS owner, m.entity_key AS key
                {endpoints}, properties.properties
             FROM graph_members m
             JOIN graph_relations relation ON relation.relation_id=m.relation_id
                AND relation.graph_id=?
             LEFT JOIN graph_writers writer ON writer.writer_id=m.writer_id
             LEFT JOIN graph_entities identity ON identity.entity_ref=m.entity_ref
                AND identity.relation_id=m.relation_id AND identity.entity_key=m.entity_key
             LEFT JOIN graph_writer_owners owner ON owner.writer_id=m.writer_id AND owner.owner_ref=m.owner_ref
             LEFT JOIN graph_properties_{relation} properties ON properties.property_ref=m.properties_ref
             {joins}
             WHERE m.relation_id=?
                AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?) AND {predicate}
             ORDER BY m.writer_id, owner.owner_key, m.entity_key"
        );
        let mut statement = connection.prepare_cached(&sql).context(DatabaseSnafu {
            operation: "prepare keyed Graph read",
        })?;
        let mut batches = statement
            .query_arrow(params![graph, relation, revision, revision])
            .context(DatabaseSnafu {
                operation: "read native Graph properties",
            })?;
        let mut empty = true;
        for batch in &mut batches {
            reserve(&batch)?;
            let valid = batch.column(0).as_any().downcast_ref::<BooleanArray>();
            if valid.is_none_or(|valid| valid.iter().any(|value| value != Some(true))) {
                return InvalidSnafu {
                    field: "Graph stored membership reference",
                }
                .fail();
            }
            let revision = batch.column(1).as_any().downcast_ref::<UInt64Array>();
            let writer = batch.column(2).as_any().downcast_ref::<UInt64Array>();
            let (Some(revision), Some(writer)) = (revision, writer) else {
                return InvalidSnafu {
                    field: "Graph read origin shape",
                }
                .fail();
            };
            let mut origins = Vec::with_capacity(batch.num_rows());
            for (revision, writer) in revision.iter().zip(writer.iter()) {
                let (Some(revision @ 1..), Some(writer @ 1..)) = (revision, writer) else {
                    return InvalidSnafu {
                        field: "Graph read origin identity",
                    }
                    .fail();
                };
                origins.push(ReadOrigin { writer, revision });
            }
            let columns = (2..batch.num_columns()).collect::<Vec<_>>();
            visit(Self::read_batch(shape, batch.project(&columns)?)?, origins)?;
            empty = false;
        }
        if empty {
            let batch = RecordBatch::new_empty(Arc::new(shape.read_schema()));
            reserve(&batch)?;
            visit(batch, Default::default())?;
        }
        Ok(())
    }

    fn read_batch(shape: &Relation, batch: RecordBatch) -> Result<RecordBatch> {
        let schema = Arc::new(shape.read_schema());
        if batch.num_columns() != schema.fields().len() {
            return InvalidSnafu {
                field: "Graph stored property shape",
            }
            .fail();
        }
        let actual = batch.schema();
        let columns = batch
            .columns()
            .iter()
            .zip(actual.fields())
            .zip(schema.fields())
            .map(|((column, actual), field)| {
                if actual.name() != field.name()
                    || !Self::storage_compatible(actual.data_type(), field.data_type())
                    || !field.is_nullable() && column.null_count() != 0
                {
                    return InvalidSnafu {
                        field: "Graph stored property null",
                    }
                    .fail();
                }
                arrow_cast::cast(column.as_ref(), field.data_type()).map_err(Into::into)
            })
            .collect::<Result<Vec<_>>>()?;
        RecordBatch::try_new(schema, columns).map_err(Into::into)
    }

    pub(crate) fn storage_compatible(actual: &DataType, expected: &DataType) -> bool {
        use DataType::*;
        match (actual, expected) {
            (Binary, FixedSizeBinary(_)) | (Utf8View, Utf8) | (BinaryView, Binary) => true,
            (List(left), List(right)) => {
                Self::storage_compatible(left.data_type(), right.data_type())
            }
            (FixedSizeList(left, a), FixedSizeList(right, b)) => {
                a == b && Self::storage_compatible(left.data_type(), right.data_type())
            }
            (Struct(left), Struct(right)) => {
                left.len() == right.len()
                    && left.iter().zip(right).all(|(left, right)| {
                        left.name() == right.name()
                            && Self::storage_compatible(left.data_type(), right.data_type())
                    })
            }
            _ => actual == expected,
        }
    }
}
