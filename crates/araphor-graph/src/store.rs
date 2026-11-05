use std::collections::{BTreeMap, BTreeSet};

use duckdb::{params, Connection, OptionalExt as _, Transaction};
use snafu::ResultExt as _;

use crate::{
    error::{ConflictSnafu, DatabaseSnafu, InvalidSnafu},
    Result,
};

pub struct GraphStore {
    pub(crate) shape: std::sync::Arc<std::sync::Mutex<Option<arrow_schema::SchemaRef>>>,
}

pub struct LayerRequest {
    pub writer: u64,
    pub layer: u64,
    pub parent: Option<u64>,
}

pub struct PendingGraph<'a> {
    pub(crate) connection: &'a Transaction<'a>,
    pub(crate) heads: BTreeMap<u64, u64>,
    pub(crate) revision: u64,
}

impl GraphStore {
    pub const SCHEMA: &'static str = "
        CREATE TABLE graph_writers (writer_id UBIGINT PRIMARY KEY, graph_id UBIGINT NOT NULL);
        CREATE TABLE graph_relations (relation_id UBIGINT PRIMARY KEY, graph_id UBIGINT NOT NULL,
            entity_kind UTINYINT NOT NULL, from_relation UBIGINT, to_relation UBIGINT,
            CHECK((entity_kind=0 AND from_relation IS NULL AND to_relation IS NULL)
                OR (entity_kind=1 AND from_relation IS NOT NULL AND to_relation IS NOT NULL)));
        CREATE SEQUENCE graph_entities_seq;
        CREATE SEQUENCE graph_properties_seq;
        CREATE SEQUENCE graph_owners_seq;
        CREATE SEQUENCE graph_labels_seq;
        CREATE TABLE graph_labels (label_ref UBIGINT PRIMARY KEY, graph_id UBIGINT NOT NULL,
            label_key BLOB NOT NULL, UNIQUE(graph_id,label_key));
        CREATE TABLE graph_entities (entity_ref UBIGINT PRIMARY KEY, relation_id UBIGINT NOT NULL,
            entity_key BLOB NOT NULL, UNIQUE(relation_id,entity_key));
        CREATE TABLE graph_layers (layer_id UBIGINT PRIMARY KEY, writer_id UBIGINT NOT NULL,
            revision UBIGINT NOT NULL, parent_id UBIGINT, UNIQUE(writer_id,revision));
        CREATE TABLE graph_writer_owners (writer_id UBIGINT NOT NULL, owner_ref UBIGINT NOT NULL,
            owner_key BLOB NOT NULL, PRIMARY KEY(writer_id,owner_ref), UNIQUE(writer_id,owner_key));
        CREATE TABLE graph_members (writer_id UBIGINT NOT NULL, owner_ref UBIGINT NOT NULL,
            relation_id UBIGINT NOT NULL, entity_kind UTINYINT NOT NULL, entity_key BLOB NOT NULL, entity_ref UBIGINT NOT NULL,
            properties_ref UBIGINT NOT NULL, from_ref UBIGINT, to_ref UBIGINT, label_ref UBIGINT,
            valid_from UBIGINT NOT NULL, valid_to UBIGINT,
            PRIMARY KEY(writer_id,owner_ref,relation_id,entity_kind,entity_key,valid_from),
            CHECK(entity_kind IN (0,1)), CHECK(valid_to IS NULL OR valid_to>valid_from));
        CREATE INDEX graph_member_keys ON graph_members(writer_id,relation_id,entity_key);
        CREATE INDEX graph_member_from ON graph_members(relation_id,from_ref);
        CREATE INDEX graph_member_to ON graph_members(relation_id,to_ref);
        CREATE INDEX graph_member_labels ON graph_members(relation_id,label_ref);
        CREATE INDEX graph_member_opened ON graph_members(valid_from);
        CREATE INDEX graph_member_closed ON graph_members(valid_to);";

    pub fn intern_entities(
        connection: &Transaction<'_>,
        relation: u64,
        keys: &[Vec<u8>],
    ) -> Result<Vec<u64>> {
        if relation == 0 {
            return InvalidSnafu {
                field: "Graph transaction",
            }
            .fail();
        }
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM graph_relations WHERE relation_id=?)",
                params![relation],
                |row| row.get(0),
            )
            .context(DatabaseSnafu {
                operation: "check Graph entity relation",
            })?;
        if !exists {
            return InvalidSnafu {
                field: "Graph entity relation",
            }
            .fail();
        }
        connection.execute_batch("CREATE TEMP TABLE graph_entity_keys (ordinal UBIGINT PRIMARY KEY,entity_key BLOB NOT NULL)")
            .context(DatabaseSnafu { operation: "create Graph entity keys" })?;
        let result = Self::insert_entities(connection, relation, keys);
        let cleanup = connection
            .execute_batch("DROP TABLE graph_entity_keys")
            .context(DatabaseSnafu {
                operation: "release Graph entity keys",
            });
        let result = result?;
        cleanup?;
        Ok(result)
    }

    fn insert_entities(
        connection: &Connection,
        relation: u64,
        keys: &[Vec<u8>],
    ) -> Result<Vec<u64>> {
        {
            let mut appender = connection
                .appender("graph_entity_keys")
                .context(DatabaseSnafu {
                    operation: "open Graph entity keys",
                })?;
            for (ordinal, key) in keys.iter().enumerate() {
                appender
                    .append_row(params![ordinal as u64, key])
                    .context(DatabaseSnafu {
                        operation: "append Graph entity key",
                    })?;
            }
            appender.flush().context(DatabaseSnafu {
                operation: "flush Graph entity keys",
            })?;
        }
        connection.execute(
            "INSERT INTO graph_entities
             SELECT nextval('graph_entities_seq'),?,entity_key FROM (
                SELECT DISTINCT input.entity_key FROM graph_entity_keys input
                LEFT JOIN graph_entities stored ON stored.relation_id=? AND stored.entity_key=input.entity_key
                WHERE stored.entity_ref IS NULL)",
            params![relation,relation],
        ).context(DatabaseSnafu { operation: "intern Graph entities" })?;
        let mut statement = connection.prepare(
            "SELECT input.ordinal,stored.entity_ref FROM graph_entity_keys input
             JOIN graph_entities stored ON stored.relation_id=? AND stored.entity_key=input.entity_key
             ORDER BY input.ordinal",
        ).context(DatabaseSnafu { operation: "prepare Graph entity identities" })?;
        let mut rows = statement.query(params![relation]).context(DatabaseSnafu {
            operation: "read Graph entity identities",
        })?;
        let mut identities = Vec::with_capacity(keys.len());
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance Graph entity identities",
        })? {
            let ordinal: u64 = row.get(0).context(DatabaseSnafu {
                operation: "decode Graph entity ordinal",
            })?;
            let identity: u64 = row.get(1).context(DatabaseSnafu {
                operation: "decode Graph entity identity",
            })?;
            if ordinal != identities.len() as u64 || identity == 0 {
                return InvalidSnafu {
                    field: "Graph entity identity",
                }
                .fail();
            }
            identities.push(identity);
        }
        if identities.len() != keys.len() {
            return InvalidSnafu {
                field: "Graph entity count",
            }
            .fail();
        }
        Ok(identities)
    }

    pub fn begin_layers<'a>(
        connection: &'a Transaction<'_>,
        revision: u64,
        requests: &[LayerRequest],
    ) -> Result<PendingGraph<'a>> {
        if revision == 0 {
            return InvalidSnafu {
                field: "Graph transaction",
            }
            .fail();
        }
        let mut heads = BTreeMap::new();
        let mut layers = BTreeSet::new();
        for request in requests {
            if request.writer == 0
                || request.layer == 0
                || heads.insert(request.writer, request.layer).is_some()
                || !layers.insert(request.layer)
            {
                return InvalidSnafu {
                    field: "Graph layer request",
                }
                .fail();
            }
            let previous: Option<(u64,u64)> = connection.query_row(
                "SELECT layer_id,revision FROM graph_layers WHERE writer_id=? ORDER BY revision DESC LIMIT 1",
                params![request.writer], |row| Ok((row.get(0)?,row.get(1)?)),
            ).optional().context(DatabaseSnafu { operation: "read writer head" })?;
            if previous.as_ref().map(|(layer, _)| *layer) != request.parent
                || previous.is_some_and(|(_, before)| before >= revision)
            {
                return ConflictSnafu {
                    resource: "writer head",
                }
                .fail();
            }
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM graph_writers WHERE writer_id=?)",
                    params![request.writer],
                    |row| row.get(0),
                )
                .context(DatabaseSnafu {
                    operation: "check writer identity",
                })?;
            if !exists {
                return InvalidSnafu {
                    field: "writer identity",
                }
                .fail();
            }
        }
        for request in requests {
            connection
                .execute(
                    "INSERT INTO graph_layers VALUES(?,?,?,?)",
                    params![request.layer, request.writer, revision, request.parent],
                )
                .context(DatabaseSnafu {
                    operation: "stage Graph layer",
                })?;
        }
        Ok(PendingGraph {
            connection,
            heads,
            revision,
        })
    }

    pub(crate) fn check_edges(connection: &Connection, revision: u64) -> Result<()> {
        let invalid: bool = connection.query_row(
            "WITH changed AS (
                SELECT DISTINCT writer.graph_id,node.relation_id,node.entity_ref
                FROM graph_members node JOIN graph_writers writer USING(writer_id)
                WHERE node.entity_kind=0 AND (node.valid_from=? OR node.valid_to=?)
             ) SELECT EXISTS(
                SELECT 1 FROM graph_members edge
                LEFT JOIN graph_writers writer ON writer.writer_id=edge.writer_id
                LEFT JOIN graph_relations relation ON relation.relation_id=edge.relation_id
                    AND relation.graph_id=writer.graph_id
                LEFT JOIN graph_entities identity ON identity.relation_id=edge.relation_id
                    AND identity.entity_key=edge.entity_key AND identity.entity_ref=edge.entity_ref
                LEFT JOIN graph_relations source ON source.relation_id=relation.from_relation
                    AND source.graph_id=writer.graph_id AND source.entity_kind=0
                LEFT JOIN graph_relations target ON target.relation_id=relation.to_relation
                    AND target.graph_id=writer.graph_id AND target.entity_kind=0
                WHERE edge.entity_kind=1 AND edge.valid_to IS NULL
                    AND (edge.valid_from=? OR EXISTS(SELECT 1 FROM changed node
                        WHERE (node.graph_id=writer.graph_id OR writer.writer_id IS NULL)
                            AND (node.entity_ref=edge.from_ref OR node.entity_ref=edge.to_ref)))
                    AND (writer.writer_id IS NULL OR identity.entity_ref IS NULL
                        OR relation.relation_id IS NULL OR relation.entity_kind<>1
                        OR source.relation_id IS NULL OR target.relation_id IS NULL
                        OR NOT EXISTS(SELECT 1 FROM graph_members node
                            JOIN graph_writers owner ON owner.writer_id=node.writer_id
                            JOIN graph_entities identity ON identity.relation_id=node.relation_id
                                AND identity.entity_key=node.entity_key AND identity.entity_ref=node.entity_ref
                            WHERE owner.graph_id=writer.graph_id AND node.entity_kind=0
                                AND node.relation_id=source.relation_id AND node.entity_ref=edge.from_ref
                                AND node.valid_to IS NULL)
                        OR NOT EXISTS(SELECT 1 FROM graph_members node
                            JOIN graph_writers owner ON owner.writer_id=node.writer_id
                            JOIN graph_entities identity ON identity.relation_id=node.relation_id
                                AND identity.entity_key=node.entity_key AND identity.entity_ref=node.entity_ref
                            WHERE owner.graph_id=writer.graph_id AND node.entity_kind=0
                                AND node.relation_id=target.relation_id AND node.entity_ref=edge.to_ref
                                AND node.valid_to IS NULL)))",
            params![revision,revision,revision], |row|row.get(0),
        ).context(DatabaseSnafu { operation: "check changed Graph endpoints" })?;
        if invalid {
            return InvalidSnafu {
                field: "Graph endpoint membership",
            }
            .fail();
        }
        Ok(())
    }
}

impl PendingGraph<'_> {
    pub(crate) fn check_heads(&self) -> Result<()> {
        for (writer, layer) in &self.heads {
            let head: Option<(u64,u64)> = self.connection.query_row(
                "SELECT layer_id,revision FROM graph_layers WHERE writer_id=? ORDER BY revision DESC LIMIT 1",
                params![writer], |row| Ok((row.get(0)?,row.get(1)?)),
            ).optional().context(DatabaseSnafu { operation: "check pending Graph head" })?;
            if head != Some((*layer, self.revision)) {
                return ConflictSnafu {
                    resource: "writer head",
                }
                .fail();
            }
        }
        Ok(())
    }
}
