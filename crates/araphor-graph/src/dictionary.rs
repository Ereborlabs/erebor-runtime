use std::collections::BTreeSet;

use duckdb::{params, Connection, Transaction};
use snafu::ResultExt as _;

use crate::error::{DatabaseSnafu, InvalidSnafu};
use crate::{GraphStore, Result};

pub(crate) struct KeyGroup<'a> {
    pub(crate) scope: u64,
    pub(crate) keys: &'a [Vec<u8>],
}

#[derive(Clone, Copy)]
pub(crate) enum Dictionary {
    Owners,
    Entities,
    Labels,
}

impl GraphStore {
    pub fn intern_owners(
        connection: &Transaction<'_>,
        writer: u64,
        keys: &[Vec<u8>],
    ) -> Result<Vec<u64>> {
        Dictionary::Owners.intern(
            connection,
            &[KeyGroup {
                scope: writer,
                keys,
            }],
            |_| Ok(()),
        )
    }

    pub fn intern_entities(
        connection: &Transaction<'_>,
        relation: u64,
        keys: &[Vec<u8>],
    ) -> Result<Vec<u64>> {
        Dictionary::Entities.intern(
            connection,
            &[KeyGroup {
                scope: relation,
                keys,
            }],
            |_| Ok(()),
        )
    }

    pub fn intern_labels(
        connection: &Transaction<'_>,
        graph: u64,
        keys: &[Vec<u8>],
    ) -> Result<Vec<u64>> {
        Dictionary::Labels.intern(connection, &[KeyGroup { scope: graph, keys }], |_| Ok(()))
    }
}

impl Dictionary {
    pub(crate) fn intern(
        self,
        connection: &Connection,
        groups: &[KeyGroup<'_>],
        mut check: impl FnMut(usize) -> Result<()>,
    ) -> Result<Vec<u64>> {
        let mut checked = BTreeSet::new();
        for (index, group) in groups.iter().enumerate() {
            check(index)?;
            if checked.insert(group.scope) {
                self.check_scope(connection, group.scope)?;
            }
        }
        if groups.is_empty() {
            return Ok(Vec::new());
        }
        connection
            .execute_batch(
                "CREATE TEMP TABLE graph_dictionary_keys
                (ordinal UBIGINT PRIMARY KEY,scope_id UBIGINT NOT NULL,entity_key BLOB NOT NULL)",
            )
            .context(DatabaseSnafu {
                operation: "create Graph dictionary keys",
            })?;
        let result = self.insert(connection, groups, &mut check);
        let cleanup = connection
            .execute_batch("DROP TABLE graph_dictionary_keys")
            .context(DatabaseSnafu {
                operation: "release Graph dictionary keys",
            });
        let result = result?;
        cleanup?;
        Ok(result)
    }

    fn check_scope(self, connection: &Connection, scope: u64) -> Result<()> {
        if scope == 0 {
            return InvalidSnafu {
                field: match self {
                    Self::Entities => "Graph transaction",
                    _ => "Graph dictionary scope",
                },
            }
            .fail();
        }
        let (query, operation, field) = match self {
            Self::Owners => (
                "SELECT EXISTS(SELECT 1 FROM graph_writers WHERE writer_id=?)",
                "check Graph owner writer",
                "Graph owner writer",
            ),
            Self::Entities => (
                "SELECT EXISTS(SELECT 1 FROM graph_relations WHERE relation_id=?)",
                "check Graph entity relation",
                "Graph entity relation",
            ),
            Self::Labels => return Ok(()),
        };
        let exists: bool = connection
            .query_row(query, params![scope], |row| row.get(0))
            .context(DatabaseSnafu { operation })?;
        if !exists {
            return InvalidSnafu { field }.fail();
        }
        Ok(())
    }

    fn insert(
        self,
        connection: &Connection,
        groups: &[KeyGroup<'_>],
        check: &mut impl FnMut(usize) -> Result<()>,
    ) -> Result<Vec<u64>> {
        let mut count = 0;
        {
            let mut appender =
                connection
                    .appender("graph_dictionary_keys")
                    .context(DatabaseSnafu {
                        operation: "open Graph dictionary keys",
                    })?;
            for (index, group) in groups.iter().enumerate() {
                check(index)?;
                for key in group.keys {
                    check(index)?;
                    appender
                        .append_row(params![count as u64, group.scope, key])
                        .context(DatabaseSnafu {
                            operation: "append Graph dictionary key",
                        })?;
                    count += 1;
                }
            }
            appender.flush().context(DatabaseSnafu {
                operation: "flush Graph dictionary keys",
            })?;
        }
        let (table, scope, identity, key, sequence) = match self {
            Self::Owners => (
                "graph_writer_owners",
                "writer_id",
                "owner_ref",
                "owner_key",
                "graph_owners_seq",
            ),
            Self::Entities => (
                "graph_entities",
                "relation_id",
                "entity_ref",
                "entity_key",
                "graph_entities_seq",
            ),
            Self::Labels => (
                "graph_labels",
                "graph_id",
                "label_ref",
                "label_key",
                "graph_labels_seq",
            ),
        };
        for index in 0..groups.len() {
            check(index)?;
        }
        connection.execute(&format!(
            "INSERT INTO {table}({scope},{identity},{key})
             SELECT scope_id,nextval('{sequence}'),entity_key FROM (
                SELECT DISTINCT input.scope_id,input.entity_key FROM graph_dictionary_keys input
                LEFT JOIN {table} stored ON stored.{scope}=input.scope_id AND stored.{key}=input.entity_key
                WHERE stored.{identity} IS NULL)"
        ), []).context(DatabaseSnafu { operation: "intern Graph dictionary values" })?;
        let mut statement = connection
            .prepare(&format!(
                "SELECT input.ordinal,stored.{identity} FROM graph_dictionary_keys input
             JOIN {table} stored ON stored.{scope}=input.scope_id AND stored.{key}=input.entity_key
             ORDER BY input.ordinal"
            ))
            .context(DatabaseSnafu {
                operation: "prepare Graph dictionary identities",
            })?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read Graph dictionary identities",
        })?;
        let mut identities = Vec::with_capacity(count);
        let mut group = 0;
        let mut offset = 0;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance Graph dictionary identities",
        })? {
            while group < groups.len() && identities.len() >= offset + groups[group].keys.len() {
                offset += groups[group].keys.len();
                group += 1;
            }
            if group == groups.len() {
                return InvalidSnafu {
                    field: match self {
                        Self::Entities => "Graph entity count",
                        _ => "Graph dictionary size",
                    },
                }
                .fail();
            }
            check(group)?;
            let ordinal: u64 = row.get(0).context(DatabaseSnafu {
                operation: "decode Graph dictionary ordinal",
            })?;
            let identity: u64 = row.get(1).context(DatabaseSnafu {
                operation: "decode Graph dictionary identity",
            })?;
            if ordinal != identities.len() as u64 || identity == 0 {
                return InvalidSnafu {
                    field: match self {
                        Self::Entities => "Graph entity identity",
                        _ => "Graph dictionary identity",
                    },
                }
                .fail();
            }
            identities.push(identity);
        }
        if identities.len() != count {
            return InvalidSnafu {
                field: match self {
                    Self::Entities => "Graph entity count",
                    _ => "Graph dictionary size",
                },
            }
            .fail();
        }
        Ok(identities)
    }
}
