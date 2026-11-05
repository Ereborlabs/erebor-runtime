use std::collections::BTreeMap;

use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::scratch::Scratch;
use super::WriterCut;
use crate::error::{DatabaseSnafu, InvalidSnafu};
use crate::{Journal, PendingGraph, Result};

type Identity = (u64, u64, Vec<u8>, Vec<u8>);
type Entry = (Identity, (u64, u64));

pub(super) struct BaseRows {
    rows: Vec<Entry>,
}

impl BaseRows {
    pub(super) fn closures(&self) -> Vec<(u64, u64, u64, Vec<u8>, u64)> {
        self.rows.iter().map(|((writer,relation,_,key),(owner,revision))|
            (*writer,*owner,*relation,key.clone(),*revision)).collect()
    }
    const BASE: &'static str = "FROM graph_members m JOIN graph_delta_heads h USING(writer_id)
        LEFT JOIN graph_writer_owners o
        ON o.writer_id=m.writer_id AND o.owner_ref=m.owner_ref
        WHERE m.valid_from<=h.cut_revision AND (m.valid_to IS NULL OR m.valid_to>h.cut_revision)
        AND (EXISTS(
            SELECT 1 FROM graph_delta_keys k WHERE k.writer_id=m.writer_id
                AND k.relation_id=m.relation_id AND k.owner_key=o.owner_key AND k.entity_key=m.entity_key)
            OR EXISTS(SELECT 1 FROM graph_delta_clear c WHERE c.writer_id=m.writer_id
                AND (c.owner_key IS NULL OR c.owner_key=o.owner_key)))";

    pub(super) fn load(
        connection: &Connection,
        cuts: &[WriterCut],
        journals: &[&Journal],
        scratch: &mut Scratch<'_>,
    ) -> Result<Self> {
        connection.execute_batch(
            "CREATE TEMP TABLE graph_delta_heads(writer_id UBIGINT PRIMARY KEY,cut_revision UBIGINT);
             CREATE TEMP TABLE graph_delta_keys (writer_id UBIGINT,relation_id UBIGINT,owner_key BLOB,entity_key BLOB);
             CREATE TEMP TABLE graph_delta_clear (writer_id UBIGINT,owner_key BLOB)"
        ).context(DatabaseSnafu { operation: "create Graph base requests" })?;
        let result = Self::read(connection, cuts, journals, scratch);
        let cleanup = connection
            .execute_batch("DROP TABLE graph_delta_keys; DROP TABLE graph_delta_clear; DROP TABLE graph_delta_heads")
            .context(DatabaseSnafu {
                operation: "release Graph base requests",
            });
        let result = result?;
        cleanup?;
        Ok(result)
    }

    fn read(
        connection: &Connection,
        cuts: &[WriterCut],
        journals: &[&Journal],
        scratch: &mut Scratch<'_>,
    ) -> Result<Self> {
        {
            let mut heads = connection
                .appender("graph_delta_heads")
                .context(DatabaseSnafu {
                    operation: "open Graph base cuts",
                })?;
            for cut in cuts {
                scratch.check(cut.writer)?;
                heads
                    .append_row(params![cut.writer, cut.revision])
                    .context(DatabaseSnafu {
                        operation: "append Graph base cut",
                    })?;
            }
            heads.flush().context(DatabaseSnafu {
                operation: "flush Graph base cuts",
            })?;
        }
        {
            let mut keys = connection
                .appender("graph_delta_keys")
                .context(DatabaseSnafu {
                    operation: "open Graph base keys",
                })?;
            for journal in journals {
                for (relation, owner, key, _) in journal.touched_keys() {
                    scratch.check(journal.writer())?;
                    keys.append_row(params![journal.writer(), relation, owner, key])
                        .context(DatabaseSnafu {
                            operation: "append Graph base key",
                        })?;
                }
            }
            keys.flush().context(DatabaseSnafu {
                operation: "flush Graph base keys",
            })?;
        }
        {
            let mut clears = connection
                .appender("graph_delta_clear")
                .context(DatabaseSnafu {
                    operation: "open Graph base clears",
                })?;
            for journal in journals {
                for owner in journal.clear_owners() {
                    scratch.check(journal.writer())?;
                    clears
                        .append_row(params![journal.writer(), owner])
                        .context(DatabaseSnafu {
                            operation: "append Graph base clear",
                        })?;
                }
            }
            clears.flush().context(DatabaseSnafu {
                operation: "flush Graph base clears",
            })?;
        }
        let mut bounds = BTreeMap::<u64, (usize, usize)>::new();
        let mut count = 0usize;
        {
            let mut statement = connection.prepare(&format!(
                "SELECT m.writer_id,count(*),CAST(coalesce(sum(octet_length(o.owner_key)+octet_length(m.entity_key)),0) AS UBIGINT)
                 {} GROUP BY m.writer_id", Self::BASE
            )).context(DatabaseSnafu { operation: "prepare Graph base bounds" })?;
            let mut rows = statement.query([]).context(DatabaseSnafu {
                operation: "read Graph base bounds",
            })?;
            while let Some(row) = rows.next().context(DatabaseSnafu {
                operation: "advance Graph base bounds",
            })? {
                let (writer, rows, bytes): (u64, usize, usize) =
                    (|| -> duckdb::Result<_> { Ok((row.get(0)?, row.get(1)?, row.get(2)?)) })()
                        .context(DatabaseSnafu {
                            operation: "decode Graph base bounds",
                        })?;
                let allocation = rows
                    .checked_mul(std::mem::size_of::<Entry>() + 4 * std::mem::size_of::<usize>())
                    .and_then(|size| size.checked_add(bytes))
                    .and_then(|size| {
                        size.checked_add(12 * std::mem::size_of::<(u64, (usize, usize))>())
                    })
                    .ok_or_else(|| {
                        InvalidSnafu {
                            field: "Graph base memory",
                        }
                        .build()
                    })?;
                scratch.charge(writer, allocation)?;
                count = count.checked_add(rows).ok_or_else(|| {
                    InvalidSnafu {
                        field: "Graph base row count",
                    }
                    .build()
                })?;
                if bounds.insert(writer, (rows, bytes)).is_some() {
                    return InvalidSnafu {
                        field: "Graph base writer bounds",
                    }
                    .fail();
                }
            }
        }
        let mut base = Vec::new();
        base.try_reserve_exact(count).map_err(|_| {
            InvalidSnafu {
                field: "Graph base allocation",
            }
            .build()
        })?;
        let mut statement = connection
            .prepare(&format!(
            "SELECT m.writer_id,m.relation_id,o.owner_key,m.entity_key,m.owner_ref,m.valid_from,
                octet_length(o.owner_key),octet_length(m.entity_key) {}", Self::BASE
        ))
            .context(DatabaseSnafu {
                operation: "prepare touched Graph base",
            })?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read touched Graph base",
        })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance touched Graph base",
        })? {
            let (writer, owner_bytes, key_bytes): (u64, usize, usize) =
                (|| -> duckdb::Result<_> { Ok((row.get(0)?, row.get(6)?, row.get(7)?)) })()
                    .context(DatabaseSnafu {
                        operation: "read touched Graph size",
                    })?;
            scratch.check(writer)?;
            let remaining = bounds.get_mut(&writer).ok_or_else(|| {
                InvalidSnafu {
                    field: "Graph base writer bounds",
                }
                .build()
            })?;
            remaining.0 = remaining.0.checked_sub(1).ok_or_else(|| {
                InvalidSnafu {
                    field: "Graph base row bounds",
                }
                .build()
            })?;
            remaining.1 = owner_bytes
                .checked_add(key_bytes)
                .and_then(|size| remaining.1.checked_sub(size))
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "Graph base byte bounds",
                    }
                    .build()
                })?;
            let identity: Identity =
                (|| -> duckdb::Result<_> { Ok((writer, row.get(1)?, row.get(2)?, row.get(3)?)) })()
                    .context(DatabaseSnafu {
                        operation: "decode touched Graph identity",
                    })?;
            let (owner, revision): (u64, u64) =
                (|| -> duckdb::Result<_> { Ok((row.get(4)?, row.get(5)?)) })().context(
                    DatabaseSnafu {
                        operation: "decode touched Graph base",
                    },
                )?;
            if writer == 0
                || identity.1 == 0
                || owner == 0
                || revision == 0
                || cuts
                    .iter()
                    .find(|cut| cut.writer == writer)
                    .is_none_or(|cut| revision > cut.revision)
            {
                return InvalidSnafu {
                    field: "Graph open base identity",
                }
                .fail();
            }
            base.push((identity, (owner, revision)));
        }
        if base.len() != count || bounds.values().any(|remaining| *remaining != (0, 0)) {
            return InvalidSnafu {
                field: "Graph base bounds",
            }
            .fail();
        }
        base.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        for pair in base.windows(2) {
            scratch.check(pair[0].0 .0)?;
            if pair[0].0 == pair[1].0 {
                return InvalidSnafu {
                    field: "Graph duplicate open identity",
                }
                .fail();
            }
        }
        Ok(Self { rows: base })
    }

    pub(super) fn check(&self, journals: &[&Journal], scratch: &Scratch<'_>) -> Result<()> {
        for journal in journals {
            for (relation, owner, key, expected) in journal.touched_keys() {
                scratch.check(journal.writer())?;
                if let Some(expected) = expected {
                    let present = self
                        .rows
                        .binary_search_by(|entry| {
                            (
                                entry.0 .0,
                                entry.0 .1,
                                entry.0 .2.as_slice(),
                                entry.0 .3.as_slice(),
                            )
                                .cmp(&(
                                    journal.writer(),
                                    relation,
                                    owner,
                                    key,
                                ))
                        })
                        .is_ok();
                    if present != expected {
                        return InvalidSnafu {
                            field: "Graph journal base state",
                        }
                        .fail();
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn close(
        self,
        graph: &PendingGraph<'_>,
        scratch: &Scratch<'_>,
    ) -> Result<BTreeMap<u64, (u64, u64)>> {
        if self.rows.is_empty() {
            return Ok(BTreeMap::new());
        }
        graph.connection.execute_batch(
            "CREATE TEMP TABLE graph_delta_close (writer_id UBIGINT,owner_ref UBIGINT,relation_id UBIGINT,
                entity_key BLOB,valid_from UBIGINT)"
        ).context(DatabaseSnafu { operation: "create Graph base closes" })?;
        let result = self.close_rows(graph, scratch);
        let cleanup = graph
            .connection
            .execute_batch("DROP TABLE graph_delta_close")
            .context(DatabaseSnafu {
                operation: "release Graph base closes",
            });
        let result = result?;
        cleanup?;
        Ok(result)
    }

    fn close_rows(
        self,
        graph: &PendingGraph<'_>,
        scratch: &Scratch<'_>,
    ) -> Result<BTreeMap<u64, (u64, u64)>> {
        let mut counts = BTreeMap::<u64, (u64, u64)>::new();
        let expected = self.rows.len();
        {
            let mut rows =
                graph
                    .connection
                    .appender("graph_delta_close")
                    .context(DatabaseSnafu {
                        operation: "open Graph base closes",
                    })?;
            for ((writer, relation, _, key), (owner, revision)) in self.rows {
                scratch.check(writer)?;
                rows.append_row(params![writer, owner, relation, key, revision])
                    .context(DatabaseSnafu {
                        operation: "append Graph base close",
                    })?;
                counts.entry(writer).or_default().1 += 1;
            }
            rows.flush().context(DatabaseSnafu {
                operation: "flush Graph base closes",
            })?;
        }
        let closed = graph.connection.execute(
            "UPDATE graph_members m SET valid_to=? WHERE m.valid_to IS NULL AND EXISTS(
                SELECT 1 FROM graph_delta_close c WHERE c.writer_id=m.writer_id AND c.owner_ref=m.owner_ref
                    AND c.relation_id=m.relation_id AND c.entity_key=m.entity_key AND c.valid_from=m.valid_from)",
            params![graph.revision],
        ).context(DatabaseSnafu { operation: "close final Graph base" })?;
        if closed != expected {
            return InvalidSnafu {
                field: "Graph closed base count",
            }
            .fail();
        }
        Ok(counts)
    }
}
