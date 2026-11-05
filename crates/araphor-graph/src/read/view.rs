use super::*;
use std::collections::BTreeMap;

pub struct GraphReadView {
    pub(crate) store: GraphStore,
    pub(crate) heads: BTreeMap<u64, u64>,
    pub(crate) relations: BTreeMap<u64, (u8, Option<u64>, Option<u64>)>,
}

impl GraphStore {
    pub fn read_view(
        &self,
        connection: &Connection,
        graph: u64,
        revision: u64,
        relations: &[u64],
        mut check: impl FnMut() -> Result<()>,
        mut reserve: impl FnMut(usize) -> Result<()>,
    ) -> Result<GraphReadView> {
        check()?;
        if graph == 0 || revision == 0 || relations.contains(&0) {
            return InvalidSnafu {
                field: "Graph read view",
            }
            .fail();
        }
        reserve(
            std::mem::size_of::<GraphReadView>()
                .saturating_add(relations.len().saturating_mul(512)),
        )?;
        let mut heads = BTreeMap::new();
        let mut query = connection
            .prepare_cached(
                "SELECT writer.writer_id,max(layer.revision) FROM graph_writers writer
             JOIN graph_layers layer USING(writer_id) WHERE writer.graph_id=? AND layer.revision<=?
             GROUP BY writer.writer_id",
            )
            .context(DatabaseSnafu {
                operation: "prepare Graph view heads",
            })?;
        let mut rows = query
            .query(params![graph, revision])
            .context(DatabaseSnafu {
                operation: "read Graph view heads",
            })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance Graph view heads",
        })? {
            check()?;
            reserve(12 * std::mem::size_of::<(u64, u64)>())?;
            let (writer, head) = (|| -> duckdb::Result<_> { Ok((row.get(0)?, row.get(1)?)) })()
                .context(DatabaseSnafu {
                    operation: "decode Graph view head",
                })?;
            heads.insert(writer, head);
        }
        drop(rows);
        drop(query);
        let mut declared = BTreeMap::new();
        if !relations.is_empty() {
            let placeholders = std::iter::repeat_n("?", relations.len())
                .collect::<Vec<_>>()
                .join(",");
            let mut query = connection
                .prepare(&format!(
                    "SELECT relation_id,entity_kind,from_relation,to_relation FROM graph_relations
                 WHERE graph_id=? AND relation_id IN ({placeholders})"
                ))
                .context(DatabaseSnafu {
                    operation: "prepare Graph view relations",
                })?;
            let parameters = std::iter::once(&graph).chain(relations);
            let mut rows =
                query
                    .query(duckdb::params_from_iter(parameters))
                    .context(DatabaseSnafu {
                        operation: "read Graph view relations",
                    })?;
            while let Some(row) = rows.next().context(DatabaseSnafu {
                operation: "advance Graph view relations",
            })? {
                check()?;
                let (relation, kind, from, to) = (|| -> duckdb::Result<_> {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })()
                .context(DatabaseSnafu {
                    operation: "decode Graph view relation",
                })?;
                declared.insert(relation, (kind, from, to));
            }
        }
        Ok(GraphReadView {
            store: GraphStore {
                shape: Arc::clone(&self.shape),
                committed: Arc::clone(&self.committed),
            },
            heads,
            relations: declared,
        })
    }
}
