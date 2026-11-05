use super::*;

#[derive(Default)]
pub(in crate::analysis) struct GraphDelta {
    pub publication: Option<GraphPublication>,
    pub origins: Vec<GraphOrigin>,
    pub canonical: Vec<((u64, u64), (u64, u64))>,
}

pub(in crate::analysis) struct GraphPublication {
    pub graph: u64,
    pub revision: u64,
    pub heads: BTreeMap<u64, u64>,
}

pub(in crate::analysis) struct GraphOrigin {
    pub tenant: [u8; 16],
    pub graph: u64,
    pub result: String,
    pub writer: u64,
    pub revision: u64,
    pub restricted: bool,
    pub reads: Vec<GraphRead>,
    pub facts: BTreeMap<crate::AnalysisContextKeyV1, Vec<u8>>,
}

pub(in crate::analysis) struct GraphRead {
    pub relation: u64,
    pub writer: u64,
    pub revision: u64,
    pub owner: Vec<u8>,
    pub key: Vec<u8>,
    pub producer: String,
}

impl GraphOrigin {
    pub(in crate::analysis) fn read_facts(
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<BTreeMap<crate::AnalysisContextKeyV1, Vec<u8>>> {
        let mut query = reader.prepare(
            "SELECT pin.owner_id,pin.entity_key,pin.lifetime_key,pin.owner_revision,fact.record_key,
                octet_length(encode(pin.owner_id))+octet_length(pin.entity_key)+octet_length(pin.lifetime_key)+octet_length(fact.record_key)
             FROM context_refs pin JOIN context_versions context ON context.tenant_id=pin.tenant_id
                AND context.owner_id=pin.owner_id AND context.entity_key=pin.entity_key
                AND context.lifetime_key=pin.lifetime_key AND context.owner_revision=pin.owner_revision
                AND context.commit_revision=pin.commit_revision
             JOIN graph_fact_records fact ON fact.version_key=context.version_key
             WHERE pin.tenant_id=? AND pin.ref_id=?"
        ).context(AnalysisDatabaseSnafu { operation: "prepare committed context facts" })?;
        let mut rows =
            query
                .query(params![tenant.as_slice(), result])
                .context(AnalysisDatabaseSnafu {
                    operation: "read committed context facts",
                })?;
        let mut facts = BTreeMap::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance committed context facts",
        })? {
            let bytes: usize = row.get(5).context(AnalysisDatabaseSnafu {
                operation: "bound committed context fact",
            })?;
            charge(
                bytes.saturating_mul(4)
                    + 12 * std::mem::size_of::<(crate::AnalysisContextKeyV1, Vec<u8>)>(),
            )?;
            let (key, record) = (|| -> duckdb::Result<_> {
                Ok((
                    crate::AnalysisContextKeyV1 {
                        tenant_id: tenant,
                        owner_id: row.get(0)?,
                        entity_key: row.get(1)?,
                        lifetime_key: row.get(2)?,
                        owner_revision: row.get(3)?,
                    },
                    row.get(4)?,
                ))
            })()
            .context(AnalysisDatabaseSnafu {
                operation: "decode committed context fact",
            })?;
            facts.insert(key, record);
        }
        Ok(facts)
    }
}

impl CommittedOwners {
    pub(in crate::analysis) fn graph_publication(
        &self,
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
    ) -> Result<Option<Arc<GraphPublication>>> {
        let publication = self
            .0
            .lock()
            .map_err(|_| Code::Invalid.error("committed managed owner lock"))?
            .publications
            .get(&(tenant, result.to_owned()))
            .cloned();
        let Some(publication) = publication else {
            return Ok(None);
        };
        let visible: bool = reader.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_graph_publications WHERE result_id=? AND revision=?)",
            params![result, publication.revision], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "read native publication visibility" })?;
        Ok(visible.then_some(publication))
    }

    pub(in crate::analysis) fn graph_origin(
        &self,
        tenant: [u8; 16],
        writer: u64,
        revision: u64,
    ) -> Result<Option<Arc<GraphOrigin>>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| Code::Invalid.error("committed managed owner lock"))?
            .origins
            .get(&(writer, revision))
            .filter(|value| value.tenant == tenant)
            .cloned())
    }

    pub(in crate::analysis) fn graph_canonical(
        &self,
        relation: u64,
        property: u64,
    ) -> Result<Option<(u64, u64)>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| Code::Invalid.error("committed managed owner lock"))?
            .canonical
            .get(&(relation, property))
            .copied())
    }

    pub(super) fn restore_graph(&self, reader: &Connection) -> Result<()> {
        let mut owners = self
            .0
            .lock()
            .map_err(|_| Code::Invalid.error("committed managed owner lock"))?;
        let mut query = reader.prepare(
            "SELECT graph.tenant_id,publication.result_id,publication.graph_id,publication.revision,pin.writer_id,layer.revision
             FROM managed_graph_publications publication JOIN managed_graphs graph USING(graph_id)
             LEFT JOIN managed_graph_publication_layers pin USING(result_id)
             LEFT JOIN graph_layers layer ON layer.layer_id=pin.layer_id AND layer.writer_id=pin.writer_id"
        ).context(AnalysisDatabaseSnafu { operation: "prepare committed Graph publications" })?;
        let mut rows = query.query([]).context(AnalysisDatabaseSnafu {
            operation: "read committed Graph publications",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance committed Graph publications",
        })? {
            let (tenant, result, graph, revision, writer, head) = (|| -> duckdb::Result<_> {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, Option<u64>>(4)?,
                    row.get::<_, Option<u64>>(5)?,
                ))
            })()
            .context(AnalysisDatabaseSnafu {
                operation: "decode committed Graph publication",
            })?;
            let tenant = tenant
                .try_into()
                .map_err(|_| Code::Invalid.error("Graph publication tenant"))?;
            let publication = owners
                .publications
                .entry((tenant, result))
                .or_insert_with(|| {
                    Arc::new(GraphPublication {
                        graph,
                        revision,
                        heads: BTreeMap::new(),
                    })
                });
            if let (Some(writer), Some(head)) = (writer, head) {
                Arc::get_mut(publication)
                    .expect("unpublished Graph owner")
                    .heads
                    .insert(writer, head);
            }
        }
        let mut query = reader.prepare(
            "SELECT graph.tenant_id,writer.graph_id,result.result_id,result.writer_id,result.revision,result.restricted
             FROM managed_graph_results result JOIN managed_graph_writers writer USING(writer_id)
             JOIN managed_graphs graph ON graph.graph_id=writer.graph_id"
        ).context(AnalysisDatabaseSnafu { operation: "prepare committed Graph origins" })?;
        let origins = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read committed Graph origins",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode committed Graph origins",
            })?;
        for (tenant, graph, result, writer, revision, restricted) in origins {
            let tenant = tenant
                .try_into()
                .map_err(|_| Code::Invalid.error("Graph origin tenant"))?;
            let facts = GraphOrigin::read_facts(reader, tenant, &result, &mut |_| Ok(()))?;
            let mut query = reader.prepare(
                "SELECT pin.relation_id,pin.writer_id,pin.revision,pin.owner_key,pin.entity_key,origin.producer_id
                 FROM managed_graph_row_reads pin JOIN managed_graph_reads origin
                    ON origin.result_id=pin.result_id AND origin.writer_id=pin.writer_id AND origin.revision=pin.revision
                 WHERE pin.result_id=? ORDER BY pin.revision,pin.writer_id"
            ).context(AnalysisDatabaseSnafu { operation: "prepare committed Graph read pins" })?;
            let reads = query
                .query_map(params![result], |row| {
                    Ok(GraphRead {
                        relation: row.get(0)?,
                        writer: row.get(1)?,
                        revision: row.get(2)?,
                        owner: row.get(3)?,
                        key: row.get(4)?,
                        producer: row.get(5)?,
                    })
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read committed Graph read pins",
                })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode committed Graph read pins",
                })?;
            owners.origins.insert(
                (writer, revision),
                Arc::new(GraphOrigin {
                    tenant,
                    graph,
                    result,
                    writer,
                    revision,
                    restricted,
                    reads,
                    facts,
                }),
            );
        }
        let mut query = reader.prepare(
            "SELECT relation_id,properties_ref,canonical_relation_id,canonical_properties_ref FROM managed_graph_finding_values"
        ).context(AnalysisDatabaseSnafu { operation: "prepare committed finding references" })?;
        let rows = query
            .query_map([], |row| {
                Ok(((row.get(0)?, row.get(1)?), (row.get(2)?, row.get(3)?)))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read committed finding references",
            })?;
        for row in rows {
            let (key, value) = row.context(AnalysisDatabaseSnafu {
                operation: "decode committed finding reference",
            })?;
            owners.canonical.insert(key, value);
        }
        Ok(())
    }
}
