use super::*;
use sdk::arrow_array::{Array, StringArray, StructArray};
use std::collections::BTreeMap;
use std::sync::Arc;

pub(in crate::analysis) struct FindingRow {
    pub member: Arc<araphor_graph::Member>,
    pub revision: u64,
    pub origin: String,
    pub origin_revision: u64,
    pub restricted: bool,
    pub value: u64,
}

impl FindingRow {
    pub(in crate::analysis) fn id(&self) -> Result<&str> {
        let value = self
            .member
            .properties()
            .column_by_name("value")
            .and_then(|array| array.as_any().downcast_ref::<StructArray>())
            .and_then(|array| array.column_by_name("finding_id"))
            .and_then(|array| array.as_any().downcast_ref::<StringArray>())
            .filter(|array| !array.is_null(self.member.row))
            .ok_or_else(|| Code::Invalid.error("native finding identity"))?;
        Ok(value.value(self.member.row))
    }

    pub(in crate::analysis) fn decode(
        &self,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<FindingMember> {
        let batch = self.member.property_batch()?;
        let bytes = batch.get_array_memory_size();
        charge(
            bytes,
            bytes
                .checked_mul(12)
                .ok_or_else(|| Code::Limit.error("native finding memory"))?,
        )?;
        let port = FindingMember::port();
        let batch = sdk::Dataset::normalize_batch(batch, Arc::new(port.schema))
            .context(crate::AnalysisContractSnafu)?;
        let mut values = FindingMember::decode(&sdk::Dataset {
            name: port.name,
            batches: vec![batch],
        })
        .context(crate::AnalysisContractSnafu)?;
        values
            .pop()
            .ok_or_else(|| Code::Invalid.error("native finding value"))
    }

    pub(in crate::analysis) fn order(&self) -> (u64, u64, u64, u64) {
        (
            self.member.relation,
            self.member.property,
            self.member.writer,
            self.member.owner,
        )
    }
}

impl DomainProjection {
    pub(in crate::analysis) fn read_findings(
        &self,
        engine: &araphor_graph::GraphStore,
        connection: &Connection,
        tenant: [u8; 16],
        result: &str,
        wanted: Option<&[Vec<u8>]>,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Vec<FindingRow>> {
        let mut query = connection.prepare_cached(
            "SELECT publication.graph_id,publication.revision,pin.writer_id,layer.revision
             FROM managed_graph_publications publication JOIN managed_graphs graph USING(graph_id)
             JOIN managed_graph_publication_layers pin USING(result_id)
             JOIN graph_layers layer ON layer.layer_id=pin.layer_id AND layer.writer_id=pin.writer_id
             WHERE graph.tenant_id=? AND publication.result_id=?"
        ).context(AnalysisDatabaseSnafu { operation: "prepare native finding view" })?;
        let mut input =
            query
                .query(params![tenant.as_slice(), result])
                .context(AnalysisDatabaseSnafu {
                    operation: "read native finding view",
                })?;
        let mut pins = Vec::new();
        while let Some(row) = input.next().context(AnalysisDatabaseSnafu {
            operation: "advance native finding view",
        })? {
            charge(0, 12 * std::mem::size_of::<(u64, u64, u64, u64)>())?;
            pins.push(
                (|| -> duckdb::Result<(u64, u64, u64, u64)> {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode native finding view",
                })?,
            );
        }
        let Some((graph, revision, _, _)) = pins.first().copied() else {
            return Ok(Vec::new());
        };
        let heads = pins
            .into_iter()
            .map(|(_, _, writer, head)| (writer, head))
            .collect::<BTreeMap<_, _>>();
        charge(
            0,
            wanted.map_or(0, |keys| {
                keys.len().saturating_mul(12 * std::mem::size_of::<usize>())
            }),
        )?;
        let mut selected = Vec::new();
        for (_, relation) in self.findings.iter().filter(|(id, _)| *id == graph) {
            let budget = std::cell::RefCell::new(&mut *charge);
            engine.visit_members(
                *relation,
                &heads,
                wanted,
                || budget.borrow_mut()(0, 0).map_err(araphor_graph::Error::backend),
                |member| {
                    budget.borrow_mut()(0, 12 * std::mem::size_of::<FindingRow>())
                        .map_err(araphor_graph::Error::backend)?;
                    selected.push(Arc::clone(member));
                    Ok(())
                },
            )?;
        }
        if selected.is_empty() {
            return Ok(Vec::new());
        }
        let row_bytes = 5 * ((u64::MAX.ilog10() + 1) as usize + "::UBIGINT".len()) + 7;
        let capacity = selected
            .len()
            .checked_mul(row_bytes)
            .ok_or_else(|| Code::Limit.error("native finding coordinates"))?;
        charge(
            0,
            capacity
                .checked_mul(3)
                .ok_or_else(|| Code::Limit.error("native finding coordinates"))?,
        )?;
        let mut values = String::with_capacity(capacity);
        use std::fmt::Write as _;
        for (row, member) in selected.iter().enumerate() {
            if row != 0 {
                values.push(',');
            }
            write!(
                values,
                "({row}::UBIGINT,{}::UBIGINT,{}::UBIGINT,{}::UBIGINT,{}::UBIGINT)",
                member.writer, member.revision, member.relation, member.property
            )
            .expect("String formatting cannot fail");
        }
        let mut query = connection
            .prepare(&format!(
            "WITH wanted(ordinal,writer_id,revision,relation_id,properties_ref) AS (VALUES {values})
             SELECT wanted.ordinal,origin.result_id,origin.revision,origin.restricted,
                canonical.canonical_properties_ref,octet_length(encode(origin.result_id))
             FROM wanted JOIN managed_graph_results origin USING(writer_id,revision)
             JOIN managed_graph_finding_values canonical USING(relation_id,properties_ref)
             ORDER BY wanted.ordinal"
        ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare native finding coordinates",
            })?;
        let mut rows = query.query([]).context(AnalysisDatabaseSnafu {
            operation: "read native finding coordinates",
        })?;
        let mut findings = Vec::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance native finding coordinates",
        })? {
            let bytes: usize = row.get(5).context(AnalysisDatabaseSnafu {
                operation: "bound native finding coordinates",
            })?;
            charge(0, bytes.saturating_mul(4))?;
            let (ordinal, origin, origin_revision, restricted, value): (
                usize,
                String,
                u64,
                bool,
                u64,
            ) = (|| -> duckdb::Result<_> {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })()
            .context(AnalysisDatabaseSnafu {
                operation: "decode native finding coordinates",
            })?;
            findings.push(FindingRow {
                member: Arc::clone(&selected[ordinal]),
                revision,
                origin,
                origin_revision,
                restricted,
                value,
            });
        }
        findings.sort_unstable_by_key(FindingRow::order);
        Ok(findings)
    }
}
