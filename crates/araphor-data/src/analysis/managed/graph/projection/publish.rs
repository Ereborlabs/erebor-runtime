use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use duckdb::arrow::array::{Array, ArrayRef, BinaryArray, StringArray, StructArray, UInt64Array};
use duckdb::arrow::compute::kernels::partition::partition;
use duckdb::arrow::compute::{SortColumn, concat, lexsort_to_indices, take};
use duckdb::{Transaction, params};
use snafu::ResultExt as _;

use super::*;

type Coordinate = (u64, u64);

impl DomainProjection {
    pub(super) fn publish_findings(
        &self,
        engine: &araphor_graph::GraphStore,
        connection: &Transaction<'_>,
        result: &str,
        revision: u64,
        heads: &BTreeMap<u64, u64>,
        pending: Option<&araphor_graph::PendingLayer>,
        memory: &super::super::super::budget::PreparedMemory<'_>,
    ) -> Result<Vec<(Coordinate, Coordinate)>> {
        if self.findings.is_empty() {
            return Ok(Vec::new());
        }
        let started = std::time::Instant::now();
        let mut leases = Vec::new();
        let mut current = Vec::<(Coordinate, u64)>::new();
        for (_, relation) in &self.findings {
            engine.visit_members(
                *relation,
                heads,
                None,
                || memory.check().map_err(araphor_graph::Error::backend),
                |member| {
                    leases.push(
                        memory
                            .reserve(12 * std::mem::size_of::<(Coordinate, u64)>())
                            .map_err(araphor_graph::Error::backend)?,
                    );
                    current.push(((member.relation, member.property), member.revision));
                    Ok(())
                },
            )?;
        }
        if current.is_empty() {
            return Ok(Vec::new());
        }
        let mut touched = BTreeSet::<Coordinate>::new();
        if let Some(pending) = pending {
            pending.visit_changes(|member| {
                memory.check().map_err(araphor_graph::Error::backend)?;
                if self
                    .findings
                    .iter()
                    .any(|(_, relation)| *relation == member.relation)
                {
                    leases.push(
                        memory
                            .reserve(12 * std::mem::size_of::<Coordinate>())
                            .map_err(araphor_graph::Error::backend)?,
                    );
                    touched.insert((member.relation, member.property));
                }
                Ok(())
            })?;
        }
        if touched.is_empty() {
            return Ok(Vec::new());
        }
        let heads_at = std::time::Instant::now();
        let mut known = BTreeMap::<Coordinate, Coordinate>::new();
        let prefix = "SELECT relation_id,properties_ref,canonical_relation_id,canonical_properties_ref FROM managed_graph_finding_values WHERE relation_id IN (";
        let capacity = self
            .findings
            .len()
            .checked_mul((u64::MAX.ilog10() + 2) as usize)
            .and_then(|bytes| bytes.checked_add(prefix.len() + 1))
            .ok_or_else(|| Code::Limit.error("finding dictionary memory"))?;
        leases.push(memory.reserve(capacity + std::mem::size_of::<String>())?);
        let mut sql = String::with_capacity(capacity);
        sql.push_str(prefix);
        use std::fmt::Write as _;
        for (index, (_, relation)) in self.findings.iter().enumerate() {
            if index != 0 {
                sql.push(',');
            }
            write!(sql, "{relation}").expect("String formatting cannot fail");
        }
        sql.push(')');
        let mut query = connection.prepare(&sql).context(AnalysisDatabaseSnafu {
            operation: "prepare canonical finding coordinates",
        })?;
        let mut rows = query.query([]).context(AnalysisDatabaseSnafu {
            operation: "read canonical finding coordinates",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance canonical finding coordinates",
        })? {
            leases.push(memory.reserve(12 * std::mem::size_of::<(Coordinate, Coordinate)>())?);
            let (relation, property, canonical_relation, canonical_property) =
                (|| -> duckdb::Result<_> {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode canonical finding coordinates",
                })?;
            known.insert(
                (relation, property),
                (canonical_relation, canonical_property),
            );
        }
        let mut parts = Vec::<ArrayRef>::new();
        let mut coordinates = Vec::<Coordinate>::new();
        for (_, relation) in &self.findings {
            engine.visit_properties(connection, *relation, |batch| {
                memory.check().map_err(araphor_graph::Error::backend)?;
                let bytes =
                    batch
                        .get_array_memory_size()
                        .checked_mul(8)
                        .and_then(|bytes| {
                            bytes.checked_add(batch.num_rows().checked_mul(
                                16 * std::mem::size_of::<(Coordinate, Coordinate)>(),
                            )?)
                        })
                        .ok_or_else(|| {
                            araphor_graph::Error::backend(
                                Code::Limit.error("finding dictionary memory"),
                            )
                        })?;
                leases.push(
                    memory
                        .reserve(bytes)
                        .map_err(araphor_graph::Error::backend)?,
                );
                let properties = batch
                    .column_by_name("properties")
                    .and_then(|array| array.as_any().downcast_ref::<StructArray>())
                    .ok_or_else(|| {
                        araphor_graph::Error::backend(
                            Code::Invalid.error("native finding properties"),
                        )
                    })?;
                let values = properties.column_by_name("value").ok_or_else(|| {
                    araphor_graph::Error::backend(Code::Invalid.error("native finding value"))
                })?;
                let ids = batch
                    .column_by_name("property_ref")
                    .and_then(|array| array.as_any().downcast_ref::<UInt64Array>())
                    .ok_or_else(|| {
                        araphor_graph::Error::backend(
                            Code::Invalid.error("native finding property identity"),
                        )
                    })?;
                coordinates.extend(ids.values().iter().map(|id| (*relation, *id)));
                parts.push(Arc::clone(values));
                Ok(())
            })?;
        }
        let values = concat(&parts.iter().map(AsRef::as_ref).collect::<Vec<_>>())
            .context(crate::PackageArrowSnafu)?;
        let positions = coordinates
            .iter()
            .enumerate()
            .map(|(row, id)| (*id, row))
            .collect::<BTreeMap<_, _>>();
        let refs = UInt64Array::from_iter_values(
            coordinates.iter().map(|id| known.get(id).unwrap_or(id).1),
        );
        let relations = UInt64Array::from_iter_values(coordinates.iter().map(|id| id.0));
        let order = lexsort_to_indices(
            &[
                SortColumn {
                    values: Arc::clone(&values),
                    options: None,
                },
                SortColumn {
                    values: Arc::new(refs),
                    options: None,
                },
                SortColumn {
                    values: Arc::new(relations),
                    options: None,
                },
            ],
            None,
        )
        .context(crate::PackageArrowSnafu)?;
        let sorted = take(values.as_ref(), &order, None).context(crate::PackageArrowSnafu)?;
        let groups = partition(&[sorted])
            .context(crate::PackageArrowSnafu)?
            .ranges();
        let mut dictionary = vec![0usize; coordinates.len()];
        let mut canonical = vec![(0u64, 0u64); coordinates.len()];
        for (group, range) in groups.into_iter().enumerate() {
            memory.check()?;
            let first = coordinates[order.value(range.start) as usize];
            let winner = known.get(&first).copied().unwrap_or(first);
            for row in range {
                let row = order.value(row) as usize;
                dictionary[row] = group;
                canonical[row] = winner;
            }
        }
        let dictionary_at = std::time::Instant::now();
        let values_struct = values
            .as_any()
            .downcast_ref::<StructArray>()
            .ok_or_else(|| Code::Invalid.error("native finding value"))?;
        let tenants = values_struct
            .column_by_name("tenant_id")
            .and_then(|array| array.as_any().downcast_ref::<BinaryArray>())
            .ok_or_else(|| Code::Invalid.error("native finding tenant"))?;
        let ids = values_struct
            .column_by_name("finding_id")
            .and_then(|array| array.as_any().downcast_ref::<StringArray>())
            .ok_or_else(|| Code::Invalid.error("native finding identity"))?;
        let locate = |id: &Coordinate| {
            positions
                .get(id)
                .copied()
                .ok_or_else(|| Code::Invalid.error("native finding property identity"))
        };
        let touched = touched
            .iter()
            .map(|id| {
                let row = locate(id)?;
                Ok((tenants.value(row), ids.value(row)))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let distinct = current.iter().map(|(id, _)| *id).collect::<BTreeSet<_>>();
        let current_rows = UInt64Array::from_iter_values(
            distinct
                .iter()
                .map(|id| locate(id).map(|row| row as u64))
                .collect::<Result<Vec<_>>>()?,
        );
        let groups = UInt64Array::from_iter_values(
            current_rows
                .values()
                .iter()
                .map(|row| dictionary[*row as usize] as u64),
        );
        let order = lexsort_to_indices(
            &[SortColumn {
                values: Arc::new(groups),
                options: None,
            }],
            None,
        )
        .context(crate::PackageArrowSnafu)?;
        let ordered_rows = UInt64Array::from_iter_values(
            order
                .values()
                .iter()
                .map(|row| current_rows.value(*row as usize)),
        );
        let keys = [
            take(tenants, &ordered_rows, None).context(crate::PackageArrowSnafu)?,
            take(ids, &ordered_rows, None).context(crate::PackageArrowSnafu)?,
        ];
        for range in partition(&keys).context(crate::PackageArrowSnafu)?.ranges() {
            memory.check()?;
            let first = ordered_rows.value(range.start) as usize;
            let last = ordered_rows.value(range.end - 1) as usize;
            if touched.contains(&(tenants.value(first), ids.value(first)))
                && dictionary[first] != dictionary[last]
            {
                return Err(Code::Conflict.error("public Graph finding value"));
            }
        }
        let checked_at = std::time::Instant::now();
        let wanted = current
            .iter()
            .filter(|(id, opened)| *opened == revision && !known.contains_key(id))
            .map(|(id, _)| *id)
            .collect::<BTreeSet<_>>();
        let mut mappings = Vec::with_capacity(wanted.len());
        if !wanted.is_empty() {
            let mut append = connection
                .appender("managed_graph_finding_values")
                .context(AnalysisDatabaseSnafu {
                    operation: "open canonical finding mappings",
                })?;
            for id in wanted {
                memory.check()?;
                let winner = canonical[locate(&id)?];
                mappings.push((id, winner));
                append
                    .append_row(params![id.0, id.1, winner.0, winner.1])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append canonical finding mapping",
                    })?;
            }
            append.flush().context(AnalysisDatabaseSnafu {
                operation: "flush canonical finding mappings",
            })?;
        }
        erebor_telemetry::debug!(
            stage = "graph_finding_dictionary_timing",
            result_id = result,
            heads_s = heads_at.duration_since(started).as_secs_f64(),
            dictionary_s = dictionary_at.duration_since(heads_at).as_secs_f64(),
            conflicts_s = checked_at.duration_since(dictionary_at).as_secs_f64(),
            mappings_s = checked_at.elapsed().as_secs_f64(),
            elapsed_s = started.elapsed().as_secs_f64(),
            "Graph finding dictionary publication completed"
        );
        Ok(mappings)
    }
}
