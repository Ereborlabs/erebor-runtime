use std::collections::BTreeMap;
use std::io::Write;
use std::mem::size_of;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use sdk::arrow_array::{ArrayRef, RecordBatch};

use super::{AnalysisTableRead, ReadBudget};
use crate::{
    AnalysisExtractionV1, AnalysisGapV1, AnalysisPositionPageV1, AnalysisReadControl,
    AnalysisSelectionV1, AnalysisStore, AnalysisStreamIdentityV1, AnalysisWitnessV1, Result,
    StorePositionV1, TraceRecipeV1,
};

mod builder;
mod context;
mod discovery;
mod events;
mod graph;
mod metadata;
mod notification;
mod schema;
#[cfg(test)]
mod tests;
mod trace;

use builder::{table_row, Table};

pub(super) struct Capture<'a> {
    read: &'a AnalysisTableRead<'a>,
    scope: &'a AnalysisSelectionV1,
    tables: BTreeMap<String, Table>,
    witnesses: Vec<AnalysisWitnessV1>,
    removals: BTreeMap<AnalysisStreamIdentityV1, Vec<AnalysisGapV1>>,
    latest: BTreeMap<([u8; 16], String), (u64, usize)>,
    trace_recipes: BTreeMap<[u8; 16], TraceRecipeV1>,
    mutable_discovery: bool,
    received_min: Option<u64>,
    next_change: Option<u64>,
    packages: BTreeMap<usize, (Arc<sdk::Schema>, Vec<RecordBatch>, sdk::Coverage)>,
}

impl<'a> Capture<'a> {
    pub(super) fn new(read: &'a AnalysisTableRead<'a>, scope: &'a AnalysisSelectionV1) -> Self {
        Self {
            read,
            scope,
            tables: BTreeMap::new(),
            witnesses: Vec::new(),
            removals: BTreeMap::new(),
            latest: BTreeMap::new(),
            trace_recipes: BTreeMap::new(),
            mutable_discovery: false,
            received_min: None,
            next_change: None,
            packages: BTreeMap::new(),
        }
    }

    pub(super) fn graph_headers(&self) -> bool {
        self.read.requests.contains_key("graph_manifest")
    }

    fn table(
        &mut self,
        name: &str,
        names: &'static [&'static str],
        budget: &mut ReadBudget<'_>,
    ) -> Result<&mut Table> {
        if !self.tables.contains_key(name) {
            let indices = self
                .read
                .projected(name)
                .ok_or_else(|| invalid("the table has no requested columns"))?;
            budget.charge(
                name.len()
                    + 512
                    + size_of::<sdk::Schema>()
                    + indices.len() * (size_of::<usize>() + size_of::<Arc<sdk::Field>>()),
            )?;
            let indices = indices.iter().copied().collect::<Vec<_>>();
            let schema = AnalysisStore::table_schemas()
                .get(name)
                .ok_or_else(|| invalid("the relation has no native Arrow schema"))?;
            self.tables.insert(
                name.into(),
                Table::new(
                    Arc::new(schema.project(&indices).map_err(arrow_error)?),
                    names,
                    budget,
                )?,
            );
        }
        let table = self
            .tables
            .get_mut(name)
            .ok_or_else(|| invalid("the native table builder is absent"))?;
        if !std::ptr::eq(table.names, names) && table.names != names {
            return Err(invalid("the native table field mapping changed"));
        }
        Ok(table)
    }

    pub(super) fn remove(
        &mut self,
        identity: &AnalysisStreamIdentityV1,
        gap: AnalysisGapV1,
        budget: &mut ReadBudget<'_>,
    ) -> Result<()> {
        if !self.removals.contains_key(identity) {
            budget.charge(
                size_of::<(AnalysisStreamIdentityV1, Vec<AnalysisGapV1>)>()
                    + match identity {
                        AnalysisStreamIdentityV1::Evidence(value) => value.node_id.len(),
                        AnalysisStreamIdentityV1::Diagnostic(value) => value.node_id.len(),
                    },
            )?;
            self.removals.insert(identity.clone(), Vec::new());
        }
        let ranges = self
            .removals
            .get_mut(identity)
            .ok_or_else(|| invalid("the retirement identity is absent"))?;
        budget.grow(ranges)?;
        ranges.push(gap);
        Ok(())
    }

    pub(super) fn package(
        &mut self,
        index: usize,
        dataset: Option<&sdk::wire::Dataset>,
        coverage: &sdk::Coverage,
        budget: &mut ReadBudget<'_>,
    ) -> Result<()> {
        let inputs = self
            .read
            .inputs
            .ok_or_else(|| invalid("the package source has no input scope"))?;
        let (reference, schema) = inputs
            .outputs
            .get(index)
            .ok_or_else(|| invalid("the package source index is absent"))?;
        let Some(dataset) = dataset else {
            return Ok(());
        };
        if self.packages.contains_key(&index) {
            return Err(invalid("the package source is bound twice"));
        }
        let shared = inputs
            .outputs
            .iter()
            .enumerate()
            .filter(|(_, (previous, expected))| previous == reference && expected == schema)
            .find_map(|(index, _)| self.packages.get(&index));
        let batches = match shared {
            Some((_, batches, _)) => {
                budget.charge(batch_metadata(batches))?;
                batches.clone()
            }
            None => {
                let mut limits = inputs.limits;
                limits.max_bytes = limits.max_bytes.min(budget.remaining_bytes() as u64);
                let data = dataset.decode(schema, limits).map_err(|source| {
                    crate::Error::AnalysisContract {
                        source,
                        location: snafu::location!(),
                    }
                })?;
                for batch in &data.batches {
                    budget.charge(batch.get_array_memory_size())?;
                }
                budget.charge(batch_metadata(&data.batches))?;
                data.batches
            }
        };
        budget.charge(
            size_of::<(usize, sdk::Coverage)>()
                + coverage.limits.capacity() * size_of::<String>()
                + coverage.limits.iter().map(String::capacity).sum::<usize>(),
        )?;
        self.packages
            .insert(index, (Arc::clone(schema), batches, coverage.clone()));
        Ok(())
    }

    pub(super) fn finish(
        mut self,
        mut extraction: AnalysisExtractionV1,
        scanned_through: StorePositionV1,
        exhausted: bool,
        control: &AnalysisReadControl,
    ) -> Result<AnalysisPositionPageV1> {
        self.metadata(&mut extraction, control)?;
        {
            let mut budget = extraction.sink(control);
            for table in self.tables.values_mut() {
                table.finish(&mut budget)?;
            }
            if let Some(findings) = self.tables.get_mut("findings") {
                budget.charge(
                    self.latest
                        .len()
                        .checked_mul(size_of::<usize>())
                        .ok_or_else(overflow)?,
                )?;
                let mut selected: Vec<_> = self.latest.values().map(|(_, row)| *row).collect();
                selected.sort_unstable();
                findings.select_rows(&selected, &mut budget)?;
            }
        }
        let inherited = std::mem::take(&mut extraction.witnesses);
        {
            let mut budget = extraction.sink(control);
            for witness in inherited {
                budget.grow(&mut self.witnesses)?;
                self.witnesses.push(witness);
            }
        }
        extraction.witnesses = self.witnesses;
        control.check()?;
        Ok(AnalysisPositionPageV1 {
            extraction,
            scanned_through,
            exhausted,
            tables: self
                .tables
                .into_iter()
                .map(|(name, table)| (name, table.batches))
                .collect(),
            packages: self.packages,
            removals: self.removals,
            mutable_discovery: self.mutable_discovery,
            received_min: self.received_min,
            next_change: self.next_change,
        })
    }
}

fn batch_metadata(batches: &Vec<RecordBatch>) -> usize {
    batches.capacity() * size_of::<RecordBatch>()
        + batches
            .iter()
            .map(|batch| {
                let schema = batch.schema_ref();
                batch.num_columns() * size_of::<ArrayRef>()
                    + size_of::<sdk::Schema>()
                    + schema.fields().size()
                    + schema.metadata().capacity() * size_of::<(String, String)>()
                    + schema
                        .metadata()
                        .iter()
                        .map(|(key, value)| key.capacity() + value.capacity())
                        .sum::<usize>()
            })
            .sum::<usize>()
}

fn json<T: serde::Serialize + ?Sized>(
    value: Option<&T>,
    budget: &mut ReadBudget<'_>,
) -> Result<Option<Vec<u8>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let mut counter = JsonSize {
        bytes: 0,
        limit: budget.remaining_bytes(),
    };
    serde_json::to_writer(&mut counter, value).map_err(|_| overflow())?;
    budget.charge(counter.bytes)?;
    let mut buffer = sdk::wire::BoundedBuffer::from_writer(
        Vec::with_capacity(counter.bytes),
        counter.bytes as u64,
    );
    serde_json::to_writer(&mut buffer, value).map_err(|source| crate::Error::PackageEncoding {
        source,
        location: snafu::location!(),
    })?;
    Ok(Some(buffer.finish()))
}

fn invalid(reason: &'static str) -> crate::Error {
    crate::Error::AnalysisState {
        path: "<native table>".into(),
        reason: reason.into(),
        location: snafu::location!(),
    }
}
fn overflow() -> crate::Error {
    crate::Error::AnalysisInputTooLarge {
        resource: "native source Arrow allocation",
        location: snafu::location!(),
    }
}
fn arrow_error(source: duckdb::arrow::error::ArrowError) -> crate::Error {
    crate::Error::AnalysisContract {
        source: source.into(),
        location: snafu::location!(),
    }
}

struct JsonSize {
    bytes: usize,
    limit: usize,
}
impl Write for JsonSize {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|bytes| *bytes <= self.limit)
            .ok_or_else(|| std::io::Error::other("source JSON exceeds its input bound"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
