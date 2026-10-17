use std::mem::size_of;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::ProjectionSink;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::{DataFusionError, Result};

use super::{ArrowBatch, Capture, Captured, SourceOrigin, SourceSnapshot};

impl Captured {
    pub(super) fn table_bytes(schema: &SchemaRef, batches: &Vec<sdk::RecordBatch>) -> usize {
        let bytes = size_of::<(SourceOrigin, (SchemaRef, Vec<usize>, Vec<sdk::RecordBatch>))>()
            .saturating_add(schema.fields().len().saturating_mul(size_of::<usize>()))
            .saturating_add(
                batches
                    .capacity()
                    .saturating_mul(size_of::<sdk::RecordBatch>()),
            )
            .saturating_add(Self::schema_bytes(schema));
        batches.iter().fold(bytes, |bytes, batch| {
            bytes
                .saturating_add(
                    batch
                        .num_columns()
                        .saturating_mul(size_of::<sdk::arrow_array::ArrayRef>()),
                )
                .saturating_add(batch.columns().iter().fold(0usize, |bytes, array| {
                    bytes.saturating_add(
                        array
                            .get_array_memory_size()
                            .saturating_sub(array.get_buffer_memory_size()),
                    )
                }))
                .saturating_add(Self::schema_bytes(batch.schema_ref()))
        })
    }

    fn schema_bytes(schema: &SchemaRef) -> usize {
        size_of::<sdk::Schema>()
            .saturating_add(schema.fields().size())
            .saturating_add(
                schema
                    .metadata()
                    .capacity()
                    .saturating_mul(size_of::<(String, String)>()),
            )
            .saturating_add(
                schema
                    .metadata()
                    .iter()
                    .fold(0usize, |bytes, (key, value)| {
                        bytes
                            .saturating_add(key.capacity())
                            .saturating_add(value.capacity())
                    }),
            )
    }

    pub(super) fn coverage_bytes(coverage: &sdk::Coverage) -> usize {
        size_of::<(usize, sdk::Coverage)>()
            .saturating_add(
                coverage
                    .limits
                    .capacity()
                    .saturating_mul(size_of::<String>()),
            )
            .saturating_add(coverage.limits.iter().fold(0usize, |bytes, limit| {
                bytes.saturating_add(limit.capacity())
            }))
    }
}

impl Capture<'_> {
    pub(super) fn package(
        &mut self,
        reference: &sdk::OutputRef,
        dataset: Option<&sdk::wire::Dataset>,
        coverage: &sdk::Coverage,
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<bool> {
        let inputs = self
            .inputs
            .ok_or_else(|| ArrowBatch::invalid("the package source has no input scope"))?;
        let Some(dataset) = dataset else {
            return Ok(true);
        };
        for (slot, binding, schema) in &inputs.bindings {
            if binding != reference {
                continue;
            }
            if self.packages.contains_key(slot) {
                return Err(ArrowBatch::invalid("the package source is bound twice"));
            }
            let decoded = inputs
                .bindings
                .iter()
                .filter(|(_, binding, expected)| binding == reference && expected == schema)
                .find_map(|(slot, _, _)| self.packages.get(slot));
            let batches = match decoded {
                Some((_, batches, _)) => {
                    sink.charge(Captured::table_bytes(schema, batches))?;
                    batches.clone()
                }
                None => {
                    let mut limits = inputs.limits;
                    limits.max_bytes = limits.max_bytes.min(sink.remaining_bytes() as u64);
                    let data = dataset.decode(schema, limits).map_err(|source| {
                        araphor_data::Error::AnalysisContract {
                            source,
                            location: snafu::location!(),
                        }
                    })?;
                    for batch in &data.batches {
                        sink.charge(batch.get_array_memory_size())?;
                    }
                    sink.charge(Captured::table_bytes(schema, &data.batches))?;
                    data.batches
                }
            };
            sink.charge(Captured::coverage_bytes(coverage))?;
            self.packages
                .insert(*slot, (Arc::clone(schema), batches, coverage.clone()));
        }
        Ok(true)
    }
}

impl SourceSnapshot {
    pub(crate) fn package_coverage(&self, slot: usize) -> Result<sdk::Coverage> {
        self.captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?
            .as_ref()
            .and_then(|captured| captured.package_coverage.get(&slot))
            .cloned()
            .ok_or_else(|| {
                DataFusionError::Execution("the package source coverage is absent".into())
            })
    }

    pub(crate) fn port_table(&self, slot: usize) -> Result<(SchemaRef, Vec<sdk::RecordBatch>)> {
        let captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        let captured = captured
            .as_ref()
            .ok_or_else(|| DataFusionError::Execution("the source snapshot is absent".into()))?;
        let (schema, _, batches) = captured
            .tables
            .get(&SourceOrigin::Port(slot))
            .ok_or_else(|| DataFusionError::Execution("the materialized port is absent".into()))?;
        Ok((Arc::clone(schema), batches.clone()))
    }

    pub(crate) fn retain_ports(&self) -> Result<()> {
        let mut captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        let captured = captured
            .as_mut()
            .ok_or_else(|| DataFusionError::Execution("the source snapshot is absent".into()))?;
        captured
            .tables
            .retain(|origin, _| matches!(origin, SourceOrigin::Port(_)));
        captured.package_coverage.clear();
        captured
            ._memory
            .shrink(std::mem::take(&mut captured.package_bytes));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::Arc;
    use std::time::Duration;

    use araphor_data::{
        AnalysisExtractLimits, AnalysisReadControl, AnalysisSelectionV1, AnalysisStore,
    };

    use super::{sdk, SourceSnapshot};

    #[test]
    fn port_metadata_is_bounded() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let capacity = 32 * 1024;
        let memory = crate::memory::Memory::new(capacity, 1024);
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
        let source = SourceSnapshot::new(
            store,
            AnalysisSelectionV1::tenant([1; 16]),
            None,
            AnalysisExtractLimits {
                input_bytes: 16 * 1024,
                ..Default::default()
            },
            control.within(control.remaining()?)?,
            Duration::from_secs(30),
            1,
            Arc::clone(&memory),
        );
        let captured = source.read(
            &BTreeSet::new(),
            &BTreeMap::new(),
            None,
            super::super::ReadMode::Snapshot,
            &control,
        )?;
        let held = memory.reserve_input(capacity - captured.receipt._metadata.size() - 1024)?;
        *source.captured.lock().map_err(|_| "source lock")? = Some(captured);
        let schema = Arc::new(sdk::Schema::new_with_metadata(
            vec![sdk::Field::new("value", sdk::DataType::UInt64, false)],
            HashMap::from([("description".into(), "x".repeat(4096))]),
        ));
        let batch = sdk::RecordBatch::new_empty(Arc::clone(&schema));
        let error = source
            .bind_port(0, Arc::clone(&schema), vec![batch.clone()])
            .expect_err("schema metadata exceeds the remaining reservation");
        assert!(
            matches!(error, datafusion::common::DataFusionError::External(source)
            if matches!(source.downcast_ref::<crate::Error>(), Some(crate::Error::Capacity { resource: "shared input", .. })))
        );
        assert!(!source
            .captured
            .lock()
            .map_err(|_| "source lock")?
            .as_ref()
            .ok_or("source capture")?
            .tables
            .contains_key(&super::SourceOrigin::Port(0)));
        drop(held);
        source.bind_port(0, schema, vec![batch])?;
        let charged = source
            .captured
            .lock()
            .map_err(|_| "source lock")?
            .as_ref()
            .ok_or("source capture")?
            ._memory
            .size();
        assert!(charged >= 4096);
        source.retain_ports()?;
        assert_eq!(
            source
                .captured
                .lock()
                .map_err(|_| "source lock")?
                .as_ref()
                .ok_or("source capture")?
                ._memory
                .size(),
            charged
        );
        drop(source);
        drop(memory.reserve_input(capacity)?);
        Ok(())
    }
}
