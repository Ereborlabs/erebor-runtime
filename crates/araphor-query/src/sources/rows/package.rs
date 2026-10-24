use std::mem::size_of;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::{DataFusionError, Result};

use super::{Captured, SourceOrigin, SourceSnapshot, Table};

impl Captured {
    pub(super) fn table_bytes(schema: &SchemaRef, batches: &Vec<sdk::RecordBatch>) -> usize {
        let bytes = size_of::<(SourceOrigin, Table)>()
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
}

impl SourceSnapshot {
    pub(crate) fn captured_input(&self, origin: &SourceOrigin) -> Result<Option<Arc<sdk::Input>>> {
        let captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        let input = &captured
            .as_ref()
            .ok_or_else(|| DataFusionError::Execution("the source snapshot is absent".into()))?
            .tables
            .get(origin)
            .ok_or_else(|| DataFusionError::Execution("the materialized input is absent".into()))?
            .3;
        Ok(input.as_ref().map(Arc::clone))
    }

    pub(crate) fn package_indices(
        &self,
        origins: &std::collections::BTreeSet<SourceOrigin>,
    ) -> std::collections::BTreeSet<usize> {
        self.inputs
            .as_ref()
            .map(|inputs| {
                inputs
                    .bindings
                    .iter()
                    .enumerate()
                    .filter(|(_, (slot, _, _))| origins.contains(&SourceOrigin::Package(*slot)))
                    .map(|(index, _)| index)
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
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
        let memory = crate::memory::Memory::new(Some(capacity), Some(1024));
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
            Some(Duration::from_secs(30)),
            1,
            Arc::clone(&memory),
            None,
        );
        let captured = source.read(
            &BTreeMap::new(),
            &Default::default(),
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
            .bind_port(0, Arc::clone(&schema), vec![batch.clone()], None)
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
        source.bind_port(0, schema, vec![batch], None)?;
        let charged = source
            .captured
            .lock()
            .map_err(|_| "source lock")?
            .as_ref()
            .ok_or("source capture")?
            ._memory
            .size();
        assert!(charged >= 4096);
        drop(source);
        drop(memory.reserve_input(capacity)?);
        Ok(())
    }

    #[test]
    fn bound_metadata_is_charged() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let capacity = 64 * 1024;
        let memory = crate::memory::Memory::new(Some(capacity), Some(1024));
        let control = AnalysisReadControl::default();
        let source = SourceSnapshot::new(
            store,
            AnalysisSelectionV1::tenant([1; 16]),
            None,
            AnalysisExtractLimits::default(),
            control.within(None)?,
            None,
            1,
            Arc::clone(&memory),
            None,
        );
        let captured = source.read(
            &BTreeMap::new(),
            &Default::default(),
            super::super::ReadMode::Snapshot,
            &control,
        )?;
        let held = memory.reserve_input(capacity - captured.receipt._metadata.size() - 1024)?;
        *source.captured.lock().map_err(|_| "source lock")? = Some(captured);
        let schema = Arc::new(sdk::Schema::new(vec![sdk::Field::new(
            "value",
            sdk::DataType::UInt64,
            false,
        )]));
        let input = sdk::Input {
            data: sdk::Dataset {
                name: "input".into(),
                batches: vec![sdk::RecordBatch::new_empty(Arc::clone(&schema))],
            },
            revision: sdk::Revision {
                owner: "external-local".into(),
                id: "x".repeat(8192),
                window: Some(sdk::SourceWindow {
                    source: vec![9; 4096],
                    start_utc_ns: 1,
                    end_utc_ns: 2,
                }),
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Gapped,
                limits: vec!["y".repeat(8192)],
            },
        };
        let error = source
            .bind_port(
                0,
                Arc::clone(&schema),
                input.data.batches.clone(),
                Some(&input),
            )
            .expect_err("SDK metadata exceeds the remaining reservation");
        assert!(
            matches!(error, datafusion::common::DataFusionError::External(source)
            if matches!(source.downcast_ref::<crate::Error>(), Some(crate::Error::Capacity { resource: "shared input", .. })))
        );
        assert!(source
            .captured_input(&super::SourceOrigin::Port(0))
            .is_err());
        drop(memory.reserve_input(1024)?);
        drop(held);
        source.bind_port(
            0,
            Arc::clone(&schema),
            input.data.batches.clone(),
            Some(&input),
        )?;
        let stored = source
            .captured_input(&super::SourceOrigin::Port(0))?
            .ok_or("stored SDK input")?;
        assert_eq!(stored.data.name, input.data.name);
        assert_eq!(stored.data.batches, input.data.batches);
        assert_eq!(stored.revision, input.revision);
        assert_eq!(stored.coverage, input.coverage);
        assert!(Arc::ptr_eq(
            &stored,
            &source
                .captured_input(&super::SourceOrigin::Port(0))?
                .ok_or("same SDK input")?
        ));
        assert!(Arc::ptr_eq(
            stored.data.batches[0].column(0),
            input.data.batches[0].column(0)
        ));
        assert!(source
            .bind_port(0, Arc::clone(&schema), Vec::new(), None)
            .is_err());
        let charged = source
            .captured
            .lock()
            .map_err(|_| "source lock")?
            .as_ref()
            .ok_or("source capture")?
            ._memory
            .size();
        assert!(charged >= input.metadata_bytes());
        control.cancel()?;
        assert!(source
            .bind_port(1, schema, input.data.batches.clone(), Some(&input))
            .is_err());
        assert!(source
            .captured_input(&super::SourceOrigin::Port(1))
            .is_err());
        drop(stored);
        drop(source);
        drop(memory.reserve_input(capacity)?);
        Ok(())
    }
}
