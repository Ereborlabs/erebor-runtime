use std::mem::size_of;
use std::sync::{Arc, Mutex};

use araphor_analysis_sdk as sdk;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::{DataFusionError, Result};
use futures_util::future::{BoxFuture, Either, Shared, WeakShared};
use futures_util::FutureExt as _;

use super::{Captured, SourceOrigin, SourceSnapshot, Table};

#[derive(Debug)]
pub(super) struct PortBinding {
    scope: Option<super::super::port::PortScope>,
    ready: Arc<Mutex<PortReady>>,
}

type PortFill = BoxFuture<'static, std::result::Result<usize, Arc<DataFusionError>>>;

enum PortReady {
    Empty,
    Pending(WeakShared<PortFill>),
    Complete(usize),
}

impl std::fmt::Debug for PortReady {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("Empty"),
            Self::Pending(_) => f.write_str("Pending"),
            Self::Complete(read) => f.debug_tuple("Complete").field(read).finish(),
        }
    }
}

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
    pub(crate) async fn bind_shared(
        self: &Arc<Self>,
        key: super::super::port::PortKey,
        demand: Option<&super::super::port::PortDemand>,
        read: usize,
        schema: SchemaRef,
        context: &datafusion::execution::TaskContext,
        bind: impl std::future::Future<Output = Result<()>> + Send + 'static,
    ) -> Result<()> {
        let (_, control, _lease) = self.read_context(context)?;
        let cut = self
            .snapshot()
            .ok()
            .map(|snapshot| snapshot.page.extraction.meta.commit_revision);
        let snapshot_id = Arc::as_ptr(self) as usize;
        let key_slot = demand.map(|demand| demand.slot);
        let trace = move |action: &'static str| {
            if let Some(cut) = cut {
                erebor_telemetry::debug!(
                    stage = "source_binding_lifecycle",
                    action,
                    cut_revision = cut,
                    snapshot_id,
                    family_id = key.0,
                    image = ?key.1,
                    read_id = read,
                    key_slot,
                    "Native source binding lifecycle changed"
                );
            }
        };
        trace("demand_wait");
        let scope = match demand {
            Some(demand) => Some(demand.resolve(self, &control).await?),
            None => None,
        };
        trace("demand_ready");
        let binding = {
            let mut captured = self.captured.lock().map_err(|_| {
                DataFusionError::Internal("source snapshot lock is poisoned".into())
            })?;
            let captured = captured.as_mut().ok_or_else(|| {
                DataFusionError::Execution("the source snapshot is absent".into())
            })?;
            let mut shared = None;
            if let Some(bindings) = captured.ports.get(&key) {
                for binding in bindings {
                    control.check().map_err(Self::data_error)?;
                    let same = match (&binding.scope, &scope) {
                        (None, None) => true,
                        (Some(saved), Some(current)) => saved.same(current, &control)?,
                        _ => false,
                    };
                    if same {
                        shared = Some(Arc::clone(&binding.ready));
                        break;
                    }
                }
            }
            match shared {
                Some(binding) => binding,
                None => {
                    let bucket = captured.ports.get(&key);
                    let growth =
                        usize::from(bucket.is_none_or(|bucket| bucket.len() == bucket.capacity()))
                            * size_of::<PortBinding>();
                    let entry = usize::from(bucket.is_none())
                        * (size_of::<(super::super::port::PortKey, Vec<PortBinding>)>()
                            + 6 * size_of::<usize>());
                    captured
                        ._memory
                        .try_grow(
                            entry
                                .saturating_add(growth)
                                .saturating_add(size_of::<Mutex<PortReady>>())
                                .saturating_add(2 * size_of::<usize>()),
                        )
                        .map_err(|source| {
                            DataFusionError::External(Box::new(crate::Error::Capacity {
                                resource: "shared input",
                                source,
                            }))
                        })?;
                    let binding = Arc::new(Mutex::new(PortReady::Empty));
                    let bucket = captured.ports.entry(key).or_default();
                    if bucket.len() == bucket.capacity() {
                        bucket.reserve_exact(1);
                    }
                    bucket.push(PortBinding {
                        scope,
                        ready: Arc::clone(&binding),
                    });
                    binding
                }
            }
        };
        let wait = {
            let mut ready = binding.lock().map_err(|_| {
                DataFusionError::Internal("shared source binding is poisoned".into())
            })?;
            let completed = match &*ready {
                PortReady::Complete(read) => Some(*read),
                _ => None,
            };
            let pending = match &*ready {
                PortReady::Pending(pending) => pending.upgrade(),
                _ => None,
            };
            if let Some(from) = completed {
                Either::Left(std::future::ready(Ok(from)))
            } else if let Some(pending) = pending {
                Either::Right(pending)
            } else {
                let completed = Arc::downgrade(&binding);
                let fill = async move {
                    trace("fill_start");
                    bind.await.map_err(Arc::new)?;
                    if let Some(completed) = completed.upgrade() {
                        *completed.lock().map_err(|_| {
                            Arc::new(DataFusionError::Internal(
                                "shared source binding is poisoned".into(),
                            ))
                        })? = PortReady::Complete(read);
                    }
                    trace("fill_done");
                    Ok(read)
                };
                let bytes = std::mem::size_of_val(&fill)
                    .saturating_add(size_of::<Shared<PortFill>>())
                    .saturating_add(2 * size_of::<Mutex<usize>>())
                    .saturating_add(size_of::<std::task::Waker>())
                    .saturating_add(16 * size_of::<usize>());
                self.charge_binding(bytes)?;
                let pending = fill.boxed().shared();
                *ready = PortReady::Pending(pending.downgrade().ok_or_else(|| {
                    DataFusionError::Internal("shared source fill is absent".into())
                })?);
                Either::Right(pending)
            }
        };
        if matches!(&wait, Either::Right(_)) {
            self.charge_binding(
                size_of::<Shared<PortFill>>()
                    + size_of::<std::task::Waker>()
                    + 4 * size_of::<usize>(),
            )?;
        }
        trace("binding_wait");
        let result = control
            .query_async(async { Ok::<_, araphor_data::Error>(wait.await) })
            .await;
        control.check().map_err(Self::data_error)?;
        let from = result
            .map_err(Self::data_error)?
            .map_err(|error| Arc::try_unwrap(error).unwrap_or_else(DataFusionError::Shared))?;
        if let Ok(snapshot) = self.snapshot() {
            erebor_telemetry::debug!(
                stage = "source_port_binding",
                cut_revision = snapshot.page.extraction.meta.commit_revision,
                snapshot_id = Arc::as_ptr(self) as usize,
                family_id = key.0,
                read_id = read,
                source_read = from,
                demand_bound = demand.is_some(),
                reused = from != read,
                "Native source binding completed"
            );
        }
        if from != read {
            let (batches, input) = {
                let captured = self.captured.lock().map_err(|_| {
                    DataFusionError::Internal("source snapshot lock is poisoned".into())
                })?;
                let (saved, _, batches, input) = captured
                    .as_ref()
                    .and_then(|captured| captured.tables.get(&SourceOrigin::Port(from)))
                    .ok_or_else(|| {
                        DataFusionError::Internal("the shared source input is absent".into())
                    })?;
                if saved != &schema {
                    return datafusion::common::exec_err!("shared source schema differs");
                }
                (batches.clone(), input.clone())
            };
            self.bind_port(read, schema, batches, input.as_deref())?;
            self.share_lineage(from, read)?;
        }
        control.check().map_err(Self::data_error)
    }

    fn charge_binding(&self, bytes: usize) -> Result<()> {
        let mut captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        captured
            .as_mut()
            .ok_or_else(|| DataFusionError::Execution("the source snapshot is absent".into()))?
            ._memory
            .try_grow(bytes)
            .map_err(|source| {
                DataFusionError::External(Box::new(crate::Error::Capacity {
                    resource: "shared input",
                    source,
                }))
            })
    }

    pub(crate) fn captured_input(&self, origin: &SourceOrigin) -> Result<Option<Arc<sdk::Input>>> {
        let captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        let input = captured
            .as_ref()
            .ok_or_else(|| DataFusionError::Execution("the source snapshot is absent".into()))?
            .tables
            .get(origin)
            .and_then(|table| table.3.as_ref());
        Ok(input.map(Arc::clone))
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
        let held = memory.reserve_input(capacity - memory.input_reserved() - 1024)?;
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
        let held = memory.reserve_input(capacity - memory.input_reserved() - 1024)?;
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
            .captured_input(&super::SourceOrigin::Port(0))?
            .is_none());
        assert!(!source
            .captured
            .lock()
            .map_err(|_| "source lock")?
            .as_ref()
            .ok_or("source capture")?
            .tables
            .contains_key(&super::SourceOrigin::Port(0)));
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
            .captured_input(&super::SourceOrigin::Port(1))?
            .is_none());
        assert!(!source
            .captured
            .lock()
            .map_err(|_| "source lock")?
            .as_ref()
            .ok_or("source capture")?
            .tables
            .contains_key(&super::SourceOrigin::Port(1)));
        drop(stored);
        drop(source);
        drop(memory.reserve_input(capacity)?);
        Ok(())
    }
}
