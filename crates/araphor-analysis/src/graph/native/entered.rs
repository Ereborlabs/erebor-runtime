use std::sync::{Arc, Weak};

use araphor_analysis_builtins::graph::Unit;
use araphor_analysis_sdk as sdk;
use araphor_data::{
    DiscoveryRecordIdV1, EvidenceIntakeIdentityV1, ManagedSourceRead, PackageErrorCodeV1 as Code,
};
use araphor_query::execution::Session;
use araphor_query::sources::{PortRead, PortSource, SourceImage, SourceSnapshot};
use datafusion::arrow::array::{Array, StructArray, UInt64Array};
use datafusion::arrow::compute::take;
use datafusion::common::Result;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{LogicalPlan, LogicalPlanBuilder};
use futures_util::{future::BoxFuture, FutureExt};

use super::{GraphRun, Projection};

#[derive(Debug)]
pub(super) struct EnteredPort {
    append: bool,
}

impl EnteredPort {
    fn grow(memory: &MemoryReservation, bytes: usize, limit: usize) -> Result<()> {
        if memory
            .size()
            .checked_add(bytes)
            .is_none_or(|size| size > limit)
        {
            return Err(Projection::external(
                Code::Limit.error("Graph entered input bytes"),
            ));
        }
        memory.try_grow(bytes)?;
        Ok(())
    }

    fn encode(
        identity: &EvidenceIntakeIdentityV1,
        keys: &sdk::RecordBatch,
        memory: &MemoryReservation,
        limit: usize,
    ) -> Result<sdk::RecordBatch> {
        let schema = Arc::new(Unit::affected_port().schema);
        let empty = sdk::RecordBatch::new_empty(Arc::clone(&schema));
        let overflow = || Projection::external(Code::Limit.error("Graph entered input bytes"));
        keys.num_rows()
            .checked_mul(identity.node_id.len().max(identity.tenant_id.len()))
            .and_then(|bytes| i32::try_from(bytes).ok())
            .ok_or_else(overflow)?;
        let fixed = empty
            .get_array_memory_size()
            .checked_add(std::mem::size_of::<DiscoveryRecordIdV1>())
            .and_then(|bytes| bytes.checked_add(identity.node_id.len()))
            .and_then(|bytes| bytes.checked_mul(4))
            .ok_or_else(overflow)?;
        Self::grow(memory, fixed, limit)?;
        if keys.num_rows() == 0 {
            return Ok(empty);
        }
        let template = Unit::encode_affected(&[DiscoveryRecordIdV1 {
            stream: identity.clone(),
            cpu_id: 0,
            durable_cursor: 1,
        }])
        .map_err(Projection::external)?;
        let batch = template
            .batches
            .first()
            .ok_or_else(|| Projection::invalid("Graph entered template"))?;
        let record = Projection::column::<StructArray>(batch, "record")?;
        let bytes = record
            .get_array_memory_size()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<u64>()))
            .and_then(|bytes| bytes.checked_mul(keys.num_rows()))
            .ok_or_else(overflow)?;
        Self::grow(memory, bytes, limit)?;
        let indices = UInt64Array::from(vec![0; keys.num_rows()]);
        let stream = take(
            record
                .column_by_name("stream")
                .ok_or_else(|| Projection::invalid("Graph entered stream"))?
                .as_ref(),
            &indices,
            None,
        )?;
        let columns = record
            .fields()
            .iter()
            .map(|field| match field.name().as_str() {
                "stream" => Ok(Arc::clone(&stream)),
                "cpu_id" => keys
                    .column_by_name("cpu_id")
                    .cloned()
                    .ok_or_else(|| Projection::invalid("Graph entered CPU")),
                "durable_cursor" => keys
                    .column_by_name("source_cursor")
                    .cloned()
                    .ok_or_else(|| Projection::invalid("Graph entered cursor")),
                _ => Err(Projection::invalid("Graph entered field")),
            })
            .collect::<Result<Vec<_>>>()?;
        let record = StructArray::try_new(record.fields().clone(), columns, None)?;
        Ok(sdk::RecordBatch::try_new(schema, vec![Arc::new(record)])?)
    }

    pub(super) async fn plan(
        session: &Session,
        control: LogicalPlan,
        append: bool,
    ) -> araphor_query::Result<LogicalPlan> {
        let driver = LogicalPlanBuilder::empty(true)
            .build()
            .map_err(|source| araphor_query::Error::Sql { source })?;
        araphor_query::sources::SourcePort::new(
            session,
            "__graph_entered".into(),
            Arc::new(Unit::affected_port().schema),
            driver,
            control,
            Arc::new(Self { append }),
        )
        .await?
        .plan()
    }
}

impl PortSource for EnteredPort {
    fn reusable(&self) -> bool {
        true
    }
    fn snapshot_bound(&self) -> bool {
        true
    }
    fn key_columns(&self) -> &[(usize, usize)] {
        &[]
    }

    fn header(&self, image: SourceImage, header: &LogicalPlan) -> Result<Option<LogicalPlan>> {
        match image {
            SourceImage::Before => LogicalPlanBuilder::empty(true).build().map(Some),
            SourceImage::After => Ok(Some(header.clone())),
            _ => datafusion::common::not_impl_err!("Graph entered delta image"),
        }
    }

    fn read<'a>(
        &'a self,
        image: Option<SourceImage>,
        driver: Vec<sdk::RecordBatch>,
        header: Vec<sdk::RecordBatch>,
        source: Arc<SourceSnapshot>,
        context: Arc<TaskContext>,
    ) -> BoxFuture<'a, Result<PortRead>> {
        async move {
            if matches!(image, Some(SourceImage::Inserted | SourceImage::Removed)) {
                return datafusion::common::not_impl_err!("Graph entered delta image");
            }
            let memory = source.memory().reserve_input(0)?;
            let append = self.append;
            let callback = Arc::clone(&context);
            source
                .blocking(&context, (), move |source, control| {
                    (|| -> Result<_> {
                        let resume = append
                            && image != Some(SourceImage::Before)
                            && source.with_capture(|_, capture, _| {
                                Ok(!capture.rebuild()
                                    && capture.source().is_some_and(|frame| {
                                        matches!(frame.read(), ManagedSourceRead::Changes(_))
                                    }))
                            })?;
                        let selected = if resume {
                            let run = callback
                                .session_config()
                                .get_extension::<GraphRun>()
                                .ok_or_else(|| Projection::invalid("Graph entered context"))?;
                            let capture = run
                                .captured
                                .lock()
                                .map_err(|_| Projection::invalid("Graph entered lock"))?;
                            let capture = capture
                                .as_ref()
                                .ok_or_else(|| Projection::invalid("Graph entered header"))?;
                            if !Weak::ptr_eq(&capture.source, &Arc::downgrade(source)) {
                                return Err(Projection::invalid("Graph entered source"));
                            }
                            capture
                                .base_last
                                .and_then(|last| last.checked_add(1))
                                .filter(|_| !capture.expired)
                                .map(|first| {
                                    (
                                        capture.metadata.scope.identity.clone(),
                                        first.max(capture.metadata.first_cursor),
                                        capture.metadata.last_cursor,
                                    )
                                })
                                .filter(|(_, first, last)| first <= last)
                        } else {
                            None
                        };
                        let batches = match selected {
                            Some((identity, first, last)) => {
                                let batch = source.event_keys(&identity, (first, last), &memory)?;
                                vec![Self::encode(
                                    &identity,
                                    &batch,
                                    &memory,
                                    source.extraction_limits().input_bytes,
                                )?]
                            }
                            None => Vec::new(),
                        };
                        let data = sdk::Dataset {
                            name: "__graph_entered".into(),
                            batches,
                        };
                        let input = sdk::Input {
                            data,
                            revision: sdk::Revision {
                                owner: "araphor-analysis.GraphEntered".into(),
                                id: source.with_capture(|_, capture, _| {
                                    Ok(format!(
                                        "{}:{}:{image:?}",
                                        capture.instance().generation,
                                        capture.revision()
                                    ))
                                })?,
                                window: None,
                            },
                            coverage: sdk::Coverage {
                                state: sdk::CoverageState::Complete,
                                limits: Vec::new(),
                            },
                        };
                        drop((driver, header));
                        for batch in &input.data.batches {
                            source.memory().retain_input(batch, &memory)?;
                        }
                        memory.try_resize(input.metadata_bytes())?;
                        control.check().map_err(Projection::external)?;
                        Ok((input, memory))
                    })()
                    .map_err(|source| araphor_query::Error::Sql { source })
                })
                .await
        }
        .map(|result| result.map(Into::into))
        .boxed()
    }
}
