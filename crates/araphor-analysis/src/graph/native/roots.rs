use std::sync::Arc;

use araphor_analysis_builtins::graph::Unit;
use araphor_analysis_sdk as sdk;
use araphor_query::sources::{PortRead, PortSource, SourceImage, SourceSnapshot};
use datafusion::common::Result;
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{LogicalPlan, LogicalPlanBuilder};
use futures_util::{future::BoxFuture, FutureExt};

use super::{GraphRun, Projection};

pub(super) struct RootPort {
    pub(super) owner: Arc<Projection>,
}

impl std::fmt::Debug for RootPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GraphRoots")
    }
}

impl PortSource for RootPort {
    fn reusable(&self) -> bool {
        true
    }
    fn snapshot_bound(&self) -> bool {
        true
    }
    fn key_columns(&self) -> &[(usize, usize)] {
        &[(0, 0)]
    }
    fn image_keys(&self, image: SourceImage) -> &[(usize, usize)] {
        if image == SourceImage::Before {
            &[]
        } else {
            self.key_columns()
        }
    }

    fn driver(&self, image: SourceImage, _driver: &LogicalPlan) -> Result<Option<LogicalPlan>> {
        match image {
            SourceImage::Before => LogicalPlanBuilder::empty(true).build().map(Some),
            SourceImage::After => Ok(None),
            _ => datafusion::common::not_impl_err!("Graph root delta image"),
        }
    }

    fn header(&self, image: SourceImage, header: &LogicalPlan) -> Result<Option<LogicalPlan>> {
        match image {
            SourceImage::Before => LogicalPlanBuilder::empty(true).build().map(Some),
            SourceImage::After => Ok(Some(header.clone())),
            _ => datafusion::common::not_impl_err!("Graph root delta image"),
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
            let memory = source
                .memory()
                .prepare_input(source.extraction_limits().input_bytes)?;
            let owner = Arc::clone(&self.owner);
            let callback = Arc::clone(&context);
            source
                .blocking(&context, (), move |source, control| {
                    (|| -> Result<_> {
                        let mut limits = source.extraction_limits();
                        Projection::read_limit(source, &memory, &mut limits);
                        let before = image == Some(SourceImage::Before);
                        let (records, restricted, base) = if before {
                            source.with_capture(|store, capture, reference| {
                                let base = reference
                                    .and_then(|reference| reference.receipt())
                                    .and_then(|receipt| receipt.graph.as_ref())
                                    .ok_or_else(|| {
                                        araphor_data::PackageErrorCodeV1::Incomplete
                                            .error("Graph before owning result")
                                    })?;
                                let (summary, _, _) = store.graph_frozen_facts(
                                    capture,
                                    reference,
                                    base,
                                    &Default::default(),
                                    limits,
                                    control,
                                )?;
                                let count = summary.restricted_count.ok_or_else(|| {
                                    araphor_data::PackageErrorCodeV1::Incomplete
                                        .error("Graph root disclosure")
                                })?;
                                let records = if summary.expired {
                                    Vec::new()
                                } else {
                                    store.graph_record_keys(
                                        capture, reference, base, limits, control,
                                    )?
                                };
                                Ok((records, count != 0, base.commit_revision))
                            })?
                        } else {
                            let run = GraphRun::from_context(&callback, &owner)?;
                            let capture = run
                                .captured
                                .lock()
                                .unwrap_or_else(|error| error.into_inner());
                            let capture = capture
                                .as_ref()
                                .ok_or_else(|| Projection::invalid("Graph root header"))?;
                            let count = capture
                                .restricted
                                .ok_or_else(|| Projection::invalid("Graph root disclosure"))?;
                            let records = if capture.expired {
                                Vec::new()
                            } else {
                                Unit::decode_affected(&sdk::Dataset {
                                    name: "affected".into(),
                                    batches: driver.clone(),
                                })
                                .map_err(Projection::external)?
                            };
                            (
                                records,
                                count != 0,
                                capture.base.as_ref().map_or(0, |base| base.commit_revision),
                            )
                        };
                        let rows = records
                            .into_iter()
                            .map(|record| Unit {
                                record,
                                window_ns: araphor_data::GRAPH_WINDOW_NS,
                                restricted,
                            })
                            .collect::<Vec<_>>();
                        let mut data = Unit::encode(&rows).map_err(Projection::external)?;
                        data.name = "__graph_roots".into();
                        let input = sdk::Input {
                            data,
                            revision: sdk::Revision {
                                owner: "araphor-analysis.GraphRoots".into(),
                                id: source.with_capture(|_, capture, _| {
                                    Ok(format!(
                                        "{}:{}:{base}:{image:?}",
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
                        drop(rows);
                        drop(driver);
                        drop(header);
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
