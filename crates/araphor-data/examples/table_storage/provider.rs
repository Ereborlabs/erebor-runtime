use std::{
    collections::BTreeSet,
    fmt,
    sync::{Arc, Mutex, RwLock},
};

use araphor_data::analysis::native::benchmark::columnar::{Counts, Header, Owner, Page, View};
use async_trait::async_trait;
use datafusion::{
    arrow::{
        array::{Array, ArrayRef, BooleanArray, UInt32Array, UInt64Array},
        compute::filter_record_batch,
        datatypes::SchemaRef,
    },
    catalog::{Session, TableProvider},
    common::{
        pruning::PruningStatistics, tree_node::TreeNodeRecursion, Column, DFSchema,
        DataFusionError, Result, Statistics,
    },
    datasource::source::{DataSource, DataSourceExec},
    execution::TaskContext,
    logical_expr::{utils::conjunction, Expr, TableProviderFilterPushDown, TableType},
    physical_expr::{projection::ProjectionExprs, EquivalenceProperties, PhysicalExpr},
    physical_optimizer::pruning::{PruningPredicate, PruningPredicateBuilder},
    physical_plan::{
        stream::RecordBatchStreamAdapter, DisplayFormatType, ExecutionPlan, Partitioning,
        SendableRecordBatchStream,
    },
};
use futures_util::{stream, StreamExt};

pub struct Binding {
    pub table: Arc<Owner>,
    pub view: View,
    pub only: Option<Vec<u8>>,
}

pub struct Provider {
    pub binding: Arc<RwLock<Binding>>,
    pub counts: Arc<Mutex<Counts>>,
    pub schema: SchemaRef,
}

impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("TableBenchmark")
    }
}

#[async_trait]
impl TableProvider for Provider {
    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }
    fn table_type(&self) -> TableType {
        TableType::Base
    }
    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> Result<Vec<TableProviderFilterPushDown>> {
        Ok(vec![TableProviderFilterPushDown::Exact; filters.len()])
    }
    async fn scan(
        &self,
        session: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        _limit: Option<usize>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let indices = projection
            .cloned()
            .unwrap_or_else(|| (0..self.schema.fields().len()).collect());
        let columns = filters
            .iter()
            .flat_map(|expr| expr.column_refs().into_iter())
            .map(|column| self.schema.index_of(&column.name))
            .collect::<std::result::Result<BTreeSet<_>, _>>()?
            .into_iter()
            .collect();
        let predicate = conjunction(filters.iter().cloned())
            .map(|expr| {
                session.create_physical_expr(expr, &DFSchema::try_from(Arc::clone(&self.schema))?)
            })
            .transpose()?;
        let pruning = predicate.as_ref().and_then(|expr| {
            PruningPredicateBuilder::new()
                .with_file_schema(Arc::clone(&self.schema))
                .build(Arc::clone(expr))
        });
        let schema = Arc::new(self.schema.project(&indices)?);
        Ok(DataSourceExec::from_data_source(Source {
            binding: Arc::clone(&self.binding),
            counts: Arc::clone(&self.counts),
            schema,
            indices,
            columns,
            predicate,
            pruning,
        }))
    }
}

struct Metadata<'a>(&'a Header);
impl PruningStatistics for Metadata<'_> {
    fn num_containers(&self) -> usize {
        1
    }
    fn min_values(&self, column: &Column) -> Option<ArrayRef> {
        (column.name == "cpu_id")
            .then(|| {
                self.0
                    .cpu
                    .map(|cpu| Arc::new(UInt32Array::from(vec![cpu])) as ArrayRef)
            })
            .flatten()
    }
    fn max_values(&self, column: &Column) -> Option<ArrayRef> {
        self.min_values(column)
    }
    fn null_counts(&self, column: &Column) -> Option<ArrayRef> {
        (column.name == "cpu_id" && self.0.cpu.is_some())
            .then(|| Arc::new(UInt64Array::from(vec![0])) as ArrayRef)
    }
    fn row_counts(&self) -> Option<ArrayRef> {
        Some(Arc::new(UInt64Array::from(vec![self.0.rows as u64])))
    }
    fn contained(
        &self,
        _column: &Column,
        _values: &std::collections::HashSet<datafusion::common::ScalarValue>,
    ) -> Option<BooleanArray> {
        None
    }
}

struct Source {
    binding: Arc<RwLock<Binding>>,
    counts: Arc<Mutex<Counts>>,
    schema: SchemaRef,
    indices: Vec<usize>,
    columns: Vec<usize>,
    predicate: Option<Arc<dyn PhysicalExpr>>,
    pruning: Option<Arc<PruningPredicate>>,
}

impl fmt::Debug for Source {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("TableBenchmarkSource")
    }
}

impl DataSource for Source {
    fn open(
        &self,
        partition: usize,
        _context: Arc<TaskContext>,
    ) -> Result<SendableRecordBatchStream> {
        assert_eq!(partition, 0);
        let binding = self.binding.read().unwrap();
        let owner = Arc::clone(&binding.table);
        let view = binding.view.clone();
        let only = binding.only.clone();
        drop(binding);
        if matches!(owner.as_ref(), Owner::Production(_)) {
            let requested = self
                .indices
                .iter()
                .chain(&self.columns)
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let mut counts = Counts::default();
            let batches = owner
                .capture(&view, only.as_deref(), &requested, &mut counts)
                .map_err(DataFusionError::External)?;
            self.counts.lock().unwrap().add(counts);
            let predicate = self.predicate.clone();
            let indices = self.indices.clone();
            let schema = Arc::clone(&self.schema);
            let full = owner.schema();
            let stream = stream::iter(batches).map(
                move |batch| -> Result<datafusion::arrow::record_batch::RecordBatch> {
                    let columns = (0..full.fields().len())
                        .map(|index| {
                            requested
                                .iter()
                                .position(|&selected| selected == index)
                                .map(|slot| Arc::clone(batch.column(slot)))
                                .unwrap_or_else(|| {
                                    datafusion::arrow::array::new_null_array(
                                        full.field(index).data_type(),
                                        batch.num_rows(),
                                    )
                                })
                        })
                        .collect::<Vec<_>>();
                    let batch = datafusion::arrow::record_batch::RecordBatch::try_new(
                        Arc::new(datafusion::arrow::datatypes::Schema::new(
                            full.fields()
                                .iter()
                                .map(|field| field.as_ref().clone().with_nullable(true))
                                .collect::<Vec<_>>(),
                        )),
                        columns,
                    )?;
                    let mask = predicate
                        .as_ref()
                        .map(|predicate| predicate.evaluate(&batch)?.into_array(batch.num_rows()))
                        .transpose()?;
                    let output = datafusion::arrow::record_batch::RecordBatch::try_new(
                        Arc::clone(&schema),
                        indices
                            .iter()
                            .map(|&index| Arc::clone(batch.column(index)))
                            .collect(),
                    )?;
                    if let Some(mask) = mask {
                        let mask =
                            mask.as_any()
                                .downcast_ref::<BooleanArray>()
                                .ok_or_else(|| {
                                    DataFusionError::Execution(
                                        "nonboolean production predicate".into(),
                                    )
                                })?;
                        Ok(filter_record_batch(&output, mask)?)
                    } else {
                        Ok(output)
                    }
                },
            );
            return Ok(Box::pin(RecordBatchStreamAdapter::new(
                Arc::clone(&self.schema),
                stream,
            )));
        }
        let (Owner::Candidate(table), View::Candidate(view)) = (owner.as_ref(), view) else {
            return Err(DataFusionError::Execution("source view mismatch".into()));
        };
        let table = Arc::clone(table);
        let mut counts = Counts::default();
        let headers = table
            .headers(&view, only.as_deref(), &mut counts)
            .map_err(DataFusionError::External)?;
        self.counts.lock().unwrap().add(counts);
        let predicate = self.predicate.clone();
        let pruning = self.pruning.clone();
        let columns = self.columns.clone();
        let indices = self.indices.clone();
        let counts = Arc::clone(&self.counts);
        let stream = stream::iter(headers).filter_map(move |(key, header)| {
            let result = (|| -> Result<Option<datafusion::arrow::record_batch::RecordBatch>> {
                if let Some(pruning) = &pruning {
                    if !pruning.prune(&Metadata(&header))?[0] {
                        return Ok(None);
                    }
                }
                let mut page = Page::new(&table, &view, &key, &header);
                let mask = if let Some(predicate) = &predicate {
                    let batch = page
                        .predicate(&columns)
                        .map_err(DataFusionError::External)?;
                    let value = predicate.evaluate(&batch)?.into_array(header.rows)?;
                    let mask = value
                        .as_any()
                        .downcast_ref::<BooleanArray>()
                        .ok_or_else(|| DataFusionError::Execution("nonboolean predicate".into()))?
                        .clone();
                    if mask.true_count() == 0 {
                        counts.lock().unwrap().add(page.counts);
                        return Ok(None);
                    }
                    Some(mask)
                } else {
                    None
                };
                let batch = page.read(&indices).map_err(DataFusionError::External)?;
                counts.lock().unwrap().add(page.counts);
                Ok(Some(if let Some(mask) = mask {
                    filter_record_batch(&batch, &mask)?
                } else {
                    batch
                }))
            })();
            std::future::ready(match result {
                Ok(Some(batch)) => Some(Ok(batch)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            })
        });
        Ok(Box::pin(RecordBatchStreamAdapter::new(
            Arc::clone(&self.schema),
            stream,
        )))
    }
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("TableBenchmarkSource")
    }
    fn output_partitioning(&self) -> Partitioning {
        Partitioning::UnknownPartitioning(1)
    }
    fn eq_properties(&self) -> EquivalenceProperties {
        EquivalenceProperties::new(Arc::clone(&self.schema))
    }
    fn partition_statistics(&self, _partition: Option<usize>) -> Result<Arc<Statistics>> {
        Ok(Arc::new(Statistics::new_unknown(&self.schema)))
    }
    fn with_fetch(&self, _limit: Option<usize>) -> Option<Arc<dyn DataSource>> {
        None
    }
    fn fetch(&self) -> Option<usize> {
        None
    }
    fn try_swapping_with_projection(
        &self,
        _projection: &ProjectionExprs,
    ) -> Result<Option<Arc<dyn DataSource>>> {
        Ok(None)
    }
    fn apply_expressions(
        &self,
        visitor: &mut dyn FnMut(&Arc<dyn PhysicalExpr>) -> Result<TreeNodeRecursion>,
    ) -> Result<TreeNodeRecursion> {
        datafusion::physical_plan::apply_expression_roots(self.predicate.iter(), visitor)
    }
}
