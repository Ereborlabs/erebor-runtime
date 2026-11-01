use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::Result;
use datafusion::datasource::source::DataSourceExec;
use datafusion::datasource::{provider_as_source, source_as_provider};
use datafusion::logical_expr::{Expr, LogicalPlan, TableType};
use datafusion::physical_plan::ExecutionPlan;

use super::{SourceData, SourceImage, SourceOrigin, SourceProvider};

impl SourceImage {
    pub(crate) fn plan(self, plan: &LogicalPlan) -> Result<LogicalPlan> {
        Ok(plan
            .clone()
            .transform_up_with_subqueries(|node| {
                let LogicalPlan::TableScan(mut scan) = node else {
                    return Ok(Transformed::no(node));
                };
                let table = source_as_provider(&scan.source)?;
                let table = if let Some(source) = table.as_any().downcast_ref::<SourceProvider>() {
                    if matches!(&source.origin, SourceOrigin::Durable(name)
                        if araphor_data::AnalysisTableRead::source_header(name))
                    {
                        return Ok(Transformed::no(LogicalPlan::TableScan(scan)));
                    }
                    source.image(self)?
                } else if let Some(source) = table.as_any().downcast_ref::<SourcePort>() {
                    source.image(self)
                } else if let Some(plan) = table.get_logical_plan() {
                    Arc::new(datafusion::catalog::view::ViewTable::new(
                        self.plan(&plan)?,
                        None,
                    )) as Arc<dyn TableProvider>
                } else if table.as_any().is::<datafusion::datasource::MemTable>()
                    || table
                        .as_any()
                        .is::<datafusion::datasource::empty::EmptyTable>()
                {
                    match self {
                        Self::After | Self::Inserted => table,
                        Self::Before | Self::Removed => Arc::new(
                            datafusion::datasource::empty::EmptyTable::new(table.schema()),
                        ),
                    }
                } else {
                    return datafusion::common::not_impl_err!(
                        "the source table has no change view"
                    );
                };
                scan.source = provider_as_source(table);
                Ok(Transformed::yes(LogicalPlan::TableScan(scan)))
            })?
            .data)
    }
}

pub trait PortSource: fmt::Debug + Send + Sync {
    /// Return true only when the physical plan supports DataFusion state reset.
    /// The plan must read each capture from the current TaskContext.
    fn reusable(&self) -> bool {
        false
    }

    fn plan(
        &self,
        slot: usize,
        inputs: &[Arc<dyn ExecutionPlan>],
        image: Option<SourceImage>,
    ) -> Result<Arc<dyn ExecutionPlan>>;
}

#[derive(Clone)]
pub struct SourcePort {
    pub(crate) slot: usize,
    role: String,
    schema: SchemaRef,
    inputs: Vec<LogicalPlan>,
    source: Arc<dyn PortSource>,
    image: Option<SourceImage>,
}

impl SourcePort {
    pub(crate) fn reusable(&self) -> bool {
        self.source.reusable()
    }

    pub(crate) fn inputs(&self) -> &[LogicalPlan] {
        &self.inputs
    }

    pub(crate) fn image(&self, image: SourceImage) -> Arc<dyn TableProvider> {
        Arc::new(Self {
            image: Some(image),
            ..self.clone()
        })
    }

    pub fn new(
        role: String,
        schema: SchemaRef,
        inputs: Vec<LogicalPlan>,
        source: Arc<dyn PortSource>,
    ) -> crate::Result<Self> {
        datafusion::common::DFSchema::try_from(schema.as_ref().clone())
            .map_err(|source| crate::Error::Sql { source })?;
        let options = datafusion::execution::context::SQLOptions::new()
            .with_allow_ddl(false)
            .with_allow_dml(false)
            .with_allow_statements(false);
        for input in &inputs {
            options
                .verify_plan(input)
                .map_err(|source| crate::Error::Sql { source })?;
        }
        Ok(Self {
            slot: SourceProvider::identity()?,
            role,
            schema,
            inputs,
            source,
            image: None,
        })
    }
}

impl fmt::Debug for SourcePort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourcePort")
            .field("slot", &self.slot)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl TableProvider for SourcePort {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        session: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let mut inputs = Vec::with_capacity(self.inputs.len() + 1);
        for input in &self.inputs {
            let plan = match self.image {
                Some(image) => image.plan(input)?,
                None => input.clone(),
            };
            let physical = session.create_physical_plan(&plan).await?;
            inputs.push(
                physical
                    .transform_up(|plan| {
                        let Some(scan) = plan.as_any().downcast_ref::<DataSourceExec>() else {
                            return Ok(Transformed::no(plan));
                        };
                        let Some(source) = scan.data_source().as_any().downcast_ref::<SourceData>()
                        else {
                            return Ok(Transformed::no(plan));
                        };
                        if source.owners.contains(&self.slot) {
                            return Ok(Transformed::no(plan));
                        }
                        let mut source = source.clone();
                        source.owners.push(self.slot);
                        let properties = plan.properties();
                        let bound: Arc<dyn ExecutionPlan> = Arc::new(
                            scan.clone()
                                .with_data_source(Arc::new(source))
                                .with_constraints(properties.eq_properties.constraints().clone())
                                .with_partitioning(properties.partitioning.clone()),
                        );
                        Ok(Transformed::yes(bound))
                    })?
                    .data,
            );
        }
        let reader = SourceProvider::port(self.slot, Arc::clone(&self.schema))
            .scan(session, projection, filters, limit)
            .await?;
        let schema = reader.schema();
        inputs.push(reader);
        let plan = self.source.plan(self.slot, &inputs, self.image)?;
        if plan.schema() != schema {
            return datafusion::common::internal_err!("bound source schema changed");
        }
        Ok(plan)
    }
}
