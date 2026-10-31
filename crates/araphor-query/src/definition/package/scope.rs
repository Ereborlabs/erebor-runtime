use std::collections::BTreeMap;
use std::sync::Arc;

use datafusion::arrow::datatypes::{DataType, FieldRef, SchemaRef};
use datafusion::catalog::TableProvider;
use datafusion::common::config::ConfigOptions;
use datafusion::common::file_options::file_type::FileType;
use datafusion::common::tree_node::Transformed;
use datafusion::common::{Result, TableReference};
use datafusion::datasource::provider_as_source;
use datafusion::logical_expr::planner::{
    ContextProvider, ExprPlanner, RelationPlanner, TypePlanner,
};
use datafusion::logical_expr::LogicalPlan;
use datafusion::logical_expr::{AggregateUDF, Expr, ScalarUDF, TableSource, WindowUDF};

pub(super) struct Scope<'a> {
    pub provider: &'a dyn ContextProvider,
    pub tables: &'a BTreeMap<String, Arc<dyn TableProvider>>,
}

impl Scope<'_> {
    pub(super) fn image_plan(
        plan: &LogicalPlan,
        image: crate::sources::SourceImage,
    ) -> Result<LogicalPlan> {
        Ok(plan
            .clone()
            .transform_up_with_subqueries(|node| {
                let LogicalPlan::TableScan(mut scan) = node else {
                    return Ok(Transformed::no(node));
                };
                let table = datafusion::datasource::source_as_provider(&scan.source)?;
                let table = if let Some(source) = table
                    .as_any()
                    .downcast_ref::<crate::sources::SourceProvider>()
                {
                    source.image(image)?
                } else if let Some(plan) = table.get_logical_plan() {
                    Arc::new(datafusion::catalog::view::ViewTable::new(
                        Self::image_plan(&plan, image)?,
                        None,
                    )) as Arc<dyn TableProvider>
                } else if table.as_any().is::<datafusion::datasource::MemTable>()
                    || table
                        .as_any()
                        .is::<datafusion::datasource::empty::EmptyTable>()
                {
                    match image {
                        crate::sources::SourceImage::After
                        | crate::sources::SourceImage::Inserted => table,
                        crate::sources::SourceImage::Before
                        | crate::sources::SourceImage::Removed => Arc::new(
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

impl ContextProvider for Scope<'_> {
    fn get_table_source(&self, name: TableReference) -> Result<Arc<dyn TableSource>> {
        let options = self.provider.options();
        let image = match name.schema() {
            Some("before") => Some(crate::sources::SourceImage::Before),
            Some("after") => Some(crate::sources::SourceImage::After),
            Some("inserted") => Some(crate::sources::SourceImage::Inserted),
            Some("removed") => Some(crate::sources::SourceImage::Removed),
            _ => None,
        };
        if name
            .catalog()
            .is_none_or(|catalog| catalog == options.catalog.default_catalog)
        {
            if let Some(image) = image {
                if let Some(table) = self.tables.get(&format!(
                    "{}.{}",
                    name.schema().unwrap_or_default(),
                    name.table()
                )) {
                    return Ok(provider_as_source(Arc::clone(table)));
                }
                if let Some(source) = self.tables.get(name.table()).and_then(|table| {
                    table
                        .as_any()
                        .downcast_ref::<crate::sources::SourceProvider>()
                }) {
                    return Ok(provider_as_source(source.image(image)?));
                }
            }
        }
        if name
            .catalog()
            .is_none_or(|catalog| catalog == options.catalog.default_catalog)
            && name
                .schema()
                .is_none_or(|schema| schema == options.catalog.default_schema)
        {
            if let Some(table) = self.tables.get(name.table()) {
                return Ok(provider_as_source(Arc::clone(table)));
            }
        }
        datafusion::common::plan_err!("table '{name}' not found")
    }
    fn get_file_type(&self, extension: &str) -> Result<Arc<dyn FileType>> {
        self.provider.get_file_type(extension)
    }
    fn get_table_function_source(
        &self,
        name: &str,
        arguments: Vec<Expr>,
    ) -> Result<Arc<dyn TableSource>> {
        self.provider.get_table_function_source(name, arguments)
    }
    fn create_cte_work_table(&self, name: &str, schema: SchemaRef) -> Result<Arc<dyn TableSource>> {
        self.provider.create_cte_work_table(name, schema)
    }
    fn get_expr_planners(&self) -> &[Arc<dyn ExprPlanner>] {
        self.provider.get_expr_planners()
    }
    fn get_relation_planners(&self) -> &[Arc<dyn RelationPlanner>] {
        self.provider.get_relation_planners()
    }
    fn get_type_planner(&self) -> Option<Arc<dyn TypePlanner>> {
        self.provider.get_type_planner()
    }
    fn get_function_meta(&self, name: &str) -> Option<Arc<ScalarUDF>> {
        self.provider.get_function_meta(name)
    }
    fn get_aggregate_meta(&self, name: &str) -> Option<Arc<AggregateUDF>> {
        self.provider.get_aggregate_meta(name)
    }
    fn get_window_meta(&self, name: &str) -> Option<Arc<WindowUDF>> {
        self.provider.get_window_meta(name)
    }
    fn get_variable_type(&self, names: &[String]) -> Option<DataType> {
        self.provider.get_variable_type(names)
    }
    fn get_variable_field(&self, names: &[String]) -> Option<FieldRef> {
        self.provider.get_variable_field(names)
    }
    fn options(&self) -> &ConfigOptions {
        self.provider.options()
    }
    fn udf_names(&self) -> Vec<String> {
        self.provider.udf_names()
    }
    fn udaf_names(&self) -> Vec<String> {
        self.provider.udaf_names()
    }
    fn udwf_names(&self) -> Vec<String> {
        self.provider.udwf_names()
    }
}
