use std::collections::BTreeMap;
use std::sync::Arc;

use datafusion::arrow::datatypes::{DataType, FieldRef, SchemaRef};
use datafusion::catalog::TableProvider;
use datafusion::common::config::ConfigOptions;
use datafusion::common::file_options::file_type::FileType;
use datafusion::common::{Result, TableReference};
use datafusion::datasource::provider_as_source;
use datafusion::logical_expr::planner::{
    ContextProvider, ExprPlanner, RelationPlanner, TypePlanner,
};
use datafusion::logical_expr::{AggregateUDF, Expr, ScalarUDF, TableSource, WindowUDF};

pub(super) struct Scope<'a> {
    pub provider: &'a dyn ContextProvider,
    pub tables: &'a BTreeMap<String, Arc<dyn TableProvider>>,
    pub sources: &'a BTreeMap<String, Arc<dyn TableProvider>>,
}

impl ContextProvider for Scope<'_> {
    fn get_table_source(&self, name: TableReference) -> Result<Arc<dyn TableSource>> {
        let options = self.provider.options();
        if name
            .catalog()
            .is_none_or(|catalog| catalog == options.catalog.default_catalog)
            && name
                .schema()
                .is_none_or(|schema| schema == options.catalog.default_schema)
        {
            if let Some(table) = self
                .tables
                .get(name.table())
                .or_else(|| self.sources.get(name.table()))
            {
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
