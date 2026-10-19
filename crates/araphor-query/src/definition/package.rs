use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_discovery_definition::{ImagePin, PackageCall as DefinitionCall};
use araphor_package::{
    ModelRef, PackageBundleV1, PackageImplementationV1, PackageRefV1, SqlModelV1,
};
use datafusion::catalog::TableProvider;
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::common::{DFSchema, DataFusionError};
use datafusion::datasource::{MemTable, ViewTable};
use datafusion::execution::SessionState;
use datafusion::logical_expr::LogicalPlan;
use snafu::ResultExt as _;

use super::PackageCall;
use crate::execution::{Engine, Session};
use crate::follow::Window;
use crate::inputs::Inputs;
use crate::sources::{SourceOrigin, SourceProvider, SourceSnapshot};
use crate::{InvalidSnafu, Result, SqlSnafu};

pub(super) struct PackagePlanner<'a> {
    engine: &'a Engine,
    bundle: &'a PackageBundleV1,
    pin: ImagePin,
}

pub(super) struct CallPlan {
    pub call: PackageCall,
    pub sql: Option<LogicalPlan>,
}

struct ExportPlans {
    calls: BTreeMap<String, PackageCall>,
    sql: BTreeMap<String, LogicalPlan>,
}

impl<'a> PackagePlanner<'a> {
    pub(super) fn new(engine: &'a Engine, bundle: &'a PackageBundleV1, pin: ImagePin) -> Self {
        Self {
            engine,
            bundle,
            pin,
        }
    }

    pub(super) async fn admit(&self, call: &DefinitionCall) -> Result<CallPlan> {
        let root = ModelRef {
            package: call.image.clone(),
            export: call.export.clone(),
        };
        let order = self
            .bundle
            .order_for(&call.image, Some(&call.export))
            .map_err(araphor_data::Error::from)?;
        let mut needed = BTreeSet::from([root.clone()]);
        for key in order.iter().rev() {
            if !needed.contains(key) {
                continue;
            }
            let artifact = self
                .bundle
                .artifact(&key.package)
                .map_err(araphor_data::Error::from)?;
            let model = artifact
                .descriptor
                .exports
                .iter()
                .find(|model| model.name == key.export)
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "package export",
                    }
                    .build()
                })?;
            for (port, dependency) in model.dependencies() {
                if key == &root && call.inputs.contains_key(&port.name) {
                    continue;
                }
                needed.insert(ModelRef {
                    package: PackageRefV1 {
                        package_id: dependency.package.clone(),
                        revision: dependency.revision.clone(),
                    },
                    export: dependency.export.clone(),
                });
            }
        }
        let mut exports = BTreeMap::<ModelRef, ExportPlans>::new();
        for key in order.into_iter().filter(|key| needed.contains(key)) {
            let artifact = self
                .bundle
                .artifact(&key.package)
                .map_err(araphor_data::Error::from)?;
            let model = artifact
                .descriptor
                .exports
                .iter()
                .find(|model| model.name == key.export)
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "package export",
                    }
                    .build()
                })?;
            let selected = artifact
                .implementation(&key.export)
                .map_err(araphor_data::Error::from)?;
            let effective = if key == root {
                call.clone()
            } else {
                DefinitionCall {
                    image: key.package.clone(),
                    export: key.export.clone(),
                    inputs: BTreeMap::new(),
                    parameters: serde_json::json!({}),
                    window: None,
                    output: None,
                }
            };
            if effective
                .inputs
                .keys()
                .any(|name| !model.inputs.iter().any(|input| input.port.name == *name))
            {
                return InvalidSnafu {
                    field: "undeclared package input",
                }
                .fail();
            }
            let parameters =
                araphor_data::decode_parameters(&model.parameters, Some(&effective.parameters))?;
            let inputs = self.inputs(model, &effective, &exports).await?;
            let sql = match selected {
                PackageImplementationV1::Sql { program, .. } => {
                    self.sql(model, program, &inputs, parameters).await?
                }
                _ => BTreeMap::new(),
            };
            let identity = serde_json::to_string(&(&effective, &self.pin, &artifact.descriptor))
                .map_err(|source| crate::Error::Sql {
                    source: DataFusionError::External(Box::new(source)),
                })?;
            let descriptor = Arc::new(artifact.descriptor.clone());
            let mut calls = BTreeMap::new();
            for output in &model.outputs {
                calls.insert(
                    output.name.clone(),
                    PackageCall {
                        call: effective.clone(),
                        pin: self.pin.clone(),
                        descriptor: Arc::clone(&descriptor),
                        output: output.name.clone(),
                        identity: format!("{identity}:{}", output.name),
                        children: inputs.clone(),
                        schema: Arc::new(
                            DFSchema::try_from(output.schema.clone()).context(SqlSnafu)?,
                        ),
                    },
                );
            }
            exports.insert(key, ExportPlans { calls, sql });
        }
        let mut export = exports.remove(&root).ok_or_else(|| {
            InvalidSnafu {
                field: "package export",
            }
            .build()
        })?;
        let output = match &call.output {
            Some(output) => output.clone(),
            None if export.calls.len() == 1 => {
                export.calls.keys().next().cloned().ok_or_else(|| {
                    InvalidSnafu {
                        field: "package output",
                    }
                    .build()
                })?
            }
            None => {
                return InvalidSnafu {
                    field: "package output selector",
                }
                .fail()
            }
        };
        let sql = export.sql.remove(&output);
        let sql = match sql {
            Some(plan) if !Self::contains_call(&plan)? => Some(plan),
            _ => None,
        };
        Ok(CallPlan {
            call: export.calls.remove(&output).ok_or_else(|| {
                InvalidSnafu {
                    field: "package output",
                }
                .build()
            })?,
            sql,
        })
    }

    async fn inputs(
        &self,
        model: &sdk::Model,
        call: &DefinitionCall,
        exports: &BTreeMap<ModelRef, ExportPlans>,
    ) -> Result<Vec<LogicalPlan>> {
        if model.inputs.is_empty() && call.window.is_some() {
            return InvalidSnafu {
                field: "package window input",
            }
            .fail();
        }
        let mut tables = SourceSnapshot::providers();
        for (slot, input) in model.inputs.iter().enumerate() {
            let schema = Session::indexed_schema(&input.port.schema)?;
            tables
                .entry(input.port.name.clone())
                .or_insert_with(|| SourceProvider::port(slot, schema));
        }
        let state = self.engine.catalog(tables.clone())?;
        let mut pending = Vec::new();
        for (slot, input) in model.inputs.iter().enumerate() {
            if let Some((plan, dependencies)) = Self::named(input, call, &tables)? {
                pending.push((slot, plan, dependencies));
                continue;
            }
            let sql = match Self::binding(input, call) {
                Some(sql) => sql,
                None => {
                    let sdk::InputSource::Table(sdk::TableRef::Output(reference)) = &input.source
                    else {
                        return InvalidSnafu {
                            field: "package input source",
                        }
                        .fail();
                    };
                    let key = ModelRef {
                        package: PackageRefV1 {
                            package_id: reference.package.clone(),
                            revision: reference.revision.clone(),
                        },
                        export: reference.export.clone(),
                    };
                    let export = exports.get(&key).ok_or_else(|| {
                        InvalidSnafu {
                            field: "package dependency",
                        }
                        .build()
                    })?;
                    let plan = export
                        .sql
                        .get(&reference.output)
                        .cloned()
                        .or_else(|| export.calls.get(&reference.output).map(PackageCall::plan))
                        .ok_or_else(|| {
                            InvalidSnafu {
                                field: "dependency output",
                            }
                            .build()
                        })?;
                    pending.push((slot, plan, BTreeSet::new()));
                    continue;
                }
            };
            let statement = self.engine.limits().parser.parse(&sql)?;
            let planner = crate::planner::Planner::new(&state);
            let dependencies = planner
                .sources(&statement)
                .await?
                .into_iter()
                .filter_map(|origin| {
                    if let SourceOrigin::Port(slot) = origin {
                        Some(slot)
                    } else {
                        None
                    }
                })
                .collect();
            let plan = planner.build(statement, Vec::new()).await?;
            pending.push((slot, plan, dependencies));
        }
        let mut plans = BTreeMap::<usize, LogicalPlan>::new();
        while !pending.is_empty() {
            let next = pending
                .iter()
                .position(|(_, _, dependencies)| {
                    dependencies.iter().all(|slot| plans.contains_key(slot))
                })
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "package input cycle",
                    }
                    .build()
                })?;
            let (slot, plan, dependencies) = pending.remove(next);
            let mut bindings = tables.clone();
            for dependency in &dependencies {
                let name = &model.inputs[*dependency].port.name;
                bindings.insert(
                    name.clone(),
                    Arc::new(ViewTable::new(
                        self.indexed(name, &plans[dependency]).await?,
                        None,
                    )),
                );
            }
            let input = &model.inputs[slot];
            let named = if dependencies.is_empty() {
                None
            } else {
                Self::named(input, call, &bindings)?.map(|(plan, _)| plan)
            };
            let state = self.engine.catalog(bindings)?;
            let sql = if dependencies.is_empty() {
                None
            } else {
                Self::binding(input, call)
            };
            let mut plan = match (named, sql) {
                (Some(plan), _) => plan,
                (_, Some(sql)) => {
                    crate::planner::Planner::new(&state)
                        .build(self.engine.limits().parser.parse(&sql)?, Vec::new())
                        .await?
                }
                _ => plan,
            };
            if let Some(window) = &call.window {
                plan = self.window(&state, plan, window)?;
            }
            Window::from_plan(&plan)?;
            plan = state.optimize(&plan).context(SqlSnafu)?;
            Self::schema(&plan, &input.port.schema)?;
            if !Self::contains_call(&plan)? {
                state
                    .query_planner()
                    .create_physical_plan(&plan, &state)
                    .await
                    .context(SqlSnafu)?;
            }
            plans.insert(slot, plan);
        }
        Ok(plans.into_values().collect())
    }

    fn window(&self, state: &SessionState, plan: LogicalPlan, window: &str) -> Result<LogicalPlan> {
        use datafusion::logical_expr::{Expr, LogicalPlanBuilder, Projection};

        self.engine
            .limits()
            .parser
            .parse(&format!("SELECT ({window})"))?;
        let filter = |input: LogicalPlan| -> Result<LogicalPlan> {
            let expression = state
                .create_logical_expr(window, input.schema())
                .context(SqlSnafu)?;
            let plan = LogicalPlanBuilder::from(input)
                .filter(expression)
                .and_then(LogicalPlanBuilder::build)
                .context(SqlSnafu)?;
            Window::from_plan(&plan)?;
            Ok(plan)
        };
        let error = match filter(plan.clone()) {
            Ok(plan) => return Ok(plan),
            Err(error) => error,
        };
        match plan {
            LogicalPlan::Projection(projection) => {
                let input = filter((*projection.input).clone())?;
                Ok(LogicalPlan::Projection(
                    Projection::try_new(projection.expr, Arc::new(input)).context(SqlSnafu)?,
                ))
            }
            LogicalPlan::TableScan(scan) if scan.projection.is_some() && scan.fetch.is_none() => {
                let columns = scan
                    .projected_schema
                    .columns()
                    .into_iter()
                    .map(Expr::Column)
                    .collect::<Vec<_>>();
                let input = LogicalPlanBuilder::scan_with_filters(
                    scan.table_name,
                    scan.source,
                    None,
                    scan.filters,
                )
                .and_then(LogicalPlanBuilder::build)
                .context(SqlSnafu)?;
                LogicalPlanBuilder::from(filter(input)?)
                    .project(columns)
                    .and_then(LogicalPlanBuilder::build)
                    .context(SqlSnafu)
            }
            _ => Err(error),
        }
    }

    async fn sql(
        &self,
        model: &sdk::Model,
        program: &SqlModelV1,
        inputs: &[LogicalPlan],
        parameters: Option<sdk::RecordBatch>,
    ) -> Result<BTreeMap<String, LogicalPlan>> {
        let mut tables = BTreeMap::<String, Arc<dyn TableProvider>>::new();
        for (input, plan) in model.inputs.iter().zip(inputs) {
            let plan = self.indexed(&input.port.name, plan).await?;
            tables.insert(
                input.port.name.clone(),
                Arc::new(ViewTable::new(plan, None)),
            );
        }
        if let Some(parameters) = parameters {
            if tables
                .insert(
                    "parameters".into(),
                    Arc::new(
                        MemTable::try_new(parameters.schema(), vec![vec![parameters]])
                            .context(SqlSnafu)?,
                    ),
                )
                .is_some()
            {
                return InvalidSnafu {
                    field: "package relation collision",
                }
                .fail();
            }
        }
        if let Some(checkpoint) = &model.checkpoint {
            for (slot, port) in checkpoint.datasets.iter().enumerate() {
                let name = format!("prior_{}", port.name);
                if tables
                    .insert(
                        name,
                        SourceProvider::port(
                            model.inputs.len() + slot,
                            Session::indexed_schema(&port.schema)?,
                        ),
                    )
                    .is_some()
                {
                    return InvalidSnafu {
                        field: "package relation collision",
                    }
                    .fail();
                }
            }
        }
        let state = self.engine.catalog(tables.clone())?;
        let outputs = self
            .datasets(&state, &model.outputs, &program.outputs)
            .await?;
        for (name, plan) in &outputs {
            if tables
                .insert(
                    format!("output_{name}"),
                    Arc::new(ViewTable::new(plan.clone(), None)),
                )
                .is_some()
            {
                return InvalidSnafu {
                    field: "package relation collision",
                }
                .fail();
            }
        }
        let state = self.engine.catalog(tables)?;
        self.datasets(
            &state,
            model
                .checkpoint
                .as_ref()
                .map_or(&[], |spec| spec.datasets.as_slice()),
            &program.checkpoint,
        )
        .await?;
        if let Some(sql) = &program.evidence {
            let plan = self.engine.definition_sql(&state, sql).await?;
            Self::schema(
                &plan,
                &sdk::Schema::new(vec![
                    sdk::Field::new("output_dataset", sdk::DataType::Utf8, false),
                    sdk::Field::new("output_row", sdk::DataType::UInt64, false),
                    sdk::Field::new("input_dataset", sdk::DataType::Utf8, false),
                    sdk::Field::new("input_row", sdk::DataType::UInt64, false),
                ]),
            )?;
        }
        for reason in &program.reasons {
            if !model.outputs.iter().any(|port| port.name == reason.output) {
                return InvalidSnafu {
                    field: "package reason output",
                }
                .fail();
            }
            let spec = model
                .reasons
                .iter()
                .find(|spec| spec.code == reason.code)
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "package reason code",
                    }
                    .build()
                })?;
            if spec.details.field_with_name("output_row").is_ok() {
                return InvalidSnafu {
                    field: "package reason row column",
                }
                .fail();
            }
            let schema = sdk::Schema::new(
                std::iter::once(sdk::Field::new("output_row", sdk::DataType::UInt64, false))
                    .chain(
                        spec.details
                            .fields()
                            .iter()
                            .map(|field| field.as_ref().clone()),
                    )
                    .collect::<Vec<_>>(),
            );
            Self::schema(
                &self.engine.definition_sql(&state, &reason.sql).await?,
                &schema,
            )?;
        }
        Ok(outputs)
    }

    async fn datasets(
        &self,
        state: &SessionState,
        ports: &[sdk::Port],
        queries: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, LogicalPlan>> {
        if ports.len() != queries.len() {
            return InvalidSnafu {
                field: "package SQL datasets",
            }
            .fail();
        }
        let mut plans = BTreeMap::new();
        for port in ports {
            let sql = queries.get(&port.name).ok_or_else(|| {
                InvalidSnafu {
                    field: "package SQL dataset",
                }
                .build()
            })?;
            let plan = self.engine.definition_sql(state, sql).await?;
            Self::schema(&plan, &port.schema)?;
            if !Self::contains_call(&plan)? {
                state
                    .query_planner()
                    .create_physical_plan(&plan, state)
                    .await
                    .context(SqlSnafu)?;
            }
            plans.insert(port.name.clone(), plan);
        }
        Ok(plans)
    }

    fn schema(plan: &LogicalPlan, schema: &sdk::Schema) -> Result<()> {
        sdk::Dataset::normalize_batch(
            sdk::RecordBatch::new_empty(Arc::clone(plan.schema().inner())),
            Arc::new(schema.clone()),
        )?;
        Ok(())
    }

    fn binding(input: &sdk::InputPort, call: &DefinitionCall) -> Option<String> {
        call.inputs
            .get(&input.port.name)
            .cloned()
            .or_else(|| match &input.source {
                sdk::InputSource::Query(sql) => Some(sql.clone()),
                _ => None,
            })
    }

    pub(super) fn named(
        input: &sdk::InputPort,
        call: &DefinitionCall,
        tables: &BTreeMap<String, Arc<dyn TableProvider>>,
    ) -> Result<Option<(LogicalPlan, BTreeSet<usize>)>> {
        if call.inputs.contains_key(&input.port.name) {
            return Ok(None);
        }
        let sdk::InputSource::Table(sdk::TableRef::Named(name)) = &input.source else {
            return Ok(None);
        };
        let provider = tables.get(name).cloned().ok_or_else(|| {
            InvalidSnafu {
                field: "package input table",
            }
            .build()
        })?;
        let dependencies = provider
            .as_any()
            .downcast_ref::<SourceProvider>()
            .and_then(|source| {
                if let SourceOrigin::Port(slot) = source.origin {
                    Some(slot)
                } else {
                    None
                }
            })
            .into_iter()
            .collect();
        Ok(Some((
            Inputs::scan(name, provider, &input.port.schema)?,
            dependencies,
        )))
    }

    async fn indexed(&self, name: &str, plan: &LogicalPlan) -> Result<LogicalPlan> {
        let mut tables = BTreeMap::<String, Arc<dyn TableProvider>>::new();
        tables.insert(
            name.to_owned(),
            Arc::new(ViewTable::new(plan.clone(), None)),
        );
        let state = self.engine.catalog(tables)?;
        let sql = format!(
            "SELECT *, CAST(row_number() OVER () - 1 AS BIGINT UNSIGNED) AS __row_index FROM {}",
            Self::quote(name)
        );
        self.engine.definition_sql(&state, &sql).await
    }

    fn contains_call(plan: &LogicalPlan) -> Result<bool> {
        let mut found = false;
        plan.apply_with_subqueries(|node| {
            if matches!(node, LogicalPlan::Extension(extension) if extension.node.as_any().is::<PackageCall>()) {
                found = true;
            }
            Ok(TreeNodeRecursion::Continue)
        }).context(SqlSnafu)?;
        Ok(found)
    }

    fn quote(name: &str) -> String {
        format!("\"{}\"", name.replace('"', "\"\""))
    }
}
