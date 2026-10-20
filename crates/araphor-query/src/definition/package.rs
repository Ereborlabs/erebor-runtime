use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use araphor_analysis_sdk as sdk;
use araphor_discovery_definition::ImagePin;
use araphor_package::{
    ModelRef, PackageBundleV1, PackageImplementationV1, PackageRefV1, SqlModelV1,
};
use datafusion::catalog::TableProvider;
use datafusion::common::tree_node::{Transformed, TreeNodeRecursion};
use datafusion::common::{DFSchema, DataFusionError, ScalarValue};
use datafusion::dataframe::DataFrame;
use datafusion::datasource::{provider_as_source, source_as_provider, ViewTable};
use datafusion::execution::context::SQLOptions;
use datafusion::execution::SessionState;
use datafusion::functions_window::expr_fn::row_number;
use datafusion::logical_expr::planner::{
    ContextProvider, PlannedRelation, RelationPlanner, RelationPlannerContext, RelationPlanning,
};
use datafusion::logical_expr::{
    lit, Expr, ExprSchemable, Extension, LogicalPlan, LogicalPlanBuilder,
};
use datafusion::sql::parser::Statement;
use datafusion::sql::planner::{object_name_to_table_reference, SqlToRel};
use datafusion::sql::sqlparser::ast::{
    Expr as SqlExpr, FunctionArg, FunctionArgExpr, FunctionArgOperator, ObjectName, TableFactor,
    Value, Visit, Visitor,
};
use snafu::ResultExt as _;

use super::call::SqlCall;
use super::PackageCall;
use crate::execution::{Engine, Session};
use crate::inputs::Inputs;
use crate::sources::{SourceOrigin, SourceProvider, SourceSnapshot};
use crate::{InvalidSnafu, Result, SqlSnafu};

mod scope;
use scope::Scope;

type Exports = BTreeMap<ModelRef, BTreeMap<String, LogicalPlan>>;
type InputPlans = BTreeMap<String, (LogicalPlan, BTreeSet<SourceOrigin>)>;

pub(super) struct Packages {
    pub(super) state: SessionState,
    pub(super) demand: Arc<crate::planner::SourceDemand>,
    tenant: [u8; 16],
    limits: crate::execution::Limits,
    bundles: BTreeMap<PackageRefV1, (Arc<PackageBundleV1>, String)>,
    sources: BTreeMap<String, Arc<dyn TableProvider>>,
    planning: Mutex<Planning>,
    calls: AtomicU64,
    admission: Arc<()>,
}

#[derive(Default)]
struct Planning {
    pins: BTreeMap<PackageRefV1, String>,
    active: BTreeSet<ModelRef>,
}

struct Active<'a> {
    owner: &'a Packages,
    key: ModelRef,
}

impl Drop for Active<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.owner.state() {
            state.active.remove(&self.key);
        }
    }
}

struct References(BTreeSet<PackageRefV1>);

impl Visitor for References {
    type Break = DataFusionError;
    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        if let TableFactor::Table {
            name,
            args: Some(_),
            ..
        } = factor
        {
            match Packages::reference(name) {
                Ok(Some((image, _))) => {
                    self.0.insert(image);
                }
                Ok(None) => {}
                Err(error) => return ControlFlow::Break(error),
            }
        }
        ControlFlow::Continue(())
    }
}

impl fmt::Debug for Packages {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter
            .debug_struct("Packages")
            .field("images", &self.bundles.keys())
            .finish()
    }
}

impl Packages {
    pub(super) fn new(
        engine: &Engine,
        bundles: Vec<PackageBundleV1>,
        tenant: [u8; 16],
        tables: BTreeMap<String, Arc<dyn TableProvider>>,
    ) -> Result<Self> {
        let mut images = BTreeMap::new();
        for bundle in bundles {
            bundle.validate().map_err(araphor_data::Error::from)?;
            let digest = bundle.digest().map_err(araphor_data::Error::from)?;
            if images
                .insert(bundle.root.clone(), (Arc::new(bundle), digest))
                .is_some()
            {
                return InvalidSnafu {
                    field: "duplicate definition image",
                }
                .fail();
            }
        }
        let mut sources = SourceSnapshot::providers();
        for (name, table) in tables {
            if sources.insert(name, table).is_some() {
                return InvalidSnafu {
                    field: "definition source binding",
                }
                .fail();
            }
        }
        Ok(Self {
            demand: Arc::default(),
            tenant,
            state: engine.catalog(sources.clone())?,
            limits: engine.limits().clone(),
            bundles: images,
            sources,
            planning: Mutex::default(),
            calls: AtomicU64::new(0),
            admission: Arc::new(()),
        })
    }

    pub(super) fn references(statement: &Statement) -> Result<BTreeSet<PackageRefV1>> {
        let mut references = References(BTreeSet::new());
        if let Statement::Statement(statement) = statement {
            if let ControlFlow::Break(error) = statement.visit(&mut references) {
                return Err(error).context(SqlSnafu);
            }
        }
        Ok(references.0)
    }

    fn state(&self) -> Result<MutexGuard<'_, Planning>> {
        self.planning.lock().map_err(|_| {
            InvalidSnafu {
                field: "package planning state",
            }
            .build()
        })
    }

    pub(super) fn pins(&self) -> Result<Vec<ImagePin>> {
        Ok(self
            .state()?
            .pins
            .iter()
            .map(|(image, digest)| ImagePin {
                image: image.clone(),
                digest: digest.clone(),
            })
            .collect())
    }

    fn reference(name: &ObjectName) -> datafusion::common::Result<Option<(PackageRefV1, String)>> {
        if name.0.len() != 3 {
            return Ok(None);
        }
        let reference = object_name_to_table_reference(name.clone(), true)?;
        Ok(Some((
            PackageRefV1 {
                package_id: reference
                    .catalog()
                    .ok_or_else(|| DataFusionError::Plan("Package image is absent".into()))?
                    .into(),
                revision: reference
                    .schema()
                    .ok_or_else(|| DataFusionError::Plan("Package revision is absent".into()))?
                    .into(),
            },
            reference.table().into(),
        )))
    }

    fn admit(
        &self,
        context: &mut dyn RelationPlannerContext,
        image: PackageRefV1,
        export: String,
        arguments: Vec<FunctionArg>,
    ) -> Result<LogicalPlan> {
        let (bundle, digest) = self.bundles.get(&image).ok_or_else(|| {
            InvalidSnafu {
                field: "installed package image",
            }
            .build()
        })?;
        let pin = ImagePin {
            image: image.clone(),
            digest: digest.clone(),
        };
        self.state()?.pins.insert(image.clone(), pin.digest.clone());
        let root = ModelRef {
            package: image,
            export,
        };
        let model = bundle
            .artifact(&root.package)
            .map_err(araphor_data::Error::from)?
            .descriptor
            .exports
            .iter()
            .find(|model| model.name == root.export)
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "package export",
                }
                .build()
            })?;
        let mut output = None;
        let mut supplied = BTreeMap::new();
        let mut parameters = BTreeMap::new();
        for (index, argument) in arguments.into_iter().enumerate() {
            match argument {
                FunctionArg::Unnamed(FunctionArgExpr::Expr(SqlExpr::Value(value)))
                    if index == 0 =>
                {
                    let Value::SingleQuotedString(value) = value.value else {
                        return InvalidSnafu {
                            field: "package output selector",
                        }
                        .fail();
                    };
                    output = Some(value);
                }
                FunctionArg::Named {
                    name,
                    arg: FunctionArgExpr::Expr(SqlExpr::Subquery(subquery)),
                    operator: FunctionArgOperator::RightArrow,
                } if model
                    .inputs
                    .iter()
                    .any(|input| input.port.name == context.normalize_ident(name.clone())) =>
                {
                    let name = context.normalize_ident(name);
                    let plan = self.demand.capture(|| {
                        context
                            .plan(TableFactor::Derived {
                                lateral: false,
                                subquery,
                                alias: None,
                                sample: None,
                            })
                            .context(SqlSnafu)
                    })?;
                    if supplied.insert(name, plan).is_some() {
                        return InvalidSnafu {
                            field: "duplicate package input",
                        }
                        .fail();
                    }
                }
                FunctionArg::Named {
                    name,
                    arg: FunctionArgExpr::Expr(expression),
                    operator: FunctionArgOperator::RightArrow,
                } => {
                    let name = context.normalize_ident(name);
                    if !model
                        .parameters
                        .fields()
                        .iter()
                        .any(|field| field.name() == &name)
                    {
                        return InvalidSnafu {
                            field: "package parameter",
                        }
                        .fail();
                    }
                    let expression = context
                        .sql_to_expr(expression, &DFSchema::empty())
                        .context(SqlSnafu)?;
                    if parameters.insert(name, expression).is_some() {
                        return InvalidSnafu {
                            field: "duplicate package parameter",
                        }
                        .fail();
                    }
                }
                _ => {
                    return InvalidSnafu {
                        field: "package argument",
                    }
                    .fail();
                }
            }
        }
        let output = match output {
            Some(output) if model.outputs.iter().any(|port| port.name == output) => output,
            Some(_) => {
                return InvalidSnafu {
                    field: "package output",
                }
                .fail();
            }
            None if model.outputs.len() == 1 => model.outputs[0].name.clone(),
            None => {
                return InvalidSnafu {
                    field: "package output selector",
                }
                .fail();
            }
        };
        if !self.state()?.active.insert(root.clone()) {
            return InvalidSnafu {
                field: "package SQL cycle",
            }
            .fail();
        }
        let _active = Active {
            owner: self,
            key: root.clone(),
        };
        let order = bundle
            .order_for(&root.package, Some(&root.export))
            .map_err(araphor_data::Error::from)?;
        let mut needed = BTreeSet::from([root.clone()]);
        for key in order.iter().rev() {
            if !needed.contains(key) {
                continue;
            }
            let artifact = bundle
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
                if key == &root && supplied.contains_key(&port.name) {
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
        let empty_inputs = BTreeMap::new();
        let empty_parameters = BTreeMap::new();
        let mut exports = Exports::new();
        for key in order.into_iter().filter(|key| needed.contains(key)) {
            let artifact = bundle
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
            let (inputs, origins) = self.inputs(
                context.context_provider(),
                model,
                if key == root {
                    &supplied
                } else {
                    &empty_inputs
                },
                &exports,
            )?;
            let input_scope = Arc::new(Inputs::from_plans(model, &inputs, origins)?);
            let params = self.parameters(
                model,
                if key == root {
                    &parameters
                } else {
                    &empty_parameters
                },
            )?;
            let sql = if let PackageImplementationV1::Sql { program, .. } = artifact
                .implementation(&key.export)
                .map_err(araphor_data::Error::from)?
            {
                Some(self.sql(
                    context.context_provider(),
                    model,
                    program,
                    &inputs,
                    params.as_ref(),
                )?)
            } else {
                None
            };
            let mut children = inputs;
            children.extend(params);
            let sql = sql.map(|(sql, plans)| {
                children.extend(plans);
                sql
            });
            let id = self
                .calls
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
                .map_err(|_| {
                    InvalidSnafu {
                        field: "package call identity",
                    }
                    .build()
                })?;
            let descriptor = Arc::new(artifact.descriptor.clone());
            let admitted: Arc<[LogicalPlan]> = children.clone().into();
            let mut outputs = BTreeMap::new();
            for port in &model.outputs {
                let node = PackageCall {
                    id,
                    admission: Arc::clone(&self.admission),
                    tenant: self.tenant,
                    pin: pin.clone(),
                    package: key.package.clone(),
                    export: key.export.clone(),
                    output: port.name.clone(),
                    descriptor: Arc::clone(&descriptor),
                    bundle: Arc::clone(bundle),
                    sql: sql.clone(),
                    input_scope: Arc::clone(&input_scope),
                    admitted: Arc::clone(&admitted),
                    children: children.clone(),
                    schema: Arc::new(DFSchema::try_from(port.schema.clone()).context(SqlSnafu)?),
                };
                outputs.insert(
                    port.name.clone(),
                    LogicalPlan::Extension(Extension {
                        node: Arc::new(node),
                    }),
                );
            }
            exports.insert(key, outputs);
        }
        exports
            .remove(&root)
            .and_then(|mut outputs| outputs.remove(&output))
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "package output",
                }
                .build()
            })
    }

    fn inputs(
        &self,
        provider: &dyn ContextProvider,
        model: &sdk::Model,
        supplied: &InputPlans,
        exports: &Exports,
    ) -> Result<(Vec<LogicalPlan>, Vec<BTreeSet<SourceOrigin>>)> {
        let mut tables = self.sources.clone();
        for (slot, input) in model.inputs.iter().enumerate() {
            let schema = Session::indexed_schema(&input.port.schema)?;
            tables
                .entry(input.port.name.clone())
                .or_insert_with(|| SourceProvider::port(slot, schema));
        }
        let mut pending = Vec::new();
        for (slot, input) in model.inputs.iter().enumerate() {
            let local = !supplied.contains_key(&input.port.name)
                && !matches!(
                    &input.source,
                    sdk::InputSource::Table(sdk::TableRef::Output(_))
                );
            let (plan, mut origins) = if let Some(plan) = supplied.get(&input.port.name) {
                plan.clone()
            } else {
                self.demand.capture(|| match &input.source {
                    sdk::InputSource::Query(sql) => self.plan(provider, &tables, sql),
                    sdk::InputSource::Table(sdk::TableRef::Named(name)) => {
                        let source = tables.get(name).cloned().ok_or_else(|| {
                            InvalidSnafu {
                                field: "package input table",
                            }
                            .build()
                        })?;
                        Inputs::scan(name, source, &input.port.schema)
                    }
                    sdk::InputSource::Table(sdk::TableRef::Output(reference)) => {
                        let key = ModelRef {
                            package: PackageRefV1 {
                                package_id: reference.package.clone(),
                                revision: reference.revision.clone(),
                            },
                            export: reference.export.clone(),
                        };
                        exports
                            .get(&key)
                            .and_then(|outputs| outputs.get(&reference.output))
                            .cloned()
                            .ok_or_else(|| {
                                InvalidSnafu {
                                    field: "package dependency",
                                }
                                .build()
                            })
                    }
                })?
            };
            origins.extend(crate::planner::Planner::sources(&plan)?);
            let mut dependencies = BTreeSet::new();
            if local {
                plan.apply_with_subqueries(|plan| {
                    if let Some(slot) = Self::input_slot(plan) {
                        dependencies.insert(slot);
                    }
                    Ok(TreeNodeRecursion::Continue)
                })
                .context(SqlSnafu)?;
            }
            pending.push((slot, plan, dependencies, origins));
        }
        let mut plans = BTreeMap::new();
        let mut scopes = BTreeMap::<usize, BTreeSet<SourceOrigin>>::new();
        while !pending.is_empty() {
            let next = pending
                .iter()
                .position(|(_, _, dependencies, _)| {
                    dependencies.iter().all(|slot| plans.contains_key(slot))
                })
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "package input cycle",
                    }
                    .build()
                })?;
            let (slot, mut plan, dependencies, mut origins) = pending.remove(next);
            let input = &model.inputs[slot];
            if !dependencies.is_empty() {
                let mut bindings = BTreeMap::new();
                for dependency in dependencies {
                    origins.remove(&SourceOrigin::Port(dependency));
                    origins.extend(scopes[&dependency].iter().cloned());
                    bindings.insert(
                        dependency,
                        provider_as_source(Arc::new(ViewTable::new(
                            self.indexed(&plans[&dependency])?,
                            None,
                        ))),
                    );
                }
                plan = plan
                    .transform_up_with_subqueries(|node| {
                        let source = Self::input_slot(&node).and_then(|slot| bindings.get(&slot));
                        match (node, source) {
                            (LogicalPlan::TableScan(scan), Some(source)) => {
                                if !scan.filters.is_empty() || scan.fetch.is_some() {
                                    return datafusion::common::internal_err!(
                                        "Package input binding must precede optimization"
                                    );
                                }
                                LogicalPlanBuilder::scan(
                                    scan.table_name,
                                    Arc::clone(source),
                                    scan.projection,
                                )
                                .and_then(LogicalPlanBuilder::build)
                                .map(Transformed::yes)
                            }
                            (node, _) => Ok(Transformed::no(node)),
                        }?
                        .map_data(LogicalPlan::recompute_schema)
                    })
                    .context(SqlSnafu)?
                    .data;
                crate::planner::Planner::quotas(&plan, &self.limits)?;
            }
            Self::schema(&plan, &input.port.schema)?;
            plans.insert(slot, plan);
            scopes.insert(slot, origins);
        }
        Ok((
            plans.into_values().collect(),
            scopes.into_values().collect(),
        ))
    }

    fn input_slot(plan: &LogicalPlan) -> Option<usize> {
        let LogicalPlan::TableScan(scan) = plan else {
            return None;
        };
        let provider = source_as_provider(&scan.source).ok()?;
        match provider.as_any().downcast_ref::<SourceProvider>()?.origin {
            SourceOrigin::Port(slot) => Some(slot),
            _ => None,
        }
    }

    fn parameters(
        &self,
        model: &sdk::Model,
        parameters: &BTreeMap<String, Expr>,
    ) -> Result<Option<LogicalPlan>> {
        if model.parameters.fields().is_empty() {
            return Ok(None);
        }
        let schema = DFSchema::empty();
        let mut values = Vec::new();
        for field in model.parameters.fields() {
            let value = match parameters.get(field.name()) {
                Some(value) => value.clone(),
                None if field.is_nullable() => Expr::Literal(
                    ScalarValue::try_from(field.data_type()).context(SqlSnafu)?,
                    None,
                ),
                None => {
                    return InvalidSnafu {
                        field: "missing package parameter",
                    }
                    .fail();
                }
            };
            let value = value
                .cast_to(field.data_type(), &schema)
                .context(SqlSnafu)?;
            values.push(value.alias(field.name()));
        }
        let plan = LogicalPlanBuilder::empty(true)
            .project(values)
            .and_then(LogicalPlanBuilder::build)
            .context(SqlSnafu)?;
        Self::schema(&plan, &model.parameters)?;
        if plan
            .schema()
            .fields()
            .iter()
            .zip(model.parameters.fields())
            .any(|(actual, expected)| !expected.is_nullable() && actual.is_nullable())
        {
            return InvalidSnafu {
                field: "null package parameter",
            }
            .fail();
        }
        Ok(Some(plan))
    }

    fn sql(
        &self,
        provider: &dyn ContextProvider,
        model: &sdk::Model,
        program: &SqlModelV1,
        inputs: &[LogicalPlan],
        parameters: Option<&LogicalPlan>,
    ) -> Result<(SqlCall, Vec<LogicalPlan>)> {
        let mut tables = BTreeMap::<String, Arc<dyn TableProvider>>::new();
        let mut bindings = SqlCall {
            inputs: Vec::new(),
            parameters: None,
            prior: Vec::new(),
            outputs: Vec::new(),
            evidence: program.evidence.is_some(),
            reasons: Vec::new(),
            used: BTreeSet::new(),
        };
        let relation = |tables: &mut BTreeMap<String, Arc<dyn TableProvider>>,
                        name: String,
                        schema: &sdk::Schema,
                        indexed: bool|
         -> Result<usize> {
            static PORTS: AtomicUsize = AtomicUsize::new(0);
            let slot = PORTS
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |slot| {
                    slot.checked_add(1)
                })
                .map_err(|_| {
                    InvalidSnafu {
                        field: "package relation identity",
                    }
                    .build()
                })?;
            let source = SourceProvider::port(slot, Arc::new(schema.clone()));
            let plan = Inputs::scan(&name, source, schema)?;
            let plan = if indexed { self.indexed(&plan)? } else { plan };
            if tables
                .insert(name, Arc::new(ViewTable::new(plan, None)))
                .is_some()
            {
                return InvalidSnafu {
                    field: "package relation collision",
                }
                .fail();
            }
            Ok(slot)
        };
        for (input, plan) in model.inputs.iter().zip(inputs) {
            Self::schema(plan, &input.port.schema)?;
            bindings.inputs.push(relation(
                &mut tables,
                input.port.name.clone(),
                &input.port.schema,
                true,
            )?);
        }
        if parameters.is_some() {
            bindings.parameters = Some(relation(
                &mut tables,
                "parameters".into(),
                &model.parameters,
                false,
            )?);
        }
        if let Some(checkpoint) = &model.checkpoint {
            for port in &checkpoint.datasets {
                bindings.prior.push(relation(
                    &mut tables,
                    format!("prior_{}", port.name),
                    &port.schema,
                    true,
                )?);
            }
        }
        let outputs = self.datasets(provider, &tables, &model.outputs, &program.outputs)?;
        let mut plans = Vec::new();
        for port in &model.outputs {
            plans.push(outputs[&port.name].clone());
            bindings.outputs.push(relation(
                &mut tables,
                format!("output_{}", port.name),
                &port.schema,
                true,
            )?);
        }
        let checkpoint = self.datasets(
            provider,
            &tables,
            model
                .checkpoint
                .as_ref()
                .map_or(&[], |spec| spec.datasets.as_slice()),
            &program.checkpoint,
        )?;
        for port in model
            .checkpoint
            .as_ref()
            .map_or(&[][..], |spec| spec.datasets.as_slice())
        {
            plans.push(checkpoint[&port.name].clone());
        }
        if let Some(sql) = &program.evidence {
            let plan = self.plan(provider, &tables, sql)?;
            Self::schema(
                &plan,
                &sdk::Schema::new(vec![
                    sdk::Field::new("output_dataset", sdk::DataType::Utf8, false),
                    sdk::Field::new("output_row", sdk::DataType::UInt64, false),
                    sdk::Field::new("input_dataset", sdk::DataType::Utf8, false),
                    sdk::Field::new("input_row", sdk::DataType::UInt64, false),
                ]),
            )?;
            plans.push(plan);
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
            let plan = self.plan(provider, &tables, &reason.sql)?;
            Self::schema(&plan, &schema)?;
            plans.push(plan);
            bindings
                .reasons
                .push((reason.output.clone(), reason.code.clone()));
        }
        for plan in &plans {
            plan.apply_with_subqueries(|plan| {
                if let Some(slot) = Self::input_slot(plan) {
                    bindings.used.insert(slot);
                }
                Ok(TreeNodeRecursion::Continue)
            })
            .context(SqlSnafu)?;
        }
        Ok((bindings, plans))
    }

    fn datasets(
        &self,
        provider: &dyn ContextProvider,
        tables: &BTreeMap<String, Arc<dyn TableProvider>>,
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
            let plan = self.plan(provider, tables, sql)?;
            Self::schema(&plan, &port.schema)?;
            plans.insert(port.name.clone(), plan);
        }
        Ok(plans)
    }

    fn plan(
        &self,
        provider: &dyn ContextProvider,
        tables: &BTreeMap<String, Arc<dyn TableProvider>>,
        sql: &str,
    ) -> Result<LogicalPlan> {
        let statement = self.limits.parser.parse(sql)?;
        if !matches!(&statement, Statement::Statement(statement) if matches!(statement.as_ref(), datafusion::sql::sqlparser::ast::Statement::Query(_)))
        {
            return InvalidSnafu {
                field: "SQL statement",
            }
            .fail();
        }
        let scope = Scope { provider, tables };
        let plan = SqlToRel::new(&scope)
            .statement_to_plan(statement)
            .context(SqlSnafu)?;
        SQLOptions::new()
            .with_allow_ddl(false)
            .with_allow_dml(false)
            .with_allow_statements(false)
            .verify_plan(&plan)
            .context(SqlSnafu)?;
        crate::planner::Planner::quotas(&plan, &self.limits)?;
        Ok(plan)
    }

    fn indexed(&self, plan: &LogicalPlan) -> Result<LogicalPlan> {
        Session::indexed_schema(plan.schema().as_arrow())?;
        let plan = DataFrame::new(self.state.clone(), plan.clone())
            .with_column("__row_index", row_number() - lit(1u64))
            .context(SqlSnafu)?
            .into_unoptimized_plan();
        crate::planner::Planner::quotas(&plan, &self.limits)?;
        Ok(plan)
    }

    fn schema(plan: &LogicalPlan, schema: &sdk::Schema) -> Result<()> {
        sdk::Dataset::normalize_batch(
            sdk::RecordBatch::new_empty(Arc::clone(plan.schema().inner())),
            Arc::new(schema.clone()),
        )?;
        Ok(())
    }
}

impl RelationPlanner for Packages {
    fn plan_relation(
        &self,
        relation: TableFactor,
        context: &mut dyn RelationPlannerContext,
    ) -> datafusion::common::Result<RelationPlanning> {
        let TableFactor::Table {
            name,
            args: Some(_),
            ..
        } = &relation
        else {
            return Ok(RelationPlanning::Original(Box::new(relation)));
        };
        let Some((image, export)) = Self::reference(name)? else {
            return Ok(RelationPlanning::Original(Box::new(relation)));
        };
        let TableFactor::Table {
            alias,
            args: Some(args),
            with_hints,
            version,
            with_ordinality,
            partitions,
            json_path,
            sample,
            index_hints,
            ..
        } = relation
        else {
            return datafusion::common::internal_err!("Package relation changed");
        };
        if args.settings.is_some()
            || !with_hints.is_empty()
            || version.is_some()
            || with_ordinality
            || !partitions.is_empty()
            || json_path.is_some()
            || sample.is_some()
            || !index_hints.is_empty()
        {
            return datafusion::common::plan_err!("Package relation modifiers are invalid");
        }
        let plan = self
            .admit(context, image, export, args.args)
            .map_err(|source| DataFusionError::External(Box::new(source)))?;
        Ok(RelationPlanning::Planned(Box::new(PlannedRelation::new(
            plan, alias,
        ))))
    }
}
