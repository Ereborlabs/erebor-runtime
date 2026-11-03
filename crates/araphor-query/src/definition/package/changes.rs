use datafusion::common::{Column, NullEquality};
use datafusion::logical_expr::{ExprFunctionExt, JoinType};

use super::*;
use crate::definition::call::{BagDifference, ChangeCall, ChangePort};
use crate::sources::SourceImage;

impl Packages {
    pub(super) fn changes(
        &self,
        model: &sdk::Model,
        lookups: LookupInputs,
        resets: Vec<LogicalPlan>,
        children: &mut Vec<LogicalPlan>,
    ) -> Result<Option<ChangeCall>> {
        let Some(contract) = &model.change_inputs else {
            return Ok(None);
        };
        if resets.len() != contract.ports.len() {
            return InvalidSnafu {
                field: "change reset plans",
            }
            .fail();
        }
        let mut ports = Vec::new();
        for (pair, reset) in contract.ports.iter().zip(resets) {
            let before = model
                .inputs
                .iter()
                .position(|input| input.port.name == pair.before)
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "change before port",
                    }
                    .build()
                })?;
            let after = model
                .inputs
                .iter()
                .position(|input| input.port.name == pair.after)
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "change after port",
                    }
                    .build()
                })?;
            let affected = model
                .inputs
                .iter()
                .position(|input| input.port.name == pair.affected)
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "change affected port",
                    }
                    .build()
                })?;
            let index = children.len();
            children.push(reset);
            let id = lookups
                .bindings
                .iter()
                .find_map(|(id, slot)| (*slot == after).then_some(*id))
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "change reset binding",
                    }
                    .build()
                })?;
            let schema = Arc::new(model.inputs[after].port.schema.clone());
            let scan = Inputs::scan(
                &pair.after,
                SourceProvider::port(id, Arc::clone(&schema)),
                &schema,
            )?;
            let keys = LogicalPlanBuilder::from(scan)
                .project(
                    model.inputs[affected]
                        .port
                        .schema
                        .fields()
                        .iter()
                        .map(|field| {
                            Expr::Column(Column::new(Some(pair.after.as_str()), field.name()))
                        }),
                )
                .and_then(LogicalPlanBuilder::distinct)
                .and_then(LogicalPlanBuilder::build)
                .context(SqlSnafu)?;
            let reset_keys = children.len();
            children.push(keys);
            let difference =
                if matches!(&model.inputs[before].source, sdk::InputSource::Query(_)) {
                    None
                } else {
                    Some(self.bag_difference(
                        Arc::new(model.inputs[after].port.schema.clone()),
                        children,
                    )?)
                };
            ports.push(ChangePort {
                before,
                after,
                affected,
                reset: index,
                reset_keys,
                difference,
            });
        }
        Ok(Some(ChangeCall { lookups, ports }))
    }

    fn bag_difference(
        &self,
        schema: Arc<sdk::Schema>,
        children: &mut Vec<LogicalPlan>,
    ) -> Result<BagDifference> {
        let columns = schema
            .fields()
            .iter()
            .map(|field| field.name().clone())
            .collect::<Vec<_>>();
        let mut ordinal = "__change_occurrence".to_owned();
        while schema.field_with_name(&ordinal).is_ok() {
            ordinal.push('_');
        }
        let mut position = "__change_position".to_owned();
        while schema.field_with_name(&position).is_ok() || position == ordinal {
            position.push('_');
        }
        let numbered = |name: &str| -> Result<_> {
            let (id, provider) = Self::port(Arc::clone(&schema))?;
            let scan = Inputs::scan(name, provider, &schema)?;
            let ordered = DataFrame::new(self.state.clone(), scan)
                .with_column(&position, row_number())
                .context(SqlSnafu)?
                .into_unoptimized_plan();
            let row = row_number()
                .partition_by(
                    columns
                        .iter()
                        .map(|name| Expr::Column(Column::from_name(name)))
                        .collect(),
                )
                .build()
                .context(SqlSnafu)?;
            let plan = DataFrame::new(self.state.clone(), ordered)
                .with_column(&ordinal, row)
                .context(SqlSnafu)?
                .into_unoptimized_plan();
            let plan = LogicalPlanBuilder::from(plan)
                .alias(name)
                .and_then(LogicalPlanBuilder::build)
                .context(SqlSnafu)?;
            self.demand
                .record(&BTreeSet::new(), [id].into_iter())
                .context(SqlSnafu)?;
            Ok((id, plan))
        };
        let (base, old) = numbered("before")?;
        let (target, new) = numbered("after")?;
        let start = children.len();
        for (left, right, left_name, right_name) in [
            (&old, &new, "before", "after"),
            (&new, &old, "after", "before"),
        ] {
            let keys = |name: &str| {
                columns
                    .iter()
                    .chain(std::iter::once(&ordinal))
                    .map(|column| Column::new(Some(name), column))
                    .collect::<Vec<_>>()
            };
            let plan = LogicalPlanBuilder::from(left.clone())
                .join_detailed(
                    right.clone(),
                    JoinType::LeftAnti,
                    (keys(left_name), keys(right_name)),
                    None,
                    NullEquality::NullEqualsNull,
                )
                .and_then(|plan| {
                    plan.sort(vec![
                        Expr::Column(Column::new(Some(left_name), &position)).sort(true, false)
                    ])
                })
                .and_then(|plan| {
                    plan.project(
                        columns
                            .iter()
                            .map(|column| Expr::Column(Column::new(Some(left_name), column))),
                    )
                })
                .and_then(LogicalPlanBuilder::build)
                .context(SqlSnafu)?;
            crate::planner::Planner::quotas(&plan, &self.limits)?;
            children.push(plan);
        }
        Ok(BagDifference {
            base,
            target,
            removed: start,
            inserted: start + 1,
        })
    }

    pub(super) fn change_plans(
        &self,
        provider: &dyn ContextProvider,
        model: &sdk::Model,
        complete: InputPlans,
    ) -> Result<PlannedInputs> {
        let contract = model.change_inputs.as_ref().ok_or_else(|| {
            InvalidSnafu {
                field: "change contract",
            }
            .build()
        })?;
        let mut tables = self.sources.clone();
        for table in tables.values_mut() {
            if let Some(source) = table.downcast_ref::<SourceProvider>() {
                if matches!(&source.origin, SourceOrigin::Durable(_)) {
                    *table = source.image(SourceImage::After).context(SqlSnafu)?;
                }
            }
        }
        let mut ports = BTreeMap::new();
        for (slot, input) in model.inputs.iter().enumerate() {
            let (id, source) = Self::port(Arc::new(input.port.schema.clone()))?;
            let plan = Inputs::scan(&input.port.name, source, &input.port.schema)?;
            tables.insert(
                input.port.name.clone(),
                Arc::new(ViewTable::new(self.indexed(&plan)?, None)),
            );
            ports.insert(id, slot);
        }
        for pair in &contract.ports {
            let base = complete
                .get(&pair.after)
                .map(|(plan, _)| plan.clone())
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "change input query",
                    }
                    .build()
                })?;
            for (name, image) in [
                ("before", SourceImage::Before),
                ("after", SourceImage::After),
                ("inserted", SourceImage::Inserted),
                ("removed", SourceImage::Removed),
            ] {
                let plan = image.plan(&base).context(SqlSnafu)?;
                tables.insert(
                    format!("{name}.{}", pair.after),
                    Arc::new(ViewTable::new(plan, None)),
                );
            }
        }
        let mut pending = Vec::new();
        for (slot, input) in model.inputs.iter().enumerate() {
            let (plan, mut origins) = self.demand.capture(|| {
                if input.port.name == contract.reset {
                    return Inputs::scan(
                        &input.port.name,
                        Arc::new(datafusion::datasource::empty::EmptyTable::new(Arc::new(
                            input.port.schema.clone(),
                        ))),
                        &input.port.schema,
                    );
                }
                let pair = contract
                    .ports
                    .iter()
                    .find(|pair| pair.before == input.port.name || pair.after == input.port.name);
                if let Some(pair) = pair {
                    if pair.before == input.port.name {
                        if let sdk::InputSource::Query(sql) = &input.source {
                            return self.plan(provider, &tables, sql);
                        }
                    }
                    let image = if pair.before == input.port.name {
                        SourceImage::Before
                    } else {
                        SourceImage::After
                    };
                    let base = image.plan(&complete[&pair.after].0).context(SqlSnafu)?;
                    let key = model
                        .inputs
                        .iter()
                        .find(|input| input.port.name == pair.affected)
                        .ok_or_else(|| {
                            InvalidSnafu {
                                field: "affected port",
                            }
                            .build()
                        })?;
                    let keys = Inputs::scan(
                        &pair.affected,
                        Arc::clone(&tables[&pair.affected]),
                        &key.port.schema,
                    )?;
                    let keys = LogicalPlanBuilder::from(keys)
                        .project(key.port.schema.fields().iter().map(|field| {
                            Expr::Column(Column::new(Some(pair.affected.as_str()), field.name()))
                        }))
                        .and_then(LogicalPlanBuilder::build)
                        .context(SqlSnafu)?;
                    let names = key
                        .port
                        .schema
                        .fields()
                        .iter()
                        .map(|field| field.name().clone())
                        .collect::<Vec<_>>();
                    let left = names.iter().map(Column::from_name).collect::<Vec<_>>();
                    let right = names.iter().map(Column::from_name).collect::<Vec<_>>();
                    return LogicalPlanBuilder::from(keys)
                        .join_detailed(
                            base,
                            JoinType::RightSemi,
                            (left, right),
                            None,
                            NullEquality::NullEqualsNull,
                        )
                        .and_then(LogicalPlanBuilder::build)
                        .context(SqlSnafu);
                }
                if let Some((plan, _)) = complete.get(&input.port.name) {
                    return Ok(plan.clone());
                }
                match &input.source {
                    sdk::InputSource::Query(sql) | sdk::InputSource::Lookup(sql) => {
                        self.plan(provider, &tables, sql)
                    }
                    _ => InvalidSnafu {
                        field: "change input source",
                    }
                    .fail(),
                }
            })?;
            let name = contract
                .ports
                .iter()
                .find_map(|pair| {
                    (pair.before == input.port.name || pair.after == input.port.name)
                        .then_some(pair.after.as_str())
                })
                .unwrap_or(&input.port.name);
            if let Some((_, inherited)) = complete.get(name) {
                origins.extend(inherited.iter().cloned());
            }
            origins.extend(crate::planner::Planner::sources(&plan)?);
            let dependencies = origins
                .iter()
                .filter_map(|origin| match origin {
                    SourceOrigin::Port(id) if ports.contains_key(id) => Some(*id),
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            if !contract
                .ports
                .iter()
                .any(|pair| pair.after == input.port.name)
            {
                Self::check_input_phase(model, slot, &dependencies, &ports)?;
            }
            Self::schema(&plan, &input.port.schema)?;
            pending.push((slot, plan, dependencies, origins));
        }
        let mut plans = BTreeMap::new();
        let mut scopes = BTreeMap::<usize, BTreeSet<SourceOrigin>>::new();
        let mut order = LookupInputs {
            bindings: ports.iter().map(|(id, slot)| (*id, *slot)).collect(),
            order: Vec::new(),
        };
        while !pending.is_empty() {
            let next = pending
                .iter()
                .position(|(_, _, dependencies, _)| {
                    dependencies.iter().all(|id| plans.contains_key(&ports[id]))
                })
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "change input cycle",
                    }
                    .build()
                })?;
            let (slot, plan, dependencies, mut origins) = pending.remove(next);
            for id in dependencies {
                origins.extend(scopes[&ports[&id]].iter().cloned());
            }
            let id = ports
                .iter()
                .find_map(|(id, port)| (*port == slot).then_some(*id));
            self.demand
                .record(&origins, id.into_iter())
                .context(SqlSnafu)?;
            plans.insert(slot, plan);
            scopes.insert(slot, origins);
            order.order.push(slot);
        }
        let resets = contract
            .ports
            .iter()
            .map(|pair| {
                SourceImage::After
                    .plan(&complete[&pair.after].0)
                    .context(SqlSnafu)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(PlannedInputs {
            plans: plans.into_values().collect(),
            origins: scopes.into_values().collect(),
            lookups: order,
            resets,
        })
    }
}
