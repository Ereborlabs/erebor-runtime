use datafusion::common::{Column, NullEquality};
use datafusion::logical_expr::JoinType;

use super::*;
use crate::definition::call::ChangeCall;
use crate::sources::SourceImage;

impl Packages {
    pub(super) fn changes(&self, model: &sdk::Model, lookups: LookupInputs) -> Option<ChangeCall> {
        model.change_inputs.as_ref().map(|_| ChangeCall { lookups })
    }

    pub(super) fn change_plans(
        &self,
        provider: &dyn ContextProvider,
        model: &sdk::Model,
        supplied: &InputPlans,
        exports: &Exports,
    ) -> Result<(Vec<LogicalPlan>, Vec<BTreeSet<SourceOrigin>>, LookupInputs)> {
        let contract = model.change_inputs.as_ref().ok_or_else(|| {
            InvalidSnafu {
                field: "change contract",
            }
            .build()
        })?;
        let mut tables = self.sources.clone();
        for table in tables.values_mut() {
            if let Some(source) = table.as_any().downcast_ref::<SourceProvider>() {
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
        let mut bases = BTreeMap::new();
        for pair in &contract.ports {
            let input = model
                .inputs
                .iter()
                .find(|input| input.port.name == pair.after)
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "change after port",
                    }
                    .build()
                })?;
            let base = if let Some((plan, _)) = supplied.get(&pair.after) {
                plan.clone()
            } else {
                match &input.source {
                    sdk::InputSource::Query(sql) => {
                        let mut sources = self.sources.clone();
                        sources.extend(
                            tables
                                .iter()
                                .filter(|(name, _)| *name != &pair.after)
                                .map(|(name, table)| (name.clone(), Arc::clone(table))),
                        );
                        self.plan(provider, &sources, sql)?
                    }
                    sdk::InputSource::Table(sdk::TableRef::Named(name)) => Inputs::scan(
                        name,
                        self.sources.get(name).cloned().ok_or_else(|| {
                            InvalidSnafu {
                                field: "change input source",
                            }
                            .build()
                        })?,
                        &input.port.schema,
                    )?,
                    _ => {
                        return InvalidSnafu {
                            field: "change input query",
                        }
                        .fail()
                    }
                }
            };
            Self::schema(&base, &input.port.schema)?;
            for (name, image) in [
                ("before", SourceImage::Before),
                ("after", SourceImage::After),
                ("inserted", SourceImage::Inserted),
                ("removed", SourceImage::Removed),
            ] {
                let plan = Scope::image_plan(&base, image).context(SqlSnafu)?;
                tables.insert(
                    format!("{name}.{}", pair.after),
                    Arc::new(ViewTable::new(plan, None)),
                );
            }
            bases.insert(pair.after.clone(), base);
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
                    let base = Scope::image_plan(&bases[&pair.after], image).context(SqlSnafu)?;
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
                if let Some((plan, _)) = supplied.get(&input.port.name) {
                    return Ok(plan.clone());
                }
                match &input.source {
                    sdk::InputSource::Query(sql) | sdk::InputSource::Lookup(sql) => {
                        self.plan(provider, &tables, sql)
                    }
                    sdk::InputSource::Table(sdk::TableRef::Named(name)) => Inputs::scan(
                        name,
                        Arc::clone(tables.get(name).ok_or_else(|| {
                            InvalidSnafu {
                                field: "change support source",
                            }
                            .build()
                        })?),
                        &input.port.schema,
                    ),
                    sdk::InputSource::Table(sdk::TableRef::Output(reference)) => exports
                        .get(&ModelRef {
                            package: PackageRefV1 {
                                package_id: reference.package.clone(),
                                revision: reference.revision.clone(),
                            },
                            export: reference.export.clone(),
                        })
                        .and_then(|outputs| outputs.get(&reference.output))
                        .cloned()
                        .ok_or_else(|| {
                            InvalidSnafu {
                                field: "change dependency",
                            }
                            .build()
                        }),
                }
            })?;
            origins.extend(crate::planner::Planner::sources(&plan)?);
            let dependencies = origins
                .iter()
                .filter_map(|origin| match origin {
                    SourceOrigin::Port(id) if ports.contains_key(id) => Some(*id),
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
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
        Ok((
            plans.into_values().collect(),
            scopes.into_values().collect(),
            order,
        ))
    }
}
