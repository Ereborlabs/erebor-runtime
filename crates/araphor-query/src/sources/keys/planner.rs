use std::sync::Arc;

use datafusion::arrow::datatypes::DataType;
use datafusion::arrow::row::{RowConverter, SortField};
use datafusion::common::config::ConfigOptions;
use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::common::{DataFusionError, JoinSide, Result};
use datafusion::datasource::source::DataSourceExec;
use datafusion::logical_expr::JoinType;
use datafusion::physical_expr::expressions::Column;
use datafusion::physical_expr::PhysicalExpr;
use datafusion::physical_optimizer::PhysicalOptimizerRule;
use datafusion::physical_plan::aggregates::AggregateExec;
use datafusion::physical_plan::coalesce_partitions::CoalescePartitionsExec;
use datafusion::physical_plan::filter::FilterExec;
use datafusion::physical_plan::joins::utils::build_join_schema;
use datafusion::physical_plan::joins::{HashJoinExec, PartitionMode};
use datafusion::physical_plan::projection::ProjectionExec;
use datafusion::physical_plan::repartition::RepartitionExec;
use datafusion::physical_plan::sorts::sort::SortExec;
use datafusion::physical_plan::union::UnionExec;
use datafusion::physical_plan::unnest::UnnestExec;
use datafusion::physical_plan::{ChildrenPropertiesMode, ExecutionPlan, ReplaceChildrenOptions};
use std::collections::{BTreeMap, BTreeSet};

use super::{KeyBuildExec, KeyRead};
use crate::sources::{PortExec, SourceData, SourceImage, SourceKey};

#[derive(Debug)]
pub(crate) struct SourceJoin;

#[derive(Debug)]
pub(crate) struct SourceLookup;

impl SourceJoin {
    fn retained(plan: &Arc<dyn ExecutionPlan>) -> Result<bool> {
        let mut found = false;
        plan.apply(|node| {
            if let Some(port) = node.downcast_ref::<PortExec>() {
                found = !port.key_columns().is_empty() && Self::retained(port.driver())?;
                return Ok(if found {
                    TreeNodeRecursion::Stop
                } else {
                    TreeNodeRecursion::Jump
                });
            }
            if SourceData::from_plan(node.as_ref()).is_some_and(|source| {
                matches!(source.image, Some(SourceImage::Before | SourceImage::After))
                    && source
                        .origin
                        .durable()
                        .is_some_and(araphor_data::AnalysisTableRead::source_rows)
            }) {
                found = true;
                return Ok(TreeNodeRecursion::Stop);
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        Ok(found)
    }
}

impl PhysicalOptimizerRule for SourceJoin {
    fn optimize(
        &self,
        plan: Arc<dyn ExecutionPlan>,
        _config: &ConfigOptions,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        Ok(plan
            .transform_up(|plan| {
                let Some(join) = plan.downcast_ref::<HashJoinExec>() else {
                    return Ok(Transformed::no(plan));
                };
                let left = Self::retained(join.left())?;
                let right = Self::retained(join.right())?;
                if left && !right {
                    return Ok(Transformed::yes(
                        join.swap_inputs(PartitionMode::CollectLeft)?,
                    ));
                }
                if right && join.partition_mode() != &PartitionMode::CollectLeft {
                    return Ok(Transformed::yes(Arc::new(
                        join.builder()
                            .with_partition_mode(PartitionMode::CollectLeft)
                            .build()?,
                    )));
                }
                Ok(Transformed::no(plan))
            })?
            .data)
    }

    fn name(&self) -> &str {
        "retained_source_join"
    }
    fn schema_check(&self) -> bool {
        true
    }
}

impl SourceLookup {
    fn map_keys(
        columns: Vec<Arc<dyn PhysicalExpr>>,
        mapping: &[Option<Arc<dyn PhysicalExpr>>],
    ) -> Result<Option<Vec<Arc<dyn PhysicalExpr>>>> {
        let mut complete = true;
        let mapped = columns
            .into_iter()
            .map(|column| {
                Ok(column
                    .transform_up(|expr| {
                        let Some(column) = expr.downcast_ref::<Column>() else {
                            return Ok(Transformed::no(expr));
                        };
                        let Some(Some(mapped)) = mapping.get(column.index()) else {
                            complete = false;
                            return Ok(Transformed::no(expr));
                        };
                        Ok(Transformed::yes(Arc::clone(mapped)))
                    })?
                    .data)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(complete.then_some(mapped))
    }

    fn cached(
        plan: &Arc<dyn ExecutionPlan>,
        calls: Option<&crate::definition::CallContext>,
    ) -> Result<bool> {
        match (
            plan.downcast_ref::<crate::definition::physical::PackageExec>(),
            calls,
        ) {
            (Some(package), Some(calls)) => calls.cached(package.logical_call()),
            _ => Ok(false),
        }
    }

    pub(crate) fn required(
        plan: &Arc<dyn ExecutionPlan>,
        calls: Option<&crate::definition::CallContext>,
    ) -> Result<bool> {
        let mut required = false;
        PortExec::apply(plan, &mut |node| {
            if Self::cached(node, calls)? {
                return Ok(TreeNodeRecursion::Jump);
            }
            if node
                .downcast_ref::<crate::definition::physical::PackageExec>()
                .is_some_and(|package| package.has_changes())
            {
                required = true;
                return Ok(TreeNodeRecursion::Stop);
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        Ok(required)
    }

    fn bind(
        plan: Arc<dyn ExecutionPlan>,
        columns: Vec<Arc<dyn PhysicalExpr>>,
        slot: usize,
        converter: Arc<RowConverter>,
        data_types: Arc<[DataType]>,
    ) -> Result<Option<Arc<dyn ExecutionPlan>>> {
        if plan.fetch().is_some() {
            return Ok(None);
        }
        if let Some(port) = plan.downcast_ref::<PortExec>() {
            let schema = port.driver().schema();
            let mut mapping = vec![None; plan.schema().fields().len()];
            for &(output, input) in port.key_columns() {
                mapping[output] = Some(Arc::new(Column::new(schema.field(input).name(), input))
                    as Arc<dyn PhysicalExpr>);
            }
            let Some(columns) = Self::map_keys(columns, &mapping)? else {
                return Ok(None);
            };
            let Some(driver) = Self::bind(
                Arc::clone(port.driver()),
                columns,
                slot,
                converter,
                data_types,
            )?
            else {
                return Ok(None);
            };
            return Ok(Some(
                port.replace_inputs([driver, Arc::clone(&port.inputs()[1])])?,
            ));
        }
        if let Some(source) = SourceData::from_plan(plan.as_ref()) {
            if !matches!(source.image, Some(SourceImage::Before | SourceImage::After)) {
                return Ok(None);
            }
            if source.key.is_some() || source.fetch.is_some() {
                return Ok(None);
            }
            let table = source.origin.durable().ok_or_else(|| {
                DataFusionError::Internal("the retained key source is not durable".into())
            })?;
            if !araphor_data::AnalysisTableRead::source_rows(table) {
                return Ok(None);
            }
            let mut source = source.clone();
            source.key = Some(KeyRead {
                slot,
                key: SourceKey {
                    id: source.read,
                    table: table.to_owned(),
                    columns: source.indices.clone(),
                    expressions: columns.into(),
                    converter,
                    data_types,
                },
            });
            return Ok(Some(DataSourceExec::from_data_source(source)));
        }
        if let Some(join) = plan.downcast_ref::<HashJoinExec>() {
            if join.contains_projection() {
                return Ok(None);
            }
            let sides: &[JoinSide] = match join.join_type() {
                JoinType::Inner => &[JoinSide::Left, JoinSide::Right],
                JoinType::Left | JoinType::LeftSemi | JoinType::LeftAnti => &[JoinSide::Left],
                JoinType::Right | JoinType::RightSemi | JoinType::RightAnti => &[JoinSide::Right],
                _ => return Ok(None),
            };
            let (_, indices) = build_join_schema(
                join.left().schema().as_ref(),
                join.right().schema().as_ref(),
                join.join_type(),
            );
            for side in sides {
                let input = if *side == JoinSide::Left {
                    join.left()
                } else {
                    join.right()
                };
                let schema = input.schema();
                let mapping = indices
                    .iter()
                    .map(|column| {
                        (column.side == *side).then(|| {
                            Arc::new(Column::new(schema.field(column.index).name(), column.index))
                                as Arc<dyn PhysicalExpr>
                        })
                    })
                    .collect::<Vec<_>>();
                let Some(mapped) = Self::map_keys(columns.clone(), &mapping)? else {
                    continue;
                };
                let Some(bound) = Self::bind(
                    Arc::clone(input),
                    mapped,
                    slot,
                    Arc::clone(&converter),
                    Arc::clone(&data_types),
                )?
                else {
                    continue;
                };
                let children = if *side == JoinSide::Left {
                    vec![bound, Arc::clone(join.right())]
                } else {
                    vec![Arc::clone(join.left()), bound]
                };
                return Ok(Some(plan.replace_children(
                    children,
                    ReplaceChildrenOptions::new(ChildrenPropertiesMode::Keep),
                )?));
            }
            return Ok(None);
        }
        if plan.is::<UnionExec>() {
            let mut inputs = Vec::new();
            for input in plan.children() {
                if input.schema() != plan.schema() {
                    return Ok(None);
                }
                let Some(input) = Self::bind(
                    Arc::clone(input),
                    columns.clone(),
                    slot,
                    Arc::clone(&converter),
                    Arc::clone(&data_types),
                )?
                else {
                    return Ok(None);
                };
                inputs.push(input);
            }
            return if inputs.is_empty() {
                Ok(None)
            } else {
                Ok(Some(plan.replace_children(
                    inputs,
                    ReplaceChildrenOptions::new(ChildrenPropertiesMode::Keep),
                )?))
            };
        }
        let mapped = if let Some(projection) = plan.downcast_ref::<ProjectionExec>() {
            columns
                .into_iter()
                .map(|column| projection.projection_expr().unproject_expr(&column))
                .collect::<Result<Vec<_>>>()?
        } else if let Some(filter) = plan.downcast_ref::<FilterExec>() {
            if let Some(projection) = filter.projection() {
                let schema = filter.input().schema();
                let mapping = projection
                    .iter()
                    .map(|&index| {
                        Some(Arc::new(Column::new(schema.field(index).name(), index))
                            as Arc<dyn PhysicalExpr>)
                    })
                    .collect::<Vec<_>>();
                let Some(mapped) = Self::map_keys(columns, &mapping)? else {
                    return Ok(None);
                };
                mapped
            } else {
                columns
            }
        } else if let Some(aggregate) = plan.downcast_ref::<AggregateExec>() {
            let group = aggregate.group_expr();
            if group.is_empty()
                || !group.is_single()
                || !group.null_expr().is_empty()
                || group.groups().len() != 1
                || group.groups()[0].iter().any(|null| *null)
                || aggregate.limit_options().is_some()
            {
                return Ok(None);
            }
            let mut mapping = vec![None; plan.schema().fields().len()];
            for (output, (expr, _)) in group.expr().iter().enumerate() {
                mapping[output] = Some(Arc::clone(expr));
            }
            let Some(mapped) = Self::map_keys(columns, &mapping)? else {
                return Ok(None);
            };
            mapped
        } else if let Some(unnest) = plan.downcast_ref::<UnnestExec>() {
            let mut mapping = vec![None; plan.schema().fields().len()];
            for (index, field) in unnest.input().schema().fields().iter().enumerate() {
                if unnest
                    .list_column_indices()
                    .iter()
                    .any(|column| column.index_in_input_schema == index)
                    || unnest.struct_column_indices().contains(&index)
                {
                    continue;
                }
                let schema = plan.schema();
                let mut outputs = schema
                    .fields()
                    .iter()
                    .enumerate()
                    .filter(|(_, output)| output.name() == field.name());
                if let Some((output, _)) = outputs.next().filter(|_| outputs.next().is_none()) {
                    if mapping[output].is_some() {
                        return Ok(None);
                    }
                    mapping[output] =
                        Some(Arc::new(Column::new(field.name(), index)) as Arc<dyn PhysicalExpr>);
                }
            }
            let Some(mapped) = Self::map_keys(columns, &mapping)? else {
                return Ok(None);
            };
            mapped
        } else if plan.is::<KeyBuildExec>()
            || plan.is::<CoalescePartitionsExec>()
            || plan.is::<RepartitionExec>()
            || plan
                .downcast_ref::<SortExec>()
                .is_some_and(|sort| sort.fetch().is_none())
        {
            columns
        } else {
            return Ok(None);
        };
        let children = plan.children();
        let [child] = children.as_slice() else {
            return Ok(None);
        };
        let Some(child) = Self::bind(Arc::clone(child), mapped, slot, converter, data_types)?
        else {
            return Ok(None);
        };
        Ok(Some(plan.replace_children(
            vec![child],
            ReplaceChildrenOptions::new(ChildrenPropertiesMode::Keep),
        )?))
    }

    pub(crate) fn keys(
        plan: &Arc<dyn ExecutionPlan>,
        calls: Option<&crate::definition::CallContext>,
    ) -> Result<Vec<SourceKey>> {
        let mut keys = Vec::new();
        let mut producers = BTreeMap::new();
        let mut readers = BTreeMap::new();
        PortExec::apply(plan, &mut |plan| {
            if Self::cached(plan, calls)? {
                return Ok(TreeNodeRecursion::Jump);
            }
            if let Some(build) = plan.downcast_ref::<KeyBuildExec>() {
                if producers
                    .insert(
                        build.slot,
                        (Arc::clone(&build.converter), Arc::clone(&build.data_types)),
                    )
                    .is_some()
                {
                    return datafusion::common::plan_err!(
                        "the source key slot has more than one producer"
                    );
                }
                let mut dependencies = BTreeSet::new();
                PortExec::apply(&build.input, &mut |child| {
                    if Self::cached(child, calls)? {
                        return Ok(TreeNodeRecursion::Jump);
                    }
                    if let Some(key) =
                        SourceData::from_plan(child.as_ref()).and_then(|source| source.key.as_ref())
                    {
                        dependencies.insert(key.slot);
                    }
                    Ok(TreeNodeRecursion::Continue)
                })?;
                readers.insert(build.slot, dependencies);
            }
            if let Some(key) =
                SourceData::from_plan(plan.as_ref()).and_then(|source| source.key.as_ref())
            {
                keys.push(key.key.clone());
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        PortExec::apply(plan, &mut |plan| {
            if Self::cached(plan, calls)? {
                return Ok(TreeNodeRecursion::Jump);
            }
            if let Some(read) =
                SourceData::from_plan(plan.as_ref()).and_then(|source| source.key.as_ref())
            {
                if !producers
                    .get(&read.slot)
                    .is_some_and(|(converter, data_types)| {
                        Arc::ptr_eq(converter, &read.key.converter)
                            && Arc::ptr_eq(data_types, &read.key.data_types)
                    })
                {
                    return datafusion::common::plan_err!(
                        "the source key slot has no matching producer"
                    );
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        let mut ready = BTreeSet::new();
        while ready.len() < readers.len() {
            let before = ready.len();
            for (slot, dependencies) in &readers {
                if dependencies.is_subset(&ready) {
                    ready.insert(*slot);
                }
            }
            if ready.len() == before {
                return datafusion::common::plan_err!("the source key slots contain a cycle");
            }
        }
        keys.sort_by_key(|key| key.id);
        keys.dedup_by_key(|key| key.id);
        Ok(keys)
    }
}

impl PhysicalOptimizerRule for SourceLookup {
    fn optimize(
        &self,
        plan: Arc<dyn ExecutionPlan>,
        config: &ConfigOptions,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        Ok(plan
            .transform_down(|plan| {
                if let Some(port) = plan.downcast_ref::<PortExec>() {
                    return Ok(Transformed::yes(port.replace_inputs([
                        self.optimize(Arc::clone(&port.inputs()[0]), config)?,
                        self.optimize(Arc::clone(&port.inputs()[1]), config)?,
                    ])?));
                }
                let Some(join) = plan.downcast_ref::<HashJoinExec>() else {
                    return Ok(Transformed::no(plan));
                };
                if join.left().is::<KeyBuildExec>() || join.on().is_empty() {
                    return Ok(Transformed::no(plan));
                }
                if matches!(
                    join.join_type(),
                    JoinType::Right | JoinType::Full | JoinType::RightAnti | JoinType::RightMark
                ) {
                    return Ok(Transformed::no(plan));
                }
                let rows = |columns: &[Arc<dyn PhysicalExpr>]| -> Result<Option<(Arc<RowConverter>, Arc<[DataType]>)>> {
                    let data_types = columns
                        .iter()
                        .map(|column| column.data_type(join.left().schema().as_ref()))
                        .collect::<Result<Vec<_>>>()?;
                    let fields = data_types.iter().cloned().map(SortField::new).collect::<Vec<_>>();
                    if !RowConverter::supports_fields(&fields) {
                        return Ok(None);
                    }
                    Ok(Some((Arc::new(RowConverter::new(fields)?), data_types.into())))
                };
                let slot = crate::sources::SourceProvider::identity()
                    .map_err(|error| DataFusionError::External(Box::new(error)))?;
                let probe = join
                    .on()
                    .iter()
                    .map(|(_, column)| Arc::clone(column))
                    .collect();
                let build = join
                    .on()
                    .iter()
                    .map(|(column, _)| Arc::clone(column))
                    .collect::<Vec<_>>();
                let converter = rows(&build)?;
                let bound = match &converter {
                    Some((converter, data_types)) => {
                        Self::bind(Arc::clone(join.right()), probe, slot, Arc::clone(converter), Arc::clone(data_types))?
                    }
                    None => None,
                };
                let (right, build, converter, data_types) = match bound.zip(converter) {
                    Some((right, (converter, data_types))) => (right, build, converter, data_types),
                    None => {
                        let mut selected = None;
                        for (build, probe) in join.on() {
                            let build = vec![Arc::clone(build)];
                            let Some((converter, data_types)) = rows(&build)? else {
                                continue;
                            };
                            if let Some(right) = Self::bind(
                                Arc::clone(join.right()),
                                vec![Arc::clone(probe)],
                                slot,
                                Arc::clone(&converter),
                                Arc::clone(&data_types),
                            )? {
                                selected = Some((right, build, converter, data_types));
                                break;
                            }
                        }
                        let Some(selected) = selected else {
                            return Ok(Transformed::no(plan));
                        };
                        selected
                    }
                };
                let left = Arc::new(KeyBuildExec::new(
                    Arc::clone(join.left()),
                    slot,
                    build.into(),
                    converter,
                    data_types,
                )?);
                Ok(Transformed::yes(plan.replace_children(
                    vec![left, right],
                    ReplaceChildrenOptions::new(ChildrenPropertiesMode::Keep),
                )?))
            })?
            .data)
    }

    fn name(&self) -> &str {
        "retained_source_lookup"
    }
    fn schema_check(&self) -> bool {
        true
    }
}
