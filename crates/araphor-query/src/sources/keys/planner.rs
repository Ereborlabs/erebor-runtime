use std::sync::Arc;

use datafusion::common::config::ConfigOptions;
use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::common::{DataFusionError, Result};
use datafusion::datasource::source::DataSourceExec;
use datafusion::logical_expr::JoinType;
use datafusion::physical_expr::PhysicalExpr;
use datafusion::physical_optimizer::PhysicalOptimizerRule;
use datafusion::physical_plan::coalesce_partitions::CoalescePartitionsExec;
use datafusion::physical_plan::filter::FilterExec;
use datafusion::physical_plan::joins::{HashExpr, HashJoinExec, PartitionMode, SeededRandomState};
use datafusion::physical_plan::projection::ProjectionExec;
use datafusion::physical_plan::repartition::RepartitionExec;
use datafusion::physical_plan::sorts::sort::SortExec;
use datafusion::physical_plan::ExecutionPlan;
use std::collections::{BTreeMap, BTreeSet};

use super::{KeyBuildExec, KeyRead};
use crate::sources::{SourceData, SourceImage, SourceKey};

#[derive(Debug)]
pub(crate) struct SourceJoin;

#[derive(Debug)]
pub(crate) struct SourceLookup;

impl SourceJoin {
    fn retained(plan: &Arc<dyn ExecutionPlan>) -> Result<bool> {
        let mut found = false;
        plan.apply(|node| {
            if SourceData::from_plan(node.as_ref()).is_some_and(|source| {
                matches!(source.image, Some(SourceImage::Before | SourceImage::After))
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
                let Some(join) = plan.as_any().downcast_ref::<HashJoinExec>() else {
                    return Ok(Transformed::no(plan));
                };
                let left = Self::retained(join.left())?;
                let right = Self::retained(join.right())?;
                if left && !right {
                    return Ok(Transformed::yes(
                        join.swap_inputs(PartitionMode::CollectLeft)?,
                    ));
                }
                if right {
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
    fn cached(
        plan: &Arc<dyn ExecutionPlan>,
        calls: Option<&crate::definition::CallContext>,
    ) -> Result<bool> {
        match (
            plan.as_any()
                .downcast_ref::<crate::definition::physical::PackageExec>(),
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
        plan.apply(|node| {
            if Self::cached(node, calls)? {
                return Ok(TreeNodeRecursion::Jump);
            }
            if node
                .as_any()
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
        seeds: SeededRandomState,
    ) -> Result<Option<Arc<dyn ExecutionPlan>>> {
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
                    hash: Arc::new(HashExpr::new(columns, seeds, "retained_probe".into())),
                },
            });
            return Ok(Some(DataSourceExec::from_data_source(source)));
        }
        let mapped = if let Some(projection) = plan.as_any().downcast_ref::<ProjectionExec>() {
            columns
                .into_iter()
                .map(|column| projection.projection_expr().unproject_expr(&column))
                .collect::<Result<Vec<_>>>()?
        } else if plan.as_any().is::<FilterExec>()
            || plan.as_any().is::<CoalescePartitionsExec>()
            || plan.as_any().is::<RepartitionExec>()
            || plan
                .as_any()
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
        let Some(child) = Self::bind(Arc::clone(child), mapped, slot, seeds)? else {
            return Ok(None);
        };
        Ok(Some(plan.with_new_children(vec![child])?))
    }

    pub(crate) fn keys(
        plan: &Arc<dyn ExecutionPlan>,
        calls: Option<&crate::definition::CallContext>,
    ) -> Result<Vec<SourceKey>> {
        let mut keys = Vec::new();
        let mut producers = BTreeMap::new();
        let mut readers = BTreeMap::new();
        plan.apply(|plan| {
            if Self::cached(plan, calls)? {
                return Ok(TreeNodeRecursion::Jump);
            }
            if let Some(build) = plan.as_any().downcast_ref::<KeyBuildExec>() {
                if producers.insert(build.slot, build.hash.seeds()).is_some() {
                    return datafusion::common::plan_err!(
                        "the source key slot has more than one producer"
                    );
                }
                let mut dependencies = BTreeSet::new();
                build.input.apply(|child| {
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
        plan.apply(|plan| {
            if Self::cached(plan, calls)? {
                return Ok(TreeNodeRecursion::Jump);
            }
            if let Some(read) =
                SourceData::from_plan(plan.as_ref()).and_then(|source| source.key.as_ref())
            {
                if producers.get(&read.slot) != Some(&read.key.hash.seeds()) {
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
        _config: &ConfigOptions,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        Ok(plan
            .transform_up(|plan| {
                let Some(join) = plan.as_any().downcast_ref::<HashJoinExec>() else {
                    return Ok(Transformed::no(plan));
                };
                if join.left().as_any().is::<KeyBuildExec>() || join.on().is_empty() {
                    return Ok(Transformed::no(plan));
                }
                if matches!(
                    join.join_type(),
                    JoinType::Right | JoinType::Full | JoinType::RightAnti | JoinType::RightMark
                ) {
                    return Ok(Transformed::no(plan));
                }
                let (a, b) = uuid::Uuid::new_v4().as_u64_pair();
                let (c, d) = uuid::Uuid::new_v4().as_u64_pair();
                let seeds = SeededRandomState::with_seeds(a, b, c, d);
                let slot = crate::sources::SourceProvider::identity()
                    .map_err(|error| DataFusionError::External(Box::new(error)))?;
                let probe = join
                    .on()
                    .iter()
                    .map(|(_, column)| Arc::clone(column))
                    .collect();
                let Some(right) = Self::bind(Arc::clone(join.right()), probe, slot, seeds.clone())?
                else {
                    return Ok(Transformed::no(plan));
                };
                let build = join
                    .on()
                    .iter()
                    .map(|(column, _)| Arc::clone(column))
                    .collect();
                let left = Arc::new(KeyBuildExec::new(
                    Arc::clone(join.left()),
                    slot,
                    Arc::new(HashExpr::new(build, seeds, "retained_build".into())),
                )?);
                Ok(Transformed::yes(plan.with_new_children(vec![left, right])?))
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
