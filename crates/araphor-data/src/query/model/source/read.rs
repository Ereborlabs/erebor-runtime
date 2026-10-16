use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use datafusion::{datasource::MemTable, logical_expr::LogicalPlan};
use snafu::ResultExt as _;

use crate::analysis::{AnalysisExtractLimits, AnalysisExtractionV1, PackageResultRefV1};
use crate::query::{budget::QueryLease, engine::QueryEngine, InputProjection, InputRelations};
use crate::{
    AnalysisContextRefV1, AnalysisReadControl, AnalysisSelectionV1, AnalysisWitnessV1, QueryOwner,
    QueryPlan, QuerySql, Result,
};

use super::super::{execute::ModelExecution, projection::ModelProjection};
use super::{ModelInputRequest, ModelSource};

pub(super) struct SourceRows {
    pub(super) extraction: AnalysisExtractionV1<()>,
    pub(super) inputs: InputRelations,
    pub(super) witnesses: Vec<AnalysisWitnessV1>,
    pub(super) contexts: Vec<AnalysisContextRefV1>,
    pub(super) results: Vec<PackageResultRefV1>,
}

impl SourceRows {
    pub(super) fn extract(
        owner: &QueryOwner,
        plan: &QueryPlan,
        selection: &AnalysisSelectionV1,
        now: u64,
        bounds: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        query: &LogicalPlan,
    ) -> Result<Self> {
        let stage = control.within(owner.limits.extract_timeout)?;
        let mut witnesses = Vec::new();
        let mut contexts = Vec::new();
        let mut results = Vec::new();
        let project = ModelProjection {
            inner: InputProjection::new(&plan.template, selection, now, Some(query)),
            witnesses: &mut witnesses,
            contexts: &mut contexts,
            results: &mut results,
        };
        let (mut page, project) = if plan.reads_raw() {
            owner
                .store
                .extract_rows(selection, bounds, &stage, project)?
        } else {
            owner
                .store
                .metadata_rows(selection, bounds, &stage, project)?
        };
        if !page.exhausted || !page.extraction.missing_results.is_empty() {
            return crate::QueryInvalidSnafu {
                field: "incomplete model source",
            }
            .fail();
        }
        let inputs = project.inner.finish(&mut page.extraction, &stage)?;
        Ok(Self {
            extraction: page.extraction,
            inputs,
            witnesses,
            contexts,
            results,
        })
    }
}

impl super::super::operation::ModelOperation<'_> {
    pub(in crate::query::model) fn read_input(
        &mut self,
        request: &ModelInputRequest<'_>,
        port: &sdk::Port,
        sql: &QuerySql,
        control: &AnalysisReadControl,
        catalog: &BTreeMap<String, ModelSource>,
    ) -> Result<ModelSource> {
        let owner = self.owner;
        let inherited: Vec<_> = catalog
            .iter()
            .filter_map(|(name, source)| {
                (self.bound.contains_key(&name.to_ascii_lowercase())
                    && sql.dependencies().contains(&name.to_ascii_lowercase()))
                .then_some(source)
            })
            .collect();
        let plan = QueryPlan::model(request.grant.selection.clone(), sql.clone())?;
        let binding = sql.bind_complete(request.now)?;
        let selection = plan.dependencies_bound(request.now, &binding)?;
        let tables = self.bound.clone();
        let bounds = AnalysisExtractLimits {
            scan_bytes: owner.limits.scan_bytes,
            input_bytes: owner
                .limits
                .input_bytes
                .saturating_sub(self.retained_bytes)
                .min(request.model.limits.max_bytes as usize),
            ..Default::default()
        };
        let preparation = control.within(owner.limits.evaluate_timeout)?;
        let (state, _) = self.engine()?;
        let (query, actual) = QueryEngine::prepare(state, &binding, None)?;
        preparation.check()?;
        let mut rows = SourceRows::extract(
            owner,
            &plan,
            &selection,
            request.now,
            bounds,
            control,
            &query,
        )?;
        let input = std::mem::take(&mut rows.inputs);
        let held = input.allocation_bytes();
        if held > bounds.input_bytes {
            return crate::QueryLimitSnafu {
                resource: "model source input",
                limit: bounds.input_bytes,
            }
            .fail();
        }
        let time = i64::try_from(request.now).map_err(|_| {
            crate::QueryInvalidSnafu {
                field: "model source time",
            }
            .build()
        })?;
        let stage = control.within(owner.limits.evaluate_timeout)?;
        let host = crate::QueryLimits {
            output_capacity: bounds.input_bytes.saturating_sub(held),
            ..owner.limits.clone()
        };
        let (state, lease) = self.engine()?;
        let retained = lease.clone();
        let mut executor = ModelExecution::new(
            owner,
            state,
            &stage,
            lease,
            time,
            request.model.limits,
            &host,
        );
        executor.tables = tables;
        for (name, mut table) in input.tables {
            stage.check()?;
            for batch in &mut table.batches {
                *batch = lease.retain_batch(batch)?;
            }
            executor.tables.insert(
                name.to_owned(),
                Arc::new(
                    MemTable::try_new(table.schema, vec![table.batches]).context(
                        crate::QueryEngineSnafu {
                            operation: "register source Arrow input",
                        },
                    )?,
                ),
            );
        }
        let batches = executor.query_schema((query, actual), Some(&port.schema))?;
        let bytes = batches
            .iter()
            .fold(executor.bytes().saturating_add(held), |bytes, batch| {
                bytes.saturating_add(QueryLease::batch_overhead(batch))
            });
        if bytes > bounds.input_bytes {
            return crate::QueryLimitSnafu {
                resource: "model source input",
                limit: bounds.input_bytes,
            }
            .fail();
        }
        drop(executor);
        self.retained_bytes = self.retained_bytes.saturating_add(bytes);
        if !rows.extraction.trace_reads.is_empty() {
            owner.store.check_trace_reads(
                selection.tenant_id,
                &rows.extraction.trace_reads,
                control,
                owner.store.reserve_reader()?,
            )?;
        }
        let mut data = sdk::Dataset {
            name: port.name.clone(),
            batches,
        };
        data.validate(port, request.model.limits)
            .context(crate::AnalysisContractSnafu)?;
        for batch in &mut data.batches {
            *batch = retained.retain_batch(batch)?;
        }
        rows.finish(owner, sql, selection, data, retained, &inherited)
    }
}
