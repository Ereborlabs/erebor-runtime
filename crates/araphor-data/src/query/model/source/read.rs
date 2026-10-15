use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use crate::analysis::{AnalysisExtractLimits, AnalysisExtractionV1, PackageResultRefV1};
use crate::query::{InputProjection, InputRelations, InputRow};
use crate::{
    AnalysisContextRefV1, AnalysisReadControl, AnalysisSelectionV1, AnalysisWitnessV1, QueryOwner,
    QueryPlan, QuerySql, Result,
};

use super::super::{execute::ModelExecution, projection::ModelProjection};
use super::{ModelInputRequest, ModelSource};

pub(super) struct SourceRows {
    pub(super) extraction: AnalysisExtractionV1<InputRow>,
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
    ) -> Result<Self> {
        let stage = control.within(owner.limits.extract_timeout)?;
        let mut witnesses = Vec::new();
        let mut contexts = Vec::new();
        let mut results = Vec::new();
        let project = ModelProjection {
            inner: InputProjection::new(&plan.template, selection, now),
            witnesses: &mut witnesses,
            contexts: &mut contexts,
            results: &mut results,
        };
        let page = if plan.reads_raw() {
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
        Ok(Self {
            extraction: page.extraction,
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
        let bound = ModelExecution::check_input(
            catalog
                .iter()
                .filter(|(name, _)| self.bound.contains_key(*name))
                .flat_map(|(_, source)| &source.input.data.batches),
            owner.limits.input_bytes,
        )?;
        let inherited: Vec<_> = catalog
            .iter()
            .filter_map(|(name, source)| {
                (self.bound.contains_key(name)
                    && sql.dependencies().contains(&name.to_ascii_lowercase()))
                .then_some(source)
            })
            .collect();
        let plan = QueryPlan::model(request.grant.selection.clone(), sql.clone())?;
        let selection = plan.dependencies(request.now)?;
        let (connection, sources) = self.engine()?;
        let bounds = AnalysisExtractLimits {
            scan_bytes: owner.limits.scan_bytes,
            input_bytes: owner
                .limits
                .input_bytes
                .saturating_sub(bound)
                .min(request.model.limits.max_bytes as usize),
            ..Default::default()
        };
        let mut rows = SourceRows::extract(owner, &plan, &selection, request.now, bounds, control)?;
        let input = InputRelations::new(&mut rows.extraction, bounds.input_bytes, &plan.template)?;
        #[cfg(test)]
        owner.test_input(&input)?;
        let held = input.allocation_bytes();
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
        let mut executor =
            ModelExecution::new(connection, &stage, time, request.model.limits, &host);
        let result = stage.query_run(connection, || {
            input.register(connection, sources)?;
            executor.query(sql, &port.schema)
        });
        let cleanup = sources.clear(connection);
        let batches = result?;
        cleanup?;
        let bytes = executor.bytes().saturating_add(held);
        drop(input);
        if !rows.extraction.trace_reads.is_empty() {
            owner.store.check_trace_reads(
                selection.tenant_id,
                &rows.extraction.trace_reads,
                control,
                owner.store.reserve_reader()?,
            )?;
        }
        let data = sdk::Dataset {
            name: port.name.clone(),
            batches,
        };
        data.validate(port, request.model.limits)
            .context(crate::AnalysisContractSnafu)?;
        rows.finish(
            owner,
            sql,
            selection,
            data,
            owner.budget.retained_input(bytes)?,
            &inherited,
        )
    }
}
