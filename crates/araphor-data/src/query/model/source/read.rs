use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use crate::analysis::{AnalysisExtractLimits, AnalysisExtractionV1, PackageResultRefV1};
use crate::query::{evaluation::QueryEvaluation, InputProjection, InputRelations, InputRow};
use crate::{
    AnalysisContextRefV1, AnalysisReadControl, AnalysisSelectionV1, AnalysisWitnessV1, QueryOwner,
    QueryPlan, Result,
};

use super::super::{execute::ModelExecution, projection::ModelProjection};
use super::SqlModelInputRequestV1;

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

    pub(super) fn evaluate(
        &mut self,
        owner: &QueryOwner,
        request: &SqlModelInputRequestV1<'_>,
        plan: &QueryPlan,
        byte_limit: usize,
        control: &AnalysisReadControl,
    ) -> Result<(sdk::Dataset, usize)> {
        let input = InputRelations::new(&mut self.extraction, byte_limit, &plan.template)?;
        #[cfg(test)]
        owner.test_input(&input)?;
        let held = input.allocation_bytes();
        let evaluation = request.evaluation()?;
        let stage = control.within(owner.limits.evaluate_timeout)?;
        let connection = QueryEvaluation::connection()?;
        let host = crate::QueryLimits {
            output_capacity: byte_limit.saturating_sub(held),
            ..owner.limits.clone()
        };
        let mut executor = ModelExecution::new(&connection, &stage, &evaluation, &host)?;
        let batches = stage.query_run(&connection, || {
            input.register(&connection)?;
            executor.query(&request.sql, &request.port.schema)
        })?;
        let bytes = executor.bytes().saturating_add(held);
        drop(connection);
        drop(input);
        if !self.extraction.trace_reads.is_empty() {
            owner.store.check_trace_reads(
                request.selection.tenant_id,
                &self.extraction.trace_reads,
                control,
                owner.store.reserve_reader()?,
            )?;
        }
        let data = sdk::Dataset {
            name: request.port.name.clone(),
            batches,
        };
        let mut model = sdk::Model::new(&request.port.name, Vec::new(), vec![request.port.clone()]);
        model.limits = request.limits;
        sdk::Package::new("source", "1", vec![model])
            .validate_output(
                &evaluation,
                &sdk::Output {
                    datasets: vec![data.clone()],
                    ..Default::default()
                },
            )
            .context(crate::AnalysisContractSnafu)?;
        Ok((data, bytes))
    }
}

impl SqlModelInputRequestV1<'_> {
    fn evaluation(&self) -> Result<sdk::Evaluation> {
        Ok(sdk::Evaluation {
            export: self.port.name.clone(),
            inputs: Vec::new(),
            parameters: None,
            checkpoint: None,
            context: sdk::EvaluationContext {
                id: "source".into(),
                time_utc_ns: i64::try_from(self.now_ns).map_err(|_| {
                    crate::QueryInvalidSnafu {
                        field: "model source time",
                    }
                    .build()
                })?,
                seed: None,
                limits: self.limits,
            },
        })
    }
}
