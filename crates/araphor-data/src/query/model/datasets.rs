use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::super::{budget::QueryLease, evaluation::QueryEvaluation};
use super::{execute::ModelExecution, schema::ModelSchema};
use crate::{AnalysisReadControl, QueryClock as _, QueryOwner, QuerySql, Result, SystemQueryClock};

pub struct SqlDatasetOutputV1 {
    pub data: sdk::Dataset,
    _lease: QueryLease,
}

impl QueryOwner {
    pub fn query_datasets(
        &self,
        tenant: [u8; 16],
        inputs: &[sdk::Dataset],
        sql: &str,
        limits: sdk::Limits,
        control: &AnalysisReadControl,
    ) -> Result<SqlDatasetOutputV1> {
        let ports = inputs
            .iter()
            .map(|input| {
                let schema = input
                    .batches
                    .first()
                    .ok_or_else(|| {
                        crate::QueryInvalidSnafu {
                            field: "committed dataset schema",
                        }
                        .build()
                    })?
                    .schema();
                Ok(sdk::Port::new(&input.name, schema.as_ref().clone()))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut model = sdk::Model::new(
            "query",
            ports,
            vec![sdk::Port::new("query", sdk::Schema::empty())],
        );
        model.limits = limits;
        let mut package = sdk::Package::new("query", "1", vec![model.clone()]);
        let evaluation = sdk::Evaluation {
            export: "query".into(),
            parameters: None,
            checkpoint: None,
            context: sdk::EvaluationContext {
                id: "query".into(),
                time_utc_ns: i64::try_from(SystemQueryClock.now_ns()?).map_err(|_| {
                    crate::QueryInvalidSnafu {
                        field: "model query time",
                    }
                    .build()
                })?,
                seed: None,
                limits,
            },
            inputs: inputs
                .iter()
                .map(|data| sdk::Input {
                    data: data.clone(),
                    revision: sdk::Revision {
                        owner: "araphor-data.AnalysisStore".into(),
                        id: "committed".into(),
                        window: None,
                    },
                    coverage: sdk::Coverage {
                        state: sdk::CoverageState::Unknown,
                        limits: Vec::new(),
                    },
                })
                .collect(),
        };
        package
            .validate_evaluation(&evaluation)
            .context(crate::AnalysisContractSnafu)?;
        let query = QuerySql::admit_relations(sql, ModelSchema::relations(&model)?)?;
        let capacity = (limits.max_bytes as usize).min(self.limits.output_capacity);
        let lease = self.budget.model(tenant, capacity)?;
        let control = control.within(self.limits.evaluate_timeout)?;
        let connection = QueryEvaluation::connection()?;
        let host = crate::QueryLimits {
            output_capacity: capacity,
            ..self.limits.clone()
        };
        let mut executor = ModelExecution::new(&connection, &control, &evaluation, &host)?;
        let batches = control.query_run(&connection, || {
            executor.register(&model)?;
            executor.query_schema(&query, None)
        })?;
        let schema = batches[0].schema();
        package.exports[0].outputs[0].schema = schema.as_ref().clone();
        let data = sdk::Dataset {
            name: "query".into(),
            batches,
        };
        package
            .validate_output(
                &evaluation,
                &sdk::Output {
                    datasets: vec![data.clone()],
                    ..Default::default()
                },
            )
            .context(crate::AnalysisContractSnafu)?;
        Ok(SqlDatasetOutputV1 {
            data,
            _lease: lease.output(executor.bytes())?,
        })
    }
}
