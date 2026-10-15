use araphor_analysis_sdk as sdk;

use super::{
    execute::ModelExecution, SqlModelInputRequestV1, SqlModelInputV1, SqlModelOutputV1, SqlModelV1,
};
use crate::query::{budget::QueryLease, evaluation::QueryEvaluation, input::ScopedSources};
use crate::{AnalysisReadControl, QueryOwner, Result};

pub(crate) struct SqlOperation<'a> {
    owner: &'a QueryOwner,
    tenant: [u8; 16],
    connection: duckdb::Connection,
    lease: QueryLease,
    sources: ScopedSources,
}

impl QueryOwner {
    pub(crate) fn sql_operation(&self, tenant: [u8; 16]) -> Result<SqlOperation<'_>> {
        let lease = self.budget.model(tenant, 0)?;
        Ok(SqlOperation {
            owner: self,
            tenant,
            connection: QueryEvaluation::connection()?,
            lease,
            sources: ScopedSources::default(),
        })
    }
}

impl SqlOperation<'_> {
    pub(crate) fn model_input(
        &mut self,
        request: SqlModelInputRequestV1<'_>,
        control: &AnalysisReadControl,
    ) -> Result<SqlModelInputV1> {
        if request.selection.tenant_id != self.tenant {
            return crate::QueryDeniedSnafu.fail();
        }
        self.owner
            .model_input_shared(request, control, &self.connection, &mut self.sources)
    }

    pub(crate) fn evaluate(
        self,
        package: &sdk::Package,
        program: &SqlModelV1,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
    ) -> Result<SqlModelOutputV1> {
        let model = package
            .exports
            .iter()
            .find(|model| model.name == evaluation.export)
            .ok_or_else(|| {
                crate::QueryInvalidSnafu {
                    field: "model export",
                }
                .build()
            })?;
        let admitted = program.admit(model)?;
        let Self {
            owner,
            connection,
            lease,
            mut sources,
            ..
        } = self;
        sources.clear(&connection)?;
        owner.evaluate_model_reserved(
            package,
            evaluation,
            control,
            |capacity| {
                let mut lease = lease;
                lease.reserve_output(capacity)?;
                Ok(lease)
            },
            |control, host, _lease| {
                let mut executor = ModelExecution::new(&connection, control, evaluation, host)?;
                let output = control.query_run(&connection, || {
                    executor.register(model)?;
                    executor.evaluate(model, program, admitted)
                })?;
                let bytes = executor.bytes();
                drop(connection);
                Ok((output, bytes))
            },
        )
    }
}

#[cfg(test)]
mod tests;
