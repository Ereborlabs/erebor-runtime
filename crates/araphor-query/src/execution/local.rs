use std::mem::size_of;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use datafusion::catalog::memory::{
    MemoryCatalogProvider, MemoryCatalogProviderList, MemorySchemaProvider,
};
use datafusion::catalog::{CatalogProvider, CatalogProviderList, SchemaProvider};
use datafusion::common::DataFusionError;
use datafusion::execution::memory_pool::MemoryReservation;
use futures_util::TryStreamExt as _;
use snafu::ResultExt as _;

use super::Session;
use crate::{InvalidSnafu, Result, SqlSnafu};

pub struct LocalOutput {
    pub data: sdk::Dataset,
    _metadata: MemoryReservation,
}

impl Session {
    pub async fn query_local(&self, inputs: &[sdk::Dataset], sql: &str) -> Result<LocalOutput> {
        self.control.check()?;
        let ports = inputs
            .iter()
            .map(|data| {
                let schema = data.batches.first().ok_or_else(|| {
                    InvalidSnafu {
                        field: "retained dataset schema",
                    }
                    .build()
                })?;
                Ok(sdk::Port::new(
                    &data.name,
                    schema.schema_ref().as_ref().clone(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        sdk::Dataset::validate_all(inputs, &ports)
            .map_err(|source| DataFusionError::External(Box::new(source)))
            .context(SqlSnafu)?;
        let name = String::from("query");
        let mut session = self.clone();
        session.tables = Arc::default();
        let input = session.memory.reserve_input(0).context(SqlSnafu)?;
        session.check_input(inputs.iter().flat_map(|data| &data.batches))?;
        for (data, port) in inputs.iter().zip(&ports) {
            let schema = Self::indexed_schema(&port.schema)?;
            let batches =
                session.index_batches(Arc::clone(&schema), &data.batches, &input, input.size())?;
            session.register(&data.name, schema, &batches)?;
        }
        let schema = Arc::new(MemorySchemaProvider::new());
        for (name, table) in session.tables.iter() {
            schema
                .register_table(name.clone(), table.provider())
                .context(SqlSnafu)?;
        }
        let mut state = session.state()?;
        let config = &state.config_options().catalog;
        let catalog = Arc::new(MemoryCatalogProvider::new());
        catalog
            .register_schema(&config.default_schema, schema)
            .context(SqlSnafu)?;
        let catalogs = Arc::new(MemoryCatalogProviderList::new());
        catalogs.register_catalog(config.default_catalog.clone(), catalog);
        state.register_catalog_list(catalogs);
        let statement = session.engine.limits.parser.parse(sql)?;
        let plan = session
            .control
            .query_async(crate::planner::Planner::new(&state).build(statement, Vec::new()))
            .await?;
        let permit = Arc::new(
            session
                .engine
                .reserve_evaluation(session.selection.tenant_id)?,
        );
        let mut stream = session.stream_local(&plan, permit).await?;
        let schema = stream.schema();
        let metadata = session.memory.reserve_output(0).context(SqlSnafu)?;
        let mut data = sdk::Dataset {
            name,
            batches: Vec::new(),
        };
        while let Some(batch) = stream.try_next().await.context(SqlSnafu)? {
            metadata
                .try_grow(size_of::<sdk::RecordBatch>())
                .context(SqlSnafu)?;
            data.batches
                .try_reserve_exact(1)
                .map_err(|source| crate::Error::Sql {
                    source: DataFusionError::External(Box::new(source)),
                })?;
            data.batches.push(batch);
            metadata
                .try_resize(data.metadata_bytes())
                .context(SqlSnafu)?;
        }
        if data.batches.is_empty() {
            data.batches.push(sdk::RecordBatch::new_empty(schema));
        }
        metadata
            .try_resize(data.metadata_bytes())
            .context(SqlSnafu)?;
        session.control.check()?;
        Ok(LocalOutput {
            data,
            _metadata: metadata,
        })
    }
}
