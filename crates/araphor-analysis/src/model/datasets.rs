use std::collections::BTreeMap;
use std::sync::Arc;

use crate::AnalysisReadControl;
use araphor_analysis_sdk as sdk;
use araphor_query::datafusion::execution::memory_pool::MemoryReservation;
use araphor_query::execution::Engine;
use snafu::ResultExt as _;

use super::{operation::ModelRun, AdmittedModel};
use crate::Result;

pub struct SqlDatasetOutputV1 {
    pub data: sdk::Dataset,
    _metadata: MemoryReservation,
}

impl SqlDatasetOutputV1 {
    pub fn query(
        owner: &Arc<Engine>,
        tenant: [u8; 16],
        control: &AnalysisReadControl,
        inputs: &[sdk::Dataset],
        sql: &str,
        limits: sdk::Limits,
    ) -> Result<SqlDatasetOutputV1> {
        control.check()?;
        let ports = inputs
            .iter()
            .map(|input| {
                let schema = input
                    .batches
                    .first()
                    .ok_or_else(|| {
                        crate::ModelInvalidSnafu {
                            field: "committed dataset schema",
                        }
                        .build()
                    })?
                    .schema();
                Ok(sdk::Port::new(&input.name, schema.as_ref().clone()))
            })
            .collect::<Result<Vec<_>>>()?;
        sdk::Dataset::validate_all(inputs, &ports, limits).context(crate::AnalysisContractSnafu)?;
        let mut relations = BTreeMap::new();
        for port in &ports {
            AdmittedModel::relation(&mut relations, &port.name, &port.schema)?;
        }
        let state = owner.catalog(relations)?;
        let plan = AdmittedModel::plan(owner, &state, sql)?;
        let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos()).map_err(
            |_| {
                crate::ModelInvalidSnafu {
                    field: "model query time",
                }
                .build()
            },
        )?;
        let mut run = ModelRun::new(
            owner,
            &owner.memory().scope(),
            tenant,
            control,
            now,
            limits,
            usize::try_from(limits.max_bytes).unwrap_or(usize::MAX),
            None,
        )?;
        run.session
            .check_input(inputs.iter().flat_map(|data| &data.batches))?;
        for (port, data) in ports.iter().zip(inputs) {
            run.table(&port.name, &port.schema, &data.batches)?;
        }
        owner.wait(async move {
            Ok(async move {
                let batches = run.query(&plan, None).await?;
                let schema = batches
                    .first()
                    .ok_or_else(|| {
                        crate::ModelInvalidSnafu {
                            field: "model query schema",
                        }
                        .build()
                    })?
                    .schema();
                let data = sdk::Dataset {
                    name: "query".into(),
                    batches,
                };
                data.validate(&sdk::Port::new("query", schema.as_ref().clone()), limits)
                    .context(crate::AnalysisContractSnafu)?;
                run.control.check()?;
                let metadata = data.metadata_bytes();
                let reservation = run.output_memory;
                reservation.try_resize(metadata)?;
                Ok::<Self, crate::Error>(Self {
                    data,
                    _metadata: reservation,
                })
            }
            .await)
        })?
    }
}
