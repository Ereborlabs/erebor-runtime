use std::collections::{BTreeMap, BTreeSet};

use araphor_data::{ManagedCall, ManagedManifest, PackageErrorCodeV1 as Code};
use araphor_query::definition::{PackageCall, PreparedDefinition};
use datafusion::logical_expr::UserDefinedLogicalNodeCore;

use super::Instance;
use araphor_query::Result;

impl Instance {
    pub(super) fn manifest(
        definition: &PreparedDefinition,
    ) -> Result<(ManagedManifest, BTreeMap<u64, PackageCall>)> {
        let mut calls = BTreeMap::new();
        let mut declarations = BTreeMap::new();
        PackageCall::any(&definition.plan, &mut |call| {
            let mut dependencies = BTreeSet::new();
            for input in call.inputs() {
                PackageCall::any(input, &mut |dependency| {
                    if dependency.id() != call.id() {
                        dependencies.insert(dependency.id());
                    }
                    Ok(false)
                })?;
            }
            let bundle = definition
                .images()
                .find(|(bundle, digest)| {
                    bundle.root == call.image().image && *digest == call.image().digest
                })
                .map(|(bundle, _)| bundle)
                .ok_or_else(|| {
                    datafusion::common::DataFusionError::External(Box::new(
                        Code::Missing.error("managed call image"),
                    ))
                })?;
            let implementation = bundle
                .artifact(call.package())
                .and_then(|artifact| artifact.implementation(call.export()))
                .map_err(|source| {
                    datafusion::common::DataFusionError::External(Box::new(
                        araphor_data::Error::from(source),
                    ))
                })?;
            let declaration = ManagedCall {
                image: call.image().clone(),
                package: call.package().clone(),
                export: call.export().into(),
                target: implementation.target().into(),
                artifact: implementation.identity().map_err(|source| {
                    datafusion::common::DataFusionError::External(Box::new(
                        araphor_data::Error::from(source),
                    ))
                })?,
                arguments: call.arguments().to_vec(),
                dependencies,
            };
            if declarations
                .insert(call.id(), declaration.clone())
                .is_some_and(|old| old != declaration)
            {
                return Err(datafusion::common::DataFusionError::External(Box::new(
                    Code::Conflict.error("managed call identity"),
                )));
            }
            calls.entry(call.id()).or_insert_with(|| call.clone());
            Ok(false)
        })
        .map_err(|source| araphor_query::Error::Sql { source })?;
        let manifest = ManagedManifest {
            format: 1,
            planner: format!(
                "datafusion/{};araphor-managed/1",
                datafusion::DATAFUSION_VERSION
            ),
            definition: definition
                .resolved
                .digest()
                .map_err(araphor_data::Error::from)?,
            calls: declarations,
        };
        manifest.order()?;
        Ok((manifest, calls))
    }
}
