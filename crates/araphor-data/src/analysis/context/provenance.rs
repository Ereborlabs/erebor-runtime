use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::*;
use crate::{InstalledRefV1, JsonSnafu, PackageRefV1};

impl AnalysisStore {
    pub(in crate::analysis) fn validate_context_packages(
        reader: &Connection,
        root: &Path,
        context: &AnalysisContextVersionV1,
    ) -> Result<()> {
        let Some(references) = InstalledRefV1::context_refs(context)? else {
            return Ok(());
        };
        let mut roots = BTreeMap::<_, Vec<_>>::new();
        for reference in &references {
            roots.entry(&reference.root).or_default().push(reference);
        }
        for (reference, references) in roots {
            let closure =
                Self::context_package_closure(reader, root, context.key.tenant_id, reference)?;
            for reference in references {
                let package = closure.get(&PackageRefV1 {
                    package_id: reference.package_id.clone(),
                    revision: reference.revision.clone(),
                });
                let Some(model) = package.and_then(|package| {
                    package
                        .exports
                        .iter()
                        .find(|model| model.name == reference.export)
                }) else {
                    return Self::reject_path(
                        root,
                        "the context package export or root is invalid",
                    );
                };
                reference.validate_parameters(model)?;
            }
        }
        Ok(())
    }

    fn context_package_closure(
        reader: &Connection,
        root: &Path,
        tenant: [u8; 16],
        reference: &PackageRefV1,
    ) -> Result<BTreeMap<PackageRefV1, sdk::Package>> {
        let mut pending = vec![reference.clone()];
        let mut packages = BTreeMap::new();
        while let Some(reference) = pending.pop() {
            if packages.contains_key(&reference) {
                continue;
            }
            if packages.len() == 64 {
                return Self::reject_path(root, "the context package closure exceeds its limit");
            }
            let (package, dependencies) = Self::context_package(reader, root, tenant, &reference)?;
            pending.extend(dependencies);
            packages.insert(reference, package);
        }
        Ok(packages)
    }

    fn context_package(
        reader: &Connection,
        root: &Path,
        tenant: [u8; 16],
        reference: &PackageRefV1,
    ) -> Result<(sdk::Package, Vec<PackageRefV1>)> {
        let stored: Option<(Vec<u8>, String)> = reader
            .query_row(
                "SELECT descriptor, dependencies FROM package_revisions
             WHERE tenant_id = ? AND package_id = ? AND revision = ?
             AND length(dependencies) <= ?",
                params![
                    tenant.as_slice(),
                    reference.package_id,
                    reference.revision,
                    crate::analysis::MAX_PACKAGE_METADATA_BYTES as u64
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read context package closure",
            })?;
        let Some((descriptor, dependencies)) = stored else {
            return Self::reject_path(root, "the context package revision is absent or too large");
        };
        let package: sdk::Package =
            serde_json::from_slice(&descriptor).context(JsonSnafu { path: root })?;
        let dependencies: Vec<crate::analysis::PackageRevisionRefV1> =
            serde_json::from_str(&dependencies).context(JsonSnafu { path: root })?;
        let declared: BTreeSet<_> = package
            .exports
            .iter()
            .flat_map(|model| model.dependencies().map(|(_, dependency)| dependency))
            .filter(|dependency| dependency.package != package.id)
            .map(|dependency| (dependency.package.as_str(), dependency.revision.as_str()))
            .collect();
        let retained: BTreeSet<_> = dependencies
            .iter()
            .map(|dependency| (dependency.package_id.as_str(), dependency.revision.as_str()))
            .collect();
        if package.id != reference.package_id
            || package.revision != reference.revision
            || package.validate().is_err()
            || declared != retained
            || retained.len() != dependencies.len()
        {
            return Self::reject_path(root, "the context package dependency closure is invalid");
        }
        Ok((
            package,
            dependencies
                .into_iter()
                .map(|dependency| PackageRefV1 {
                    package_id: dependency.package_id,
                    revision: dependency.revision,
                })
                .collect(),
        ))
    }
}
