use std::path::Path;

use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::PackageRevisionRefV1;
use crate::{AnalysisDatabaseSnafu, AnalysisStore, JsonSnafu, Result};

impl AnalysisStore {
    pub(super) fn validate_package_contracts(reader: &Connection, root: &Path) -> Result<()> {
        let query = "SELECT tenant_id, package_id, revision, descriptor, dependencies, artifact FROM package_revisions";
        let mut statement = reader.prepare(query).context(AnalysisDatabaseSnafu {
            operation: "prepare retained package contracts",
        })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read retained package contracts",
            })?;
        for row in rows {
            let (tenant, id, revision, descriptor, dependencies, artifact) =
                row.context(AnalysisDatabaseSnafu {
                    operation: "decode retained package contract",
                })?;
            let package: araphor_analysis_sdk::Package =
                serde_json::from_slice(&descriptor).context(JsonSnafu { path: root })?;
            if package.id != id || package.revision != revision || package.validate().is_err() {
                return Self::reject_path(root, "the retained package descriptor is invalid");
            }
            let retained = crate::PackageArtifactV1::from_bytes(&artifact)?;
            if retained.descriptor != package {
                return Self::reject_path(root, "the retained package artifact descriptor differs");
            }
            let dependencies: Vec<PackageRevisionRefV1> =
                serde_json::from_str(&dependencies).context(JsonSnafu { path: root })?;
            let declared: std::collections::BTreeSet<_> = package
                .exports
                .iter()
                .flat_map(|model| model.dependencies().map(|(_, dependency)| dependency))
                .filter(|dependency| dependency.package != package.id)
                .map(|dependency| (dependency.package.as_str(), dependency.revision.as_str()))
                .collect();
            let retained: std::collections::BTreeSet<_> = dependencies
                .iter()
                .map(|dependency| (dependency.package_id.as_str(), dependency.revision.as_str()))
                .collect();
            if declared != retained || retained.len() != dependencies.len() {
                return Self::reject_path(root, "the retained package dependency closure differs");
            }
            for dependency in dependencies {
                let present: bool = reader
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM package_revisions
                    WHERE tenant_id = ? AND package_id = ? AND revision = ?)",
                        params![tenant, dependency.package_id, dependency.revision],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "validate retained package dependency",
                    })?;
                if !present {
                    return Self::reject_path(root, "the retained package dependency is absent");
                }
            }
        }
        let mut statement = reader
            .prepare("SELECT tenant_id, package_id, revision, digest FROM package_images")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare retained package images",
            })?;
        let images = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read retained package images",
            })?;
        let control = crate::AnalysisReadControl::default();
        for image in images {
            let (tenant, package, revision, digest) = image.context(AnalysisDatabaseSnafu {
                operation: "decode retained package image",
            })?;
            let tenant: [u8; 16] = tenant.try_into().map_err(|_| {
                crate::AnalysisStateSnafu {
                    path: root,
                    reason: "the retained image tenant is invalid",
                }
                .build()
            })?;
            if tenant == [0; 16]
                || Self::retained_package_image_from(
                    reader,
                    tenant,
                    &araphor_discovery_definition::ImagePin {
                        image: crate::PackageRefV1 {
                            package_id: package,
                            revision,
                        },
                        digest,
                    },
                    &control,
                )?
                .is_none()
            {
                return Self::reject_path(root, "the retained package image is invalid");
            }
        }
        Ok(())
    }
}
