use std::collections::BTreeSet;

use duckdb::Connection;

use super::*;
use crate::{PackageImplementationV1, PackageRefV1};

type RevisionKey = ([u8; 16], PackageRefV1);

#[derive(Clone, Default)]
pub(in crate::analysis) struct VerifiedPackages {
    revisions: BTreeSet<RevisionKey>,
}

impl AnalysisStore {
    pub(in crate::analysis) fn verify_package_revision(
        &self,
        reader: &Connection,
        tenant: [u8; 16],
        key: &PackageRefV1,
        verified: &mut VerifiedPackages,
    ) -> Result<()> {
        let revision = (tenant, key.clone());
        if verified.revisions.contains(&revision) {
            return Ok(());
        }
        let package = Self::package_from(reader, tenant, &key.package_id, &key.revision)?
            .ok_or_else(|| crate::PackageErrorCodeV1::Missing.error("verified package revision"))?;
        let artifact = package.decode_artifact()?;
        for implementation in &artifact.implementations {
            if let PackageImplementationV1::Wasm { .. } = implementation {
                for export in implementation.exports() {
                    artifact.implementation(export)?;
                }
            }
        }
        verified.revisions.insert(revision);
        Ok(())
    }

    pub(in crate::analysis) fn validate_context_packages(
        reader: &Connection,
        context: &AnalysisContextVersionV1,
    ) -> Result<()> {
        let Some(reference) = context.package_provenance()? else {
            return Ok(());
        };
        let artifacts = Self::package_artifacts_from(
            reader,
            context.key.tenant_id,
            &reference.root,
            &crate::AnalysisReadControl::default(),
        )?;
        reference.validate(artifacts)
    }

    pub(super) fn validate_stored_context_packages(
        reader: &Connection,
        context: &AnalysisContextVersionV1,
    ) -> Result<()> {
        Self::validate_context_packages(reader, context).map_err(crate::Error::stored_artifact)
    }

    pub(super) fn verify_context_packages(
        &self,
        reader: &Connection,
        context: &AnalysisContextVersionV1,
        verified: &mut VerifiedPackages,
    ) -> Result<()> {
        let Some(reference) = context
            .package_provenance()
            .map_err(crate::Error::stored_artifact)?
        else {
            return Ok(());
        };
        let artifacts = Self::package_artifacts_from(
            reader,
            context.key.tenant_id,
            &reference.root,
            &crate::AnalysisReadControl::default(),
        )
        .map_err(crate::Error::stored_artifact)?;
        let revisions = artifacts
            .iter()
            .map(|artifact| (context.key.tenant_id, artifact.reference()))
            .collect::<Vec<_>>();
        reference
            .validate(artifacts)
            .map_err(crate::Error::stored_artifact)?;
        verified.revisions.extend(revisions);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::PackageRevisionV1;
    use crate::PackageImplementationV1;
    use crate::{PackageArtifactV1, PackageBundle, PackageBundleV1};
    use araphor_analysis_builtins::{components, graph::Detector};
    use duckdb::params;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn verified_package_rechecks_current_bytes_and_export_identity() -> TestResult {
        for component in [components::PROCESS, components::CREDENTIALS] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("store");
            let store = AnalysisStore::open(&root)?;
            let artifact = PackageArtifactV1 {
                descriptor: Detector::Process.descriptor(),
                implementations: vec![PackageImplementationV1::Wasm {
                    exports: vec!["detect".into()],
                    artifact: component.to_vec(),
                }],
                fixtures: Vec::new(),
            };
            let package = artifact.reference();
            let output = artifact.descriptor.exports[0].outputs[0].name.clone();
            let identity = artifact.implementations[0]
                .identity()?
                .ok_or("Wasm identity")?;
            let bundle = PackageBundle::try_from(PackageBundleV1 {
                schema_version: 1,
                root: package.clone(),
                artifacts: vec![artifact],
            })?;
            store.install_package(
                &PackageRevisionV1::from_bundle(&bundle, [1; 16])?,
                || Ok(()),
            )?;
            let context = AnalysisContextVersionV1::from_package(
                &bundle, [1; 16], &package, "detect", &output,
            )?;
            store.commit_context(&context)?;
            let mut writer = store.writer()?;
            let mut on_demand = VerifiedPackages::default();
            store.verify_package_revision(writer.get_mut()?, [1; 16], &package, &mut on_demand)?;
            let retained = AnalysisStore::package_from(
                writer.get_mut()?,
                [1; 16],
                &package.package_id,
                &package.revision,
            )?
            .ok_or("verified package")?
            .decode_artifact()?;
            assert_eq!(
                retained.implementation("detect")?.identity()?,
                Some(identity)
            );
            let mut warm = VerifiedPackages::default();
            store.verify_package_revision(writer.get_mut()?, [1; 16], &package, &mut warm)?;
            let mut verified = VerifiedPackages::default();
            store
                .read_context_verified_from(writer.get_mut()?, &root, &context.key, &mut verified)?
                .ok_or("verified package context")?;
            assert!(verified.revisions.contains(&([1; 16], package.clone())));
            let mut ambiguous = retained;
            ambiguous
                .implementations
                .push(ambiguous.implementations[0].clone());
            writer.get_mut()?.execute(
                "UPDATE package_revisions SET artifact = ? WHERE tenant_id = ? AND package_id = ? AND revision = ?",
                params![ambiguous.encode()?, [1u8; 16].as_slice(), package.package_id, package.revision],
            )?;
            assert!(store
                .verify_package_revision(
                    writer.get_mut()?,
                    [1; 16],
                    &package,
                    &mut VerifiedPackages::default(),
                )
                .is_err());
            writer.get_mut()?.execute(
                "UPDATE package_revisions SET artifact = ? WHERE tenant_id = ? AND package_id = ? AND revision = ?",
                params![b"changed".as_slice(), [1u8; 16].as_slice(), package.package_id, package.revision],
            )?;
            let mut fresh = VerifiedPackages::default();
            assert!(store
                .verify_package_revision(writer.get_mut()?, [1; 16], &package, &mut fresh)
                .is_err());
            assert!(store
                .read_context_verified_from(writer.get_mut()?, &root, &context.key, &mut fresh)
                .is_err());
        }
        Ok(())
    }

    #[test]
    fn mixed_image_context_accepts_unqualified_native_export() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let mut descriptor = Detector::Process.descriptor();
        let mut offline = descriptor.exports[0].clone();
        offline.name = "offline".into();
        descriptor.exports.push(offline);
        let artifact = PackageArtifactV1 {
            descriptor,
            implementations: vec![
                PackageImplementationV1::Wasm {
                    exports: vec!["detect".into()],
                    artifact: components::PROCESS.to_vec(),
                },
                PackageImplementationV1::Native {
                    export: "offline".into(),
                    artifact: vec![1],
                    qualification: None,
                },
            ],
            fixtures: Vec::new(),
        };
        let package = artifact.reference();
        let output = artifact.descriptor.exports[0].outputs[0].name.clone();
        let bundle = PackageBundle::try_from(PackageBundleV1 {
            schema_version: 1,
            root: package.clone(),
            artifacts: vec![artifact],
        })?;
        store.install_package(
            &PackageRevisionV1::from_bundle(&bundle, [1; 16])?,
            || Ok(()),
        )?;
        let context =
            AnalysisContextVersionV1::from_package(&bundle, [1; 16], &package, "detect", &output)?;
        store.commit_context(&context)?;
        let mut writer = store.writer()?;
        let mut verified = VerifiedPackages::default();
        store.verify_package_revision(writer.get_mut()?, [1; 16], &package, &mut verified)?;
        store
            .read_context_verified_from(writer.get_mut()?, &root, &context.key, &mut verified)?
            .ok_or("mixed package context")?;
        drop(writer);
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        let mut writer = reopened.writer()?;
        let mut fresh = VerifiedPackages::default();
        reopened.verify_package_revision(writer.get_mut()?, [1; 16], &package, &mut fresh)?;
        reopened
            .read_context_verified_from(writer.get_mut()?, &root, &context.key, &mut fresh)?
            .ok_or("reopened mixed package context")?;
        Ok(())
    }
}
