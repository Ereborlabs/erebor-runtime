use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;
use std::collections::BTreeMap;

use super::*;
use crate::{PackageArtifactIdentityV1, PackageImplementationV1, PackageRefV1};

type RevisionKey = ([u8; 16], PackageRefV1);
type CallKey = ([u8; 16], PackageRefV1, String);

#[derive(Clone, Eq, PartialEq)]
struct StoredHashes {
    descriptor: String,
    artifact: String,
    dependencies: String,
}

#[derive(Clone, Default)]
pub(in crate::analysis) struct VerifiedPackages {
    revisions: BTreeMap<RevisionKey, Option<StoredHashes>>,
    calls: BTreeMap<CallKey, (PackageArtifactIdentityV1, bool)>,
}

impl VerifiedPackages {
    pub(in crate::analysis) fn native_graph(
        &self,
        tenant: [u8; 16],
        call: &crate::ManagedCall,
    ) -> Result<Option<bool>> {
        if call.target != "wasm" {
            return Ok(Some(false));
        }
        let key = (tenant, call.package.clone(), call.export.clone());
        let Some((identity, supported)) = self.calls.get(&key) else {
            return Ok(None);
        };
        if call.artifact.as_ref() != Some(identity) {
            return Err(crate::PackageErrorCodeV1::Invalid.error("verified Graph artifact"));
        }
        Ok(Some(*supported))
    }
}

#[derive(Clone)]
pub(in crate::analysis) struct ValidatedProvenance {
    body: Vec<u8>,
    revisions: Vec<(PackageRefV1, StoredHashes)>,
    calls: BTreeMap<(PackageRefV1, String), (PackageArtifactIdentityV1, bool)>,
}

impl AnalysisStore {
    fn stored_package_hashes(
        reader: &Connection,
        tenant: [u8; 16],
        key: &PackageRefV1,
    ) -> Result<Option<StoredHashes>> {
        let hashes: Option<(Option<String>, Option<String>, Option<String>)> = reader
            .query_row(
                "SELECT sha256(descriptor), sha256(artifact), sha256(dependencies) FROM package_revisions WHERE tenant_id = ? AND package_id = ? AND revision = ?",
                params![tenant.as_slice(), key.package_id, key.revision],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context(crate::AnalysisDatabaseSnafu {
                operation: "hash current package revision",
            })?;
        Ok(hashes.and_then(|(descriptor, artifact, dependencies)| {
            Some(StoredHashes {
                descriptor: descriptor?,
                artifact: artifact?,
                dependencies: dependencies?,
            })
        }))
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

    pub(super) fn check_cached_provenance(
        &self,
        reader: &Connection,
        context: &AnalysisContextVersionV1,
    ) -> Result<()> {
        self.check_cached_provenance_with(reader, context, &mut VerifiedPackages::default())
    }

    pub(super) fn check_cached_provenance_with(
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
        let cached = self
            .package_provenance
            .lock()
            .map_err(|_| self.state_error("the package provenance cache lock is poisoned"))?
            .get(&context.key)
            .cloned();
        if let Some(cached) = cached {
            let mut current = cached.body == context.body;
            for (key, fingerprint) in &cached.revisions {
                let revision = (context.key.tenant_id, key.clone());
                let actual = if let Some(actual) = verified.revisions.get(&revision) {
                    actual.clone()
                } else {
                    let actual = Self::stored_package_hashes(reader, context.key.tenant_id, key)
                        .map_err(crate::Error::stored_artifact)?;
                    verified.revisions.insert(revision, actual.clone());
                    actual
                };
                current &= actual.as_ref() == Some(fingerprint);
            }
            if current {
                verified
                    .calls
                    .extend(cached.calls.into_iter().map(|((package, export), call)| {
                        ((context.key.tenant_id, package, export), call)
                    }));
                return Ok(());
            }
            return Self::validate_context_packages(reader, context)
                .map_err(crate::Error::stored_artifact);
        }
        let mut keys = Vec::new();
        let artifacts = Self::package_artifacts_inspect_from(
            reader,
            context.key.tenant_id,
            &reference.root,
            &crate::AnalysisReadControl::default(),
            |row| {
                keys.push(PackageRefV1 {
                    package_id: row.package_id.clone(),
                    revision: row.revision.clone(),
                });
            },
        )
        .map_err(crate::Error::stored_artifact)?;
        let mut calls = BTreeMap::new();
        for artifact in &artifacts {
            let package = artifact.reference();
            for implementation in &artifact.implementations {
                let PackageImplementationV1::Wasm {
                    artifact: component,
                    ..
                } = implementation
                else {
                    continue;
                };
                let identity = implementation
                    .identity()
                    .map_err(crate::Error::from)?
                    .ok_or_else(|| {
                        crate::PackageErrorCodeV1::Invalid.error("verified Wasm artifact")
                    })?;
                for export in implementation.exports() {
                    calls.insert(
                        (package.clone(), export.clone()),
                        (
                            identity.clone(),
                            araphor_analysis_builtins::graph::Detector::supports_resume(
                                &artifact.descriptor,
                                export,
                                component,
                            ),
                        ),
                    );
                }
            }
        }
        reference
            .validate(artifacts)
            .map_err(crate::Error::stored_artifact)?;
        let mut revisions = keys
            .into_iter()
            .map(|key| {
                let hashes = Self::stored_package_hashes(reader, context.key.tenant_id, &key)?
                    .ok_or_else(|| {
                        crate::PackageErrorCodeV1::Missing.error("validated package revision")
                    })?;
                Ok((key, hashes))
            })
            .collect::<Result<Vec<_>>>()?;
        revisions.sort_by(|left, right| left.0.cmp(&right.0));
        let validated = ValidatedProvenance {
            body: context.body.clone(),
            revisions,
            calls,
        };
        verified.revisions.extend(
            validated
                .revisions
                .iter()
                .map(|(key, hashes)| ((context.key.tenant_id, key.clone()), Some(hashes.clone()))),
        );
        verified
            .calls
            .extend(validated.calls.iter().map(|((package, export), call)| {
                (
                    (context.key.tenant_id, package.clone(), export.clone()),
                    call.clone(),
                )
            }));
        let mut cache = self
            .package_provenance
            .lock()
            .map_err(|_| self.state_error("the package provenance cache lock is poisoned"))?;
        cache.entry(context.key.clone()).or_insert(validated);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::PackageRevisionV1;
    use crate::{ManagedCall, PackageArtifactV1, PackageBundle, PackageBundleV1};
    use araphor_analysis_builtins::{components, graph::Detector};
    use araphor_discovery_definition::ImagePin;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn verified_graph_implementation_requires_exact_component_and_pin() -> TestResult {
        for (component, canonical) in [
            (components::PROCESS, true),
            (components::CREDENTIALS, false),
        ] {
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
            let mut verified = VerifiedPackages::default();
            let mut writer = store.writer()?;
            store
                .read_context_verified_from(writer.get_mut()?, &root, &context.key, &mut verified)?
                .ok_or("verified package context")?;
            let call = ManagedCall {
                image: ImagePin {
                    image: package.clone(),
                    digest: bundle.digest().into(),
                },
                package,
                export: "detect".into(),
                arguments: Vec::new(),
                target: "wasm".into(),
                artifact: Some(identity),
                dependencies: Default::default(),
            };
            assert_eq!(verified.native_graph([1; 16], &call)?, Some(canonical));
            let mut forged = call;
            forged.artifact.as_mut().ok_or("Wasm pin")?.digest = "0".repeat(64);
            assert!(verified.native_graph([1; 16], &forged).is_err());
            writer.get_mut()?.execute(
                "UPDATE package_revisions SET artifact = ? WHERE tenant_id = ? AND package_id = ? AND revision = ?",
                params![b"changed".as_slice(), [1u8; 16].as_slice(), forged.package.package_id, forged.package.revision],
            )?;
            let mut fresh = VerifiedPackages::default();
            assert!(store
                .read_context_verified_from(writer.get_mut()?, &root, &context.key, &mut fresh)
                .is_err());
        }
        Ok(())
    }
}
