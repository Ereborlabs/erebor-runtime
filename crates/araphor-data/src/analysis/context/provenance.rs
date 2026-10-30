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

#[derive(Clone, Eq, PartialEq)]
struct ExportProof {
    identity: PackageArtifactIdentityV1,
    native_graph: bool,
}

#[derive(Clone, Eq, PartialEq)]
struct PackageProof {
    hashes: StoredHashes,
    exports: BTreeMap<String, ExportProof>,
}

#[derive(Default)]
pub(in crate::analysis) struct ValidationCache {
    contexts: BTreeMap<AnalysisContextKeyV1, ValidatedProvenance>,
    packages: BTreeMap<RevisionKey, PackageProof>,
}

#[derive(Clone, Default)]
pub(in crate::analysis) struct VerifiedPackages {
    revisions: BTreeMap<RevisionKey, Option<StoredHashes>>,
    calls: BTreeMap<CallKey, ExportProof>,
}

impl VerifiedPackages {
    fn insert_package(&mut self, tenant: [u8; 16], key: &PackageRefV1, proof: &PackageProof) {
        self.revisions
            .insert((tenant, key.clone()), Some(proof.hashes.clone()));
        self.calls.extend(
            proof
                .exports
                .iter()
                .map(|(export, proof)| ((tenant, key.clone(), export.clone()), proof.clone())),
        );
    }

    pub(in crate::analysis) fn native_graph(
        &self,
        tenant: [u8; 16],
        call: &crate::ManagedCall,
    ) -> Result<Option<bool>> {
        if call.target != "wasm" {
            return Ok(Some(false));
        }
        let key = (tenant, call.package.clone(), call.export.clone());
        let Some(proof) = self.calls.get(&key) else {
            return Ok(None);
        };
        if call.artifact.as_ref() != Some(&proof.identity) {
            return Err(crate::PackageErrorCodeV1::Invalid.error("verified Graph artifact"));
        }
        Ok(Some(proof.native_graph))
    }
}

impl PackageProof {
    fn from_artifact(artifact: &crate::PackageArtifactV1, hashes: StoredHashes) -> Result<Self> {
        let mut exports = BTreeMap::new();
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
                artifact.implementation(export)?;
                if exports
                    .insert(
                        export.clone(),
                        ExportProof {
                            identity: identity.clone(),
                            native_graph:
                                araphor_analysis_builtins::graph::Detector::supports_resume(
                                    &artifact.descriptor,
                                    export,
                                    component,
                                ),
                        },
                    )
                    .is_some()
                {
                    return Err(crate::PackageErrorCodeV1::Invalid.error("verified Wasm export"));
                }
            }
        }
        Ok(Self { hashes, exports })
    }
}

#[derive(Clone)]
pub(in crate::analysis) struct ValidatedProvenance {
    body: Vec<u8>,
    revisions: Vec<(PackageRefV1, StoredHashes)>,
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

    fn verified_package_from(
        &self,
        reader: &Connection,
        tenant: [u8; 16],
        key: &PackageRefV1,
        verified: &mut VerifiedPackages,
    ) -> Result<PackageProof> {
        let revision = (tenant, key.clone());
        let hashes = if let Some(hashes) = verified.revisions.get(&revision) {
            hashes.clone()
        } else {
            let hashes = Self::stored_package_hashes(reader, tenant, key)?;
            verified.revisions.insert(revision.clone(), hashes.clone());
            hashes
        }
        .ok_or_else(|| crate::PackageErrorCodeV1::Missing.error("verified package revision"))?;
        let cached = self
            .package_validation
            .lock()
            .map_err(|_| self.state_error("the package validation cache lock is poisoned"))?
            .packages
            .get(&revision)
            .cloned();
        if let Some(proof) = cached {
            if proof.hashes != hashes {
                return Err(crate::PackageErrorCodeV1::Invalid.error("changed package revision"));
            }
            verified.insert_package(tenant, key, &proof);
            return Ok(proof);
        }
        let package = Self::package_from(reader, tenant, &key.package_id, &key.revision)?
            .ok_or_else(|| crate::PackageErrorCodeV1::Missing.error("verified package revision"))?;
        let artifact = package.decode_artifact()?;
        let proof = PackageProof::from_artifact(&artifact, hashes)?;
        let mut cache = self
            .package_validation
            .lock()
            .map_err(|_| self.state_error("the package validation cache lock is poisoned"))?;
        match cache.packages.entry(revision) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(proof.clone());
            }
            std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &proof => {}
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(crate::PackageErrorCodeV1::Invalid.error("changed package revision"));
            }
        }
        verified.insert_package(tenant, key, &proof);
        Ok(proof)
    }

    pub(in crate::analysis) fn verify_package_revision(
        &self,
        reader: &Connection,
        tenant: [u8; 16],
        key: &PackageRefV1,
        verified: &mut VerifiedPackages,
    ) -> Result<()> {
        self.verified_package_from(reader, tenant, key, verified)
            .map(|_| ())
    }

    pub(in crate::analysis) fn verified_native_graph_call(
        &self,
        reader: &Connection,
        tenant: [u8; 16],
        declaration: &crate::ManagedCall,
        verified: &mut VerifiedPackages,
    ) -> Result<bool> {
        if declaration.target != "wasm" {
            return Ok(false);
        }
        self.verified_package_from(reader, tenant, &declaration.package, verified)?;
        verified
            .native_graph(tenant, declaration)?
            .ok_or_else(|| crate::PackageErrorCodeV1::Unsupported.error("model target"))
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
            .package_validation
            .lock()
            .map_err(|_| self.state_error("the package validation cache lock is poisoned"))?
            .contexts
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
                for (key, _) in &cached.revisions {
                    self.verified_package_from(reader, context.key.tenant_id, key, verified)
                        .map_err(crate::Error::stored_artifact)?;
                }
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
        let hashes = revisions.iter().cloned().collect::<BTreeMap<_, _>>();
        let mut proofs = BTreeMap::new();
        for artifact in &artifacts {
            let key = artifact.reference();
            let hashes = hashes.get(&key).cloned().ok_or_else(|| {
                crate::PackageErrorCodeV1::Missing.error("validated package revision")
            })?;
            proofs.insert(key, PackageProof::from_artifact(artifact, hashes)?);
        }
        reference
            .validate(artifacts)
            .map_err(crate::Error::stored_artifact)?;
        let validated = ValidatedProvenance {
            body: context.body.clone(),
            revisions,
        };
        let mut cache = self
            .package_validation
            .lock()
            .map_err(|_| self.state_error("the package validation cache lock is poisoned"))?;
        for (key, proof) in &proofs {
            let revision = (context.key.tenant_id, key.clone());
            if cache
                .packages
                .get(&revision)
                .is_some_and(|old| old != proof)
            {
                return Err(crate::PackageErrorCodeV1::Invalid.error("changed package revision"));
            }
        }
        for (key, proof) in &proofs {
            let revision = (context.key.tenant_id, key.clone());
            cache
                .packages
                .entry(revision)
                .or_insert_with(|| proof.clone());
            verified.insert_package(context.key.tenant_id, key, proof);
        }
        cache
            .contexts
            .entry(context.key.clone())
            .or_insert(validated);
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
            let mut writer = store.writer()?;
            let mut on_demand = VerifiedPackages::default();
            assert_eq!(
                store.verified_native_graph_call(
                    writer.get_mut()?,
                    [1; 16],
                    &call,
                    &mut on_demand,
                )?,
                canonical,
            );
            let mut warm = VerifiedPackages::default();
            assert_eq!(
                store.verified_native_graph_call(writer.get_mut()?, [1; 16], &call, &mut warm)?,
                canonical,
            );
            let mut verified = VerifiedPackages::default();
            store
                .read_context_verified_from(writer.get_mut()?, &root, &context.key, &mut verified)?
                .ok_or("verified package context")?;
            assert_eq!(verified.native_graph([1; 16], &call)?, Some(canonical));
            let mut forged = call.clone();
            forged.artifact.as_mut().ok_or("Wasm pin")?.digest = "0".repeat(64);
            assert!(verified.native_graph([1; 16], &forged).is_err());
            writer.get_mut()?.execute(
                "UPDATE package_revisions SET artifact = ? WHERE tenant_id = ? AND package_id = ? AND revision = ?",
                params![b"changed".as_slice(), [1u8; 16].as_slice(), forged.package.package_id, forged.package.revision],
            )?;
            let mut fresh = VerifiedPackages::default();
            assert!(store
                .verified_native_graph_call(writer.get_mut()?, [1; 16], &call, &mut fresh)
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
        let context =
            AnalysisContextVersionV1::from_package(&bundle, [1; 16], &package, "detect", &output)?;
        store.commit_context(&context)?;
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
        let mut writer = store.writer()?;
        let mut verified = VerifiedPackages::default();
        assert!(!store.verified_native_graph_call(
            writer.get_mut()?,
            [1; 16],
            &call,
            &mut verified,
        )?);
        store
            .read_context_verified_from(writer.get_mut()?, &root, &context.key, &mut verified)?
            .ok_or("mixed package context")?;
        drop(writer);
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        let mut writer = reopened.writer()?;
        let mut fresh = VerifiedPackages::default();
        assert!(!reopened.verified_native_graph_call(
            writer.get_mut()?,
            [1; 16],
            &call,
            &mut fresh,
        )?);
        Ok(())
    }

    #[test]
    fn package_proof_rejects_ambiguous_executable_export() {
        let artifact = PackageArtifactV1 {
            descriptor: Detector::Process.descriptor(),
            implementations: vec![
                PackageImplementationV1::Wasm {
                    exports: vec!["detect".into()],
                    artifact: components::PROCESS.to_vec(),
                },
                PackageImplementationV1::Wasm {
                    exports: vec!["detect".into()],
                    artifact: components::CREDENTIALS.to_vec(),
                },
            ],
            fixtures: Vec::new(),
        };
        let hashes = StoredHashes {
            descriptor: String::new(),
            artifact: String::new(),
            dependencies: String::new(),
        };
        assert!(PackageProof::from_artifact(&artifact, hashes).is_err());
    }
}
