use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;



use super::*;
use crate::{PackageBundle, PackageRefV1};

type RevisionKey = ([u8; 16], PackageRefV1);

#[derive(Clone, Debug, Default)]
pub(in crate::analysis) struct VerifiedPackages {
    revisions: BTreeSet<RevisionKey>,
    roots: BTreeMap<RevisionKey, Arc<PackageProof>>,
    used: BTreeSet<RevisionKey>,
}

#[derive(Debug)]
struct PackageProof {
    rows: Vec<crate::analysis::PackageRevisionV1>,
    bundle: PackageBundle,
}

impl VerifiedPackages {
    pub(in crate::analysis) fn check_context(
        &mut self,
        context: &AnalysisContextVersionV1,
        mut read: impl FnMut([u8; 16], &str, &str) -> Result<Option<crate::analysis::PackageRevisionV1>>,
    ) -> Result<()> {
        let Some(reference) = context.package_provenance()? else {
            return Ok(());
        };
        let key = (context.key.tenant_id, reference.root.clone());
        if let Some(proof) = self.roots.get(&key) {
            let mut current = true;
            for row in &proof.rows {
                if read(key.0, &row.package_id, &row.revision)?.as_ref() != Some(row) {
                    current = false;
                    break;
                }
            }
            if current {
                reference.check_bundle(&proof.bundle)?;
                self.revisions.extend(proof.rows.iter().map(|row| {
                    (
                        key.0,
                        PackageRefV1 {
                            package_id: row.package_id.clone(),
                            revision: row.revision.clone(),
                        },
                    )
                }));
                self.used.insert(key);
                return Ok(());
            }
        }
        let (rows, artifacts) = crate::analysis::PackageRevisionV1::closure(
            key.0,
            &reference.root,
            &crate::AnalysisReadControl::default(),
            &mut read,
        )?;
        let bundle = reference.validate(artifacts)?;
        self.revisions.extend(rows.iter().map(|row| {
            (
                key.0,
                PackageRefV1 {
                    package_id: row.package_id.clone(),
                    revision: row.revision.clone(),
                },
            )
        }));
        self.roots
            .insert(key.clone(), Arc::new(PackageProof { rows, bundle }));
        self.used.insert(key);
        Ok(())
    }

    

    pub(in crate::analysis) fn seed(&self) -> Self {
        Self {
            roots: self.roots.clone(),
            ..Self::default()
        }
    }

    pub(in crate::analysis) fn retain(
        mut self,
        tenant: [u8; 16],
        active: &BTreeSet<&PackageRefV1>,
    ) -> Self {
        self.roots.retain(|key, _| {
            self.used.contains(key) || (key.0 == tenant && active.contains(&key.1))
        });
        self.revisions.clear();
        self.used.clear();
        self
    }

    #[cfg(test)]
    pub(in crate::analysis) fn shares_roots(&self, other: &Self) -> bool {
        self.roots.len() == other.roots.len()
            && self.roots.iter().all(|(key, proof)| {
                other
                    .roots
                    .get(key)
                    .is_some_and(|current| Arc::ptr_eq(proof, current))
            })
    }

    pub(in crate::analysis) fn metadata_bytes(&self) -> usize {
        self.roots.iter().fold(0usize, |bytes, ((_, key), proof)| {
            bytes
                .saturating_add(std::mem::size_of::<(RevisionKey, Arc<PackageProof>)>())
                .saturating_add(key.package_id.capacity())
                .saturating_add(key.revision.capacity())
                .saturating_add(std::mem::size_of::<PackageProof>())
                .saturating_add(
                    proof
                        .rows
                        .capacity()
                        .saturating_mul(std::mem::size_of::<crate::analysis::PackageRevisionV1>()),
                )
                .saturating_add(proof.bundle.allocated_bytes().unwrap_or(usize::MAX))
                .saturating_add(proof.rows.iter().fold(0usize, |bytes, row| {
                    bytes
                        .saturating_add(row.package_id.capacity())
                        .saturating_add(row.revision.capacity())
                        .saturating_add(row.descriptor.capacity())
                        .saturating_add(row.artifact.capacity())
                        .saturating_add(row.dependencies.capacity().saturating_mul(
                            std::mem::size_of::<crate::analysis::PackageRevisionRefV1>(),
                        ))
                        .saturating_add(row.dependencies.iter().fold(
                            0usize,
                            |bytes, dependency| {
                                bytes
                                    .saturating_add(dependency.package_id.capacity())
                                    .saturating_add(dependency.revision.capacity())
                            },
                        ))
                }))
        })
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::AnalysisStore;
    use crate::analysis::PackageRevisionV1;
    use crate::PackageImplementationV1;
    use crate::{PackageArtifactV1, PackageBundle, PackageBundleV1};
    use araphor_analysis_builtins::{components, graph::Detector};
    

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
            let retained_proof = verified.retain([1; 16], &BTreeSet::new());
            let active = BTreeSet::from([&package]);
            let idle = retained_proof.seed().retain([1; 16], &active);
            assert!(retained_proof.shares_roots(&idle));
            assert!(idle.revisions.is_empty());
            assert!(idle.used.is_empty());
            assert!(idle.seed().retain([2; 16], &active).roots.is_empty());
            let mut next = idle.seed();
            assert!(next.revisions.is_empty());
            store
                .read_context_verified_from(writer.get_mut()?, &root, &context.key, &mut next)?
                .ok_or("warm package context")?;
            let key = ([1; 16], package.clone());
            assert!(Arc::ptr_eq(&retained_proof.roots[&key], &next.roots[&key]));
            assert!(idle
                .seed()
                .retain([1; 16], &BTreeSet::new())
                .roots
                .is_empty());
            let original = AnalysisStore::package_from(
                writer.get_mut()?,
                [1; 16],
                &package.package_id,
                &package.revision,
            )?
            .ok_or("current package row")?;
            for (field, changed, restored) in [
                (
                    "descriptor",
                    duckdb::types::Value::Blob(b"changed".to_vec()),
                    duckdb::types::Value::Blob(original.descriptor.clone()),
                ),
                (
                    "dependencies",
                    duckdb::types::Value::Text(serde_json::to_string(&vec![
                        crate::analysis::PackageRevisionRefV1 {
                            package_id: "missing".into(),
                            revision: "r1".into(),
                        },
                    ])?),
                    duckdb::types::Value::Text(serde_json::to_string(&original.dependencies)?),
                ),
            ] {
                writer.get_mut()?.execute(
                    &format!("UPDATE package_revisions SET {field} = ? WHERE tenant_id = ? AND package_id = ? AND revision = ?"),
                    params![changed, [1u8; 16].as_slice(), package.package_id, package.revision],
                )?;
                assert!(store
                    .read_context_verified_from(
                        writer.get_mut()?,
                        &root,
                        &context.key,
                        &mut retained_proof.seed()
                    )
                    .is_err());
                writer.get_mut()?.execute(
                    &format!("UPDATE package_revisions SET {field} = ? WHERE tenant_id = ? AND package_id = ? AND revision = ?"),
                    params![restored, [1u8; 16].as_slice(), package.package_id, package.revision],
                )?;
            }
            let mut ambiguous = retained;
            ambiguous
                .implementations
                .push(ambiguous.implementations[0].clone());
            writer.get_mut()?.execute(
                "UPDATE package_revisions SET artifact = ? WHERE tenant_id = ? AND package_id = ? AND revision = ?",
                params![ambiguous.encode()?, [1u8; 16].as_slice(), package.package_id, package.revision],
            )?;
            assert!(store
                .read_context_verified_from(
                    writer.get_mut()?,
                    &root,
                    &context.key,
                    &mut retained_proof.seed()
                )
                .is_err());
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
