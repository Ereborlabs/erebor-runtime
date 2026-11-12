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
    use crate::analysis::{native::DataView, AnalysisStore, PackageRevisionV1};
    use crate::{AnalysisReadControl, PackageArtifactV1, PackageBundleV1, PackageImplementationV1};
    use araphor_analysis_builtins::{components, discovery::Discovery, graph::Detector};

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    type Stored = (PackageRevisionV1, u64, u64);

    fn artifact(descriptor: araphor_analysis_sdk::Package, component: &[u8]) -> PackageArtifactV1 {
        let exports = descriptor
            .exports
            .iter()
            .map(|model| model.name.clone())
            .collect();
        PackageArtifactV1 {
            descriptor,
            implementations: vec![PackageImplementationV1::Wasm {
                exports,
                artifact: component.to_vec(),
            }],
            fixtures: Vec::new(),
        }
    }

    fn record(view: &DataView, package: &PackageRefV1) -> TestResult<(Vec<u8>, Stored)> {
        for entry in view.snapshot().prefix(b"\0data/P") {
            let (key, bytes) = entry?;
            if key.len() != 15 {
                continue;
            }
            assert_eq!(bytes[0], 0);
            let row: Stored = rmp_serde::from_slice(&bytes[1..])?;
            if row.0.tenant_id == [1; 16]
                && row.0.package_id == package.package_id
                && row.0.revision == package.revision
            {
                assert!(row.0.artifact.is_empty());
                return Ok((key.to_vec(), row));
            }
        }
        Err("package record absent".into())
    }

    fn replace(store: &AnalysisStore, key: &[u8], row: &Stored, body: Option<&[u8]>) -> TestResult {
        let mut writer = store.write()?;
        writer
            .native()
            .insert(key, [vec![0], rmp_serde::to_vec(row)?].concat());
        if let Some(body) = body {
            assert_eq!(row.2, body.len() as u64);
            writer.native().insert(
                [b"\0data/@package-body/".as_slice(), &key[7..]].concat(),
                [vec![0], body.to_vec()].concat(),
            );
        }
        writer.commit([])?;
        Ok(())
    }

    #[test]
    fn verified_package_rechecks_current_bytes_and_export_identity() -> TestResult {
        for (descriptor, component, export) in [
            (Discovery::package(), components::DISCOVERY, "atoms"),
            (
                Detector::Credentials.descriptor(),
                components::CREDENTIALS,
                "detect",
            ),
        ] {
            let directory = tempfile::tempdir()?;
            let store = AnalysisStore::open(directory.path().join("store"))?;
            let artifact = artifact(descriptor, component);
            let package = artifact.reference();
            let output = artifact
                .descriptor
                .exports
                .iter()
                .find(|model| model.name == export)
                .and_then(|model| model.outputs.first())
                .ok_or("detect output")?
                .name
                .clone();
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
                &bundle, [1; 16], &package, export, &output,
            )?;
            store.commit_context(&context)?;
            let control = AnalysisReadControl::default();
            let held = store.view()?;
            let check = |view: &DataView, verified: &mut VerifiedPackages| {
                verified.check_context(&context, |tenant, package, revision| {
                    view.package_revision(tenant, package, revision, &control)
                })
            };
            let mut on_demand = VerifiedPackages::default();
            check(&held, &mut on_demand)?;
            let original = held
                .package_revision([1; 16], &package.package_id, &package.revision, &control)?
                .ok_or("verified package")?;
            let retained = original.decode_artifact()?;
            assert_eq!(retained.implementation(export)?.identity()?, Some(identity));
            let mut warm = VerifiedPackages::default();
            check(&held, &mut warm)?;
            assert_eq!(
                held.context(&context.key)?
                    .ok_or("verified package context")?
                    .0,
                context
            );
            let mut verified = VerifiedPackages::default();
            check(&held, &mut verified)?;
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
            assert_eq!(
                held.context(&context.key)?.ok_or("warm package context")?.0,
                context
            );
            check(&held, &mut next)?;
            let key = ([1; 16], package.clone());
            assert!(Arc::ptr_eq(&retained_proof.roots[&key], &next.roots[&key]));
            assert!(idle
                .seed()
                .retain([1; 16], &BTreeSet::new())
                .roots
                .is_empty());
            let (key, original_row) = record(&held, &package)?;
            for field in ["descriptor", "dependencies"] {
                let mut changed = original_row.clone();
                if field == "descriptor" {
                    changed.0.descriptor = b"changed".to_vec();
                } else {
                    changed.0.dependencies = vec![crate::analysis::PackageRevisionRefV1 {
                        package_id: "missing".into(),
                        revision: "r1".into(),
                    }];
                }
                replace(&store, &key, &changed, None)?;
                let current = store.view()?;
                assert!(check(&current, &mut retained_proof.seed()).is_err());
                assert!(current.context(&context.key).is_err());
                check(&held, &mut retained_proof.seed())?;
                assert_eq!(
                    held.package_revision(
                        [1; 16],
                        &package.package_id,
                        &package.revision,
                        &control
                    )?,
                    Some(original.clone())
                );
                replace(&store, &key, &original_row, None)?;
                let repaired = store.view()?;
                check(&repaired, &mut retained_proof.seed())?;
                assert_eq!(
                    repaired
                        .context(&context.key)?
                        .ok_or("repaired package context")?
                        .0,
                    context
                );
            }
            let mut ambiguous = retained;
            ambiguous
                .implementations
                .push(ambiguous.implementations[0].clone());
            for body in [ambiguous.encode()?, b"changed".to_vec()] {
                let mut changed = original_row.clone();
                changed.2 = body.len() as u64;
                replace(&store, &key, &changed, Some(&body))?;
                let current = store.view()?;
                assert_eq!(
                    current
                        .package_revision(
                            [1; 16],
                            &package.package_id,
                            &package.revision,
                            &control
                        )?
                        .ok_or("changed package")?
                        .artifact,
                    body
                );
                assert!(check(&current, &mut retained_proof.seed()).is_err());
                let mut fresh = VerifiedPackages::default();
                assert!(check(&current, &mut fresh).is_err());
                assert!(current.context(&context.key).is_err());
                check(&held, &mut retained_proof.seed())?;
            }
        }
        Ok(())
    }

    #[test]
    fn mixed_image_context_accepts_unqualified_native_export() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let mut artifact = artifact(Detector::Credentials.descriptor(), components::CREDENTIALS);
        let mut offline = artifact
            .descriptor
            .exports
            .iter()
            .find(|model| model.name == "detect")
            .ok_or("detect model")?
            .clone();
        let output = offline.outputs.first().ok_or("detect output")?.name.clone();
        offline.name = "offline".into();
        artifact.descriptor.exports.push(offline);
        artifact
            .implementations
            .push(PackageImplementationV1::Native {
                export: "offline".into(),
                artifact: vec![1],
                qualification: None,
            });
        let package = artifact.reference();
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
        let control = AnalysisReadControl::default();
        let view = store.view()?;
        let mut verified = VerifiedPackages::default();
        verified.check_context(&context, |tenant, package, revision| {
            view.package_revision(tenant, package, revision, &control)
        })?;
        assert_eq!(
            view.context(&context.key)?
                .ok_or("mixed package context")?
                .0,
            context
        );
        drop(view);
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        let view = reopened.view()?;
        let mut fresh = VerifiedPackages::default();
        fresh.check_context(&context, |tenant, package, revision| {
            view.package_revision(tenant, package, revision, &control)
        })?;
        assert_eq!(
            view.context(&context.key)?
                .ok_or("reopened mixed package context")?
                .0,
            context
        );
        Ok(())
    }
}
