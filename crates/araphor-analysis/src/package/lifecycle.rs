use std::collections::BTreeSet;
use std::sync::Arc;

use crate::analysis::{PackageActivationV1, PackageKeyV1};
use crate::{AnalysisReadControl, Result};

use super::installed::snapshot::InstalledBundle;
use super::owner::InstalledContext;
use araphor_data::ModelRef;
#[cfg(test)]
mod tests;

mod activation;
mod revisions;
use activation::ModelActivation;

use super::{
    AnalysisPackageOwner, PackageActionV1 as Action, PackageArtifactV1, PackageBundleV1,
    PackageErrorCodeV1 as Code, PackageGrantV1, PackageReadinessV1, PackageResponseV1,
};

impl AnalysisPackageOwner {
    pub(super) fn install(
        &self,
        grant: &PackageGrantV1,
        scope: &str,
        bundle: PackageBundleV1,
        parameters: Option<serde_json::Value>,
        upgrade: bool,
        control: &AnalysisReadControl,
    ) -> Result<PackageResponseV1> {
        araphor_data::validate_package_name(scope)?;
        let action = if upgrade {
            Action::Update
        } else {
            Action::Install
        };
        self.check(grant, action)?;
        let admitted = super::PackageBundleRef::new(&bundle)?;
        self.authority.admit(grant, &admitted)?;
        bundle.validate()?;
        let bundle = InstalledBundle::new(&self.query, bundle, self.query.memory())?;
        let admitted = bundle.admission();
        for artifact in &bundle.value.artifacts {
            self.admit_artifact(artifact, control)?;
        }
        Self::check_parameters(&bundle.value, parameters.as_ref())?;
        let activations = self.model_activations(grant, scope, &bundle, &parameters, upgrade)?;
        let prior_roots = if upgrade {
            self.store
                .package_activations_until(grant.selection.tenant_id, scope, None, control)?
                .into_iter()
                .map(|active| Self::decode::<InstalledContext>(&active.metadata))
                .collect::<araphor_data::Result<Vec<_>>>()?
                .into_iter()
                .map(|context| context.root)
                .filter(|root| {
                    root.package_id == bundle.value.root.package_id && *root != bundle.value.root
                })
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };
        let prior_bundles = prior_roots
            .iter()
            .map(|root| self.load_bundle(grant.selection.tenant_id, root, Some(control)))
            .collect::<araphor_data::Result<Vec<_>>>()?;
        let records = bundle
            .value
            .artifacts
            .iter()
            .map(|artifact| self.install_revision(grant, artifact))
            .collect::<Result<Vec<_>>>()?;
        self.authorize_commit(grant, action, &admitted, || {
            self.store.install_package(&records, || control.check())
        })?;
        for activation in activations {
            if let Err(error) = self.install_model(grant, &bundle, activation, upgrade, control) {
                for artifact in &bundle.value.artifacts {
                    self.store.collect_package(
                        grant.selection.tenant_id,
                        &artifact.descriptor.id,
                        &artifact.descriptor.revision,
                    )?;
                }
                return Err(error);
            }
        }
        for prior in prior_bundles {
            self.authorize_commit(grant, action, &admitted, || {
                self.prune_package(grant, scope, &prior, control)
            })?;
        }
        // The lifecycle lock prevents package replacement during this inspection.
        self.inspect(
            grant,
            scope,
            &bundle.value.root.package_id,
            Some(&bundle),
            control,
        )
    }

    fn install_model(
        &self,
        grant: &PackageGrantV1,
        bundle: &Arc<InstalledBundle>,
        prepared: ModelActivation,
        upgrade: bool,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let admitted = bundle.admission();
        control.check()?;
        let ModelActivation {
            mut active,
            previous,
            reuse,
        } = prepared;
        let action = if upgrade {
            Action::Update
        } else {
            Action::Install
        };
        if let Some(old) = previous.as_ref().filter(|_| reuse) {
            if old.metadata != active.metadata || old.grant_id != active.grant_id {
                self.authorize_commit(grant, action, &admitted, || {
                    self.store
                        .renew_package(old, &active.metadata, &grant.principal, || control.check())
                })?;
            }
            return Ok(());
        }
        if previous
            .as_ref()
            .is_some_and(|old| old.active && old.revision != active.revision)
        {
            if !active.active {
                return Err(Code::Unsupported.error("upgrade target").into());
            }
            active.checkpoint_revision = previous.as_ref().map_or(0, |old| old.checkpoint_revision);
            let artifact = bundle.value.artifact(&super::PackageRefV1 {
                package_id: active.key.package_id.clone(),
                revision: active.revision.clone(),
            })?;
            let evaluated = if artifact.prepared(&active.key.export) {
                None
            } else {
                control.check()?;
                let context: InstalledContext = Self::decode(&active.metadata)?;
                Some(
                    self.prepare_model(
                        &active,
                        &context,
                        bundle,
                        super::evaluation::RunPreparation {
                            inputs: None,
                            id: &format!(
                                "upgrade:{}:{}",
                                previous.as_ref().map_or(0, |old| old.generation),
                                active.revision
                            ),
                            rebuild: true,
                            now: Self::now(),
                        },
                        Action::Run,
                        control,
                    )?
                    .ok_or_else(|| Code::Conflict.error("prepared evaluation"))?,
                )
            };
            self.authorize_commit(grant, action, &admitted, || {
                self.store.activate_package(
                    &active,
                    previous.as_ref().map(|old| old.generation),
                    evaluated.as_ref(),
                    || control.check(),
                )
            })?;
        } else {
            let active = self.authorize_commit(grant, action, &admitted, || {
                self.store.activate_package(
                    &active,
                    previous.as_ref().map(|old| old.generation),
                    None,
                    || control.check(),
                )
            })?;
            if active.active {
                self.start_model(grant, bundle, &active, control)?;
            }
        }
        Ok(())
    }

    fn start_model(
        &self,
        grant: &PackageGrantV1,
        bundle: &Arc<InstalledBundle>,
        active: &PackageActivationV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let artifact = bundle
            .value
            .artifacts
            .iter()
            .find(|artifact| artifact.descriptor.id == active.key.package_id)
            .ok_or_else(|| Code::Missing.error("active artifact"))?;
        if artifact.prepared(&active.key.export) {
            return Ok(());
        }
        let mut context: InstalledContext = Self::decode(&active.metadata)?;
        if let Err(error) = self.evaluate_active(
            active,
            &context,
            &format!("install:{}", active.generation),
            bundle,
            control,
        ) {
            let Some(field) = error.missing_input() else {
                return Err(error);
            };
            context.readiness = PackageReadinessV1::MissingInput {
                input: field.into(),
            };
            self.authorize_commit(grant, Action::Install, &bundle.admission(), || {
                self.store.update_package_metadata(
                    &active.key,
                    active.generation,
                    &Self::encode(&context)?,
                    || control.check(),
                )
            })?;
        }
        Ok(())
    }

    pub(super) fn readiness(artifact: &PackageArtifactV1, export: &str) -> PackageReadinessV1 {
        let model = artifact
            .descriptor
            .exports
            .iter()
            .find(|model| model.name == export);
        let prepared = artifact.prepared(export);
        let domain_output = model.is_some_and(|model| {
            model
                .outputs
                .iter()
                .any(|port| port.kind != araphor_analysis_sdk::OutputKind::Table)
        });
        if prepared
            && domain_output
            && model.is_some_and(|model| {
                if crate::GraphAndFindingOwner::supports_analysis(model) {
                    return false;
                }
                let discovery = araphor_analysis_builtins::discovery::Discovery::package();
                artifact.descriptor.id != discovery.id
                    || !discovery.exports.iter().any(|expected| {
                        model.name == expected.name
                            && model
                                .inputs
                                .iter()
                                .map(|input| &input.port)
                                .eq(expected.inputs.iter().map(|input| &input.port))
                            && model.parameters == expected.parameters
                            && model.outputs == expected.outputs
                            && model.checkpoint == expected.checkpoint
                            && model.reasons == expected.reasons
                            && model.limits == expected.limits
                            && model.tolerance == expected.tolerance
                    })
            })
        {
            return PackageReadinessV1::Unsupported {
                target: "host input/output adapter".into(),
            };
        }
        if !prepared && domain_output {
            return PackageReadinessV1::Unsupported {
                target: "domain output adapter".into(),
            };
        }
        if artifact.implementation(export).is_ok() {
            PackageReadinessV1::Ready
        } else {
            PackageReadinessV1::Unsupported {
                target: artifact
                    .implementations
                    .iter()
                    .filter(|implementation| implementation.implements(export))
                    .map(|implementation| implementation.target())
                    .collect::<Vec<_>>()
                    .join(","),
            }
        }
    }

    pub(super) fn key(grant: &PackageGrantV1, scope: &str, model: &ModelRef) -> PackageKeyV1 {
        PackageKeyV1 {
            tenant_id: grant.selection.tenant_id,
            scope_id: scope.into(),
            package_id: model.package.package_id.clone(),
            export: model.export.clone(),
        }
    }
}
