use crate::analysis::PackageActivationV1;
use crate::{QueryOwner, Result};

use super::super::admission::ModelRef;
use super::super::owner::InstalledContext;
use super::super::{
    AnalysisPackageOwner, PackageBundleV1, PackageErrorCodeV1 as Code, PackageGrantV1,
    PackageReadinessV1,
};

pub(super) struct ModelActivation {
    pub active: PackageActivationV1,
    pub previous: Option<PackageActivationV1>,
    pub reuse: bool,
}

impl AnalysisPackageOwner {
    pub(super) fn model_activations(
        &self,
        grant: &PackageGrantV1,
        scope: &str,
        bundle: &PackageBundleV1,
        parameters: &Option<serde_json::Value>,
        upgrade: bool,
    ) -> Result<Vec<ModelActivation>> {
        let mut activations = Vec::new();
        for key in bundle.order()? {
            let activation =
                self.model_activation(grant, scope, bundle, &key, parameters, upgrade)?;
            activations.push(activation);
        }
        Ok(activations)
    }

    pub(super) fn model_activation(
        &self,
        grant: &PackageGrantV1,
        scope: &str,
        bundle: &PackageBundleV1,
        key: &ModelRef,
        parameters: &Option<serde_json::Value>,
        upgrade: bool,
    ) -> Result<ModelActivation> {
        let artifact = bundle.artifact(&key.package)?;
        let storage_key = Self::key(grant, scope, key);
        let previous = self.store.package_activation(&storage_key)?;
        let prior = previous
            .as_ref()
            .map(|active| Self::decode::<InstalledContext>(&active.metadata))
            .transpose()?;
        let replacing = self.store.package_installed(&storage_key)?;
        let same_revision = replacing
            && previous
                .as_ref()
                .is_some_and(|old| old.revision == key.package.revision);
        if replacing && !same_revision && !upgrade {
            return Err(Code::Conflict.error("installed revision"));
        }
        let parameters = parameters
            .clone()
            .or_else(|| prior.as_ref().and_then(|prior| prior.parameters.clone()));
        if same_revision
            && prior.as_ref().is_some_and(|prior| {
                Self::parameter_values(
                    prior.parameters.as_ref(),
                    &key.package.package_id,
                    &key.export,
                ) != Self::parameter_values(
                    parameters.as_ref(),
                    &key.package.package_id,
                    &key.export,
                ) || prior.grant.selection != grant.selection
            })
        {
            return Err(Code::Conflict.error("activation parameters or scope"));
        }
        let model = artifact
            .descriptor
            .exports
            .iter()
            .find(|model| model.name == key.export)
            .ok_or_else(|| Code::Missing.error("installed export"))?;
        QueryOwner::model_parameters(
            &model.parameters,
            Self::parameter_values(parameters.as_ref(), &key.package.package_id, &key.export),
        )?;
        let readiness = Self::readiness(artifact, &key.export);
        let restart = same_revision
            && previous.as_ref().is_some_and(|old| !old.active)
            && matches!(readiness, PackageReadinessV1::Ready);
        let reuse = same_revision && !restart;
        let mut context = if same_revision {
            prior.ok_or_else(|| Code::Missing.error("installed context"))?
        } else {
            InstalledContext {
                grant: grant.clone(),
                root: bundle.root.clone(),
                parameters,
                readiness,
                status_checkpoint: previous
                    .as_ref()
                    .map_or(0, |active| active.checkpoint_revision),
            }
        };
        if restart {
            context.readiness = PackageReadinessV1::Ready;
            context.status_checkpoint = 0;
        }
        context.grant = grant.clone();
        if key.package == bundle.root {
            context.root = bundle.root.clone();
        }
        let metadata = Self::encode(&context)?;
        if metadata.len() > crate::analysis::MAX_PACKAGE_METADATA_BYTES {
            return Err(Code::Limit.error("model metadata bytes"));
        }
        let active = PackageActivationV1 {
            key: storage_key,
            revision: key.package.revision.clone(),
            generation: 0,
            checkpoint_revision: 0,
            result_id: None,
            grant_id: grant.principal.clone(),
            metadata,
            active: if reuse {
                previous.as_ref().is_some_and(|old| old.active)
            } else {
                matches!(context.readiness, PackageReadinessV1::Ready)
            },
        };
        Ok(ModelActivation {
            active,
            previous,
            reuse,
        })
    }

    pub(in crate::package) fn parameter_values<'a>(
        parameters: Option<&'a serde_json::Value>,
        package: &str,
        export: &str,
    ) -> Option<&'a serde_json::Value> {
        parameters
            .and_then(|value| value.get(package))
            .and_then(|value| value.get(export))
    }

    pub(super) fn check_parameters(
        bundle: &PackageBundleV1,
        parameters: Option<&serde_json::Value>,
    ) -> Result<()> {
        let Some(parameters) = parameters else {
            return Ok(());
        };
        let packages = parameters
            .as_object()
            .ok_or_else(|| Code::Invalid.error("package parameter object"))?;
        for (package, values) in packages {
            let artifact = bundle
                .artifacts
                .iter()
                .find(|artifact| artifact.descriptor.id == *package)
                .ok_or_else(|| Code::Invalid.error("parameter package"))?;
            let exports = values
                .as_object()
                .ok_or_else(|| Code::Invalid.error("export parameter object"))?;
            for (export, value) in exports {
                let model = artifact
                    .descriptor
                    .exports
                    .iter()
                    .find(|model| model.name == *export)
                    .ok_or_else(|| Code::Invalid.error("parameter export"))?;
                QueryOwner::model_parameters(&model.parameters, Some(value))?;
            }
        }
        Ok(())
    }
}
