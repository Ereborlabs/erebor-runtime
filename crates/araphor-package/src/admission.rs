use std::collections::{BTreeMap, BTreeSet};

use snafu::ResultExt as _;

use crate::{AnalysisContractSnafu, Result};

use super::{ErrorCode as Code, PackageArtifactV1, PackageBundleV1, PackageRefV1};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ModelRef {
    pub package: PackageRefV1,
    pub export: String,
}

impl PackageBundleV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.artifacts.is_empty() {
            return Err(Code::Invalid.error("bundle version or package count"));
        }
        let mut packages = BTreeSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !packages.insert(artifact.reference()) {
                return Err(Code::Invalid.error("duplicate package revision"));
            }
        }
        self.artifact(&self.root)?;
        let mut used = BTreeSet::new();
        let mut visiting = BTreeSet::new();
        let mut pending = vec![(self.root.clone(), false)];
        let mut states = BTreeMap::new();
        let mut order = Vec::new();
        while let Some((reference, complete)) = pending.pop() {
            if complete {
                visiting.remove(&reference);
                used.insert(reference);
                continue;
            }
            if used.contains(&reference) {
                continue;
            }
            if !visiting.insert(reference.clone()) {
                return Err(Code::Invalid.error("artifact dependency cycle"));
            }
            let artifact = self.artifact(&reference)?;
            pending.push((reference.clone(), true));
            pending.extend(
                artifact
                    .descriptor
                    .exports
                    .iter()
                    .flat_map(|model| model.dependencies().map(|(_, dependency)| dependency))
                    .filter(|dependency| dependency.package != artifact.descriptor.id)
                    .map(|dependency| {
                        (
                            PackageRefV1 {
                                package_id: dependency.package.clone(),
                                revision: dependency.revision.clone(),
                            },
                            false,
                        )
                    }),
            );
            for model in &artifact.descriptor.exports {
                self.visit(
                    ModelRef {
                        package: reference.clone(),
                        export: model.name.clone(),
                    },
                    &mut states,
                    &mut order,
                )?;
            }
        }
        if used != packages {
            return Err(Code::Invalid.error("unreferenced package artifact"));
        }
        self.order()?;
        self.check_encoding()?;
        Ok(())
    }

    pub fn order(&self) -> Result<Vec<ModelRef>> {
        self.order_for(&self.root, None)
    }

    pub fn order_for(&self, root: &PackageRefV1, export: Option<&str>) -> Result<Vec<ModelRef>> {
        let mut states = BTreeMap::new();
        let mut order = Vec::new();
        for model in self
            .artifact(root)?
            .descriptor
            .exports
            .iter()
            .filter(|model| export.is_none_or(|export| export == model.name))
        {
            self.visit(
                ModelRef {
                    package: root.clone(),
                    export: model.name.clone(),
                },
                &mut states,
                &mut order,
            )?;
        }
        if order.is_empty() {
            return Err(Code::Missing.error("requested export"));
        }
        let mut revisions = BTreeMap::new();
        for model in &order {
            let key = (&model.package.package_id, &model.export);
            if revisions
                .insert(key, &model.package.revision)
                .is_some_and(|revision| revision != &model.package.revision)
            {
                return Err(Code::Conflict.error("dependency export revisions"));
            }
        }
        Ok(order)
    }

    fn visit(
        &self,
        key: ModelRef,
        states: &mut BTreeMap<ModelRef, bool>,
        order: &mut Vec<ModelRef>,
    ) -> Result<()> {
        let mut pending = vec![(key, false)];
        while let Some((key, complete)) = pending.pop() {
            if complete {
                states.insert(key.clone(), true);
                order.push(key);
                continue;
            }
            match states.get(&key) {
                Some(true) => continue,
                Some(false) => return Err(Code::Invalid.error("dependency cycle")),
                None => {}
            }
            let artifact = self.artifact(&key.package)?;
            let model = artifact
                .descriptor
                .exports
                .iter()
                .find(|model| model.name == key.export)
                .ok_or_else(|| Code::Missing.error("dependency export"))?;
            states.insert(key.clone(), false);
            pending.push((key, true));
            let mut dependencies = Vec::new();
            for (input, dependency) in model.dependencies() {
                let upstream = ModelRef {
                    package: PackageRefV1 {
                        package_id: dependency.package.clone(),
                        revision: dependency.revision.clone(),
                    },
                    export: dependency.export.clone(),
                };
                let output = self
                    .artifact(&upstream.package)?
                    .descriptor
                    .exports
                    .iter()
                    .find(|export| export.name == upstream.export)
                    .and_then(|export| {
                        export
                            .outputs
                            .iter()
                            .find(|port| port.name == dependency.output)
                    })
                    .ok_or_else(|| Code::Missing.error("dependency output"))?;
                if input.schema != output.schema || input.kind != output.kind {
                    return Err(Code::Invalid.error("dependency schema or kind"));
                }
                dependencies.push((upstream, false));
            }
            pending.extend(dependencies.into_iter().rev());
        }
        Ok(())
    }
}

impl PackageArtifactV1 {
    fn validate(&self) -> Result<()> {
        self.descriptor.validate().context(AnalysisContractSnafu)?;
        if self.implementations.is_empty() {
            return Err(Code::Limit.error("implementations or fixtures"));
        }
        let mut implementations = BTreeSet::new();
        for implementation in &self.implementations {
            if let super::PackageImplementationV1::Native {
                export,
                qualification: Some(qualification),
                ..
            } = implementation
            {
                if !qualification.exports.contains(export) {
                    return Err(Code::Invalid.error("native export declaration"));
                }
            }
            if implementation.exports().is_empty() {
                return Err(Code::Invalid.error("implementation export count"));
            }
            for export in implementation.exports() {
                if !self
                    .descriptor
                    .exports
                    .iter()
                    .any(|model| model.name == *export)
                    || !implementations.insert((export, implementation.target()))
                {
                    return Err(Code::Invalid.error("implementation export or target"));
                }
            }
        }
        for model in &self.descriptor.exports {
            if !self
                .implementations
                .iter()
                .any(|implementation| implementation.implements(&model.name))
            {
                return Err(Code::Missing.error("export implementation"));
            }
            match self.implementation(&model.name) {
                Ok(_)
                | Err(crate::Error::Package {
                    code: Code::Unsupported,
                    ..
                }) => {}
                Err(error) => return Err(error),
            }
        }
        let mut fixtures = BTreeSet::new();
        for fixture in &self.fixtures {
            if fixture.name.is_empty()
                || !fixtures.insert(&fixture.name)
                || !self
                    .descriptor
                    .exports
                    .iter()
                    .any(|model| model.name == fixture.export)
            {
                return Err(Code::Invalid.error("fixture name or export"));
            }
        }
        Ok(())
    }
}
