use std::collections::{BTreeMap, BTreeSet};

use snafu::ResultExt as _;

use crate::{AnalysisContractSnafu, Result};

use super::{PackageArtifactV1, PackageBundleV1, PackageErrorCodeV1 as Code, PackageRefV1};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ModelRef {
    pub package: PackageRefV1,
    pub export: String,
}

impl PackageBundleV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.artifacts.is_empty() || self.artifacts.len() > 64 {
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
                    .dependencies
                    .iter()
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
        self.encode()?;
        Ok(())
    }

    pub(super) fn order(&self) -> Result<Vec<ModelRef>> {
        self.order_for(&self.root, None)
    }

    pub(super) fn order_for(
        &self,
        root: &PackageRefV1,
        export: Option<&str>,
    ) -> Result<Vec<ModelRef>> {
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
        match states.get(&key) {
            Some(true) => return Ok(()),
            Some(false) => return Err(Code::Invalid.error("dependency cycle")),
            None => {}
        }
        if states.len() >= 256 {
            return Err(Code::Limit.error("dependency models"));
        }
        let artifact = self.artifact(&key.package)?;
        let model = artifact
            .descriptor
            .exports
            .iter()
            .find(|model| model.name == key.export)
            .ok_or_else(|| Code::Missing.error("dependency export"))?;
        states.insert(key.clone(), false);
        for dependency in artifact
            .descriptor
            .dependencies
            .iter()
            .filter(|dependency| dependency.model == key.export)
        {
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
            let input = model
                .inputs
                .iter()
                .find(|port| port.name == dependency.input)
                .ok_or_else(|| Code::Invalid.error("dependency input"))?;
            if input.schema != output.schema || input.kind != output.kind {
                return Err(Code::Invalid.error("dependency schema or kind"));
            }
            self.visit(upstream, states, order)?;
        }
        states.insert(key.clone(), true);
        order.push(key);
        Ok(())
    }
}

impl PackageArtifactV1 {
    fn validate(&self) -> Result<()> {
        self.descriptor.validate().context(AnalysisContractSnafu)?;
        if self.implementations.is_empty()
            || self.implementations.len() > 256
            || self.fixtures.len() > 64
        {
            return Err(Code::Limit.error("implementations or fixtures"));
        }
        let mut implementations = BTreeSet::new();
        for implementation in &self.implementations {
            if implementation.exports().is_empty() || implementation.exports().len() > 256 {
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
            let Some(sources) = self
                .implementation(&model.name)
                .ok()
                .and_then(|entry| entry.bindings())
            else {
                continue;
            };
            let dependencies: BTreeSet<_> = self
                .descriptor
                .dependencies
                .iter()
                .filter(|dependency| dependency.model == model.name)
                .map(|dependency| dependency.input.as_str())
                .collect();
            if sources
                .keys()
                .any(|name| !model.inputs.iter().any(|port| port.name == *name))
                || model.inputs.iter().any(|port| {
                    sources.contains_key(&port.name) == dependencies.contains(port.name.as_str())
                })
            {
                return Err(Code::Invalid.error("input binding"));
            }
        }
        let mut fixtures = BTreeSet::new();
        for fixture in &self.fixtures {
            if fixture.name.is_empty()
                || fixture.name.len() > 256
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
