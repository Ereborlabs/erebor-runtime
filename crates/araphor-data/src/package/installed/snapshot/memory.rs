use std::collections::BTreeMap;
use std::mem::size_of;
use std::sync::Arc;

use serde_json::Value;

use crate::analysis::PackageActivationV1;
use crate::package::{
    PackageBundleV1, PackageCheckpointV1, PackageDatasetV1, PackageErrorCodeV1 as Code,
    PackageFixtureV1, PackageImplementationV1, PackageOutputV1,
};
use crate::{Result, SqlModelV1};

use super::{InstalledBundle, InstalledSnapshot};

pub(super) struct BundleMemory {
    bytes: usize,
}

impl BundleMemory {
    pub(super) fn bundle(value: &PackageBundleV1) -> Result<usize> {
        let mut memory = Self { bytes: 0 };
        memory.add(size_of::<InstalledBundle>() + 2 * size_of::<usize>())?;
        memory.strings([&value.root.package_id, &value.root.revision])?;
        memory.vector(&value.artifacts)?;
        for artifact in &value.artifacts {
            memory.add(artifact.descriptor.allocated_bytes())?;
            memory.vector(&artifact.implementations)?;
            for implementation in &artifact.implementations {
                memory.implementation(implementation)?;
            }
            memory.vector(&artifact.fixtures)?;
            for fixture in &artifact.fixtures {
                memory.fixture(fixture)?;
            }
        }
        Ok(memory.bytes)
    }

    pub(super) fn snapshot(
        pins: &Vec<PackageActivationV1>,
        bundles: &Vec<Arc<InstalledBundle>>,
    ) -> Result<usize> {
        let mut memory = Self { bytes: 0 };
        memory.add(size_of::<InstalledSnapshot>() + 2 * size_of::<usize>())?;
        memory.vector(pins)?;
        memory.vector(bundles)?;
        for pin in pins {
            memory.strings([
                &pin.key.scope_id,
                &pin.key.package_id,
                &pin.key.export,
                &pin.revision,
                &pin.grant_id,
            ])?;
            if let Some(result) = &pin.result_id {
                memory.add(result.capacity())?;
            }
            memory.vector(&pin.metadata)?;
        }
        Ok(memory.bytes)
    }

    fn add(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| Code::Limit.error("installed snapshot memory"))?;
        Ok(())
    }

    fn vector<T>(&mut self, values: &Vec<T>) -> Result<()> {
        self.add(
            values
                .capacity()
                .checked_mul(size_of::<T>())
                .ok_or_else(|| Code::Limit.error("installed snapshot memory"))?,
        )
    }

    fn strings<'a>(&mut self, values: impl IntoIterator<Item = &'a String>) -> Result<()> {
        for value in values {
            self.add(value.capacity())?;
        }
        Ok(())
    }

    fn tree<K, V>(&mut self, count: usize) -> Result<()> {
        // Allow one full node per entry and one node for an empty tree.
        let node = size_of::<(K, V)>()
            .checked_mul(11)
            .and_then(|bytes| bytes.checked_add(16 * size_of::<usize>()))
            .and_then(|bytes| bytes.checked_mul(count.max(1)))
            .ok_or_else(|| Code::Limit.error("installed snapshot memory"))?;
        self.add(node)
    }

    fn bindings(&mut self, values: &BTreeMap<String, String>) -> Result<()> {
        self.tree::<String, String>(values.len())?;
        for (key, value) in values {
            self.strings([key, value])?;
        }
        Ok(())
    }

    fn value(&mut self, value: &Value) -> Result<()> {
        match value {
            Value::String(value) => self.add(value.capacity()),
            Value::Array(values) => {
                self.vector(values)?;
                for value in values {
                    self.value(value)?;
                }
                Ok(())
            }
            Value::Object(values) => {
                self.tree::<String, Value>(values.len())?;
                for (key, value) in values {
                    self.add(key.capacity())?;
                    self.value(value)?;
                }
                Ok(())
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
        }
    }

    fn implementation(&mut self, value: &PackageImplementationV1) -> Result<()> {
        match value {
            PackageImplementationV1::Sql {
                export,
                inputs,
                program,
            } => {
                self.add(export.capacity())?;
                self.bindings(inputs)?;
                self.program(program)
            }
            PackageImplementationV1::Wasm {
                exports,
                inputs,
                artifact,
            } => {
                self.vector(exports)?;
                self.strings(exports)?;
                if let Some(inputs) = inputs {
                    self.bindings(inputs)?;
                }
                self.vector(artifact)
            }
            PackageImplementationV1::Native {
                export,
                artifact,
                qualification,
            } => {
                self.add(export.capacity())?;
                self.vector(artifact)?;
                if let Some(qualification) = qualification {
                    self.vector(&qualification.exports)?;
                    self.strings(&qualification.exports)?;
                    self.add(qualification.target.capacity())?;
                    self.vector(&qualification.cpu_features)?;
                    self.strings(&qualification.cpu_features)?;
                    if let Some(inputs) = &qualification.inputs {
                        self.bindings(inputs)?;
                    }
                    self.vector(&qualification.dependencies)?;
                    for dependency in &qualification.dependencies {
                        self.strings([&dependency.name, &dependency.digest])?;
                        self.vector(&dependency.artifact)?;
                    }
                    self.vector(&qualification.system_libraries)?;
                    for library in &qualification.system_libraries {
                        self.add(library.name.capacity())?;
                        self.vector(&library.symbols)?;
                        self.strings(&library.symbols)?;
                        self.vector(&library.versions)?;
                        self.strings(&library.versions)?;
                    }
                }
                Ok(())
            }
            PackageImplementationV1::Python { export, artifact } => {
                self.add(export.capacity())?;
                self.vector(artifact)
            }
        }
    }

    fn program(&mut self, value: &SqlModelV1) -> Result<()> {
        self.bindings(&value.outputs)?;
        self.bindings(&value.checkpoint)?;
        if let Some(evidence) = &value.evidence {
            self.add(evidence.capacity())?;
        }
        self.vector(&value.reasons)?;
        for reason in &value.reasons {
            self.strings([&reason.output, &reason.code, &reason.sql])?;
        }
        Ok(())
    }

    fn fixture(&mut self, value: &PackageFixtureV1) -> Result<()> {
        self.strings([&value.name, &value.export])?;
        self.vector(&value.inputs)?;
        for input in &value.inputs {
            self.dataset(&input.data)?;
            self.strings([&input.revision.owner, &input.revision.id])?;
            if let Some(window) = &input.revision.window {
                self.vector(&window.source)?;
            }
            self.vector(&input.coverage.limits)?;
            self.strings(&input.coverage.limits)?;
        }
        if let Some(parameters) = &value.parameters {
            self.value(parameters)?;
        }
        if let Some(checkpoint) = &value.checkpoint {
            self.checkpoint(checkpoint)?;
        }
        self.output(&value.expected)
    }

    fn dataset(&mut self, value: &PackageDatasetV1) -> Result<()> {
        self.add(value.name.capacity())?;
        self.vector(&value.ipc)
    }

    fn checkpoint(&mut self, value: &PackageCheckpointV1) -> Result<()> {
        self.vector(&value.datasets)?;
        for data in &value.datasets {
            self.dataset(data)?;
        }
        Ok(())
    }

    fn output(&mut self, value: &PackageOutputV1) -> Result<()> {
        self.vector(&value.datasets)?;
        for data in &value.datasets {
            self.dataset(data)?;
        }
        self.vector(&value.evidence)?;
        for link in &value.evidence {
            self.strings([&link.output.dataset, &link.input.dataset])?;
        }
        self.vector(&value.reasons)?;
        for reason in &value.reasons {
            self.strings([&reason.output.dataset, &reason.code])?;
            self.dataset(&reason.details)?;
        }
        if let Some(checkpoint) = &value.checkpoint {
            self.checkpoint(checkpoint)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
