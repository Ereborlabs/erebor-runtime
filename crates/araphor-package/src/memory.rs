use std::collections::BTreeMap;
use std::mem::size_of;

use crate::{
    ErrorCode, PackageArtifactV1, PackageBundleV1, PackageFixtureV1, PackageImplementationV1,
    Qualification, Result, SqlModelV1,
};

impl PackageBundleV1 {
    pub fn allocated_bytes(&self) -> Result<usize> {
        sum([
            self.root.package_id.capacity(),
            self.root.revision.capacity(),
            vector(&self.artifacts, |artifact| artifact.allocated_bytes())?,
        ])
    }
}

impl PackageArtifactV1 {
    fn allocated_bytes(&self) -> Result<usize> {
        sum([
            self.descriptor.allocated_bytes(),
            vector(&self.implementations, |implementation| {
                implementation.allocated_bytes()
            })?,
            vector(&self.fixtures, |fixture| fixture.allocated_bytes())?,
        ])
    }
}

impl PackageImplementationV1 {
    fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::Sql { export, program } => sum([export.capacity(), program.allocated_bytes()?]),
            Self::Wasm { exports, artifact } => sum([strings(exports)?, artifact.capacity()]),
            Self::Native {
                export,
                artifact,
                qualification,
            } => sum([
                export.capacity(),
                artifact.capacity(),
                qualification
                    .as_ref()
                    .map(Qualification::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
            ]),
            Self::Python { export, artifact } => sum([export.capacity(), artifact.capacity()]),
        }
    }
}

impl SqlModelV1 {
    fn allocated_bytes(&self) -> Result<usize> {
        sum([
            tree(&self.outputs)?,
            tree(&self.checkpoint)?,
            self.evidence.as_ref().map_or(0, String::capacity),
            vector(&self.reasons, |reason| {
                sum([
                    reason.output.capacity(),
                    reason.code.capacity(),
                    reason.sql.capacity(),
                ])
            })?,
        ])
    }
}

impl Qualification {
    fn allocated_bytes(&self) -> Result<usize> {
        sum([
            strings(&self.exports)?,
            self.target.capacity(),
            strings(&self.cpu_features)?,
            vector(&self.system_libraries, |library| {
                sum([
                    library.name.capacity(),
                    strings(&library.symbols)?,
                    strings(&library.versions)?,
                ])
            })?,
            vector(&self.dependencies, |dependency| {
                sum([
                    dependency.name.capacity(),
                    dependency.artifact.capacity(),
                    dependency.digest.capacity(),
                ])
            })?,
        ])
    }
}

impl PackageFixtureV1 {
    fn allocated_bytes(&self) -> Result<usize> {
        sum([
            self.name.capacity(),
            self.export.capacity(),
            vector(&self.inputs, |input| Ok(input.allocated_bytes()))?,
            self.parameters
                .as_ref()
                .map(value)
                .transpose()?
                .unwrap_or(0),
            self.checkpoint
                .as_ref()
                .map_or(0, |checkpoint| checkpoint.allocated_bytes()),
            vector(&self.previous_outputs, |data| Ok(data.allocated_bytes()))?,
            self.expected.allocated_bytes(),
        ])
    }
}

fn sum(values: impl IntoIterator<Item = usize>) -> Result<usize> {
    values.into_iter().try_fold(0_usize, |total, bytes| {
        total
            .checked_add(bytes)
            .ok_or_else(|| ErrorCode::Limit.error("package image memory"))
    })
}

fn vector<T>(values: &Vec<T>, heap: impl Fn(&T) -> Result<usize>) -> Result<usize> {
    let storage = values
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or_else(|| ErrorCode::Limit.error("package image memory"))?;
    values
        .iter()
        .try_fold(storage, |total, value| sum([total, heap(value)?]))
}

fn strings(values: &Vec<String>) -> Result<usize> {
    vector(values, |value| Ok(value.capacity()))
}

fn tree(values: &BTreeMap<String, String>) -> Result<usize> {
    values.iter().try_fold(0, |total, (key, value)| {
        sum([
            total,
            size_of::<(String, String)>(),
            key.capacity(),
            value.capacity(),
        ])
    })
}

fn value(value: &serde_json::Value) -> Result<usize> {
    match value {
        serde_json::Value::String(value) => Ok(value.capacity()),
        serde_json::Value::Array(values) => vector(values, self::value),
        serde_json::Value::Object(values) => values.iter().try_fold(0, |total, (key, value)| {
            sum([
                total,
                size_of::<(String, serde_json::Value)>(),
                key.capacity(),
                self::value(value)?,
            ])
        }),
        _ => Ok(0),
    }
}

#[cfg(test)]
mod tests;
