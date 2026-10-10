use std::collections::BTreeSet;
use std::path::Path;

use snafu::ResultExt as _;

use crate::{
    DataType, Error, ErrorCode, Field, IoSnafu, Limits, Model, Package, Port, Result, Schema,
    TimeUnit, CONTRACT_VERSION,
};

pub(crate) const MAX_DESCRIPTOR_BYTES: usize = 1024 * 1024;

impl Package {
    pub fn validate(&self) -> Result<()> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(Error::contract(ErrorCode::Incompatible, "contract version"));
        }
        Self::name(&self.id)?;
        Self::text(&self.revision)?;
        if self.exports.is_empty() || self.exports.len() > 64 || self.dependencies.len() > 64 {
            return Err(Error::contract(ErrorCode::Limit, "exports or dependencies"));
        }
        Self::unique(self.exports.iter().map(|model| model.name.as_str()))?;
        for model in &self.exports {
            model.validate(&self.id)?;
        }
        let mut dependencies = BTreeSet::new();
        for dependency in &self.dependencies {
            Self::name(&dependency.model)?;
            Self::name(&dependency.input)?;
            Self::name(&dependency.package)?;
            Self::text(&dependency.revision)?;
            Self::name(&dependency.export)?;
            Self::name(&dependency.output)?;
            let input = self
                .exports
                .iter()
                .find(|model| model.name == dependency.model)
                .and_then(|model| {
                    model
                        .inputs
                        .iter()
                        .find(|port| port.name == dependency.input)
                })
                .ok_or_else(|| Error::contract(ErrorCode::Invalid, "dependency input"))?;
            if !dependencies.insert((&dependency.model, &dependency.input)) {
                return Err(Error::contract(ErrorCode::Invalid, "dependency"));
            }
            if dependency.package == self.id {
                let output = self
                    .exports
                    .iter()
                    .find(|model| model.name == dependency.export)
                    .and_then(|model| {
                        model
                            .outputs
                            .iter()
                            .find(|port| port.name == dependency.output)
                    })
                    .ok_or_else(|| Error::contract(ErrorCode::Invalid, "dependency output"))?;
                if dependency.revision != self.revision || input.schema != output.schema {
                    return Err(Error::contract(
                        ErrorCode::Incompatible,
                        "dependency schema or revision",
                    ));
                }
            }
        }
        serde_json::to_writer_pretty(DescriptorLimit(MAX_DESCRIPTOR_BYTES), self)
            .map_err(|_| Error::contract(ErrorCode::Limit, "descriptor bytes"))?;
        Ok(())
    }

    pub fn inspect(&self) -> Result<String> {
        Ok(self.interfaces()?.descriptor_json)
    }

    pub fn build(&self, directory: &Path) -> Result<()> {
        let declarations = self.interfaces()?;
        std::fs::create_dir_all(directory).context(IoSnafu { path: directory })?;
        for (name, content) in [
            ("descriptor.json", declarations.descriptor_json),
            ("analysis.wit", declarations.wit),
            ("analysis.h", declarations.native_header),
        ] {
            let path = directory.join(name);
            std::fs::write(&path, content).context(IoSnafu { path })?;
        }
        Ok(())
    }

    pub(crate) fn name(value: &str) -> Result<()> {
        if value.is_empty()
            || value.len() > 256
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(Error::contract(ErrorCode::Invalid, "name"));
        }
        Ok(())
    }

    pub(crate) fn text(value: &str) -> Result<()> {
        if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
            return Err(Error::contract(ErrorCode::Invalid, "reference or limit"));
        }
        Ok(())
    }

    pub(crate) fn unique<'a>(names: impl Iterator<Item = &'a str>) -> Result<()> {
        let mut seen = BTreeSet::new();
        for name in names {
            Self::name(name)?;
            if !seen.insert(name) {
                return Err(Error::contract(ErrorCode::Invalid, "duplicate name"));
            }
        }
        Ok(())
    }
}

struct DescriptorLimit(usize);

impl std::io::Write for DescriptorLimit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("Descriptor exceeds its byte limit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Model {
    fn validate(&self, package: &str) -> Result<()> {
        Package::name(&self.name)?;
        self.limits.validate()?;
        Self::ports(&self.inputs)?;
        Self::ports(&self.outputs)?;
        Self::schema(&self.parameters)?;
        if self.outputs.is_empty() || self.reasons.len() > 128 {
            return Err(Error::contract(ErrorCode::Invalid, "outputs or reasons"));
        }
        if !self.tolerance.absolute.is_finite()
            || !self.tolerance.relative.is_finite()
            || self.tolerance.absolute < 0.0
            || self.tolerance.relative < 0.0
        {
            return Err(Error::contract(ErrorCode::Invalid, "numeric tolerance"));
        }
        if self.inputs.iter().any(|port| port.evidence_required) {
            return Err(Error::contract(
                ErrorCode::Invalid,
                "input evidence requirement",
            ));
        }
        Package::unique(self.reasons.iter().map(|reason| reason.code.as_str()))?;
        for reason in &self.reasons {
            let Some(local) = reason.code.strip_prefix(&format!("{package}.")) else {
                return Err(Error::contract(ErrorCode::Invalid, "reason namespace"));
            };
            Package::name(local)?;
            Self::schema(&reason.details)?;
        }
        if let Some(checkpoint) = &self.checkpoint {
            if checkpoint.version == 0
                || checkpoint.datasets.is_empty()
                || checkpoint
                    .datasets
                    .iter()
                    .any(|port| port.evidence_required)
            {
                return Err(Error::contract(
                    ErrorCode::Invalid,
                    "checkpoint declaration",
                ));
            }
            Self::ports(&checkpoint.datasets)?;
        }
        Ok(())
    }

    fn ports(ports: &[Port]) -> Result<()> {
        if ports.len() > 64 {
            return Err(Error::contract(ErrorCode::Limit, "ports"));
        }
        Package::unique(ports.iter().map(|port| port.name.as_str()))?;
        for port in ports {
            Self::schema(&port.schema)?;
        }
        Ok(())
    }

    pub(crate) fn schema(schema: &Schema) -> Result<()> {
        let mut fields = 0;
        Self::fields(schema.fields(), 0, &mut fields)
    }

    fn fields<'a>(
        fields: impl IntoIterator<Item = &'a std::sync::Arc<Field>>,
        depth: usize,
        count: &mut usize,
    ) -> Result<()> {
        let fields: Vec<_> = fields.into_iter().collect();
        let mut names = BTreeSet::new();
        for field in fields {
            Package::text(field.name())?;
            if !names.insert(field.name()) {
                return Err(Error::contract(ErrorCode::Invalid, "duplicate field"));
            }
            *count += 1;
            if depth > 16 || *count > 1024 {
                return Err(Error::contract(ErrorCode::Limit, "schema depth or fields"));
            }
            match field.data_type() {
                DataType::Null
                | DataType::Boolean
                | DataType::Int8
                | DataType::Int16
                | DataType::Int32
                | DataType::Int64
                | DataType::UInt8
                | DataType::UInt16
                | DataType::UInt32
                | DataType::UInt64
                | DataType::Float32
                | DataType::Float64
                | DataType::Utf8
                | DataType::Binary => {}
                DataType::Timestamp(TimeUnit::Nanosecond, Some(zone)) if zone.as_ref() == "UTC" => {
                }
                DataType::FixedSizeBinary(size) if (1..=65536).contains(size) => {}
                DataType::List(child) => Self::fields([child], depth + 1, count)?,
                DataType::FixedSizeList(child, size) if (1..=65536).contains(size) => {
                    Self::fields([child], depth + 1, count)?;
                }
                DataType::Struct(children) => Self::fields(children, depth + 1, count)?,
                _ => return Err(Error::contract(ErrorCode::Incompatible, field.name())),
            }
        }
        Ok(())
    }
}

impl Limits {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.max_batches == 0
            || self.max_rows == 0
            || self.max_bytes == 0
            || self.max_checkpoint_bytes == 0
        {
            return Err(Error::contract(ErrorCode::Invalid, "limits"));
        }
        Ok(())
    }

    pub(crate) fn permits(&self, limits: &Self) -> bool {
        limits.max_batches <= self.max_batches
            && limits.max_rows <= self.max_rows
            && limits.max_bytes <= self.max_bytes
            && limits.max_checkpoint_bytes <= self.max_checkpoint_bytes
    }
}
