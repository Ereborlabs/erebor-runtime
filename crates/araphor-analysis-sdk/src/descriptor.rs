use std::collections::BTreeSet;
use std::path::Path;

use snafu::ResultExt as _;

use crate::{
    DataType, Error, ErrorCode, Field, InputMode, InputSource, IoSnafu, Model, Package, Port,
    Result, Schema, TableRef, TimeUnit, CONTRACT_VERSION,
};

impl Package {
    pub fn validate(&self) -> Result<()> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(Error::contract(ErrorCode::Incompatible, "contract version"));
        }
        Self::name(&self.id)?;
        Self::text(&self.revision)?;
        if self.exports.is_empty() {
            return Err(Error::contract(ErrorCode::Limit, "exports or dependencies"));
        }
        Self::unique(self.exports.iter().map(|model| model.name.as_str()))?;
        for model in &self.exports {
            model.validate(&self.id)?;
        }
        for model in &self.exports {
            for (input, dependency) in model.dependencies() {
                Self::name(&dependency.package)?;
                Self::text(&dependency.revision)?;
                Self::name(&dependency.export)?;
                Self::name(&dependency.output)?;
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
                    if dependency.revision != self.revision
                        || input.schema != output.schema
                        || input.kind != output.kind
                    {
                        return Err(Error::contract(
                            ErrorCode::Incompatible,
                            "dependency schema or revision",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn inspect(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.descriptor_value()?).context(crate::EncodingSnafu)
    }

    pub(crate) fn descriptor_value(&self) -> Result<serde_json::Value> {
        self.validate()?;
        let mut descriptor = serde_json::to_value(self).context(crate::EncodingSnafu)?;
        descriptor.sort_all_objects();
        Ok(descriptor)
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
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(Error::contract(ErrorCode::Invalid, "name"));
        }
        Ok(())
    }

    pub(crate) fn text(value: &str) -> Result<()> {
        if value.is_empty() || value.chars().any(char::is_control) {
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

impl Model {
    fn validate(&self, package: &str) -> Result<()> {
        Package::name(&self.name)?;
        Self::ports(self.inputs.iter().map(|input| &input.port))?;
        for input in &self.inputs {
            match &input.source {
                InputSource::Table(TableRef::Named(name)) => Package::name(name)?,
                InputSource::Table(TableRef::Output(_)) => {}
                InputSource::Query(_) if self.input_mode == InputMode::Resolved => {}
                _ => return Err(Error::contract(ErrorCode::Invalid, "input source mode")),
            }
        }
        Self::ports(self.outputs.iter())?;
        Self::schema(&self.parameters)?;
        if self.outputs.is_empty() {
            return Err(Error::contract(ErrorCode::Invalid, "outputs or reasons"));
        }
        if !self.tolerance.absolute.is_finite()
            || !self.tolerance.relative.is_finite()
            || self.tolerance.absolute < 0.0
            || self.tolerance.relative < 0.0
        {
            return Err(Error::contract(ErrorCode::Invalid, "numeric tolerance"));
        }
        if self.inputs.iter().any(|input| input.port.evidence_required) {
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
            Self::ports(checkpoint.datasets.iter())?;
        }
        Ok(())
    }

    pub(crate) fn ports<'a>(ports: impl Clone + ExactSizeIterator<Item = &'a Port>) -> Result<()> {
        Package::unique(ports.clone().map(|port| port.name.as_str()))?;
        for port in ports {
            Self::schema(&port.schema)?;
        }
        Ok(())
    }

    pub(crate) fn schema(schema: &Schema) -> Result<()> {
        Self::fields(schema.fields())
    }

    fn fields<'a>(fields: impl IntoIterator<Item = &'a std::sync::Arc<Field>>) -> Result<()> {
        let fields: Vec<_> = fields.into_iter().collect();
        let mut names = BTreeSet::new();
        for field in fields {
            Package::text(field.name())?;
            if !names.insert(field.name()) {
                return Err(Error::contract(ErrorCode::Invalid, "duplicate field"));
            }
            match field.data_type() {
                DataType::Null if field.is_nullable() => {}
                DataType::Boolean
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
                DataType::FixedSizeBinary(size) if *size > 0 => {}
                DataType::List(child) => Self::fields([child])?,
                DataType::FixedSizeList(child, size) if *size > 0 => {
                    Self::fields([child])?;
                }
                DataType::Struct(children) => Self::fields(children)?,
                _ => return Err(Error::contract(ErrorCode::Incompatible, field.name())),
            }
        }
        Ok(())
    }
}
