use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use araphor_package::PackageRefV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::error::{InvalidSnafu, IoSnafu, JsonSnafu};
use crate::Result;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    pub program: Program,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Program {
    Sql { source: Source },
    Prql { source: Source },
    Package { call: PackageCall },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Source {
    Inline { inline: String },
    File { file: PathBuf },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageCall {
    pub image: PackageRefV1,
    pub export: String,
    #[serde(default)]
    pub inputs: BTreeMap<String, String>,
    #[serde(default = "PackageCall::default_parameters")]
    pub parameters: serde_json::Value,
    #[serde(default)]
    pub window: Option<String>,
    #[serde(default)]
    pub output: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePin {
    pub image: PackageRefV1,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedDefinition {
    pub definition: Definition,
    pub sql: String,
    pub images: Vec<ImagePin>,
}

impl Definition {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).context(IoSnafu { path })?;
        let mut definition: Self = serde_json::from_slice(&bytes).context(JsonSnafu)?;
        definition.validate()?;
        if let Some(source) = definition.program.source_mut() {
            source.capture(path.parent().unwrap_or(Path::new(".")))?;
        }
        definition.validate_captured()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return InvalidSnafu { field: "name" }.fail();
        }
        self.program.validate()
    }

    pub fn validate_captured(&self) -> Result<()> {
        self.validate()?;
        if let Some(source) = self.program.source() {
            source.inline()?;
        }
        Ok(())
    }
}

impl Program {
    pub fn source(&self) -> Option<&Source> {
        match self {
            Self::Sql { source } | Self::Prql { source } => Some(source),
            Self::Package { .. } => None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Sql { source } | Self::Prql { source } => source.validate(),
            Self::Package { call } => call.validate(),
        }
    }

    fn source_mut(&mut self) -> Option<&mut Source> {
        match self {
            Self::Sql { source } | Self::Prql { source } => Some(source),
            Self::Package { .. } => None,
        }
    }
}

impl Source {
    pub fn inline(&self) -> Result<&str> {
        self.validate()?;
        match self {
            Self::Inline { inline } => Ok(inline),
            Self::File { .. } => InvalidSnafu {
                field: "uncaptured source",
            }
            .fail(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Inline { inline } if !inline.trim().is_empty() => Ok(()),
            Self::File { file } if !file.as_os_str().is_empty() => Ok(()),
            _ => InvalidSnafu { field: "source" }.fail(),
        }
    }

    fn capture(&mut self, directory: &Path) -> Result<()> {
        if let Self::File { file } = self {
            let path = directory.join(&*file);
            let inline = std::fs::read_to_string(&path).context(IoSnafu { path })?;
            *self = Self::Inline { inline };
        }
        self.validate()
    }
}

impl PackageCall {
    pub fn validate(&self) -> Result<()> {
        if self.image.package_id.trim().is_empty() || self.image.revision.trim().is_empty() {
            return InvalidSnafu { field: "image" }.fail();
        }
        if self.export.trim().is_empty() {
            return InvalidSnafu { field: "export" }.fail();
        }
        if self
            .inputs
            .iter()
            .any(|(name, sql)| name.trim().is_empty() || sql.trim().is_empty())
        {
            return InvalidSnafu { field: "inputs" }.fail();
        }
        if self
            .window
            .as_ref()
            .is_some_and(|sql| sql.trim().is_empty())
        {
            return InvalidSnafu { field: "window" }.fail();
        }
        if self
            .output
            .as_ref()
            .is_some_and(|name| name.trim().is_empty())
        {
            return InvalidSnafu { field: "output" }.fail();
        }
        Ok(())
    }

    fn default_parameters() -> serde_json::Value {
        serde_json::Value::Object(serde_json::Map::default())
    }
}

impl ImagePin {
    pub fn validate(&self) -> Result<()> {
        if self.image.package_id.trim().is_empty() || self.image.revision.trim().is_empty() {
            return InvalidSnafu { field: "image" }.fail();
        }
        if !self.digest.strip_prefix("sha256:").is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return InvalidSnafu {
                field: "image digest",
            }
            .fail();
        }
        Ok(())
    }
}

impl ResolvedDefinition {
    pub fn new(definition: Definition, sql: String, mut images: Vec<ImagePin>) -> Result<Self> {
        images.sort_by(|left, right| left.image.cmp(&right.image));
        let resolved = Self {
            definition,
            sql,
            images,
        };
        resolved.validate()?;
        Ok(resolved)
    }

    pub fn validate(&self) -> Result<()> {
        self.definition.validate_captured()?;
        if self.sql.trim().is_empty() {
            return InvalidSnafu { field: "SQL" }.fail();
        }
        for image in &self.images {
            image.validate()?;
        }
        if self
            .images
            .windows(2)
            .any(|pair| pair[0].image >= pair[1].image)
        {
            return InvalidSnafu {
                field: "image order",
            }
            .fail();
        }
        if let Program::Package { call } = &self.definition.program {
            if !self.images.iter().any(|pin| pin.image == call.image) {
                return InvalidSnafu { field: "image pin" }.fail();
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let mut json = serde_json::to_value(self).context(JsonSnafu)?;
        json.sort_all_objects();
        let bytes = serde_json::to_vec(&json).context(JsonSnafu)?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }
}
