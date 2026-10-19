use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use araphor_package::PackageRefV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::error::{InvalidSnafu, JsonSnafu};
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
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Source {
    Inline { inline: String },
    File { file: PathBuf },
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
        crate::file::YamlDefinition::read(path)
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return InvalidSnafu { field: "name" }.fail();
        }
        self.program.source().validate()
    }

    pub fn validate_captured(&self) -> Result<()> {
        self.validate()?;
        self.program.source().inline()?;
        Ok(())
    }
}

impl Program {
    pub fn source(&self) -> &Source {
        match self {
            Self::Sql { source } | Self::Prql { source } => source,
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
