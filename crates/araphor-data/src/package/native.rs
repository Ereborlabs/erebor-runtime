use std::collections::BTreeMap;

use object::{NameOrOrdinal, Object as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::IntoError as _;

use super::PackageErrorCodeV1 as Code;
use crate::Result;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryRequirement {
    pub name: String,
    pub symbols: Vec<String>,
    pub versions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub name: String,
    pub artifact: Vec<u8>,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Qualification {
    pub exports: Vec<String>,
    pub target: String,
    pub cpu_features: Vec<String>,
    pub contract_version: u32,
    pub system_libraries: Vec<LibraryRequirement>,
    pub dependencies: Vec<Dependency>,
}

impl Qualification {
    pub fn inspect(artifact: &[u8], exports: Vec<String>, target: String) -> Result<Self> {
        let file = object::File::parse(artifact)
            .map_err(|_| Code::Invalid.error("native artifact format"))?;
        let mut libraries = BTreeMap::<String, LibraryRequirement>::new();
        for entry in file
            .import_libraries()
            .map_err(|_| Code::Invalid.error("native library imports"))?
        {
            let entry = entry.map_err(|_| Code::Invalid.error("native library import"))?;
            let name = native_text(entry.name())?.to_owned();
            libraries.insert(
                name.clone(),
                LibraryRequirement {
                    name,
                    symbols: Vec::new(),
                    versions: Vec::new(),
                },
            );
        }
        for entry in file
            .imports()
            .map_err(|_| Code::Invalid.error("native symbol imports"))?
        {
            let entry = entry.map_err(|_| Code::Invalid.error("native symbol import"))?;
            if entry.is_weak() || entry.library().is_empty() {
                continue;
            }
            let library = libraries
                .get_mut(native_text(entry.library())?)
                .ok_or_else(|| Code::Invalid.error("native imported library"))?;
            if let NameOrOrdinal::Name(name) = entry.name() {
                library.symbols.push(native_text(name)?.into());
            }
            if let object::ImportFlags::Elf {
                version: Some(version),
                ..
            } = entry.flags()
            {
                library.versions.push(native_text(version)?.into());
            }
        }
        for library in libraries.values_mut() {
            library.symbols.sort();
            library.symbols.dedup();
            library.versions.sort();
            library.versions.dedup();
        }
        Ok(Self {
            exports,
            target,
            cpu_features: Vec::new(),
            contract_version: 1,
            system_libraries: libraries.into_values().collect(),
            dependencies: Vec::new(),
        })
    }

    pub fn digest(artifact: &[u8]) -> String {
        format!("{:x}", Sha256::digest(artifact))
    }

    pub fn closure_digest(&self, artifact: &[u8]) -> Result<String> {
        let bytes = serde_json::to_vec(&(Self::digest(artifact), self))
            .map_err(|source| crate::PackageEncodingSnafu.into_error(source))?;
        Ok(Self::digest(&bytes))
    }
}

fn native_text(value: &[u8]) -> Result<&str> {
    std::str::from_utf8(value).map_err(|_| Code::Invalid.error("native artifact text"))
}
