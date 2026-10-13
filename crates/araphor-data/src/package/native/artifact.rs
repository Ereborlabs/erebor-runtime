use snafu::IntoError as _;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use object::{NameOrOrdinal, Object as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::Code;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<BTreeMap<String, String>>,
    pub target: String,
    pub cpu_features: Vec<String>,
    pub contract_version: u32,
    pub system_libraries: Vec<LibraryRequirement>,
    pub dependencies: Vec<Dependency>,
}

impl Qualification {
    pub fn inspect(artifact: &[u8], exports: Vec<String>, target: String) -> Result<Self> {
        let file = Self::parse(artifact)?;
        let mut libraries = BTreeMap::<String, LibraryRequirement>::new();
        for entry in file
            .import_libraries()
            .map_err(|_| Code::Invalid.error("native library imports"))?
        {
            let entry = entry.map_err(|_| Code::Invalid.error("native library import"))?;
            let name = Self::text(entry.name())?.to_owned();
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
                .get_mut(Self::text(entry.library())?)
                .ok_or_else(|| Code::Invalid.error("native imported library"))?;
            if let NameOrOrdinal::Name(name) = entry.name() {
                library.symbols.push(Self::text(name)?.into());
            }
            if let object::ImportFlags::Elf {
                version: Some(version),
                ..
            } = entry.flags()
            {
                library.versions.push(Self::text(version)?.into());
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
            inputs: None,
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

    pub(crate) fn validate(&self, artifact: &[u8]) -> Result<()> {
        let mut systems = BTreeMap::new();
        for library in &self.system_libraries {
            if !Self::system_name(&library.name) {
                return Err(Code::Invalid.error("native system library identity"));
            }
            let path = Self::system_path(&library.name)?;
            let bytes = std::fs::read(&path)
                .map_err(|source| crate::IoSnafu { path: &path }.into_error(source))?;
            systems.insert(library.name.clone(), bytes);
        }
        self.validate_files(artifact, &systems)
    }

    pub(super) fn validate_files(
        &self,
        artifact: &[u8],
        systems: &BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        if self.target != env!("ARAPHOR_NATIVE_TARGET") || self.contract_version != 1 {
            return Err(Code::Unsupported.error("native platform or ABI"));
        }
        if self.exports.is_empty()
            || self.exports.iter().collect::<BTreeSet<_>>().len() != self.exports.len()
        {
            return Err(Code::Invalid.error("native exports"));
        }
        for feature in &self.cpu_features {
            if !Self::cpu_feature(feature) {
                return Err(Code::Unsupported.error("native CPU feature"));
            }
        }
        let mut names = BTreeSet::new();
        let mut files = vec![artifact];
        for dependency in &self.dependencies {
            if dependency.name == "algorithm.so"
                || !Self::file_name(&dependency.name)
                || !names.insert(dependency.name.as_str())
                || dependency.digest != Self::digest(&dependency.artifact)
            {
                return Err(Code::Invalid.error("native dependency identity"));
            }
            if Self::soname(&dependency.artifact)?.is_some_and(|name| name != dependency.name) {
                return Err(Code::Invalid.error("native dependency SONAME"));
            }
            files.push(&dependency.artifact);
        }
        let mut requirements = BTreeMap::new();
        for library in &self.system_libraries {
            if !Self::system_name(&library.name)
                || names.contains(library.name.as_str())
                || requirements
                    .insert(library.name.as_str(), library)
                    .is_some()
            {
                return Err(Code::Invalid.error("native system library identity"));
            }
        }
        let mut available = BTreeMap::new();
        for dependency in &self.dependencies {
            available.insert(
                dependency.name.as_str(),
                Self::exported_symbols(&dependency.artifact)?,
            );
        }
        for library in &self.system_libraries {
            let bytes = systems
                .get(&library.name)
                .ok_or_else(|| Code::Invalid.error("native system file pin"))?;
            available.insert(library.name.as_str(), Self::exported_symbols(bytes)?);
        }
        let library_files = self
            .dependencies
            .iter()
            .map(|dependency| (dependency.name.as_str(), dependency.artifact.as_slice()))
            .chain(
                systems
                    .iter()
                    .map(|(name, bytes)| (name.as_str(), bytes.as_slice())),
            )
            .collect::<BTreeMap<_, _>>();
        for bytes in files {
            let reachable = Self::reachable(bytes, &library_files)?;
            let file = Self::parse(bytes)?;
            Self::platform(&file)?;
            let mut sibling = false;
            for library in file
                .import_libraries()
                .map_err(|_| Code::Invalid.error("native library imports"))?
            {
                let library = library.map_err(|_| Code::Invalid.error("native library import"))?;
                let name = Self::text(library.name())?;
                sibling |= names.contains(name);
                if !names.contains(name) && !requirements.contains_key(name) {
                    return Err(Code::Invalid.error("undeclared native dependency"));
                }
            }
            Self::search_paths(&file, bytes, sibling)?;
            for symbol in file
                .imports()
                .map_err(|_| Code::Invalid.error("native symbol imports"))?
            {
                let symbol = symbol.map_err(|_| Code::Invalid.error("native symbol import"))?;
                if symbol.is_weak() {
                    continue;
                }
                let library = Self::text(symbol.library())?;
                let symbol_name = match symbol.name() {
                    NameOrOrdinal::Name(name) => Self::text(name)?.to_owned(),
                    NameOrOrdinal::Ordinal(ordinal) => format!("#{ordinal}"),
                };
                let version = match symbol.flags() {
                    object::ImportFlags::Elf {
                        version: Some(version),
                        ..
                    } => Some(Self::text(version)?.to_owned()),
                    _ => None,
                };
                let matches = |symbols: &BTreeSet<(String, Option<String>)>| {
                    symbols.iter().any(|(name, exported)| {
                        name == &symbol_name && (version.is_none() || exported == &version)
                    })
                };
                let found = if library.is_empty() {
                    available
                        .iter()
                        .any(|(name, symbols)| reachable.contains(*name) && matches(symbols))
                } else {
                    reachable.contains(library) && available.get(library).is_some_and(matches)
                };
                if !found {
                    return Err(Code::Unsupported.error("native dependency symbol version"));
                }
                if let Some(requirement) = requirements.get(library) {
                    if !requirement.symbols.contains(&symbol_name) {
                        return Err(Code::Invalid.error("undeclared native symbol"));
                    }
                    if let Some(version) = version {
                        if !requirement.versions.contains(&version) {
                            return Err(Code::Invalid.error("undeclared native symbol version"));
                        }
                    }
                }
            }
        }
        let root = Self::parse(artifact)?;
        let accessor = root.exports().map_err(|_| Code::Invalid.error("native exports"))?
            .any(|entry| entry.is_ok_and(|entry| matches!(entry.name(), NameOrOrdinal::Name(name) if name == b"araphor_analysis_get_api_v1")));
        if !accessor {
            return Err(Code::Invalid.error("native ABI accessor"));
        }
        for library in &self.system_libraries {
            let exports = &available[library.name.as_str()];
            for name in &library.symbols {
                if !exports.iter().any(|(value, _)| value == name) {
                    return Err(Code::Unsupported.error("native system symbol"));
                }
            }
            for version in &library.versions {
                if !exports
                    .iter()
                    .any(|(_, value)| value.as_ref() == Some(version))
                {
                    return Err(Code::Unsupported.error("native system version"));
                }
            }
        }
        Ok(())
    }

    fn reachable<'a>(
        artifact: &'a [u8],
        files: &BTreeMap<&str, &'a [u8]>,
    ) -> Result<BTreeSet<String>> {
        let mut pending = vec![artifact];
        let mut reachable = BTreeSet::new();
        while let Some(bytes) = pending.pop() {
            let file = Self::parse(bytes)?;
            for library in file
                .import_libraries()
                .map_err(|_| Code::Invalid.error("native library imports"))?
            {
                let library = library.map_err(|_| Code::Invalid.error("native library import"))?;
                let name = Self::text(library.name())?;
                if reachable.insert(name.to_owned()) {
                    pending.push(
                        *files
                            .get(name)
                            .ok_or_else(|| Code::Invalid.error("undeclared native dependency"))?,
                    );
                }
            }
        }
        Ok(reachable)
    }

    pub(super) fn system_path(name: &str) -> Result<PathBuf> {
        if Path::new(name).is_absolute() && Self::system_name(name) {
            return std::fs::canonicalize(name)
                .map_err(|source| crate::IoSnafu { path: name }.into_error(source));
        }
        let multiarch = Self::multiarch(env!("ARAPHOR_NATIVE_TARGET"));
        let directories = [
            format!("/lib/{multiarch}"),
            format!("/usr/lib/{multiarch}"),
            "/lib64".into(),
            "/usr/lib64".into(),
            "/lib".into(),
            "/usr/lib".into(),
        ];
        for directory in directories {
            let path = Path::new(&directory).join(name);
            if path.is_file() {
                return std::fs::canonicalize(&path)
                    .map_err(|source| crate::IoSnafu { path }.into_error(source));
            }
        }
        Err(Code::Unsupported.error("native system library"))
    }

    fn multiarch(target: &str) -> String {
        let machine = target.split('-').next().unwrap_or(std::env::consts::ARCH);
        let abi = target.rsplit('-').next().unwrap_or("gnu");
        let machine = if machine.starts_with("i") && machine.ends_with("86") {
            "i386"
        } else if machine.starts_with("arm") || machine.starts_with("thumb") {
            "arm"
        } else {
            machine
        };
        format!("{machine}-linux-{abi}")
    }

    fn parse(bytes: &[u8]) -> Result<object::File<'_>> {
        object::File::parse(bytes).map_err(|_| Code::Invalid.error("native artifact format"))
    }

    fn exported_symbols(bytes: &[u8]) -> Result<BTreeSet<(String, Option<String>)>> {
        let file = Self::parse(bytes)?;
        file.exports()
            .map_err(|_| Code::Invalid.error("native dependency exports"))?
            .map(|export| {
                let export = export.map_err(|_| Code::Invalid.error("native dependency export"))?;
                let name = match export.name() {
                    NameOrOrdinal::Name(name) => Self::text(name)?.to_owned(),
                    NameOrOrdinal::Ordinal(ordinal) => format!("#{ordinal}"),
                };
                let version = match export.flags() {
                    object::ExportFlags::Elf {
                        version: Some(version),
                        ..
                    } => Some(Self::text(version)?.to_owned()),
                    _ => None,
                };
                Ok((name, version))
            })
            .collect()
    }

    fn system_name(name: &str) -> bool {
        Self::file_name(name)
            || (cfg!(target_os = "macos")
                && Path::new(name).is_absolute()
                && ["/usr/lib/", "/System/Library/Frameworks/"]
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
                && !Path::new(name)
                    .components()
                    .any(|entry| matches!(entry, Component::ParentDir)))
    }

    fn platform(file: &object::File<'_>) -> Result<()> {
        let format = match object::BinaryFormat::native_object() {
            object::BinaryFormat::Coff => object::BinaryFormat::Pe,
            format => format,
        };
        let architecture = match std::env::consts::ARCH {
            "x86_64" => object::Architecture::X86_64,
            "aarch64" => object::Architecture::Aarch64,
            "x86" => object::Architecture::I386,
            "arm" => object::Architecture::Arm,
            "riscv64" => object::Architecture::Riscv64,
            "riscv32" => object::Architecture::Riscv32,
            "powerpc" => object::Architecture::PowerPc,
            "powerpc64" => object::Architecture::PowerPc64,
            "s390x" => object::Architecture::S390x,
            "mips" => object::Architecture::Mips,
            "mips64" => object::Architecture::Mips64,
            "loongarch64" => object::Architecture::LoongArch64,
            "sparc" => object::Architecture::Sparc,
            "sparc64" => object::Architecture::Sparc64,
            _ => return Err(Code::Unsupported.error("native architecture")),
        };
        if file.format() != format
            || file.is_64() != (usize::BITS == 64)
            || file.architecture() != architecture
            || file.is_little_endian() != cfg!(target_endian = "little")
            || file.kind() != object::ObjectKind::Dynamic
        {
            return Err(Code::Unsupported.error("native artifact platform"));
        }
        Ok(())
    }

    fn text(bytes: &[u8]) -> Result<&str> {
        std::str::from_utf8(bytes).map_err(|_| Code::Invalid.error("native library name"))
    }

    fn file_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 256
            && Path::new(name).components().count() == 1
            && matches!(
                Path::new(name).components().next(),
                Some(Component::Normal(_))
            )
            && !name.contains('\\')
            && !name.as_bytes().contains(&0)
    }

    pub(super) fn soname(bytes: &[u8]) -> Result<Option<String>> {
        match Self::parse(bytes)? {
            object::File::Elf64(file) => Self::elf_name(&file, bytes),
            object::File::Elf32(file) => Self::elf_name(&file, bytes),
            _ => Ok(None),
        }
    }

    pub(super) fn file_soname(file: std::fs::File) -> Result<Option<String>> {
        let cache = object::read::ReadCache::new(file);
        let object =
            object::File::parse(&cache).map_err(|_| Code::Invalid.error("mapped native object"))?;
        match object {
            object::File::Elf64(file) => Self::elf_name(&file, &cache),
            object::File::Elf32(file) => Self::elf_name(&file, &cache),
            _ => Ok(None),
        }
    }

    fn elf_name<'a, Elf: object::read::elf::FileHeader, R: object::read::ReadRef<'a>>(
        file: &object::read::elf::ElfFile<'a, Elf, R>,
        bytes: R,
    ) -> Result<Option<String>> {
        let table = file
            .elf_section_table()
            .dynamic_table(file.endian(), bytes)
            .map_err(|_| Code::Invalid.error("native dynamic table"))?;
        for entry in table.iter() {
            if entry.tag == object::elf::DT_SONAME {
                return table
                    .string(entry)
                    .map_err(|_| Code::Invalid.error("native SONAME"))
                    .and_then(Self::text)
                    .map(|name| Some(name.to_owned()));
            }
        }
        Ok(None)
    }

    fn search_paths(file: &object::File<'_>, bytes: &[u8], dependencies: bool) -> Result<()> {
        match file {
            object::File::Elf64(file) => Self::elf_paths(file, bytes, dependencies),
            object::File::Elf32(file) => Self::elf_paths(file, bytes, dependencies),
            _ => Ok(()),
        }
    }

    fn elf_paths<'a, Elf: object::read::elf::FileHeader>(
        file: &object::read::elf::ElfFile<'a, Elf>,
        bytes: &'a [u8],
        dependencies: bool,
    ) -> Result<()> {
        let table = file
            .elf_section_table()
            .dynamic_table(file.endian(), bytes)
            .map_err(|_| Code::Invalid.error("native dynamic table"))?;
        let mut origin = false;
        for entry in table.iter() {
            if entry.tag == object::elf::DT_RPATH || entry.tag == object::elf::DT_RUNPATH {
                if table
                    .string(entry)
                    .map_err(|_| Code::Invalid.error("native search path"))?
                    != b"$ORIGIN"
                {
                    return Err(Code::Invalid.error("native search path"));
                }
                origin = true;
            }
        }
        if dependencies && !origin {
            return Err(Code::Invalid.error("native closure search path"));
        }
        Ok(())
    }

    fn cpu_feature(feature: &str) -> bool {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            match feature {
                "sse2" => std::is_x86_feature_detected!("sse2"),
                "sse3" => std::is_x86_feature_detected!("sse3"),
                "ssse3" => std::is_x86_feature_detected!("ssse3"),
                "sse4.1" => std::is_x86_feature_detected!("sse4.1"),
                "sse4.2" => std::is_x86_feature_detected!("sse4.2"),
                "avx" => std::is_x86_feature_detected!("avx"),
                "avx2" => std::is_x86_feature_detected!("avx2"),
                "fma" => std::is_x86_feature_detected!("fma"),
                "bmi1" => std::is_x86_feature_detected!("bmi1"),
                "bmi2" => std::is_x86_feature_detected!("bmi2"),
                _ => false,
            }
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            let _ = feature;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_names_cannot_escape() {
        for name in ["", ".", "..", "/tmp/code.so", "a/b.so", "a\\b.so", "a\0.so"] {
            assert!(!Qualification::file_name(name), "{name:?}");
        }
        assert!(Qualification::file_name("libcode.so"));
    }

    #[test]
    fn admission_rejects_foreign_target() {
        let qualification = Qualification {
            exports: vec!["detect".into()],
            inputs: None,
            target: "foreign-target".into(),
            cpu_features: Vec::new(),
            contract_version: 1,
            system_libraries: Vec::new(),
            dependencies: Vec::new(),
        };
        assert!(matches!(
            qualification.validate(b"not executable"),
            Err(crate::Error::Package {
                code: Code::Unsupported,
                ..
            })
        ));
        assert!(matches!(
            Qualification::parse(b"malformed"),
            Err(crate::Error::Package {
                code: Code::Invalid,
                ..
            })
        ));
    }
    #[test]
    fn multiarch_preserves_platform_abi() {
        for (target, directory) in [
            ("x86_64-unknown-linux-gnu", "x86_64-linux-gnu"),
            ("i686-unknown-linux-gnu", "i386-linux-gnu"),
            ("armv7-unknown-linux-gnueabihf", "arm-linux-gnueabihf"),
            ("powerpc64le-unknown-linux-gnu", "powerpc64le-linux-gnu"),
            ("mips64el-unknown-linux-gnuabi64", "mips64el-linux-gnuabi64"),
            ("x86_64-unknown-linux-gnux32", "x86_64-linux-gnux32"),
        ] {
            assert_eq!(Qualification::multiarch(target), directory);
        }
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn platform_rejects_wrong_class() -> crate::Result<()> {
        let mut bytes = [0u8; 52];
        bytes[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[40..42].copy_from_slice(&52u16.to_le_bytes());
        let file = Qualification::parse(&bytes)?;
        assert!(matches!(
            Qualification::platform(&file),
            Err(crate::Error::Package {
                code: Code::Unsupported,
                field: "native artifact platform",
                ..
            })
        ));
        Ok(())
    }
}
