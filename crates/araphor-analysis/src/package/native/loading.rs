use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use libloading::{Library, Symbol};
use snafu::IntoError as _;

use super::files::{FilePin, MappedFiles};
use super::{Code, NativeAdmission, Qualification};
use crate::{AnalysisReadControl, Result};

pub(in crate::package) struct NativeLibrary {
    api: *const sdk::native::Api,
    _library: Library,
    _dependencies: Vec<Library>,
    _directory: tempfile::TempDir,
    _files: Vec<FilePin>,
}

impl NativeLibrary {
    #[allow(unsafe_code)]
    pub(in crate::package) fn load(
        artifact: &[u8],
        qualification: &Qualification,
        control: &AnalysisReadControl,
    ) -> Result<Self> {
        control.check()?;
        let directory = tempfile::Builder::new()
            .prefix("araphor-native-")
            .tempdir()
            .map_err(|source| {
                crate::IoSnafu {
                    path: "<native artifacts>",
                }
                .into_error(source)
            })?;
        let root = FilePin::package(directory.path(), "algorithm.so", artifact)?;
        let mut files = Vec::new();
        let mut systems = BTreeMap::new();
        for system in &qualification.system_libraries {
            let (pin, bytes) = FilePin::system(directory.path(), &system.name)?;
            systems.insert(system.name.clone(), bytes);
            files.push(pin);
        }
        NativeAdmission::validate_files(qualification, artifact, &systems)?;
        for dependency in &qualification.dependencies {
            files.push(FilePin::package(
                directory.path(),
                &dependency.name,
                &dependency.artifact,
            )?);
        }
        let mut mapped = MappedFiles::read()?;
        root.check()?;
        mapped.check(&root, artifact)?;
        for (index, pin) in files.iter().enumerate() {
            pin.check()?;
            let bytes = if index < qualification.system_libraries.len() {
                &systems[&qualification.system_libraries[index].name]
            } else {
                &qualification.dependencies[index - qualification.system_libraries.len()].artifact
            };
            mapped.check(pin, bytes)?;
        }
        let mut dependencies = Vec::new();
        for pin in files.iter().take(qualification.system_libraries.len()) {
            control.check()?;
            pin.check()?;
            dependencies.push(Self::open(
                pin.path(),
                Code::Unsupported,
                "system library load",
            )?);
        }
        control.check()?;
        root.check()?;
        // The author must finish background work before the ABI call returns.
        let library = Self::open(root.path(), Code::Incomplete, "library load")?;
        let mut mapped = MappedFiles::read()?;
        for (index, pin) in files.iter().enumerate() {
            let bytes = if index < qualification.system_libraries.len() {
                &systems[&qualification.system_libraries[index].name]
            } else {
                &qualification.dependencies[index - qualification.system_libraries.len()].artifact
            };
            mapped.check(pin, bytes)?;
        }
        files.push(root);
        let accessor: Symbol<'_, unsafe extern "C" fn() -> *const sdk::native::Api> =
            unsafe { library.get(sdk::native::ACCESSOR_SYMBOL) }.map_err(|source| {
                crate::PackageNativeSnafu {
                    code: Code::Invalid,
                    operation: "ABI accessor",
                }
                .into_error(Box::new(source) as Box<dyn std::error::Error + Send + Sync>)
            })?;
        control.check()?;
        let api = unsafe { accessor() };
        if api.is_null() || !(api as usize).is_multiple_of(std::mem::align_of::<sdk::native::Api>())
        {
            return Err(crate::Error::from(Code::Invalid.error("native ABI table")));
        }
        unsafe { &*api }
            .validate()
            .map_err(|source| Self::failure_at(source, "ABI table"))?;
        Ok(Self {
            api,
            _library: library,
            _dependencies: dependencies,
            _directory: directory,
            _files: files,
        })
    }

    #[allow(unsafe_code)]
    pub(in crate::package) fn call(
        &self,
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
        output_limits: sdk::Limits,
        control: &AnalysisReadControl,
    ) -> Result<sdk::Output> {
        control.check()?;
        let invocation =
            sdk::native::Invocation::new(package, evaluation, || control.check().is_err())
                .map_err(|source| crate::AnalysisContractSnafu.into_error(source))?;
        // The library pin covers copying output and all producer release callbacks.
        let result = unsafe { invocation.call(&*self.api, output_limits) }.map_err(Self::failure);
        control.check()?;
        result
    }

    fn failure(source: sdk::Error) -> crate::Error {
        Self::failure_at(source, "evaluation")
    }

    fn failure_at(source: sdk::Error, operation: &'static str) -> crate::Error {
        let code = match source.code() {
            sdk::ErrorCode::Invalid => Code::Invalid,
            sdk::ErrorCode::Incompatible => Code::Unsupported,
            sdk::ErrorCode::Unauthorized => Code::Denied,
            sdk::ErrorCode::Incomplete | sdk::ErrorCode::Failed => Code::Incomplete,
            sdk::ErrorCode::Limit => Code::Limit,
        };
        crate::PackageNativeSnafu { code, operation }
            .into_error(Box::new(source) as Box<dyn std::error::Error + Send + Sync>)
    }

    #[allow(unsafe_code)]
    fn open(path: &std::path::Path, code: Code, operation: &'static str) -> Result<Library> {
        #[cfg(unix)]
        let loaded = unsafe {
            libloading::os::unix::Library::open(
                Some(path),
                libloading::os::unix::RTLD_NOW | libloading::os::unix::RTLD_LOCAL,
            )
        }
        .map(Library::from);
        #[cfg(not(unix))]
        let loaded = unsafe { Library::new(path) };
        loaded.map_err(|source| {
            crate::PackageNativeSnafu { code, operation }
                .into_error(Box::new(source) as Box<dyn std::error::Error + Send + Sync>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    struct LibraryFixture {
        bytes: Vec<u8>,
        qualification: Qualification,
        _directory: tempfile::TempDir,
    }

    #[test]
    fn failures_preserve_typed_codes() -> std::result::Result<(), Box<dyn std::error::Error>> {
        for (sdk_code, code) in [
            (sdk::ErrorCode::Invalid, Code::Invalid),
            (sdk::ErrorCode::Incompatible, Code::Unsupported),
            (sdk::ErrorCode::Unauthorized, Code::Denied),
            (sdk::ErrorCode::Incomplete, Code::Incomplete),
            (sdk::ErrorCode::Failed, Code::Incomplete),
            (sdk::ErrorCode::Limit, Code::Limit),
        ] {
            let error = NativeLibrary::failure(sdk::Error::contract(sdk_code, "test"));
            let crate::Error::PackageNative {
                code: actual,
                source,
                ..
            } = error
            else {
                return Err("wrong native error owner".into());
            };
            assert_eq!(actual, code);
            assert_eq!(
                source.downcast_ref::<sdk::Error>().map(sdk::Error::code),
                Some(sdk_code)
            );
        }
        Ok(())
    }

    impl LibraryFixture {
        fn build(source: &str) -> std::result::Result<Self, Box<dyn std::error::Error>> {
            Self::build_named(source, None)
        }

        fn build_named(
            source: &str,
            soname: Option<&str>,
        ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
            Self::build_options(source, soname, &[])
        }

        fn build_options(
            source: &str,
            soname: Option<&str>,
            options: &[String],
        ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
            let directory = tempfile::tempdir()?;
            let source_path = directory.path().join("plugin.rs");
            let artifact = directory
                .path()
                .join(format!("plugin{}", std::env::consts::DLL_SUFFIX));
            std::fs::write(&source_path, source)?;
            let mut command = Command::new("rustc");
            command
                .args(["--edition=2021", "--crate-type=cdylib"])
                .args(options);
            if let Some(name) = soname {
                command.arg(format!("-Clink-arg=-Wl,-soname,{name}"));
            }
            let compiled = command
                .arg(&source_path)
                .arg("-o")
                .arg(&artifact)
                .output()?;
            if !compiled.status.success() {
                return Err(std::io::Error::other(
                    String::from_utf8_lossy(&compiled.stderr).into_owned(),
                )
                .into());
            }
            let bytes = std::fs::read(artifact)?;
            let qualification = Qualification::inspect(
                &bytes,
                vec!["detect".into()],
                env!("ARAPHOR_NATIVE_TARGET").into(),
            )?;
            Ok(Self {
                bytes,
                qualification,
                _directory: directory,
            })
        }
    }

    #[test]
    fn loading_rejects_null_accessor() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let fixture = LibraryFixture::build(
            "#[no_mangle] pub extern \"C\" fn araphor_analysis_get_api_v1() -> *const u8 { std::ptr::null() }",
        )?;
        super::NativeAdmission::validate(&fixture.qualification, &fixture.bytes)?;
        let error = NativeLibrary::load(
            &fixture.bytes,
            &fixture.qualification,
            &AnalysisReadControl::default(),
        )
        .err()
        .ok_or("null ABI loaded")?;
        assert!(
            matches!(
                error,
                crate::Error::Data {
                    source: araphor_data::Error::Package {
                        code: Code::Invalid,
                        field: "native ABI table",
                        ..
                    }
                }
            ),
            "{error:?}"
        );
        Ok(())
    }

    #[test]
    fn cancellation_prevents_native_load() -> crate::Result<()> {
        let control = AnalysisReadControl::default();
        control.cancel()?;
        let qualification = Qualification {
            exports: vec!["detect".into()],
            target: env!("ARAPHOR_NATIVE_TARGET").into(),
            cpu_features: Vec::new(),
            contract_version: 1,
            system_libraries: Vec::new(),
            dependencies: Vec::new(),
        };
        assert!(matches!(
            NativeLibrary::load(b"invalid", &qualification, &control),
            Err(crate::Error::Data {
                source: araphor_data::Error::AnalysisReadCancelled { .. }
            })
        ));
        Ok(())
    }

    #[test]
    fn loading_rejects_system_paths() {
        for name in ["/araphor-native-missing.so", "../araphor-native-missing.so"] {
            let qualification = Qualification {
                exports: vec!["detect".into()],
                target: env!("ARAPHOR_NATIVE_TARGET").into(),
                cpu_features: Vec::new(),
                contract_version: 1,
                system_libraries: vec![araphor_data::LibraryRequirement {
                    name: name.into(),
                    symbols: Vec::new(),
                    versions: Vec::new(),
                }],
                dependencies: Vec::new(),
            };
            assert!(matches!(
                NativeLibrary::load(b"invalid", &qualification, &AnalysisReadControl::default()),
                Err(crate::Error::Data {
                    source: araphor_data::Error::Package {
                        code: Code::Invalid,
                        field: "native system library identity",
                        ..
                    }
                })
            ));
        }
    }

    #[test]
    fn admission_checks_system_requirements() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let mut fixture = LibraryFixture::build(
            "#[no_mangle] pub extern \"C\" fn araphor_analysis_get_api_v1() -> *const u8 { std::ptr::null() }",
        )?;
        let library = fixture
            .qualification
            .system_libraries
            .first_mut()
            .ok_or("fixture imports no system library")?;
        library.symbols.push("araphor_missing_system_symbol".into());
        for error in [
            super::NativeAdmission::validate(&fixture.qualification, &fixture.bytes).err(),
            NativeLibrary::load(
                &fixture.bytes,
                &fixture.qualification,
                &AnalysisReadControl::default(),
            )
            .err(),
        ] {
            assert!(matches!(
                error,
                Some(crate::Error::Data {
                    source: araphor_data::Error::Package {
                        code: Code::Unsupported,
                        field: "native system symbol",
                        ..
                    }
                })
            ));
        }
        Ok(())
    }

    #[test]
    fn admission_checks_dependency_content() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let mut fixture = LibraryFixture::build(
            "#[no_mangle] pub extern \"C\" fn araphor_analysis_get_api_v1() -> *const u8 { std::ptr::null() }",
        )?;
        fixture
            .qualification
            .dependencies
            .push(super::super::Dependency {
                name: "dependency.so".into(),
                artifact: vec![1],
                digest: Qualification::digest(&[2]),
            });
        for error in [
            super::NativeAdmission::validate(&fixture.qualification, &fixture.bytes).err(),
            NativeLibrary::load(
                &fixture.bytes,
                &fixture.qualification,
                &AnalysisReadControl::default(),
            )
            .err(),
        ] {
            assert!(matches!(
                error,
                Some(crate::Error::Data {
                    source: araphor_data::Error::Package {
                        code: Code::Invalid,
                        field: "native dependency identity",
                        ..
                    }
                })
            ));
        }
        Ok(())
    }

    #[test]
    fn extraction_rejects_replacement() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("artifact.so");
        let pin = FilePin::package(directory.path(), "artifact.so", b"exact artifact")?;
        assert_eq!(std::fs::read(&path)?, b"exact artifact");
        assert!(FilePin::package(directory.path(), "artifact.so", b"replacement").is_err());
        pin.check()?;
        #[cfg(target_os = "linux")]
        assert!(std::fs::write(&path, b"replacement").is_err());
        Ok(())
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn mapped_dependency_rejects_alias() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let name = "araphor-native-collision-test.so";
        let first = LibraryFixture::build_named(
            "#[no_mangle] pub extern \"C\" fn araphor_analysis_get_api_v1() -> *const u8 { std::ptr::null() } #[no_mangle] pub extern \"C\" fn identity() -> u64 { 1 }",
            Some(name),
        )?;
        let second = LibraryFixture::build_named(
            "#[no_mangle] pub extern \"C\" fn araphor_analysis_get_api_v1() -> *const u8 { std::ptr::null() } #[no_mangle] pub extern \"C\" fn identity() -> u64 { 2 }",
            Some(name),
        )?;
        let path = first
            ._directory
            .path()
            .join(format!("plugin{}", std::env::consts::DLL_SUFFIX));
        let _library = NativeLibrary::open(&path, Code::Incomplete, "test load")?;
        let directory = tempfile::tempdir()?;
        let pin = FilePin::package(directory.path(), name, &second.bytes)?;
        assert!(matches!(
            pin.mapped(&second.bytes),
            Err(crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Conflict,
                    field: "loaded native library identity",
                    ..
                }
            })
        ));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_path_rejects_replacement() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let original = FilePin::package(directory.path(), "original.so", b"original")?;
        let replacement = FilePin::package(directory.path(), "replacement.so", b"replacement")?;
        std::fs::rename(replacement.path(), original.path())?;
        assert!(matches!(
            original.check(),
            Err(crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Conflict,
                    field: "native file identity",
                    ..
                }
            })
        ));
        Ok(())
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_closure_loads_sibling() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let name = "libaraphor_sibling_test.so";
        let dependency = LibraryFixture::build_named(
            "#[no_mangle] pub extern \"C\" fn araphor_analysis_get_api_v1() -> *const u8 { std::ptr::null() } #[no_mangle] pub extern \"C\" fn sibling_value() -> usize { 0 }",
            Some(name),
        )?;
        let directory = tempfile::tempdir()?;
        std::fs::write(directory.path().join(name), &dependency.bytes)?;
        let mut fixture = LibraryFixture::build_options(
            "#[link(name=\"araphor_sibling_test\")] extern \"C\" { fn sibling_value() -> usize; } #[no_mangle] pub unsafe extern \"C\" fn araphor_analysis_get_api_v1() -> *const u8 { sibling_value() as *const u8 }",
            None,
            &[
                format!("-Lnative={}", directory.path().display()),
                "-Clink-arg=-Wl,-rpath,$ORIGIN".into(),
            ],
        )?;
        fixture
            .qualification
            .system_libraries
            .retain(|library| library.name != name);
        for library in dependency.qualification.system_libraries {
            if let Some(existing) = fixture
                .qualification
                .system_libraries
                .iter_mut()
                .find(|existing| existing.name == library.name)
            {
                existing.symbols.extend(library.symbols);
                existing.versions.extend(library.versions);
                existing.symbols.sort();
                existing.symbols.dedup();
                existing.versions.sort();
                existing.versions.dedup();
            } else {
                fixture.qualification.system_libraries.push(library);
            }
        }
        fixture
            .qualification
            .dependencies
            .push(super::super::Dependency {
                name: name.into(),
                digest: Qualification::digest(&dependency.bytes),
                artifact: dependency.bytes,
            });
        super::NativeAdmission::validate(&fixture.qualification, &fixture.bytes)?;
        let error = NativeLibrary::load(
            &fixture.bytes,
            &fixture.qualification,
            &AnalysisReadControl::default(),
        )
        .err()
        .ok_or("sibling ABI loaded")?;
        assert!(
            matches!(
                error,
                crate::Error::Data {
                    source: araphor_data::Error::Package {
                        code: Code::Invalid,
                        field: "native ABI table",
                        ..
                    }
                }
            ),
            "{error:?}"
        );
        Ok(())
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn dependency_soname_matches_name() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut fixture = LibraryFixture::build_named(
            "#[no_mangle] pub extern \"C\" fn araphor_analysis_get_api_v1() -> *const u8 { std::ptr::null() }",
            Some("actual.so"),
        )?;
        fixture
            .qualification
            .dependencies
            .push(super::super::Dependency {
                name: "different.so".into(),
                digest: Qualification::digest(&fixture.bytes),
                artifact: fixture.bytes.clone(),
            });
        assert!(matches!(
            super::NativeAdmission::validate(&fixture.qualification, &fixture.bytes),
            Err(crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Invalid,
                    field: "native dependency SONAME",
                    ..
                }
            })
        ));
        Ok(())
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn admission_rejects_unreachable_provider(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dependency = LibraryFixture::build_named(
            "#[no_mangle] pub extern \"C\" fn araphor_analysis_get_api_v1() -> *const u8 { std::ptr::null() } #[no_mangle] pub extern \"C\" fn unreachable_value() -> usize { 0 }",
            Some("unreachable.so"),
        )?;
        let mut fixture = LibraryFixture::build(
            "extern \"C\" { fn unreachable_value() -> usize; } #[no_mangle] pub unsafe extern \"C\" fn araphor_analysis_get_api_v1() -> *const u8 { unreachable_value() as *const u8 }",
        )?;
        fixture
            .qualification
            .dependencies
            .push(super::super::Dependency {
                name: "unreachable.so".into(),
                digest: Qualification::digest(&dependency.bytes),
                artifact: dependency.bytes,
            });
        assert!(matches!(
            super::NativeAdmission::validate(&fixture.qualification, &fixture.bytes),
            Err(crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Unsupported,
                    field: "native dependency symbol version",
                    ..
                }
            })
        ));
        Ok(())
    }
    #[test]
    fn loading_rejects_incompatible_table() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let fixture = LibraryFixture::build(
            r#"
            #[repr(C)] struct Api { version: u32, size: u64,
                evaluate: Option<unsafe extern "C" fn(*const u8, *mut u8) -> u32>,
                release: Option<unsafe extern "C" fn(*mut u8)> }
            unsafe extern "C" fn evaluate(_: *const u8, _: *mut u8) -> u32 { 0 }
            unsafe extern "C" fn release(_: *mut u8) {}
            static API: Api = Api { version: 2, size: std::mem::size_of::<Api>() as u64,
                evaluate: Some(evaluate), release: Some(release) };
            #[no_mangle] pub extern "C" fn araphor_analysis_get_api_v1() -> *const Api { &API }
        "#,
        )?;
        super::NativeAdmission::validate(&fixture.qualification, &fixture.bytes)?;
        let error = NativeLibrary::load(
            &fixture.bytes,
            &fixture.qualification,
            &AnalysisReadControl::default(),
        )
        .err()
        .ok_or("incompatible ABI loaded")?;
        let crate::Error::PackageNative {
            code,
            operation,
            source,
            ..
        } = error
        else {
            return Err("wrong native error owner".into());
        };
        assert_eq!(code, Code::Unsupported);
        assert_eq!(operation, "ABI table");
        assert_eq!(
            source.downcast_ref::<sdk::Error>().map(sdk::Error::code),
            Some(sdk::ErrorCode::Incompatible)
        );
        Ok(())
    }
}
