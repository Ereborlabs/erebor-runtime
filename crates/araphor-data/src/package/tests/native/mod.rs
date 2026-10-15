use std::path::PathBuf;

use super::wasm::{component, evaluate, parameters};
use super::{Fixture, TestResult};
use crate::package::*;

mod checkpoint;
mod failures;
mod interruption;
mod lifecycle;
mod restart;

fn native(mut bundle: PackageBundleV1) -> TestResult<PackageBundleV1> {
    let directory = PathBuf::from(
        std::env::var_os("ARAPHOR_NATIVE_DIR").ok_or("ARAPHOR_NATIVE_DIR is required")?,
    );
    let artifact =
        std::fs::read(directory.join(format!("runtime.{}", std::env::consts::DLL_EXTENSION)))?;
    let package = &mut bundle.artifacts[0];
    let exports: Vec<_> = package
        .descriptor
        .exports
        .iter()
        .map(|model| model.name.clone())
        .collect();
    let qualification = crate::package::native::Qualification::inspect(
        &artifact,
        exports.clone(),
        env!("ARAPHOR_NATIVE_TARGET").into(),
    )?;
    package.implementations = vec![PackageImplementationV1::Native {
        export: exports[0].clone(),
        artifact,
        qualification: Some(qualification),
    }];
    Ok(bundle)
}
