use std::env;
use std::path::PathBuf;

use araphor_component_build::ComponentBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    if env::var("TARGET")?.starts_with("wasm32") {
        return Ok(());
    }
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
        .join("../..")
        .canonicalize()?;
    let output = PathBuf::from(env::var("OUT_DIR")?).canonicalize()?;
    let target = env::var_os("ARAPHOR_COMPONENT_TARGET")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target/analysis-guest"));
    let target = if target.is_absolute() {
        target
    } else {
        root.join(target)
    };
    std::fs::create_dir_all(&target)?;
    let target = target.canonicalize()?;
    if output.starts_with(&target) {
        return Err(std::io::Error::other(format!(
            "guest Cargo cache {} contains native OUT_DIR {}; set ARAPHOR_COMPONENT_TARGET to a separate cache",
            target.display(),
            output.display(),
        ))
        .into());
    }
    println!("cargo:rerun-if-env-changed=ARAPHOR_COMPONENT_TARGET");
    for input in ComponentBuilder::inputs(&root) {
        println!("cargo:rerun-if-changed={}", input.display());
    }
    ComponentBuilder::workspace(&root, &target, &output)?;
    Ok(())
}
