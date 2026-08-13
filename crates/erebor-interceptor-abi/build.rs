use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

fn main() {
    if let Err(error) = generate_header() {
        eprintln!("failed to generate erebor-interceptor ABI header: {error:?}");
        std::process::exit(1);
    }
}

fn generate_header() -> Result<(), Box<dyn std::error::Error>> {
    let crate_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "CARGO_MANIFEST_DIR is not set")
        })?);
    let config_path = crate_dir.join("cbindgen.toml");
    println!("cargo:rerun-if-changed={}", config_path.display());
    println!(
        "cargo:rerun-if-changed={}",
        crate_dir.join("src/abi.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        crate_dir.join("src/abi/identity.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        crate_dir.join("src/abi/ipc.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        crate_dir.join("src/abi/path.rs").display()
    );
    println!("cargo:rerun-if-env-changed=EREBOR_UPDATE_ABI");

    let config = cbindgen::Config::from_file(&config_path)?;
    let bindings = cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()?;
    let output = PathBuf::from(
        env::var_os("OUT_DIR")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "OUT_DIR is not set"))?,
    )
    .join("erebor_interceptor_abi.h");
    bindings.write_to_file(&output);
    let generated = fs::read(&output)?;
    let checked_path =
        crate_dir.join("../../bpf/erebor-interceptor/include/erebor_interceptor_abi.h");
    if env::var_os("EREBOR_UPDATE_ABI").is_some() {
        fs::write(&checked_path, &generated)?;
        return Ok(());
    }
    let checked = fs::read(&checked_path)?;
    if generated != checked {
        return Err(io::Error::other(
            "checked-in erebor_interceptor_abi.h differs from cbindgen output",
        )
        .into());
    }
    Ok(())
}
