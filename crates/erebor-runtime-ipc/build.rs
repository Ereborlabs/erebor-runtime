use std::{io, path::PathBuf};

fn main() -> Result<(), io::Error> {
    let proto = PathBuf::from("proto/erebor/runtime/ipc/v1/control.proto");
    println!("cargo:rerun-if-changed={}", proto.display());
    println!("cargo:rustc-check-cfg=cfg(erebor_runtime_ipc_contract_tests)");
    println!("cargo:rustc-cfg=erebor_runtime_ipc_contract_tests");

    prost_build::Config::new().compile_protos(&[proto], &[PathBuf::from("proto")])?;

    Ok(())
}
