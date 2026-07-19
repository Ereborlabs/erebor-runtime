use std::{io, path::PathBuf};

fn main() -> Result<(), io::Error> {
    let proto_directory = PathBuf::from("proto/erebor/runtime/ipc/v1");
    let protos = [
        proto_directory.join("envelope.proto"),
        proto_directory.join("guard.proto"),
        proto_directory.join("hook.proto"),
        proto_directory.join("daemon.proto"),
    ];
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }
    println!("cargo:rustc-check-cfg=cfg(erebor_runtime_ipc_contract_tests)");
    println!("cargo:rustc-cfg=erebor_runtime_ipc_contract_tests");

    prost_build::Config::new().compile_protos(&protos, &[PathBuf::from("proto")])?;

    Ok(())
}
