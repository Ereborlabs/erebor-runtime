use std::{io, path::PathBuf};

fn main() -> Result<(), io::Error> {
    let proto_directory = PathBuf::from("proto/erebor/runtime/ipc/v1");
    let protos = [
        proto_directory.join("hook.proto"),
        proto_directory.join("daemon.proto"),
        proto_directory.join("mithril.proto"),
    ];
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }
    let descriptor_path = PathBuf::from(
        std::env::var_os("OUT_DIR")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Cargo did not set OUT_DIR"))?,
    )
    .join("erebor.runtime.ipc.v1.bin");

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .file_descriptor_set_path(descriptor_path)
        .compile_protos(&protos, &[PathBuf::from("proto")])?;

    Ok(())
}
