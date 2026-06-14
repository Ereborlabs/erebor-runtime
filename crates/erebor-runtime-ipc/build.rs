use std::{io, path::PathBuf};

fn main() -> Result<(), io::Error> {
    let proto = PathBuf::from("proto/erebor/runtime/ipc/v1/control.proto");
    println!("cargo:rerun-if-changed={}", proto.display());

    prost_build::Config::new().compile_protos(&[proto], &[PathBuf::from("proto")])?;

    Ok(())
}
