use std::io;
use std::path::PathBuf;

fn main() -> Result<(), io::Error> {
    let proto = PathBuf::from("proto/erebor/mithril/control/v1/control.proto");
    println!("cargo:rerun-if-changed={}", proto.display());
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto], &[PathBuf::from("proto")])
}
