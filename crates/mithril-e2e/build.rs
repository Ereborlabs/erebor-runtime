use std::io;
use std::path::PathBuf;

fn main() -> Result<(), io::Error> {
    let proto = PathBuf::from("proto/erebor/mithril/e2e/v1/throughput.proto");
    println!("cargo:rerun-if-changed={}", proto.display());
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .bytes([".erebor.mithril.e2e.v1.FileChunk.payload"])
        .compile_protos(&[proto], &[PathBuf::from("proto")])
}
