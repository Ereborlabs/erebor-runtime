use std::io;
use std::path::PathBuf;

fn main() -> Result<(), io::Error> {
    let proto = PathBuf::from("proto/erebor/mithril/control/v1/control.proto");
    let shared = PathBuf::from("../araphor-data/proto");
    println!("cargo:rerun-if-changed={}", proto.display());
    println!(
        "cargo:rerun-if-changed={}",
        shared
            .join("erebor/mithril/control/v1/evidence.proto")
            .display()
    );
    let descriptor_path = PathBuf::from(
        std::env::var_os("OUT_DIR")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Cargo did not set OUT_DIR"))?,
    )
    .join("erebor.mithril.control.v1.bin");
    let mut builder = tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .bytes([".erebor.mithril.control.v1.EvidenceBatch.framed_records"]);
    for name in [
        "EvidenceRecord",
        "EvidenceDecisionContext",
        "EvidenceExactFileObject",
        "EvidenceRecords",
        "EvidenceTemporalCoverage",
        "CoverageCounters",
        "CoverageInterval",
        "CoverageReport",
    ] {
        builder = builder.extern_path(
            format!(".erebor.mithril.control.v1.{name}"),
            format!("::araphor_data::{name}"),
        );
    }
    builder
        .file_descriptor_set_path(descriptor_path)
        .compile_protos(&[proto], &[PathBuf::from("proto"), shared])
}
