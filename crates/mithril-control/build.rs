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
        .compile_protos(&[proto], &[PathBuf::from("proto"), shared])?;
    let directory = PathBuf::from("../../packages/default-definitions");
    println!("cargo:rerun-if-changed={}", directory.display());
    let mut files = std::fs::read_dir(&directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    files.retain(|path| {
        path.extension()
            .is_some_and(|extension| extension == "yaml" || extension == "yml")
    });
    files.sort();
    let mut definitions = std::collections::BTreeMap::new();
    for path in files {
        let definition =
            araphor_discovery_definition::Definition::read(&path).map_err(io::Error::other)?;
        if definitions
            .insert(definition.name.clone(), definition)
            .is_some()
        {
            return Err(io::Error::other("default Definition names must be unique"));
        }
    }
    let output = PathBuf::from(
        std::env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("Cargo did not set OUT_DIR"))?,
    );
    std::fs::write(
        output.join("default-definitions.json"),
        serde_json::to_vec(&definitions.into_values().collect::<Vec<_>>())
            .map_err(io::Error::other)?,
    )
}
