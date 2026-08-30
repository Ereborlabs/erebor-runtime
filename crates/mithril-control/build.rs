use std::io;
use std::path::PathBuf;

fn main() -> Result<(), io::Error> {
    let proto = PathBuf::from("proto/erebor/mithril/control/v1/control.proto");
    println!("cargo:rerun-if-changed={}", proto.display());
    let descriptor_path = PathBuf::from(
        std::env::var_os("OUT_DIR")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Cargo did not set OUT_DIR"))?,
    )
    .join("erebor.mithril.control.v1.bin");
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .bytes([
            ".erebor.mithril.control.v1.EvidenceBatch.framed_records",
            ".erebor.mithril.control.v1.EvidenceRecord.coverage_interval_id",
            ".erebor.mithril.control.v1.EvidenceRecord.process_lineage_id",
            ".erebor.mithril.control.v1.EvidenceRecord.authority_domain_id",
            ".erebor.mithril.control.v1.EvidenceRecord.execution_set_id",
            ".erebor.mithril.control.v1.EvidenceRecord.exact_object_id",
        ])
        .file_descriptor_set_path(descriptor_path)
        .compile_protos(&[proto], &[PathBuf::from("proto")])
}
