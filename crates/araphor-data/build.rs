use std::io;
use std::path::PathBuf;

fn main() -> Result<(), io::Error> {
    let proto = PathBuf::from("proto/erebor/mithril/control/v1/evidence.proto");
    println!("cargo:rerun-if-changed={}", proto.display());
    prost_build::Config::new()
        .type_attribute(
            ".erebor.mithril.control.v1.EvidenceDecisionContext",
            "#[derive(serde::Serialize, serde::Deserialize, Eq)] #[serde(deny_unknown_fields)]",
        )
        .type_attribute(
            ".erebor.mithril.control.v1.EvidenceExactFileObject",
            "#[derive(serde::Serialize, serde::Deserialize, Eq)] #[serde(deny_unknown_fields)]",
        )
        .bytes([
            ".erebor.mithril.control.v1.EvidenceRecord.coverage_interval_id",
            ".erebor.mithril.control.v1.EvidenceRecord.process_lineage_id",
            ".erebor.mithril.control.v1.EvidenceRecord.authority_domain_id",
            ".erebor.mithril.control.v1.EvidenceRecord.execution_set_id",
            ".erebor.mithril.control.v1.EvidenceRecord.exact_object_id",
        ])
        .compile_protos(&[proto], &[PathBuf::from("proto")])
}
