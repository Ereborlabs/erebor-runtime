use std::{error::Error as StdError, fs, path::Path};

use araphor_data::{
    AnalysisStore, EvidenceStoreOutcomeV1, ValidatedCoverageV1, ValidatedEvidenceBatchV1,
};
use mithril_control::{ControlStore, DiscoveryInputManifestV1, DiscoveryOwner};
use prost::Message as _;
use snafu::ensure;

use crate::error::InvalidInputSnafu;

pub fn run(output: &Path) -> Result<(), Box<dyn StdError>> {
    let fixture = include_bytes!("../../fixtures/discovery/manifest.json");
    let input = DiscoveryInputManifestV1::from_json(fixture)?;
    let derived = DiscoveryOwner::derive_recorded(&input)?;
    let coverage = input.coverage.first().ok_or("coverage fixture is absent")?;
    let identity = coverage.stream.clone();
    ensure!(
        coverage.first_cursor == 1
            && coverage.last_cursor == 3
            && coverage.expected_records == 3
            && input.records.len() == 4
            && input.records[3] == input.records[0],
        InvalidInputSnafu {
            path: output,
            reason: "the storage fixture cursor or duplicate changed",
        }
    );

    let temporary = tempfile::tempdir()?;
    let control = ControlStore::open(temporary.path().join("control"))?;
    let policy_before = control.policy_document("offline-storage-candidate")?;
    let root = temporary.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let mut framed_records = Vec::new();
    let mut frame_ends = Vec::new();
    for (index, record) in input.records.iter().take(3).enumerate() {
        ensure!(
            record.id.stream == identity
                && record.id.cpu_id == coverage.cpu_id
                && record.id.durable_cursor == index as u64 + 1,
            InvalidInputSnafu {
                path: output,
                reason: "the storage fixture source identity changed",
            }
        );
        let wire = record.observation.to_wire_record()?.encode_to_vec();
        let frame_start = framed_records.len();
        framed_records.extend_from_slice(&u32::try_from(wire.len())?.to_be_bytes());
        framed_records.extend_from_slice(&wire);
        let checksum = crc32c::crc32c(&framed_records[frame_start..]);
        framed_records.extend_from_slice(&checksum.to_be_bytes());
        frame_ends.push(framed_records.len());
    }
    let first_frame_len = frame_ends[0];
    ensure!(
        store.accept_validated_batch(
            identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: coverage.cpu_id,
                first_cursor: coverage.first_cursor,
                last_cursor: coverage.last_cursor,
                intake_utc_ns: 1_800_000_000_000_000_000,
                framed_records: framed_records.clone().into(),
                frame_ends,
            },
        )? == EvidenceStoreOutcomeV1::Accepted,
        InvalidInputSnafu {
            path: output,
            reason: "the storage fixture batch was not durably accepted",
        }
    );
    let first_frame = framed_records[..first_frame_len].to_vec();
    let duplicate = ValidatedEvidenceBatchV1 {
        cpu_id: coverage.cpu_id,
        first_cursor: coverage.first_cursor,
        last_cursor: coverage.first_cursor,
        intake_utc_ns: 1_800_000_000_000_000_000,
        framed_records: first_frame.clone().into(),
        frame_ends: vec![first_frame.len()],
    };
    let revision_after_batch = store.meta()?.commit_revision;
    ensure!(
        store.accept_validated_batch(identity.clone(), duplicate.clone())?
            == EvidenceStoreOutcomeV1::Accepted
            && store.meta()?.commit_revision == revision_after_batch,
        InvalidInputSnafu {
            path: output,
            reason: "the duplicate changed the durable batch result",
        }
    );
    let mut conflicting = duplicate;
    conflicting.framed_records = {
        let mut wire = first_frame[4..first_frame.len() - 4].to_vec();
        wire.extend_from_slice(&[0xf8, 0x07, 0x01]);
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::try_from(wire.len())?.to_be_bytes());
        framed.extend_from_slice(&wire);
        framed.extend_from_slice(&crc32c::crc32c(&framed).to_be_bytes());
        conflicting.frame_ends = vec![framed.len()];
        framed.into()
    };
    ensure!(
        store
            .accept_validated_batch(identity.clone(), conflicting)
            .is_err()
            && store.meta()?.commit_revision == revision_after_batch,
        InvalidInputSnafu {
            path: output,
            reason: "the conflicting duplicate changed the store",
        }
    );

    let coverage_bytes = serde_json::to_vec(coverage)?;
    store.accept_validated_coverage(ValidatedCoverageV1 {
        identity: identity.clone(),
        cpu_id: coverage.cpu_id,
        revision: coverage.coverage_revision,
        encoded_report: coverage_bytes.clone(),
    })?;
    let before = store
        .source_status(&identity)?
        .ok_or("source status is absent")?;
    let store_meta = store.meta()?;
    ensure!(
        before.receipt.identity == identity
            && before.receipt.contiguous_cursor == coverage.last_cursor
            && before.receipt.coverage_revision == coverage.coverage_revision
            && before.retained_event_count == derived.snapshot.accepted_records
            && before.latest_coverage_report.as_deref() == Some(coverage_bytes.as_slice()),
        InvalidInputSnafu {
            path: output,
            reason: "the committed source identity, coverage or count differs",
        }
    );
    drop(store);

    let reopened = AnalysisStore::open(&root)?;
    ensure!(
        reopened.meta()? == store_meta
            && reopened.source_status(&identity)? == Some(before.clone())
            && control.policy_document("offline-storage-candidate")? == policy_before,
        InvalidInputSnafu {
            path: output,
            reason: "reopen changed retained data or Control policy state",
        }
    );
    let checks = [
        "validated-identity",
        "durable-contiguous-receipt",
        "duplicate-noop",
        "conflicting-duplicate-rejected",
        "coverage-bytes-and-revision",
        "retained-count",
        "reopen-store-identity",
        "reopen-source-status",
        "independent-policy-state",
    ];
    fs::create_dir(output)?;
    super::write_json(
        &output.join("result.json"),
        &serde_json::json!({
            "schema_version": 1,
            "analysis_schema_version": store_meta.schema_version,
            "case": "storage-contract",
            "result": "PASS",
            "production_intake": false,
            "asserted_contracts": checks,
            "assertion_count": checks.len(),
            "fixture_digest": crate::DigestV1::of(fixture),
            "source_identity": identity,
            "store_uuid": store_meta.store_uuid.to_string(),
            "recovery_epoch": store_meta.recovery_epoch,
            "commit_revision": store_meta.commit_revision,
            "contiguous_cursor": before.receipt.contiguous_cursor,
            "coverage_revision": before.receipt.coverage_revision,
            "coverage_digest": crate::DigestV1::of(&coverage_bytes),
            "retained_event_count": before.retained_event_count,
            "snapshot_digest": hex::encode(derived.snapshot.content_digest.0),
        }),
    )?;
    Ok(())
}
