use araphor_data::{
    AnalysisStore, EvidenceStoreOutcomeV1, LegacySourceImportV1, ValidatedCoverageV1,
    ValidatedEvidenceBatchV1,
};
use sha2::{Digest as _, Sha256};

use super::{ControlStore, EvidenceFramePageV1, EvidenceReadV1};
use crate::{
    AuthenticatedEvidenceNodeV1, EvidenceBatch, EvidenceIntakeIdentityV1, EvidenceIntakeOwner,
    Result,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LegacyEvidenceCopyV1 {
    pub source_count: u64,
    pub retained_records: u64,
    pub coverage_reports: u64,
    pub control_commit_index: u64,
}

impl ControlStore {
    /// Copy only while the old Control lease is owned and Node intake is stopped.
    pub fn copy_legacy_evidence(&self, data: &AnalysisStore) -> Result<LegacyEvidenceCopyV1> {
        let commit_index = self.health()?.commit_index;
        let mut summary = LegacyEvidenceCopyV1 {
            control_commit_index: commit_index,
            ..LegacyEvidenceCopyV1::default()
        };
        let mut after = None;
        loop {
            let sources = self.legacy_sources(after.as_ref())?;
            if sources.is_empty() {
                break;
            }
            for identity in &sources {
                let read = self.begin_evidence_read(identity, 1)?;
                let meta = read.metadata();
                if meta.control_commit_index != commit_index
                    || meta.last_cursor == u64::MAX
                    || meta.retained_floor == 0
                    || meta.retained_floor > meta.last_cursor + 1
                    || (meta.coverage_revision > 0 && read.coverage_bytes().is_none())
                {
                    return Err(
                        self.import_error("the old source changed or has an incomplete receipt")
                    );
                }
                let binding = meta.cpu_binding;
                if meta.last_cursor > 0 && binding.is_none() {
                    return Err(self.import_error("the old source has no durable CPU binding"));
                }
                if binding.is_some_and(|binding| {
                    meta.retained_floor <= meta.last_cursor
                        && binding.first_cursor > meta.retained_floor
                }) {
                    return Err(self.import_error("retained old evidence has no CPU proof"));
                }
                let cpu_id = binding
                    .map(|binding| binding.cpu_id)
                    .or_else(|| meta.coverage.as_ref().map(|report| report.cpu_id))
                    .ok_or_else(|| self.import_error("the old source has no CPU identity"))?;
                if meta
                    .coverage
                    .as_ref()
                    .is_some_and(|report| report.cpu_id != cpu_id)
                {
                    return Err(self.import_error("old evidence and coverage disagree on CPU"));
                }
                let mut digest = Sha256::new();
                let count = self.each_legacy_page(&read, cpu_id, |batch| {
                    digest.update(&batch.framed_records);
                    Ok(())
                })?;
                let input = LegacySourceImportV1 {
                    identity: identity.clone(),
                    cpu_id,
                    accepted_cursor: meta.last_cursor,
                    retained_floor: meta.retained_floor - 1,
                    coverage_revision: meta.coverage_revision,
                    event_sha256: digest.finalize().into(),
                    coverage_sha256: read
                        .coverage_bytes()
                        .map(|bytes| Sha256::digest(bytes).into()),
                };
                data.begin_legacy_import(&input)
                    .map_err(|error| self.data_error(error))?;
                self.each_legacy_page(&read, cpu_id, |batch| {
                    match data
                        .import_legacy_batch(identity.clone(), batch)
                        .map_err(|error| self.data_error(error))?
                    {
                        EvidenceStoreOutcomeV1::Accepted => Ok(()),
                        _ => {
                            Err(self
                                .import_error("an old accepted page did not advance its receipt"))
                        }
                    }
                })?;
                if let Some(bytes) = read.coverage_bytes() {
                    data.accept_validated_coverage(ValidatedCoverageV1 {
                        identity: identity.clone(),
                        cpu_id,
                        revision: meta.coverage_revision,
                        encoded_report: bytes.to_vec(),
                    })
                    .map_err(|error| self.data_error(error))?;
                }
                data.finish_legacy_import(&input)
                    .map_err(|error| self.data_error(error))?;
                summary.source_count = summary
                    .source_count
                    .checked_add(1)
                    .ok_or_else(|| self.import_error("the imported source count overflowed"))?;
                summary.retained_records = summary
                    .retained_records
                    .checked_add(count)
                    .ok_or_else(|| self.import_error("the imported record count overflowed"))?;
                summary.coverage_reports = summary
                    .coverage_reports
                    .checked_add(u64::from(read.coverage_bytes().is_some()))
                    .ok_or_else(|| self.import_error("the imported coverage count overflowed"))?;
            }
            after = sources.last().cloned();
        }
        if self.health()?.commit_index != commit_index {
            return Err(self.import_error("the old Control store changed during offline import"));
        }
        Ok(summary)
    }

    fn each_legacy_page(
        &self,
        read: &EvidenceReadV1,
        cpu_id: u32,
        mut use_page: impl FnMut(ValidatedEvidenceBatchV1) -> Result<()>,
    ) -> Result<u64> {
        let mut cursor = read.metadata().retained_floor;
        let mut count = 0_u64;
        while cursor <= read.metadata().last_cursor {
            let page = self.read_evidence_frames_page(read, cursor)?;
            let next = page.next_cursor;
            let checked = self.check_legacy_page(&read.metadata().identity, cpu_id, page)?;
            count = count
                .checked_add(checked.frame_ends.len() as u64)
                .ok_or_else(|| self.import_error("the old source record count overflowed"))?;
            use_page(checked)?;
            match next {
                Some(value) if value > cursor && value <= read.metadata().last_cursor => {
                    cursor = value;
                }
                None => break,
                _ => return Err(self.import_error("the old evidence page cursor is invalid")),
            }
        }
        Ok(count)
    }

    fn check_legacy_page(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        cpu_id: u32,
        page: EvidenceFramePageV1,
    ) -> Result<ValidatedEvidenceBatchV1> {
        let authenticated = AuthenticatedEvidenceNodeV1 {
            tenant_id: identity.tenant_id,
            node_id: identity.node_id.clone(),
            node_boot_id: identity.node_boot_id,
            label_epoch: identity.label_epoch,
        };
        let batch = EvidenceBatch {
            node_boot_id: identity.node_boot_id.to_vec(),
            source_id: identity.source_id.to_vec(),
            source_epoch: identity.source_epoch,
            cpu_id,
            first_cursor: page.first_cursor,
            framed_records: page.framed_records.into(),
            commit_group_tail: true,
        };
        let (checked_id, checked) = EvidenceIntakeOwner::from_store(self.clone())
            .validate_batch(&authenticated, batch)
            .map_err(|status| {
                self.import_error(format!("the old evidence frame is invalid: {status}"))
            })?;
        if checked_id != *identity || checked.frame_ends != page.frame_ends {
            return Err(self.import_error("the old frame index differs from checked record bytes"));
        }
        Ok(ValidatedEvidenceBatchV1 {
            cpu_id: checked.cpu_id,
            first_cursor: checked.first_cursor,
            last_cursor: checked.last_cursor,
            intake_utc_ns: 0,
            framed_records: checked.framed_records,
            frame_ends: checked.frame_ends,
        })
    }

    fn import_error(&self, reason: impl Into<String>) -> crate::Error {
        crate::error::DiscoverySnafu {
            code: "LEGACY_IMPORT",
            reason: reason.into(),
        }
        .build()
    }

    fn data_error(&self, source: araphor_data::Error) -> crate::Error {
        crate::Error::DataStore {
            source: Box::new(source),
            location: snafu::Location::new(file!(), line!(), column!()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;

    #[test]
    fn legacy_copy_replays_exact_accepted_frames_without_old_store_writes(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let control = ControlStore::open(directory.path().join("control"))?;
        let data = AnalysisStore::open(directory.path().join("analysis"))?;
        let manifest = crate::DiscoveryInputManifestV1::from_json(include_bytes!(
            "../../../mithril-e2e/fixtures/discovery/manifest.json"
        ))?;
        let input = &manifest.records[0];
        let identity = input.id.stream.clone();
        let record = input.observation.to_wire_record()?;
        let authenticated = AuthenticatedEvidenceNodeV1 {
            tenant_id: identity.tenant_id,
            node_id: identity.node_id.clone(),
            node_boot_id: identity.node_boot_id,
            label_epoch: identity.label_epoch,
        };
        let intake = crate::EvidenceIntakeOwner::from_store(control.clone());
        let mut last_frames = Vec::new();
        for cursor in 1..=2 {
            let mut record = record.clone();
            record.observed_boottime_ns = cursor;
            let frames = crate::EvidenceBatchInputV1::encode(cursor, vec![record])?;
            intake.receive(
                &authenticated,
                EvidenceBatch {
                    node_boot_id: identity.node_boot_id.to_vec(),
                    source_id: identity.source_id.to_vec(),
                    source_epoch: identity.source_epoch,
                    cpu_id: input.observation.cpu_id,
                    first_cursor: cursor,
                    framed_records: frames.framed_records.clone(),
                    commit_group_tail: true,
                },
            )?;
            last_frames = frames.framed_records.to_vec();
        }
        let coverage = crate::CoverageReport {
            source_id: identity.source_id.to_vec(),
            source_epoch: identity.source_epoch,
            cpu_id: input.observation.cpu_id,
            revision: 1,
            intervals: vec![crate::CoverageInterval {
                interval_id: vec![7; 16],
                source_epoch: identity.source_epoch,
                revision: 1,
                state: "HEALTHY".into(),
                first_sequence: 1,
                last_sequence: Some(2),
                opening_counters: Some(crate::CoverageCounters::default()),
                closing_counters: Some(crate::CoverageCounters {
                    attempted: 2,
                    requested: 2,
                    emitted: 2,
                    next_sequence: 3,
                    ..crate::CoverageCounters::default()
                }),
                gap_reasons: vec![],
                current: true,
            }],
        };
        intake.receive_coverage(&authenticated, &coverage)?;
        crate::EvidenceRetentionOwner::from_store(control.clone()).acknowledge(
            crate::EvidenceConsumptionWatermarkV1 {
                identity: identity.clone(),
                evidence_cursor: 1,
                coverage_revision: 0,
            },
        )?;
        let old_commit = control.health()?.commit_index;
        let summary = control.copy_legacy_evidence(&data)?;
        assert_eq!(summary.source_count, 1);
        assert_eq!(summary.retained_records, 1);
        assert_eq!(summary.coverage_reports, 1);
        assert_eq!(summary.control_commit_index, old_commit);
        assert!(data.read_page(&identity, 1).is_err());
        assert_eq!(
            data.read_page(&identity, 2)?.records[0].framed_record,
            last_frames
        );
        let receipt = data.source_receipt(&identity)?.ok_or("receipt absent")?;
        assert_eq!(receipt.contiguous_cursor, 2);
        assert_eq!(receipt.retained_floor, 1);
        assert_eq!(receipt.coverage_revision, 1);
        assert_eq!(
            data.source_status(&identity)?
                .ok_or("source absent")?
                .latest_coverage_report,
            Some(coverage.encode_to_vec())
        );
        assert_eq!(control.health()?.commit_index, old_commit);
        assert_eq!(control.copy_legacy_evidence(&data)?, summary);
        Ok(())
    }
}
