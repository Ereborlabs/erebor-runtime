use super::{records::Records, DataView};
use crate::analysis::raw::RawIdentity;
use crate::{
    AnalysisSourceReceiptV1, AnalysisSourceStatusV1, CoverageReportRef, EvidenceIntakeIdentityV1,
    NativeStateSnafu, NativeStorageSnafu, Result,
};
use fjall::BranchSnapshot;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

mod coverage;
mod raw;
mod recovery;

struct Sources;

#[derive(Deserialize, Serialize)]
struct Report {
    reference: CoverageReportRef,
    encoded_report: Vec<u8>,
}

impl Sources {
    const RECEIPTS: &'static [u8] = b"\0data/source/";
    const EPOCHS: &'static [u8] = b"\0data/epoch/";
    const ENDS: &'static [u8] = b"\0data/raw/end/";
    const NEXT: &'static [u8] = b"\0data/raw/next";
    const REPORTS: &'static [u8] = b"\0data/coverage/report/";
    const CHANGES: &'static [u8] = b"\0data/coverage/change/";

    fn key(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
        [prefix, suffix].concat()
    }

    fn report(identity: &EvidenceIntakeIdentityV1, revision: u64) -> Vec<u8> {
        [Self::REPORTS, &identity.key(), &revision.to_be_bytes()].concat()
    }

    fn boundary(tenant: &[u8; 16], revision: u64) -> Vec<u8> {
        // Source keys start with zero, below this revision boundary.
        [Self::CHANGES, tenant, &revision.to_be_bytes(), &[u8::MAX]].concat()
    }

    fn change(reference: &CoverageReportRef) -> Vec<u8> {
        [
            Self::CHANGES,
            &reference.source.tenant_id,
            &reference.position.commit_revision.to_be_bytes(),
            &reference.source.key(),
            &reference.revision.to_be_bytes(),
        ]
        .concat()
    }

    fn read<T: for<'de> Deserialize<'de>>(
        snapshot: &BranchSnapshot,
        key: &[u8],
    ) -> Result<Option<T>> {
        Records::payload(key, |key| {
            snapshot.get(key).context(NativeStorageSnafu {
                operation: "read source record",
            })
        })?
        .map(|bytes| Records::decode(&bytes))
        .transpose()
    }

    fn check_epoch(
        identity: &EvidenceIntakeIdentityV1,
        saved: &EvidenceIntakeIdentityV1,
    ) -> Result<()> {
        if saved.epoch_key() != identity.epoch_key()
            || saved.tenant_id != identity.tenant_id
            || saved.node_boot_id != identity.node_boot_id
            || saved.label_epoch != identity.label_epoch
        {
            return NativeStateSnafu {
                field: "source epoch binding",
            }
            .fail();
        }
        Ok(())
    }
}

impl DataView {
    pub fn source_binding(
        &self,
        tenant_id: [u8; 16],
        node_id: &str,
        source_id: [u8; 16],
        source_epoch: u64,
    ) -> Result<Option<EvidenceIntakeIdentityV1>> {
        if !crate::node_id_is_valid(node_id)
            || tenant_id == [0; 16]
            || source_id == [0; 16]
            || source_epoch == 0
        {
            return NativeStateSnafu {
                field: "source epoch lookup",
            }
            .fail();
        }
        for receipt in self
            .raw
            .sources
            .values()
            .filter_map(|source| source.receipt.evidence())
        {
            let identity = &receipt.identity;
            if identity.tenant_id == tenant_id
                && identity.node_id == node_id
                && identity.source_id == source_id
                && identity.source_epoch == source_epoch
                && self.source_receipt(identity)?.is_some()
            {
                return Ok(Some(identity.clone()));
            }
        }
        Ok(None)
    }

    pub fn source_receipt(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<AnalysisSourceReceiptV1>> {
        if !identity.valid() {
            return NativeStateSnafu {
                field: "source identity",
            }
            .fail();
        }
        let key = identity.key();
        let baseline: Option<AnalysisSourceReceiptV1> =
            Sources::read(&self.snapshot, &Sources::key(Sources::RECEIPTS, &key))?;
        if baseline.as_ref().is_some_and(|receipt| {
            receipt.identity != *identity || receipt.retained_floor > receipt.contiguous_cursor
        }) {
            return NativeStateSnafu {
                field: "source receipt",
            }
            .fail();
        }
        let source = self.raw.sources.get(&key);
        let visible = source.is_some_and(|source| source.written)
            && (self.raw.revision <= self.revision
                || self
                    .raw
                    .ranges
                    .range((key.clone(), 0)..=(key.clone(), u64::MAX))
                    .any(|(_, (revision, _))| *revision <= self.revision));
        let mut receipt = match baseline {
            Some(receipt) => receipt,
            None if visible => AnalysisSourceReceiptV1 {
                identity: identity.clone(),
                cpu_id: source
                    .and_then(|source| source.receipt.cpu())
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "source CPU",
                        }
                        .build()
                    })?,
                contiguous_cursor: 0,
                coverage_revision: 0,
                retained_floor: 0,
            },
            None => return Ok(None),
        };
        if let Some(source) = source {
            if !source
                .receipt
                .matches(&RawIdentity::Evidence(identity.clone()))
                || source.receipt.cpu() != Some(receipt.cpu_id)
            {
                return NativeStateSnafu {
                    field: "raw source binding",
                }
                .fail();
            }
            if self.raw.revision <= self.revision {
                receipt.contiguous_cursor = receipt.contiguous_cursor.max(source.receipt.cursor());
                return Ok(Some(receipt));
            }
        }
        for (_, &(revision, slot)) in self.raw.ranges.range((key.clone(), 0)..=(key, u64::MAX)) {
            if revision > self.revision {
                continue;
            }
            let span = &self.raw.entries[&revision].commit.spans[slot];
            if span.first > receipt.contiguous_cursor.saturating_add(1) {
                break;
            }
            receipt.contiguous_cursor = receipt.contiguous_cursor.max(span.last);
        }
        Ok(Some(receipt))
    }

    pub fn source_status(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<AnalysisSourceStatusV1>> {
        let Some(receipt) = self.source_receipt(identity)? else {
            return Ok(None);
        };
        let key = identity.key();
        let retained_event_count = self
            .raw
            .ranges
            .range((key.clone(), 0)..=(key, u64::MAX))
            .filter(|(_, (revision, _))| *revision <= self.revision)
            .map(|(_, &(revision, slot))| {
                let span = &self.raw.entries[&revision].commit.spans[slot];
                span.last - span.first + 1
            })
            .sum();
        let latest_coverage_report = if receipt.coverage_revision == 0 {
            None
        } else {
            let report: Report = Sources::read(
                &self.snapshot,
                &Sources::report(identity, receipt.coverage_revision),
            )?
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "source coverage report",
                }
                .build()
            })?;
            if report.reference.source != *identity
                || report.reference.revision != receipt.coverage_revision
                || report.reference.position.commit_revision > self.revision
                || report.encoded_report.is_empty()
            {
                return NativeStateSnafu {
                    field: "source coverage identity",
                }
                .fail();
            }
            Some(report.encoded_report)
        };
        Ok(Some(AnalysisSourceStatusV1 {
            receipt,
            retained_event_count,
            latest_coverage_report,
        }))
    }
}

impl DataView {
    pub(in crate::analysis::native) fn source_header(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        root: &std::path::Path,
        output: &mut crate::AnalysisExtractionV1,
        control: &crate::AnalysisReadControl,
    ) -> Result<crate::AnalysisSourceSnapshotV1> {
        control.check()?;
        let receipt = self.source_receipt(identity)?.ok_or_else(|| {
            NativeStateSnafu {
                field: "selected source receipt",
            }
            .build()
        })?;
        let key = identity.key();
        let mut revision = 0;
        for (_, &(id, _)) in self.raw.ranges.range((key.clone(), 0)..=(key, u64::MAX)) {
            control.check()?;
            if id <= self.revision {
                revision = revision.max(id);
            }
        }
        let coverage_report = if receipt.coverage_revision == 0 {
            None
        } else {
            let saved = output.input_bytes;
            let bytes = Records::charged_payload(
                &Sources::report(identity, receipt.coverage_revision),
                |key| Records::read(key, &self.snapshot),
                &mut |bytes| output.charge(bytes),
            )?
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "source coverage report",
                }
                .build()
            })?;
            let report: Report = Records::decode(&bytes)?;
            if report.reference.source != *identity
                || report.reference.revision != receipt.coverage_revision
                || report.reference.position.commit_revision > self.metadata_revision
                || report.encoded_report.is_empty()
            {
                return NativeStateSnafu {
                    field: "source coverage identity",
                }
                .fail();
            }
            revision = revision.max(report.reference.position.commit_revision);
            drop(bytes);
            output.input_bytes = saved;
            output.charge(report.encoded_report.capacity())?;
            Some(report.encoded_report)
        };
        let recovery = self.source_recovery(identity, output, control)?;
        for gap in &recovery {
            revision = revision.max(gap.commit_revision);
        }
        let state = self.raw.source_state(
            root,
            &receipt,
            self.revision,
            &[],
            &[],
            control,
            (output.input_bytes, output.limits.input_bytes),
        )?;
        if state.covered != receipt.contiguous_cursor {
            return crate::AnalysisStore::reject_path(
                root,
                "the selected source has an unrecorded input gap",
            );
        }
        output.charge(
            state.pending.capacity() * std::mem::size_of::<crate::AnalysisGapV1>()
                + receipt.identity.node_id.capacity(),
        )?;
        Ok(crate::AnalysisSourceSnapshotV1 {
            receipt,
            commit_revision: revision,
            expired: Vec::new(),
            recovery,
            pending: state.pending,
            coverage_report,
            typed_report: None,
        })
    }
}
