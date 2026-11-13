use super::{records::Records, DataView};
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

impl super::NativeStore {
    pub fn source_binding(
        &self,
        tenant: [u8; 16],
        node: &str,
        source: [u8; 16],
        epoch: u64,
    ) -> Result<Option<EvidenceIntakeIdentityV1>> {
        self.view()?.source_binding(tenant, node, source, epoch)
    }

    pub fn source_receipt(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<AnalysisSourceReceiptV1>> {
        self.view()?.source_receipt(identity)
    }

    pub fn source_status(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<AnalysisSourceStatusV1>> {
        self.view()?.source_status(identity)
    }

    pub fn source_page(
        &self,
        tenant: [u8; 16],
        after: Option<&EvidenceIntakeIdentityV1>,
    ) -> Result<Vec<EvidenceIntakeIdentityV1>> {
        use std::ops::Bound::{Excluded, Included};
        if tenant == [0; 16]
            || after.is_some_and(|source| source.tenant_id != tenant || !source.valid())
        {
            return crate::Error::reject_path(
                &self.root,
                "the source page tenant or cursor is invalid",
            );
        }
        let view = self.view()?;
        let prefix = [b"\0".as_slice(), &tenant].concat();
        let first = after.map_or_else(|| Included(prefix.clone()), |source| Excluded(source.key()));
        let last = match u128::from_be_bytes(tenant).checked_add(1) {
            Some(next) => [b"\0".as_slice(), &next.to_be_bytes()].concat(),
            None => vec![1],
        };
        let first = match first {
            Included(key) => Included([Sources::RECEIPTS, &key].concat()),
            Excluded(key) => Excluded([Sources::RECEIPTS, &key].concat()),
            std::ops::Bound::Unbounded => Included(Sources::RECEIPTS.to_vec()),
        };
        view.snapshot
            .range((first, Excluded([Sources::RECEIPTS, &last].concat())))
            .take(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS)
            .map(|row| {
                let (key, value) = row.context(NativeStorageSnafu {
                    operation: "read source page",
                })?;
                Ok(Sources::decode_receipt(&key, &value)?.identity)
            })
            .collect()
    }

    pub fn tenant_page(&self, after: Option<[u8; 16]>) -> Result<Vec<[u8; 16]>> {
        use std::ops::Bound::{Excluded, Included};
        let view = self.view()?;
        let mut next = after.map_or(Some(0), |tenant| u128::from_be_bytes(tenant).checked_add(1));
        let mut tenants = Vec::new();
        while let Some(tenant) = next {
            let first = [b"\0".as_slice(), &tenant.to_be_bytes()].concat();
            let Some(row) = view
                .snapshot
                .range((
                    Included([Sources::RECEIPTS, &first].concat()),
                    Excluded([Sources::RECEIPTS, &[1]].concat()),
                ))
                .next()
            else {
                break;
            };
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "read source tenant index",
            })?;
            let receipt = Sources::decode_receipt(&key, &value)?;
            tenants.push(receipt.identity.tenant_id);
            if tenants.len() == crate::analysis::MAX_ANALYSIS_PAGE_RECORDS {
                break;
            }
            next = u128::from_be_bytes(receipt.identity.tenant_id).checked_add(1);
        }
        Ok(tenants)
    }
}

pub(in crate::analysis::native) struct Sources;

#[derive(Deserialize, Serialize)]
struct Report {
    reference: CoverageReportRef,
    encoded_report: Vec<u8>,
}

impl Sources {
    pub(in crate::analysis::native) fn decode_receipt(
        key: &[u8],
        value: &[u8],
    ) -> Result<AnalysisSourceReceiptV1> {
        let value = value.strip_prefix(&[0]).ok_or_else(|| {
            NativeStateSnafu {
                field: "source receipt value",
            }
            .build()
        })?;
        let receipt: AnalysisSourceReceiptV1 = Records::decode(value)?;
        if !receipt.identity.valid()
            || receipt.retained_floor > receipt.contiguous_cursor
            || Self::key(Self::RECEIPTS, &receipt.identity.key()) != key
        {
            return NativeStateSnafu {
                field: "source receipt identity",
            }
            .fail();
        }
        Ok(receipt)
    }
    pub(in crate::analysis::native) const RECEIPTS: &'static [u8] = b"\0data/source/";
    pub(in crate::analysis::native) const EPOCHS: &'static [u8] = b"\0data/epoch/";
    pub(in crate::analysis::native) const ENDS: &'static [u8] = b"\0data/raw/end/";
    const NEXT: &'static [u8] = b"\0data/raw/next";
    const REPORTS: &'static [u8] = b"\0data/coverage/report/";
    const CHANGES: &'static [u8] = b"\0data/coverage/change/";

    pub(in crate::analysis::native) fn key(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
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

    pub(in crate::analysis::native) fn check_epoch(
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
    pub(in crate::analysis::native) fn source_receipts(
        &self,
        tenant: [u8; 16],
    ) -> impl Iterator<Item = Result<AnalysisSourceReceiptV1>> + '_ {
        let prefix = [Sources::RECEIPTS, &[0], &tenant].concat();
        self.snapshot.prefix(prefix).map(|row| {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "read native source receipts",
            })?;
            Sources::decode_receipt(&key, &value)
        })
    }
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
        let suffix =
            EvidenceIntakeIdentityV1::source_epoch_key(tenant_id, node_id, source_id, source_epoch);
        let identity: Option<EvidenceIntakeIdentityV1> =
            Sources::read(&self.snapshot, &Sources::key(Sources::EPOCHS, &suffix))?;
        if identity
            .as_ref()
            .is_some_and(|identity| !identity.valid() || identity.epoch_key() != suffix)
        {
            return NativeStateSnafu {
                field: "source epoch binding",
            }
            .fail();
        }
        Ok(identity)
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
        Ok(baseline)
    }

    pub fn source_status(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<AnalysisSourceStatusV1>> {
        let Some(receipt) = self.source_receipt(identity)? else {
            return Ok(None);
        };
        let events = super::events::Events::new(self);
        let mut retained_event_count = 0_u64;
        for row in events.spans(identity, 1, u64::MAX)? {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "read source event spans",
            })?;
            let (first, span) = super::events::Events::decode_span(identity, &key, &value)?;
            let (batch, _) = events.lookup(identity, first)?.ok_or_else(|| {
                NativeStateSnafu {
                    field: "source event span",
                }
                .build()
            })?;
            if events.expiry(batch.meta.revision)?.is_none() {
                retained_event_count = retained_event_count
                    .checked_add(span.last - first + 1)
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "source event count",
                        }
                        .build()
                    })?;
            }
        }
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
        let mut revision = 0;
        let events = super::events::Events::new(self);
        for row in events.spans(identity, 1, u64::MAX)? {
            control.check()?;
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "read source input revisions",
            })?;
            let (_, span) = super::events::Events::decode_span(identity, &key, &value)?;
            revision = revision.max(span.revision);
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
        let expired = self.expired_ranges(identity, output, control)?;
        for gap in &expired {
            revision = revision.max(gap.commit_revision);
        }
        let state = events.source_state(
            root,
            &receipt,
            control,
            (output.input_bytes, output.limits.input_bytes),
        )?;
        if state.covered != receipt.contiguous_cursor {
            return crate::Error::reject_path(
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
            expired,
            recovery,
            pending: state.pending,
            coverage_report,
            typed_report: None,
        })
    }
}
