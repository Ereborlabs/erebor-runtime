use super::super::{DataView, DataWrite, NativeStore};
use super::{Records, Report, Sources};
use crate::analysis::raw::RawReceipt;
use crate::{AnalysisReadControl, AnalysisStore, NativeStateSnafu, NativeStorageSnafu, Result};
use crate::{
    AnalysisSelectionV1, AnalysisSourceReceiptV1, CoverageRecord, CoverageReportRef,
    EvidenceIntakeIdentityV1, StorePositionV1, ValidatedCoverageV1,
};
use snafu::ResultExt as _;
use std::ops::Bound::{Excluded, Included};
impl DataView {
    pub(in crate::analysis::native) fn source_proof_coverage(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        cpu: u32,
        expected_report: u64,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<(AnalysisSourceReceiptV1, Option<crate::CoverageReport>)> {
        charge(0)?;
        let receipt = self.source_receipt(identity)?.ok_or_else(|| {
            crate::PackageErrorCodeV1::Missing.error("Graph proof source receipt")
        })?;
        if receipt.cpu_id != cpu || receipt.coverage_revision != expected_report {
            return Err(crate::PackageErrorCodeV1::Conflict.error("Graph proof source revision"));
        }
        if receipt.coverage_revision == 0 {
            return Ok((receipt, None));
        }
        let bytes = Records::charged_payload(
            &Sources::report(identity, receipt.coverage_revision),
            |key| Records::read(key, &self.snapshot),
            charge,
        )?
        .ok_or_else(|| crate::PackageErrorCodeV1::Missing.error("Graph proof coverage report"))?;
        let report: Report = Records::decode(&bytes)?;
        if report.reference.source != *identity
            || report.reference.revision != receipt.coverage_revision
            || report.reference.position.commit_revision > self.metadata_revision
        {
            return Err(crate::PackageErrorCodeV1::Invalid.error("Graph proof coverage identity"));
        }
        let body = receipt.decode_coverage(&report.encoded_report, charge)?;
        Ok((receipt, Some(body)))
    }

    pub fn coverage_changes(
        &self,
        selection: &AnalysisSelectionV1,
        after: StorePositionV1,
        control: &AnalysisReadControl,
    ) -> Result<Vec<CoverageRecord>> {
        control.check()?;
        if !selection.valid() || after.ordinal != u32::MAX || after.commit_revision > self.revision
        {
            return NativeStateSnafu {
                field: "coverage interval",
            }
            .fail();
        }
        let mut records = Vec::new();
        for row in self.snapshot.range::<Vec<u8>, _>((
            Excluded(Sources::boundary(
                &selection.tenant_id,
                after.commit_revision,
            )),
            Included(Sources::boundary(&selection.tenant_id, self.revision)),
        )) {
            control.check()?;
            let (key, bytes) = row.context(NativeStorageSnafu {
                operation: "read coverage changes",
            })?;
            let encoded = bytes.strip_prefix(&[0]).ok_or_else(|| {
                NativeStateSnafu {
                    field: "coverage change encoding",
                }
                .build()
            })?;
            let reference: CoverageReportRef = Records::decode(encoded)?;
            if Sources::change(&reference) != key.as_ref()
                || reference.source.tenant_id != selection.tenant_id
            {
                return NativeStateSnafu {
                    field: "coverage change identity",
                }
                .fail();
            }
            if selection.includes_source(&reference.source) {
                records.push(self.coverage_report(selection, &reference, control)?);
            }
        }
        Ok(records)
    }

    pub fn coverage_report(
        &self,
        selection: &AnalysisSelectionV1,
        reference: &CoverageReportRef,
        control: &AnalysisReadControl,
    ) -> Result<CoverageRecord> {
        control.check()?;
        if !selection.valid()
            || !reference.source.valid()
            || reference.revision == 0
            || reference.position.commit_revision == 0
            || reference.position.ordinal != 0
            || reference.position.commit_revision > self.revision
        {
            return NativeStateSnafu {
                field: "coverage reference",
            }
            .fail();
        }
        if !selection.includes_source(&reference.source) {
            return Err(crate::PackageErrorCodeV1::Denied.error("coverage report scope"));
        }
        let report: Report = Sources::read(
            &self.snapshot,
            &Sources::report(&reference.source, reference.revision),
        )?
        .ok_or_else(|| {
            NativeStateSnafu {
                field: "coverage report",
            }
            .build()
        })?;
        if report.reference != *reference || report.encoded_report.is_empty() {
            return NativeStateSnafu {
                field: "coverage report identity",
            }
            .fail();
        }
        Ok(CoverageRecord {
            reference: report.reference,
            encoded_report: report.encoded_report,
        })
    }
}

impl NativeStore {
    pub fn accept_validated_coverage(&self, input: ValidatedCoverageV1) -> Result<u64> {
        let revision = input.revision;
        let mut write = self.write()?;
        write.coverage(&input)?;
        write.commit([])?;
        Ok(revision)
    }
}

impl DataWrite<'_> {
    pub fn coverage(&mut self, input: &ValidatedCoverageV1) -> Result<()> {
        let identity = &input.identity;
        if !identity.valid() || input.revision == 0 || input.encoded_report.is_empty() {
            return AnalysisStore::reject_path(
                &self.store.root,
                "the validated coverage identity or bounds are invalid",
            );
        }
        let key = identity.key();
        let previous = self
            .raw
            .sources
            .get(&key)
            .and_then(|source| source.receipt.evidence());
        if previous.is_some_and(|receipt| receipt.cpu_id != input.cpu_id) {
            return AnalysisStore::reject_path(
                &self.store.root,
                "coverage changed the bound evidence CPU identity",
            );
        }
        let current = previous.map_or(0, |receipt| receipt.coverage_revision);
        if input.revision <= current {
            if input.revision == current {
                let existing = Records::payload(&Sources::report(identity, current), |key| {
                    self.transaction.get(key).context(NativeStorageSnafu {
                        operation: "read duplicate coverage",
                    })
                })?;
                if let Some(bytes) = existing {
                    let report: Report = Records::decode(&bytes)?;
                    if report.encoded_report == input.encoded_report {
                        return Ok(());
                    }
                }
            }
            return AnalysisStore::reject_path(
                &self.store.root,
                "coverage evidence is stale or has conflicting content",
            );
        }
        let epoch = Sources::key(Sources::EPOCHS, &identity.epoch_key());
        if let Some(bytes) = Records::payload(&epoch, |key| {
            self.transaction.get(key).context(NativeStorageSnafu {
                operation: "read source epoch",
            })
        })? {
            Sources::check_epoch(identity, &Records::decode(&bytes)?)?;
        } else {
            for source in self
                .raw
                .sources
                .values()
                .filter_map(|source| source.receipt.evidence())
            {
                if source.identity.epoch_key() == identity.epoch_key() {
                    Sources::check_epoch(identity, &source.identity)?;
                }
            }
        }
        let mut receipt = previous
            .cloned()
            .unwrap_or_else(|| AnalysisSourceReceiptV1 {
                identity: identity.clone(),
                cpu_id: input.cpu_id,
                contiguous_cursor: 0,
                coverage_revision: 0,
                retained_floor: 0,
            });
        receipt.coverage_revision = input.revision;
        let new_binding = previous.is_none();
        let reference = CoverageReportRef {
            source: identity.clone(),
            revision: input.revision,
            position: StorePositionV1 {
                commit_revision: self.revision,
                ordinal: 0,
            },
        };
        let report = Records::encode(&(&reference, &input.encoded_report))?;
        let encoded = Records::encode(&receipt)?;
        let change = Records::encode(&reference)?;
        let binding = Records::encode(identity)?;
        Records::stage(
            &mut self.transaction,
            Sources::report(identity, input.revision),
            report,
        );
        Records::stage(
            &mut self.transaction,
            Sources::key(Sources::RECEIPTS, &key),
            encoded,
        );
        self.transaction.insert(Sources::change(&reference), change);
        self.transaction.insert(epoch, binding);
        self.note_relation("coverage", self.revision)?;
        self.note_relation("source_receipts", self.revision)?;
        if new_binding {
            self.note_relation("source_bindings", self.revision)?;
            self.raw.binding_revision = self.revision;
        }
        if let Some(source) = self.raw.sources.get_mut(&key) {
            source.receipt = RawReceipt::Evidence(receipt);
        } else {
            self.raw.sources.insert_mut(key, receipt.into());
        }
        self.dirty = true;
        Ok(())
    }
}
