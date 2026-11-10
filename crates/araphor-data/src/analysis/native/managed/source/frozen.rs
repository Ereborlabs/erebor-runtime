use std::{collections::BTreeMap, sync::Arc};

use super::super::references::References;
use super::*;
use crate::{
    AnalysisContextRefV1, AnalysisContextVersionV1, AnalysisExtractLimits, ManagedAttempt,
    ManagedCapture,
};

mod facts;

type FrozenInput = (
    crate::analysis::graph::GraphSourceSummary,
    Vec<(AnalysisContextVersionV1, AnalysisContextRefV1)>,
    Vec<(DiscoveryRecordIdV1, AnalysisContextRefV1)>,
);

impl SourceRecord {
    pub(in crate::analysis::native) fn manifest(
        &self,
        result: &StoredResult,
        source: &EvidenceIntakeIdentityV1,
    ) -> Result<crate::GraphManifest> {
        let ResultBody::Selected(step) = &result.body else {
            return Err(Code::Invalid.error("source result kind"));
        };
        let step = step
            .source
            .as_ref()
            .ok_or_else(|| Code::Missing.error("source result step"))?;
        self.manifest_values(
            source,
            (step.first, step.last, step.deadline),
            &step.coverage,
            step.base.as_ref(),
        )
    }

    pub(super) fn manifest_values(
        &self,
        source: &EvidenceIntakeIdentityV1,
        span: (u64, u64, u64),
        coverage: &[crate::GraphCoverageKeyV1],
        base: Option<&PackageResultRefV1>,
    ) -> Result<crate::GraphManifest> {
        Ok(crate::GraphManifest {
            schema_version: crate::GRAPH_SCHEMA_VERSION,
            scope: crate::ProcessorScopeV1 {
                processor_id: crate::GRAPH_PROCESSOR.into(),
                method_version: u64::from(crate::GRAPH_SCHEMA_VERSION),
                identity: source.clone(),
            },
            first_cursor: span.0,
            last_cursor: span.1,
            input_manifest: crate::GraphRevisionV1 {
                evidence: Vec::new(),
                coverage: coverage.to_vec(),
                context: Vec::new(),
                missing_ranges: self.gaps.clone(),
            },
            facts: Vec::new(),
            packages: Vec::new(),
            missing_ranges: self.gaps.clone(),
            input_positions: Vec::new(),
            previous_result_id: base.map(|base| base.result_id.clone()),
            context_notice_revision: self.captured.commit_revision,
            witness_deadline_utc_ns: span.2,
        })
    }
}

impl NativeStore {
    pub fn graph_frozen_facts(
        &self,
        capture: &ManagedCapture,
        reference: Option<&ManagedAttempt>,
        result: &PackageResultRefV1,
        records: &BTreeSet<DiscoveryRecordIdV1>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> Result<FrozenInput> {
        self.frozen_source_input(
            capture,
            reference,
            result,
            Some(records),
            limits,
            control,
            |rows, _| Ok(rows),
        )
    }

    pub fn graph_support_facts(
        &self,
        capture: &ManagedCapture,
        reference: Option<&ManagedAttempt>,
        result: &PackageResultRefV1,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> Result<FrozenInput> {
        self.frozen_source_input(
            capture,
            reference,
            result,
            None,
            limits,
            control,
            |rows, _| Ok(rows),
        )
    }

    pub fn graph_frozen_source(
        &self,
        capture: &ManagedCapture,
        reference: Option<&ManagedAttempt>,
        result: &PackageResultRefV1,
        records: &BTreeSet<DiscoveryRecordIdV1>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> Result<(
        crate::analysis::graph::GraphSourceSummary,
        Arc<crate::ManagedSourceHistory>,
    )> {
        let frame = capture
            .source()
            .ok_or_else(|| Code::Invalid.error("historical source frame"))?;
        self.frozen_source_input(
            capture,
            reference,
            result,
            Some(records),
            limits,
            control,
            |(summary, contexts, proofs), charge| {
                frame
                    .seal_history(result.clone(), contexts, proofs, charge)
                    .map(|history| (summary, history))
            },
        )
    }

    pub fn graph_record_keys(
        &self,
        capture: &ManagedCapture,
        reference: Option<&ManagedAttempt>,
        result: &PackageResultRefV1,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> Result<Vec<DiscoveryRecordIdV1>> {
        self.source_reader(
            capture,
            reference,
            result,
            limits,
            control,
            |view, header, stored, owner, charge| {
                let prefix = view.source_members(owner)?;
                let source = Self::source_identity(capture)?;
                let mut records = Vec::new();
                for entry in view.snapshot.prefix(&prefix) {
                    control.check()?;
                    let (key, value) = entry.context(crate::NativeStorageSnafu {
                        operation: "read frozen source keys",
                    })?;
                    charge(
                        key.len() + value.len(),
                        2 * size_of::<DiscoveryRecordIdV1>() + source.node_id.len(),
                    )?;
                    records.push(view.source_record(&prefix, &key, source)?);
                }
                records.sort();
                if records.len() as u64 != header.count || stored.revision != result.commit_revision
                {
                    return Err(Code::Invalid.error("source identity count"));
                }
                Ok(records)
            },
        )
    }

    fn source_identity(capture: &ManagedCapture) -> Result<&EvidenceIntakeIdentityV1> {
        match &capture.instance().spec.destination {
            ManagedDestination::Graph { source, .. } => Ok(source),
            _ => Err(Code::Invalid.error("frozen Graph destination")),
        }
    }

    fn source_reader<T>(
        &self,
        capture: &ManagedCapture,
        reference: Option<&ManagedAttempt>,
        result: &PackageResultRefV1,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        read: impl FnOnce(
            &DataView,
            &SourceRecord,
            &StoredResult,
            &ManagedAttempt,
            &mut dyn FnMut(usize, usize) -> Result<()>,
        ) -> Result<T>,
    ) -> Result<T> {
        control.check()?;
        let source = Self::source_identity(capture)?;
        if result.result_id.is_empty()
            || result.commit_revision == 0
            || result.commit_revision > capture.revision()
                && reference
                    .and_then(ManagedAttempt::receipt)
                    .and_then(|receipt| receipt.graph.as_ref())
                    != Some(result)
            || !capture.instance().grant.selection.includes_source(source)
        {
            return Err(Code::Denied.error("frozen Graph source"));
        }
        if let Some(reference) = reference {
            capture.check_reference(reference)?;
        }
        let actual = self.view()?.meta();
        let captured = capture.source_meta();
        if actual.store_uuid != captured.store_uuid
            || actual.schema_version != captured.schema_version
            || captured.recovery_epoch == 0
            || captured.recovery_epoch > actual.recovery_epoch
            || captured.commit_revision > actual.commit_revision
        {
            return Err(Code::Conflict.error("frozen Graph store"));
        }
        let mut scanned = 0usize;
        let mut bytes = 0usize;
        let mut charge = |scan: usize, input: usize| {
            control.check()?;
            scanned = scanned
                .checked_add(scan)
                .filter(|total| *total <= limits.scan_bytes)
                .ok_or_else(|| {
                    crate::AnalysisInputTooLargeSnafu {
                        resource: "scanned Graph bytes",
                    }
                    .build()
                })?;
            bytes = bytes
                .checked_add(input)
                .filter(|total| *total <= limits.input_bytes)
                .ok_or_else(|| {
                    crate::AnalysisInputTooLargeSnafu {
                        resource: "frozen Graph bytes",
                    }
                    .build()
                })?;
            Ok(())
        };
        let view = self.read_at(result.commit_revision)?;
        let (id, stored, owner) =
            view.result_owner(source.tenant_id, &result.result_id, control, &mut |bytes| {
                charge(bytes, bytes)
            })?;
        let header =
            SourceRecord::header(id, |key| Records::read(key, &view.snapshot), &mut |bytes| {
                charge(bytes, bytes)
            })?;
        if stored.revision != result.commit_revision
            || Self::source_identity_owner(&owner)? != source
            || owner.receipt().and_then(|receipt| receipt.graph.as_ref()) != Some(result)
            || result.commit_revision > capture.revision()
                && reference.is_none_or(|reference| reference.0 != owner.0)
        {
            return Err(Code::Denied.error("frozen source publication"));
        }
        read(&view, &header, &stored, &owner, &mut charge)
    }

    fn source_identity_owner(owner: &ManagedAttempt) -> Result<&EvidenceIntakeIdentityV1> {
        match &owner.instance().spec.destination {
            ManagedDestination::Graph { source, .. } => Ok(source),
            _ => Err(Code::Invalid.error("source publication destination")),
        }
    }
}

impl DataView {
    pub(super) fn source_members(&self, owner: &ManagedAttempt) -> Result<Vec<u8>> {
        let source = NativeStore::source_identity_owner(owner)?;
        let instance = Records::find(
            &InstanceRecord::identity(source.tenant_id, &owner.instance().spec.id)?,
            |key| Records::read(key, &self.snapshot),
        )?
        .ok_or_else(|| Code::Missing.error("source member instance"))?;
        let source = Records::find(&SourceRecord::identity(source)?, |key| {
            Records::read(key, &self.snapshot)
        })?
        .ok_or_else(|| Code::Missing.error("source member identity"))?;
        Ok(SourceRecord::key(SourceRecord::MEMBER, &[instance, source]))
    }

    pub(super) fn source_record(
        &self,
        prefix: &[u8],
        key: &[u8],
        source: &EvidenceIntakeIdentityV1,
    ) -> Result<DiscoveryRecordIdV1> {
        if key.len() != prefix.len() + 12 {
            return Err(Code::Invalid.error("source member key"));
        }
        let record = DiscoveryRecordIdV1 {
            stream: source.clone(),
            cpu_id: u32::from_be_bytes(
                key[prefix.len()..prefix.len() + 4]
                    .try_into()
                    .map_err(|_| Code::Invalid.error("source member CPU"))?,
            ),
            durable_cursor: NativeStore::number(&key[prefix.len() + 4..])?,
        };
        if record.durable_cursor == 0 {
            return Err(Code::Invalid.error("source member cursor"));
        }
        Ok(record)
    }
}
