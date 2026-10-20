use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::super::AnalysisStore;
use super::model::*;
use crate::{AnalysisDatabaseSnafu, AnalysisReadControl, PackageErrorCodeV1 as Code, Result};

impl AnalysisStore {
    pub fn admit_managed(
        &self,
        spec: &ManagedSpec,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        spec.validate()?;
        let bytes = serde_json::to_vec(spec).context(crate::PackageEncodingSnafu)?;
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin managed admission",
            })?;
        Self::check_managed_images(&transaction, spec)?;
        if let Some(saved) = Self::managed_instance_from(&transaction, spec.tenant, &spec.id)? {
            if saved.spec != *spec {
                return crate::AnalysisConflictSnafu.fail();
            }
            check()?;
            return Ok(saved);
        }
        let revision = self.package_next(&transaction)?;
        transaction
            .execute(
                "INSERT INTO managed_instances VALUES (?, ?, ?, ?, 0)",
                params![spec.tenant.as_slice(), spec.id, bytes, revision],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert managed instance",
            })?;
        for call in spec.manifest.calls.keys() {
            transaction
                .execute(
                    "INSERT INTO managed_calls VALUES (?, ?, ?, 0, NULL)",
                    params![spec.tenant.as_slice(), spec.id, call],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert managed call",
                })?;
        }
        self.check_logical(&transaction, spec.tenant, false)?;
        Self::record_revision(
            &transaction,
            revision,
            &["managed_instances", "managed_calls"],
        )?;
        check()?;
        self.commit_metadata(transaction, "commit managed admission")?;
        self.revision.send_replace(revision);
        Ok(ManagedInstance {
            spec: spec.clone(),
            generation: revision,
            progress: 0,
        })
    }

    pub fn managed_instance(
        &self,
        tenant: [u8; 16],
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<Option<ManagedInstance>> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            Self::managed_instance_from(reader, tenant, id)
        })
    }

    pub(in crate::analysis) fn managed_instance_from(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<Option<ManagedInstance>> {
        let row = reader.query_row("SELECT spec, generation, progress FROM managed_instances WHERE tenant_id = ? AND instance_id = ?", params![tenant.as_slice(), id], |row|
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, u64>(1)?, row.get::<_, u64>(2)?)))
            .optional().context(AnalysisDatabaseSnafu { operation: "read managed instance" })?;
        row.map(|(bytes, generation, progress)| {
            let spec: ManagedSpec =
                serde_json::from_slice(&bytes).context(crate::PackageEncodingSnafu)?;
            if spec.tenant != tenant || spec.id != id {
                return Err(Code::Invalid.error("managed instance key"));
            }
            Ok(ManagedInstance {
                spec,
                generation,
                progress,
            })
        })
        .transpose()
    }

    pub(super) fn check_managed_images(reader: &Connection, spec: &ManagedSpec) -> Result<()> {
        let definition =
            serde_json::to_vec(&spec.definition).context(crate::PackageEncodingSnafu)?;
        let saved: Option<Vec<u8>> = reader.query_row("SELECT definition FROM discovery_definitions WHERE tenant_id = ? AND name = ? AND revision = ?",
            params![spec.tenant.as_slice(), spec.definition.definition.name, spec.manifest.definition], |row| row.get(0))
            .optional().context(AnalysisDatabaseSnafu { operation: "read managed definition pin" })?;
        if saved.as_deref() != Some(definition.as_slice()) {
            return Err(Code::Missing.error("managed definition pin"));
        }
        for pin in &spec.definition.images {
            let bundle = Self::package_image_from(
                reader,
                spec.tenant,
                &pin.image.package_id,
                Some(&pin.image.revision),
                &AnalysisReadControl::default(),
            )?
            .ok_or_else(|| Code::Missing.error("managed image"))?;
            if bundle.digest()? != pin.digest {
                return Err(Code::Conflict.error("managed image digest"));
            }
            for call in spec
                .manifest
                .calls
                .values()
                .filter(|call| call.image == *pin)
            {
                let artifact = bundle.artifact(&call.package)?;
                if !artifact
                    .descriptor
                    .exports
                    .iter()
                    .any(|model| model.name == call.export)
                {
                    return Err(Code::Missing.error("managed export"));
                }
                let implementation = artifact.implementation(&call.export)?;
                if call.target != implementation.target()
                    || call.artifact != implementation.identity()?
                {
                    return Err(Code::Invalid.error("managed implementation pin"));
                }
            }
        }
        Ok(())
    }

    pub(super) fn managed_contract(
        reader: &Connection,
        tenant: [u8; 16],
        call: &ManagedCall,
    ) -> Result<sdk::Package> {
        let bytes: Vec<u8> = reader.query_row("SELECT descriptor FROM package_revisions WHERE tenant_id = ? AND package_id = ? AND revision = ?",
            params![tenant.as_slice(), call.package.package_id, call.package.revision], |row| row.get(0))
            .context(AnalysisDatabaseSnafu { operation: "read managed SDK descriptor" })?;
        let descriptor: sdk::Package =
            serde_json::from_slice(&bytes).context(crate::PackageEncodingSnafu)?;
        if descriptor.id != call.package.package_id || descriptor.revision != call.package.revision
        {
            return Err(Code::Invalid.error("managed SDK descriptor pin"));
        }
        Ok(descriptor)
    }

    pub fn managed_attempt(
        &self,
        tenant: [u8; 16],
        instance: &str,
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<Option<ManagedAttempt>> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let Some(attempt) = Self::managed_attempt_from(reader, tenant, instance, id)? else {
                return Ok(None);
            };
            let mut instance = Self::managed_instance_from(reader, tenant, instance)?
                .ok_or_else(|| Code::Missing.error("managed attempt instance"))?;
            if instance.generation != attempt.capture.generation {
                return Err(Code::Invalid.error("managed attempt generation"));
            }
            instance.progress = attempt.capture.progress;
            Ok(Some(ManagedAttempt(
                attempt,
                instance,
                false,
                std::collections::BTreeMap::new(),
            )))
        })
    }

    pub(super) fn managed_attempt_from(
        reader: &Connection,
        tenant: [u8; 16],
        instance: &str,
        id: &str,
    ) -> Result<Option<Attempt>> {
        let bytes: Option<Vec<u8>> = reader.query_row("SELECT contract FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? AND attempt_id = ?", params![tenant.as_slice(), instance, id], |row| row.get(0))
            .optional().context(AnalysisDatabaseSnafu { operation: "read managed attempt" })?;
        bytes
            .map(|bytes| {
                let attempt: Attempt =
                    serde_json::from_slice(&bytes).context(crate::PackageEncodingSnafu)?;
                if attempt.capture.tenant != tenant
                    || attempt.capture.instance != instance
                    || attempt.request.id != id
                {
                    return Err(Code::Invalid.error("managed attempt key"));
                }
                Ok(attempt)
            })
            .transpose()
    }

    pub fn managed_result(
        &self,
        instance: &ManagedInstance,
        id: &str,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<ManagedResult> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let (record, output, commit_revision) =
                Self::managed_record_from(reader, instance.spec.tenant, id)?;
            if record.instance != instance.spec.id
                || instance.spec.manifest.calls.get(&record.call) != Some(&record.declaration)
            {
                return Err(Code::Denied.error("managed result scope"));
            }
            let output = Self::validate_managed_record(
                reader,
                instance.spec.tenant,
                id,
                &record,
                &output,
                commit_revision,
            )?;
            Ok(ManagedResult {
                context: record.context,
                output,
                commit_revision,
                current: self.managed_current(
                    reader,
                    &instance.spec,
                    id,
                    commit_revision,
                    now,
                    control,
                )?,
            })
        })
    }

    pub(super) fn managed_record_from(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<(Record, sdk::wire::Output, u64)> {
        let (metadata, body, revision): (Vec<u8>, Vec<u8>, u64) = reader.query_row("SELECT request_meta, body, commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ? AND processor_id = 'managed-package-v1'",
            params![tenant.as_slice(), id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .context(AnalysisDatabaseSnafu { operation: "read complete managed result" })?;
        let mut record: Record =
            serde_json::from_slice(&metadata).context(crate::PackageEncodingSnafu)?;
        let mut output: sdk::wire::Output =
            serde_json::from_slice(&body).context(crate::PackageEncodingSnafu)?;
        let mut blobs = reader
            .prepare(
                "SELECT role, slot, ipc FROM managed_arrow WHERE result_id = ? ORDER BY role, slot",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare managed Arrow payloads",
            })?;
        let rows = blobs
            .query_map(params![id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read managed Arrow payloads",
            })?;
        let mut seen = std::collections::BTreeSet::new();
        for row in rows {
            let (role, slot, bytes) = row.context(AnalysisDatabaseSnafu {
                operation: "decode managed Arrow payload",
            })?;
            let index =
                usize::try_from(slot).map_err(|_| Code::Invalid.error("managed Arrow slot"))?;
            let target = match role.as_str() {
                "output" => output
                    .datasets
                    .get_mut(index)
                    .map(|data| &mut data.arrow_ipc),
                "checkpoint" => output
                    .checkpoint
                    .as_mut()
                    .and_then(|state| state.datasets.get_mut(index))
                    .map(|data| &mut data.arrow_ipc),
                "reason" => output
                    .reasons
                    .get_mut(index)
                    .map(|reason| &mut reason.details),
                "parameters" if slot == 0 => {
                    record.parameters.as_mut().map(|data| &mut data.arrow_ipc)
                }
                _ => None,
            }
            .ok_or_else(|| Code::Invalid.error("managed Arrow role"))?;
            if !target.is_empty() || bytes.is_empty() || !seen.insert((role, slot)) {
                return Err(Code::Invalid.error("managed Arrow payload"));
            }
            *target = bytes;
        }
        let expected = output.datasets.len()
            + output.reasons.len()
            + output
                .checkpoint
                .as_ref()
                .map_or(0, |state| state.datasets.len())
            + usize::from(record.parameters.is_some());
        if seen.len() != expected {
            return Err(Code::Invalid.error("managed Arrow payload count"));
        }
        if Self::managed_edges(reader, tenant, id)? != record.dependencies {
            return Err(Code::Invalid.error("managed result edges"));
        }
        Ok((record, output, revision))
    }

    pub(super) fn managed_current(
        &self,
        reader: &Connection,
        spec: &ManagedSpec,
        id: &str,
        revision: u64,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<bool> {
        let mut statement = reader.prepare("WITH RECURSIVE needed(result_id, revision) AS (
            SELECT ?::VARCHAR, ?::UBIGINT UNION
            SELECT e.dependency_id, e.commit_revision FROM managed_edges e JOIN needed n ON n.result_id = e.result_id WHERE e.tenant_id = ?)
            SELECT n.result_id, n.revision, r.processor_id, c.instance_id FROM needed n
            LEFT JOIN analysis_results r ON n.result_id = r.result_id AND r.tenant_id = ? AND r.commit_revision = n.revision
            LEFT JOIN managed_calls c ON c.result_id = r.result_id AND c.tenant_id = r.tenant_id AND c.state_revision = r.commit_revision")
            .context(AnalysisDatabaseSnafu { operation: "prepare managed freshness" })?;
        let rows = statement
            .query_map(
                params![id, revision, spec.tenant.as_slice(), spec.tenant.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read managed freshness",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode managed freshness",
            })?;
        for (id, revision, processor, instance) in rows {
            control.check()?;
            let Some(processor) = processor else {
                return Ok(false);
            };
            let capture = if processor == "managed-package-v1" {
                if instance.as_deref() != Some(spec.id.as_str()) {
                    return Ok(false);
                }
                let metadata: Vec<u8> = reader.query_row("SELECT request_meta FROM analysis_results WHERE tenant_id = ? AND result_id = ?", params![spec.tenant.as_slice(), id], |row| row.get(0)).context(AnalysisDatabaseSnafu { operation: "read managed freshness metadata" })?;
                let record: Record =
                    serde_json::from_slice(&metadata).context(crate::PackageEncodingSnafu)?;
                Self::managed_attempt_from(reader, spec.tenant, &spec.id, &record.attempt)?
                    .ok_or_else(|| Code::Missing.error("managed result attempt"))?
                    .capture
            } else if processor == "managed-definition-v1" {
                let metadata: Vec<u8> = reader.query_row("SELECT request_meta FROM analysis_results WHERE tenant_id = ? AND result_id = ?", params![spec.tenant.as_slice(), id], |row| row.get(0)).context(AnalysisDatabaseSnafu { operation: "read managed selected freshness" })?;
                let step: Step =
                    serde_json::from_slice(&metadata).context(crate::PackageEncodingSnafu)?;
                let current = Self::managed_instance_from(reader, spec.tenant, &step.instance)?;
                if step.instance != spec.id
                    || current.is_none_or(|instance| instance.progress != revision)
                {
                    return Ok(false);
                }
                Self::managed_attempt_from(reader, spec.tenant, &spec.id, &step.attempt)?
                    .ok_or_else(|| Code::Missing.error("managed selected attempt"))?
                    .capture
            } else {
                if processor == "analysis-package" {
                    return Err(Code::Unsupported.error("legacy activation input"));
                }
                if self.package_source_revision(reader, spec.tenant, &id)? != revision {
                    return Ok(false);
                }
                continue;
            };
            if !Self::package_sources_current(reader, &capture.sources, control)? {
                return Ok(false);
            }
            Self::check_trace_reads_from(reader, spec.tenant, &capture.traces, control)?;
            if capture
                .witnesses
                .iter()
                .any(|witness| witness.expires_utc_ns < now)
            {
                return Ok(false);
            }
            for reference in &capture.contexts {
                if Self::read_context_from(reader, &self.root, &reference.key)?
                    .is_none_or(|(_, current)| current != reference.commit_revision)
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

impl AnalysisStore {
    pub fn managed_selected(
        &self,
        tenant: [u8; 16],
        instance: &str,
        attempt: &str,
        control: &AnalysisReadControl,
    ) -> Result<Option<ManagedSelected>> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let Some(attempt) = Self::managed_attempt_from(reader, tenant, instance, attempt)?
            else {
                return Ok(None);
            };
            let Some(receipt) = attempt.receipt else {
                return Ok(None);
            };
            let (step, packet, revision) =
                Self::managed_step_from(reader, tenant, &receipt.selected.result_id)?;
            let data = Self::decode_selected(&packet)?;
            if data.rows() != step.rows || receipt.selected.commit_revision != revision {
                return Err(Code::Invalid.error("managed selected result rows"));
            }
            Ok(Some(ManagedSelected {
                data,
                commit_revision: revision,
            }))
        })
    }

    pub(super) fn managed_step_from(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<(Step, sdk::wire::Dataset, u64)> {
        let (metadata, body, revision): (Vec<u8>, Vec<u8>, u64) = reader.query_row(
            "SELECT request_meta, body, commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ? AND processor_id = 'managed-definition-v1'",
            params![tenant.as_slice(), id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .context(AnalysisDatabaseSnafu { operation: "read managed selected relation" })?;
        let step: Step = serde_json::from_slice(&metadata).context(crate::PackageEncodingSnafu)?;
        let mut packet: sdk::wire::Dataset =
            serde_json::from_slice(&body).context(crate::PackageEncodingSnafu)?;
        if !packet.arrow_ipc.is_empty() {
            return Err(Code::Invalid.error("managed selected header"));
        }
        let blobs = reader.query_row("SELECT count(*), count(*) FILTER (WHERE role = 'selected' AND slot = 0) FROM managed_arrow WHERE result_id = ?", params![id], |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)))
            .context(AnalysisDatabaseSnafu { operation: "validate selected Arrow role" })?;
        if blobs != (1, 1) {
            return Err(Code::Invalid.error("managed selected payload"));
        }
        packet.arrow_ipc = reader.query_row("SELECT ipc FROM managed_arrow WHERE result_id = ? AND role = 'selected' AND slot = 0", params![id], |row| row.get(0))
            .context(AnalysisDatabaseSnafu { operation: "read selected Arrow payload" })?;
        if Self::managed_edges(reader, tenant, id)? != step.dependencies {
            return Err(Code::Invalid.error("managed selected edges"));
        }
        Ok((step, packet, revision))
    }

    pub(in crate::analysis) fn managed_evidence(
        processor: &str,
        metadata: &[u8],
    ) -> Result<(
        Vec<crate::AnalysisWitnessV1>,
        Vec<crate::AnalysisContextRefV1>,
    )> {
        if processor == "managed-package-v1" {
            let record: Record =
                serde_json::from_slice(metadata).context(crate::PackageEncodingSnafu)?;
            Ok((record.witnesses, record.contexts))
        } else {
            let step: Step =
                serde_json::from_slice(metadata).context(crate::PackageEncodingSnafu)?;
            Ok((step.witnesses, step.contexts))
        }
    }
}

impl AnalysisStore {
    pub(super) fn validate_managed_record(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
        record: &Record,
        packet: &sdk::wire::Output,
        revision: u64,
    ) -> Result<sdk::Output> {
        let attempt =
            Self::managed_attempt_from(reader, tenant, &record.instance, &record.attempt)?
                .ok_or_else(|| Code::Missing.error("managed result attempt"))?;
        let instance = Self::managed_instance_from(reader, tenant, &record.instance)?
            .ok_or_else(|| Code::Missing.error("managed retained instance"))?;
        if instance.generation != attempt.capture.generation {
            return Err(Code::Invalid.error("retained managed generation"));
        }
        let spec = &instance.spec;
        let receipt = attempt
            .receipt
            .as_ref()
            .ok_or_else(|| Code::Invalid.error("unpublished managed result"))?;
        if spec.manifest.calls.get(&record.call) != Some(&record.declaration)
            || receipt.results.get(&record.call).is_none_or(|reference| {
                reference.result_id != id || reference.commit_revision != revision
            })
            || receipt.commit_revision != revision
            || record.context.context.id != attempt.request.id
            || record.context.context.time_utc_ns != attempt.request.time_utc_ns as i64
            || record.context.context.seed != attempt.request.seed
            || record.witnesses != attempt.capture.witnesses
            || record.contexts != attempt.capture.contexts
        {
            return Err(Code::Invalid.error("retained managed result contract"));
        }
        let descriptor = Self::managed_contract(reader, tenant, &record.declaration)?;
        let model = descriptor
            .exports
            .iter()
            .find(|model| model.name == record.declaration.export)
            .ok_or_else(|| Code::Missing.error("retained managed model"))?;
        if record.context.target != record.declaration.target
            || record.context.artifact != record.declaration.artifact
            || record.context.inputs.len() != model.inputs.len()
            || record.context.input_coverage.len() != model.inputs.len()
            || record.context.coverage
                != crate::ResultContext::coverage(&record.context.input_coverage)
        {
            return Err(Code::Invalid.error("retained managed evaluation context"));
        }
        match (&record.parameters, model.parameters.fields().is_empty()) {
            (None, true) => {}
            (Some(packet), false) => {
                let data = packet
                    .decode(&model.parameters, record.context.context.limits)
                    .context(crate::AnalysisContractSnafu)?;
                if packet.name != "parameters" || data.batches.len() != 1 || data.rows() != 1 {
                    return Err(Code::Invalid.error("retained managed parameters"));
                }
                data.validate(
                    &sdk::Port::new("parameters", model.parameters.clone()),
                    record.context.context.limits,
                )
                .context(crate::AnalysisContractSnafu)?;
            }
            _ => return Err(Code::Invalid.error("retained managed parameters")),
        }
        let mut dependencies = attempt.capture.dependencies.clone();
        dependencies.extend(
            record
                .declaration
                .dependencies
                .iter()
                .filter_map(|call| receipt.results.get(call).cloned()),
        );
        dependencies.sort_by(|left, right| left.result_id.cmp(&right.result_id));
        dependencies.dedup();
        if dependencies != record.dependencies {
            return Err(Code::Invalid.error("retained managed dependencies"));
        }
        packet
            .decode_retained(
                &descriptor,
                &record.declaration.export,
                record.context.context.limits,
                &record.rows,
            )
            .context(crate::AnalysisContractSnafu)
    }
}

impl AnalysisStore {
    fn managed_edges(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<Vec<super::super::PackageResultRefV1>> {
        let mut statement = reader.prepare("SELECT dependency_id, commit_revision FROM managed_edges WHERE tenant_id = ? AND result_id = ? ORDER BY dependency_id")
            .context(AnalysisDatabaseSnafu { operation: "prepare managed result edges" })?;
        statement
            .query_map(params![tenant.as_slice(), id], |row| {
                Ok(super::super::PackageResultRefV1 {
                    result_id: row.get(0)?,
                    commit_revision: row.get(1)?,
                })
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read managed result edges",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode managed result edges",
            })
    }
}
