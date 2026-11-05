use super::codec::ManagedCodec;
use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;
use std::collections::BTreeMap;

use super::super::{AnalysisStore, PackageResultRefV1};
use super::model::*;
use crate::{AnalysisDatabaseSnafu, AnalysisReadControl, PackageErrorCodeV1 as Code, Result};

impl AnalysisStore {
    pub(in crate::analysis) fn managed_producer_from(
        reader: &Connection,
        selection: &crate::AnalysisSelectionV1,
        reference: &crate::analysis::PackageResultRefV1,
    ) -> Result<(super::ManagedSpec, u64, u64)> {
        let (record, revision) =
            Self::managed_meta_from(reader, selection.tenant_id, &reference.result_id)?;
        if revision != reference.commit_revision {
            return Err(Code::Conflict.error("managed producer revision"));
        }
        let (_, attempt, spec) = Self::validate_managed_header(
            reader,
            selection.tenant_id,
            &reference.result_id,
            &record,
            revision,
        )?;
        attempt.capture.grant.permitted_by(selection)?;
        let generation = attempt.capture.generation;
        Ok((spec, generation, record.call))
    }

    pub fn admit_managed(
        &self,
        spec: &ManagedSpec,
        grant: &crate::PackageGrantV1,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        spec.validate()?;
        grant.validate()?;
        if grant.selection.tenant_id != spec.tenant {
            return Err(Code::Invalid.error("managed instance grant"));
        }
        let bytes = ManagedCodec::encode(spec).context(crate::ManagedEncodingSnafu)?;
        let grant_bytes = ManagedCodec::encode(grant).context(crate::ManagedEncodingSnafu)?;
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin managed admission",
            })?;
        Self::check_managed_images(&transaction, spec)?;
        self.admit_graph(&transaction, spec)?;
        if let Some(saved) = Self::managed_instance_from(&transaction, spec.tenant, &spec.id)? {
            if saved.removed || saved.spec != *spec || saved.grant != *grant {
                return crate::AnalysisConflictSnafu.fail();
            }
            check()?;
            return Ok(saved);
        }
        Self::check_managed_addressable(&transaction, spec)?;
        let revision = self.package_next(&transaction)?;
        transaction
            .execute(
                "INSERT INTO managed_versions VALUES (?, ?, ?, ?, ?)",
                params![
                    spec.tenant.as_slice(),
                    spec.id,
                    revision,
                    bytes,
                    ManagedCodec::encode(&grant.selection).context(crate::ManagedEncodingSnafu)?
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert immutable managed version",
            })?;
        transaction
            .execute(
                "INSERT INTO managed_instances (tenant_id, instance_id, authority, generation, progress, running, removed, lifecycle) VALUES (?, ?, ?, ?, 0, false, false, ?)",
                params![spec.tenant.as_slice(), spec.id, grant_bytes, revision, revision],
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
        self.check_revision_limits(&transaction, spec.tenant)?;
        Self::record_revision(
            &transaction,
            revision,
            &["managed_versions", "managed_instances", "managed_calls"],
        )?;
        check()?;
        self.commit_metadata(transaction, "commit managed admission")?;
        self.revision.send_replace(revision);
        Ok(ManagedInstance {
            spec: spec.clone(),
            grant: grant.clone(),
            generation: revision,
            progress: 0,
            running: false,
            removed: false,
            lifecycle: revision,
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
        let row = reader.prepare_cached("SELECT v.spec, i.authority, i.generation, i.progress, i.running, i.removed, i.lifecycle FROM managed_instances i JOIN managed_versions v USING (tenant_id, instance_id, generation) WHERE i.tenant_id = ? AND i.instance_id = ?").and_then(|mut statement| statement.query_row(params![tenant.as_slice(), id], |row|
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, u64>(2)?, row.get::<_, u64>(3)?, row.get::<_, bool>(4)?, row.get::<_, bool>(5)?, row.get::<_, u64>(6)?))))
            .optional().context(AnalysisDatabaseSnafu { operation: "read managed instance" })?;
        row.map(|row| Self::managed_row(tenant, id, row))
            .transpose()
    }

    pub(super) fn managed_version_from(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
        generation: u64,
    ) -> Result<ManagedSpec> {
        let bytes: Vec<u8> = reader.query_row(
            "SELECT spec FROM managed_versions WHERE tenant_id = ? AND instance_id = ? AND generation = ?",
            params![tenant.as_slice(), id, generation], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "read immutable managed version" })?;
        let spec: ManagedSpec =
            ManagedCodec::decode(&bytes).context(crate::ManagedDecodingSnafu)?;
        spec.validate()?;
        if spec.tenant != tenant || spec.id != id {
            return Err(Code::Invalid.error("managed version key"));
        }
        Ok(spec)
    }

    pub(super) fn managed_scope_from(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
        generation: u64,
    ) -> Result<crate::AnalysisSelectionV1> {
        let bytes: Vec<u8> = reader.query_row(
            "SELECT scope FROM managed_versions WHERE tenant_id = ? AND instance_id = ? AND generation = ?",
            params![tenant.as_slice(), id, generation], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "read immutable managed scope" })?;
        let scope: crate::AnalysisSelectionV1 =
            ManagedCodec::decode(&bytes).context(crate::ManagedDecodingSnafu)?;
        if !scope.valid() || scope.tenant_id != tenant {
            return Err(Code::Invalid.error("managed version scope"));
        }
        Ok(scope)
    }

    /// The caller checks current authority before execution.
    pub fn active_managed(
        &self,
        control: &AnalysisReadControl,
    ) -> Result<(u64, Vec<ManagedMember>)> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let revision = Self::read_meta_from(reader, &self.root.join("analysis.duckdb"))?
                .commit_revision;
            let mut statement = reader.prepare("SELECT tenant_id, instance_id, generation, lifecycle FROM managed_instances WHERE running AND NOT removed ORDER BY tenant_id, instance_id")
                .context(AnalysisDatabaseSnafu { operation: "prepare active managed metadata" })?;
            let mut rows = statement.query([])
                .context(AnalysisDatabaseSnafu { operation: "read active managed metadata" })?;
            let mut active = Vec::new();
            while let Some(row) = rows.next()
                .context(AnalysisDatabaseSnafu { operation: "read active managed row" })?
            {
                control.check()?;
                let member = ManagedMember {
                    tenant: row.get::<_, Vec<u8>>(0)
                        .context(AnalysisDatabaseSnafu { operation: "read active managed tenant" })?
                        .try_into().map_err(|_| Code::Invalid.error("active managed tenant"))?,
                    id: row.get(1)
                        .context(AnalysisDatabaseSnafu { operation: "read active managed identity" })?,
                    generation: row.get(2)
                        .context(AnalysisDatabaseSnafu { operation: "read active managed generation" })?,
                    lifecycle: row.get(3)
                        .context(AnalysisDatabaseSnafu { operation: "read active managed lifecycle" })?,
                };
                if member.tenant == [0; 16] || member.id.is_empty()
                    || member.id.chars().any(char::is_control) || member.generation == 0
                    || member.lifecycle < member.generation || member.lifecycle > revision {
                    return Err(Code::Invalid.error("active managed member"));
                }
                active.push(member);
            }
            Ok((revision, active))
        })
    }

    pub(super) fn managed_row(
        tenant: [u8; 16],
        id: &str,
        (bytes, grant, generation, progress, running, removed, lifecycle): (
            Vec<u8>,
            Vec<u8>,
            u64,
            u64,
            bool,
            bool,
            u64,
        ),
    ) -> Result<ManagedInstance> {
        let spec: ManagedSpec =
            ManagedCodec::decode(&bytes).context(crate::ManagedDecodingSnafu)?;
        let grant = ManagedCodec::decode(&grant).context(crate::ManagedDecodingSnafu)?;
        if spec.tenant != tenant || spec.id != id {
            return Err(Code::Invalid.error("managed instance key"));
        }
        Ok(ManagedInstance {
            spec,
            grant,
            generation,
            progress,
            running,
            removed,
            lifecycle,
        })
    }

    pub(super) fn check_managed_images(reader: &Connection, spec: &ManagedSpec) -> Result<()> {
        let definition = spec.definition.encode()?;
        let saved: Option<Vec<u8>> = reader.query_row("SELECT definition FROM discovery_definitions WHERE tenant_id = ? AND name = ? AND commit_revision = ?",
            params![spec.tenant.as_slice(), spec.definition.definition.name, spec.manifest.definition], |row| row.get(0))
            .optional().context(AnalysisDatabaseSnafu { operation: "read managed definition pin" })?;
        if saved.as_deref() != Some(definition.as_slice()) {
            return Err(Code::Missing.error("managed definition pin"));
        }
        for pin in &spec.definition.images {
            let bundle = Self::retained_package_image_from(
                reader,
                spec.tenant,
                pin,
                &AnalysisReadControl::default(),
            )?
            .ok_or_else(|| Code::Missing.error("managed image"))?;
            if bundle.digest() != pin.digest {
                return Err(Code::Conflict.error("managed image digest"));
            }
            for call in spec
                .manifest
                .calls
                .values()
                .filter(|call| call.image == *pin)
            {
                let artifact = bundle.bundle().artifact(&call.package)?;
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

    pub(super) fn check_managed_addressable(reader: &Connection, spec: &ManagedSpec) -> Result<()> {
        for pin in &spec.definition.images {
            let installed: bool = reader.query_row(
                "SELECT EXISTS(SELECT 1 FROM package_images WHERE tenant_id = ? AND package_id = ? AND revision = ? AND digest = ? AND installed)",
                params![spec.tenant.as_slice(), pin.image.package_id, pin.image.revision, pin.digest],
                |row| row.get(0),
            ).context(AnalysisDatabaseSnafu { operation: "check installed managed image" })?;
            if !installed {
                return Err(Code::Missing.error("managed installed image"));
            }
        }
        Ok(())
    }

    pub(in crate::analysis) fn managed_contract(
        reader: &Connection,
        tenant: [u8; 16],
        call: &ManagedCall,
    ) -> Result<sdk::Package> {
        let bytes: Vec<u8> = reader.query_row("SELECT descriptor FROM package_revisions WHERE tenant_id = ? AND package_id = ? AND revision = ?",
            params![tenant.as_slice(), call.package.package_id, call.package.revision], |row| row.get(0))
            .optional().context(AnalysisDatabaseSnafu { operation: "read managed SDK descriptor" })?
            .ok_or_else(|| Code::Missing.error("managed SDK descriptor"))?;
        let descriptor: sdk::Package =
            serde_json::from_slice(&bytes).context(crate::PackageEncodingSnafu)?;
        if descriptor.id != call.package.package_id || descriptor.revision != call.package.revision
        {
            return Err(Code::Invalid.error("managed SDK descriptor pin"));
        }
        Ok(descriptor)
    }

    pub fn managed_resume(
        &self,
        tenant: [u8; 16],
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<ManagedResume> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let instance = Self::managed_instance_from(reader, tenant, id)?
                .ok_or_else(|| Code::Missing.error("managed resume instance"))?;
            if instance.removed {
                return Err(Code::Conflict.error("managed instance removed"));
            }
            Self::check_managed_pending(reader, tenant, id, instance.generation)?;
            let completed = Self::managed_completed_from(reader, tenant, id, instance.generation)?;
            let source = Self::managed_source_head(reader, &instance)?;
            if completed > instance.progress {
                let bytes: Vec<u8> = reader.query_row(
                    "SELECT contract FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? AND completed = ?",
                    params![tenant.as_slice(), id, completed], |row| row.get(0),
                ).context(AnalysisDatabaseSnafu { operation: "read managed terminal frontier" })?;
                let attempt: Attempt = ManagedCodec::decode(&bytes).context(crate::ManagedDecodingSnafu)?;
                let terminal = attempt.terminal.as_ref().filter(|terminal|
                    terminal.instance == id && terminal.attempt == attempt.request.id
                        && terminal.revision == completed && attempt.receipt.is_none())
                    .ok_or_else(|| Code::Invalid.error("managed terminal frontier"))?;
                if attempt.capture.tenant != tenant || attempt.capture.instance != id
                    || attempt.capture.generation != instance.generation {
                    return Err(Code::Invalid.error("managed terminal frontier"));
                }
                if attempt.capture.progress == instance.progress
                    && attempt.capture.lifecycle == instance.lifecycle
                    && attempt.capture.running == instance.running
                    && attempt.request.frontier.is_some()
                {
                    match terminal.exit {
                        ManagedExit::Failed(Code::Invalid | Code::Unsupported | Code::Missing | Code::Conflict | Code::Incomplete | Code::Limit) => {
                            let frontier = attempt.request.frontier.ok_or_else(||
                                Code::Incomplete.error("managed native frontier unavailable"))?;
                            control.check()?;
                            return Ok(ManagedResume {
                                source, instance, frontier: Some(frontier), completed });
                        }
                        ManagedExit::Cancelled | ManagedExit::Failed(Code::Denied) => {}
                    }
                }
            }
            let frontier = if instance.progress == 0 {
                None
            } else {
                let bytes: Vec<u8> = reader.query_row(
                    "SELECT contract FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? AND completed = ?",
                    params![tenant.as_slice(), id, instance.progress], |row| row.get(0),
                ).context(AnalysisDatabaseSnafu { operation: "read managed committed frontier" })?;
                let attempt: Attempt = ManagedCodec::decode(&bytes).context(crate::ManagedDecodingSnafu)?;
                if attempt.capture.tenant != tenant || attempt.capture.instance != id
                    || attempt.capture.generation != instance.generation
                    || attempt.receipt.as_ref().is_none_or(|receipt| {
                        receipt.instance != id || receipt.attempt != attempt.request.id
                            || receipt.commit_revision != instance.progress
                            || !receipt.matches_frontier(&attempt.request.frontier)
                    }) {
                    return Err(Code::Invalid.error("managed committed frontier"));
                }
                Some(attempt.receipt.and_then(|receipt| receipt.frontier).ok_or_else(||
                    Code::Incomplete.error("managed native frontier unavailable"))?)
            };
            control.check()?;
            Ok(ManagedResume {
                source, instance, frontier, completed })
        })
    }

    pub(in crate::analysis) fn check_managed_metadata(
        reader: &Connection,
        request: &ManagedRead,
    ) -> Result<()> {
        Self::managed_capture_owner(reader, request)?;
        let expected = request.expected();
        Self::check_managed_pending(
            reader,
            expected.spec.tenant,
            &expected.spec.id,
            expected.generation,
        )
    }

    pub(super) fn managed_capture_owner(
        reader: &Connection,
        request: &ManagedRead,
    ) -> Result<(ManagedInstance, u64)> {
        let expected = request.expected();
        if expected.removed || request.instance.removed {
            return Err(Code::Conflict.error("managed instance removed"));
        }
        if request.instance.grant.selection
            != Self::managed_scope_from(
                reader,
                request.instance.spec.tenant,
                &request.instance.spec.id,
                request.instance.generation,
            )?
        {
            return Err(Code::Conflict.error("managed capture scope"));
        }
        let current = Self::managed_instance_from(reader, expected.spec.tenant, &expected.spec.id)?
            .filter(|instance| instance == expected)
            .ok_or_else(|| Code::Conflict.error("managed capture generation"))?;
        let completed = Self::managed_completed_from(
            reader,
            expected.spec.tenant,
            &expected.spec.id,
            expected.generation,
        )?;
        if request
            .completed
            .is_some_and(|expected| expected != completed)
        {
            return Err(Code::Conflict.error("managed capture completion"));
        }
        Ok((current, completed))
    }

    pub(super) fn managed_completed_from(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
        generation: u64,
    ) -> Result<u64> {
        reader.query_row(
            "SELECT COALESCE(MAX(completed), 0) FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? AND generation = ?",
            params![tenant.as_slice(), id, generation], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "read managed completion" })
    }

    pub(super) fn check_managed_pending(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
        generation: u64,
    ) -> Result<()> {
        let pending: bool = reader.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? AND generation = ? AND completed = 0)",
            params![tenant.as_slice(), id, generation], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "read managed pending attempts" })?;
        if pending {
            return Err(Code::Incomplete.error("managed pending attempt"));
        }
        Ok(())
    }

    pub(super) fn check_managed_idle(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<()> {
        let pending: bool = reader.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? AND completed = 0)",
            params![tenant.as_slice(), id], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "read all managed pending attempts" })?;
        if pending {
            return crate::AnalysisBusySnafu {
                resource: "managed attempt",
            }
            .fail();
        }
        Ok(())
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
            let instance = ManagedInstance {
                spec: Self::managed_version_from(
                    reader,
                    tenant,
                    instance,
                    attempt.capture.generation,
                )?,
                grant: attempt.capture.grant.clone(),
                generation: attempt.capture.generation,
                progress: attempt.capture.progress,
                running: attempt.capture.running,
                removed: false,
                lifecycle: attempt.capture.lifecycle,
            };
            Ok(Some(ManagedAttempt(
                attempt,
                instance,
                None,
                std::collections::BTreeMap::new(),
                None,
                None,
            )))
        })
    }

    pub(super) fn managed_attempt_from(
        reader: &Connection,
        tenant: [u8; 16],
        instance: &str,
        id: &str,
    ) -> Result<Option<Attempt>> {
        let row: Option<(u64, Vec<u8>)> = reader.query_row("SELECT generation, contract FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? AND attempt_id = ?", params![tenant.as_slice(), instance, id], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional().context(AnalysisDatabaseSnafu { operation: "read managed attempt" })?;
        row.map(|(generation, bytes)| {
            let attempt = Attempt::decode(tenant, instance, id, &bytes)?;
            if attempt.capture.generation != generation {
                return Err(Code::Invalid.error("managed attempt version"));
            }
            Ok(attempt)
        })
        .transpose()
    }

    pub fn managed_reference(
        &self,
        instance: &ManagedInstance,
        id: &str,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<(ManagedAttempt, Option<u64>, bool)> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let processor: Option<String> = reader.query_row(
                "SELECT processor_id FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
                params![instance.spec.tenant.as_slice(), id],
                |row| row.get(0),
            ).optional().context(AnalysisDatabaseSnafu {
                operation: "read managed reference kind",
            })?;
            let processor = processor.ok_or_else(|| Code::Missing.error("managed result"))?;
            if Self::managed_version_from(
                reader,
                instance.spec.tenant,
                &instance.spec.id,
                instance.generation,
            )? != instance.spec
            {
                return Err(Code::Denied.error("managed result scope"));
            }
            let (attempt, call, current) = match processor.as_str() {
                "managed-package-v1" => {
                    let (record, revision) =
                        Self::managed_meta_from(reader, instance.spec.tenant, id)?;
                    if record.instance != instance.spec.id {
                        return Err(Code::Denied.error("managed result scope"));
                    }
                    let owner = Self::managed_attempt_from(
                        reader,
                        instance.spec.tenant,
                        &record.instance,
                        &record.attempt,
                    )?
                    .ok_or_else(|| Code::Missing.error("managed result attempt"))?;
                    owner
                        .capture
                        .grant
                        .permitted_by(&instance.grant.selection)?;
                    if Self::managed_edges(reader, instance.spec.tenant, id)? != record.dependencies
                    {
                        return Err(Code::Invalid.error("managed result edges"));
                    }
                    let (_, attempt, _) = Self::validate_managed_header(
                        reader,
                        instance.spec.tenant,
                        id,
                        &record,
                        revision,
                    )?;
                    let current =
                        self.managed_current(reader, &instance.spec, id, revision, now, control)?;
                    (attempt, Some(record.call), current)
                }
                "managed-definition-v1" => {
                    let (step, revision) =
                        Self::managed_step_meta(reader, instance.spec.tenant, id)?;
                    if step.instance != instance.spec.id {
                        return Err(Code::Denied.error("managed result scope"));
                    }
                    let owner = Self::managed_attempt_from(
                        reader,
                        instance.spec.tenant,
                        &step.instance,
                        &step.attempt,
                    )?
                    .ok_or_else(|| Code::Missing.error("managed selected attempt"))?;
                    owner
                        .capture
                        .grant
                        .permitted_by(&instance.grant.selection)?;
                    if Self::managed_edges(reader, instance.spec.tenant, id)? != step.dependencies {
                        return Err(Code::Invalid.error("managed selected edges"));
                    }
                    let (attempt, _) = Self::validate_selected_header(
                        reader,
                        instance.spec.tenant,
                        id,
                        &step,
                        revision,
                    )?;
                    (attempt, None, instance.progress == revision)
                }
                _ => return Err(Code::Missing.error("managed result")),
            };
            attempt
                .capture
                .grant
                .permitted_by(&instance.grant.selection)?;
            Self::check_managed_progress(reader, &attempt.capture)?;
            let mut historical = instance.clone();
            historical.spec = Self::managed_version_from(
                reader,
                instance.spec.tenant,
                &instance.spec.id,
                attempt.capture.generation,
            )?;
            historical.generation = attempt.capture.generation;
            historical.grant = attempt.capture.grant.clone();
            historical.progress = attempt.capture.progress;
            historical.running = attempt.capture.running;
            historical.lifecycle = attempt.capture.lifecycle;
            Ok((
                ManagedAttempt(attempt, historical, None, BTreeMap::new(), None, None),
                call,
                current,
            ))
        })
    }

    pub fn managed_result(
        &self,
        instance: &ManagedInstance,
        id: &str,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<crate::InstanceResultV1> {
        let (reference, call, current) = self.managed_reference(instance, id, now, control)?;
        let captured = &reference.0.capture;
        let receipt = reference
            .receipt()
            .cloned()
            .ok_or_else(|| Code::Invalid.error("managed result receipt"))?;
        let (result, kind) = match call {
            Some(call) => {
                let result = receipt
                    .results
                    .get(&call)
                    .cloned()
                    .ok_or_else(|| Code::Invalid.error("managed result reference"))?;
                let mut reader = self.reader_until(control)?;
                let (record, _) = control.run(&mut reader, |reader| {
                    Self::managed_meta_from(reader, instance.spec.tenant, id)
                })?;
                let declaration = &reference.1.spec.manifest.calls[&call];
                (
                    result,
                    crate::InstanceResultKindV1::Call {
                        call,
                        image: declaration.image.clone(),
                        package: declaration.package.clone(),
                        export: declaration.export.clone(),
                        context: record.context,
                    },
                )
            }
            None => (
                receipt.selected.clone(),
                crate::InstanceResultKindV1::Selected,
            ),
        };
        reference.instance().spec.definition.validate()?;
        if reference.instance().spec.manifest.definition == 0 {
            return Err(Code::Invalid.error("definition revision"));
        }
        Ok(crate::InstanceResultV1 {
            instance_id: instance.spec.id.clone(),
            result,
            definition_revision: reference.instance().spec.manifest.definition.to_string(),
            generation: captured.generation,
            source: crate::AnalysisStoreMetaV1 {
                store_uuid: captured.store,
                schema_version: captured.schema,
                recovery_epoch: captured.recovery,
                commit_revision: captured.revision,
            },
            time_utc_ns: captured.time_utc_ns,
            prior: captured.prior.clone(),
            receipt,
            current,
            kind,
        })
    }

    pub(super) fn managed_state_from(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<(Record, Option<sdk::wire::Checkpoint>, u64)> {
        let (record, revision) = Self::managed_meta_from(reader, tenant, id)?;
        let body: Vec<u8> = reader
            .query_row(
                "SELECT body FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
                params![tenant.as_slice(), id],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read canonical managed checkpoint",
            })?;
        if Self::managed_edges(reader, tenant, id)? != record.dependencies {
            return Err(Code::Invalid.error("managed result edges"));
        }
        Ok((
            record,
            ManagedCodec::decode(&body).context(crate::ManagedDecodingSnafu)?,
            revision,
        ))
    }

    pub(super) fn managed_meta_from(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<(Record, u64)> {
        let (metadata, revision): (Vec<u8>, u64) = reader.query_row(
            "SELECT request_meta, commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ? AND processor_id = 'managed-package-v1'",
            params![tenant.as_slice(), id], |row| Ok((row.get(0)?, row.get(1)?)),
        ).context(AnalysisDatabaseSnafu { operation: "read managed call reference" })?;
        Ok((
            ManagedCodec::decode(&metadata).context(crate::ManagedDecodingSnafu)?,
            revision,
        ))
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
            SELECT e.dependency_id, e.commit_revision FROM managed_edges e
                JOIN needed n ON n.result_id = e.result_id
                JOIN analysis_results parent ON parent.result_id = e.result_id
                    AND parent.tenant_id = e.tenant_id AND parent.commit_revision = n.revision
                WHERE e.tenant_id = ? AND parent.processor_id
                    IN ('managed-package-v1', 'managed-definition-v1')
                    AND NOT EXISTS(SELECT 1 FROM managed_source_publications source
                        WHERE source.result_id=e.result_id))
            SELECT n.result_id, n.revision, r.processor_id, c.instance_id,
                source.result_id IS NOT NULL FROM needed n
            LEFT JOIN analysis_results r ON n.result_id = r.result_id AND r.tenant_id = ? AND r.commit_revision = n.revision
            LEFT JOIN managed_calls c ON c.result_id = r.result_id AND c.tenant_id = r.tenant_id AND c.state_revision = r.commit_revision
            LEFT JOIN managed_source_publications source ON source.result_id=n.result_id")
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
                        row.get::<_, bool>(4)?,
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
        let mut current = true;
        for (id, revision, processor, instance, native) in rows {
            control.check()?;
            let Some(processor) = processor else {
                return Ok(false);
            };
            if native {
                Self::native_source_cut(
                    reader,
                    spec.tenant,
                    &PackageResultRefV1 {
                        result_id: id,
                        commit_revision: revision,
                    },
                    None,
                    None,
                )?
                .ok_or_else(|| Code::Conflict.error("native source dependency"))?;
                continue;
            }
            let (attempt, witnesses, contexts) = if processor == "managed-package-v1" {
                if instance.as_deref() != Some(spec.id.as_str()) {
                    return Ok(false);
                }
                let metadata: Vec<u8> = reader.query_row("SELECT request_meta FROM analysis_results WHERE tenant_id = ? AND result_id = ?", params![spec.tenant.as_slice(), id], |row| row.get(0)).context(AnalysisDatabaseSnafu { operation: "read managed freshness metadata" })?;
                let record: Record =
                    ManagedCodec::decode(&metadata).context(crate::ManagedDecodingSnafu)?;
                let attempt =
                    Self::managed_attempt_from(reader, spec.tenant, &spec.id, &record.attempt)?
                        .ok_or_else(|| Code::Missing.error("managed result attempt"))?;
                (
                    attempt,
                    record.witnesses,
                    Self::join_contexts(&record.contexts, &record.derived)?,
                )
            } else if processor == "managed-definition-v1" {
                let metadata: Vec<u8> = reader.query_row("SELECT request_meta FROM analysis_results WHERE tenant_id = ? AND result_id = ?", params![spec.tenant.as_slice(), id], |row| row.get(0)).context(AnalysisDatabaseSnafu { operation: "read managed selected freshness" })?;
                let step: Step =
                    ManagedCodec::decode(&metadata).context(crate::ManagedDecodingSnafu)?;
                let current = Self::managed_instance_from(reader, spec.tenant, &step.instance)?;
                if step.instance != spec.id
                    || current.is_none_or(|instance| instance.progress != revision)
                {
                    return Ok(false);
                }
                let attempt =
                    Self::managed_attempt_from(reader, spec.tenant, &spec.id, &step.attempt)?
                        .ok_or_else(|| Code::Missing.error("managed selected attempt"))?;
                (
                    attempt,
                    step.witnesses,
                    Self::join_contexts(&step.contexts, &step.derived)?,
                )
            } else {
                if self.package_source_revision(reader, spec.tenant, &id)? != revision {
                    return Ok(false);
                }
                continue;
            };
            if attempt
                .request
                .frontier
                .as_ref()
                .and_then(|frontier| frontier.next_change)
                .is_some_and(|deadline| deadline <= now)
            {
                return Ok(false);
            }
            let capture = attempt.capture;
            if !Self::package_sources_current(reader, &capture.sources, control)? {
                return Ok(false);
            }
            Self::check_trace_reads_from(reader, spec.tenant, &capture.traces, control)?;
            if witnesses
                .iter()
                .any(|witness| witness.expires_utc_ns <= now)
            {
                current = false;
            }
            for reference in &contexts {
                if Self::read_context_from(reader, &self.root, &reference.key)?
                    .is_none_or(|(_, current)| current != reference.commit_revision)
                {
                    return Ok(false);
                }
            }
        }
        Ok(current)
    }
}

impl AnalysisStore {
    pub(super) fn managed_step_header(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<(Step, u64)> {
        let (step, revision) = Self::managed_step_meta(reader, tenant, id)?;
        let empty: bool = reader.query_row(
            "SELECT octet_length(body) = 0 FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
            params![tenant.as_slice(), id], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "check managed selected reference" })?;
        if !empty || Self::managed_edges(reader, tenant, id)? != step.dependencies {
            return Err(Code::Invalid.error("managed selected edges"));
        }
        Ok((step, revision))
    }

    pub(super) fn managed_step_meta(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<(Step, u64)> {
        let (metadata, revision): (Vec<u8>, u64) = reader.query_row(
            "SELECT request_meta, commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ? AND processor_id = 'managed-definition-v1'",
            params![tenant.as_slice(), id], |row| Ok((row.get(0)?, row.get(1)?)),
        ).context(AnalysisDatabaseSnafu { operation: "read managed selected reference" })?;
        Ok((
            ManagedCodec::decode(&metadata).context(crate::ManagedDecodingSnafu)?,
            revision,
        ))
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
                ManagedCodec::decode(metadata).context(crate::ManagedDecodingSnafu)?;
            Ok((
                record.witnesses,
                Self::join_contexts(&record.contexts, &record.derived)?,
            ))
        } else {
            let step: Step = ManagedCodec::decode(metadata).context(crate::ManagedDecodingSnafu)?;
            Ok((
                step.witnesses,
                Self::join_contexts(&step.contexts, &step.derived)?,
            ))
        }
    }
}

impl AnalysisStore {
    pub(in crate::analysis) fn graph_capture_cut(
        reader: &Connection,
        tenant: [u8; 16],
        result: &PackageResultRefV1,
        reference: Option<&ManagedAttempt>,
        expected_call: Option<&str>,
    ) -> Result<u64> {
        if let Some(cut) =
            Self::native_source_cut(reader, tenant, result, reference, expected_call)?
        {
            return Ok(cut);
        }
        let (call, source, call_cut, metadata_cut): (String, Vec<u8>,Option<u64>,Option<u64>) = reader
            .query_row(
                "SELECT v.result_id,r.stream_key,v.captured_revision,metadata.captured_revision FROM graph_versions g
             JOIN analysis_results r ON r.result_id=g.result_id
             JOIN graph_producer_versions metadata ON metadata.result_id=g.metadata_result_id
             JOIN graph_result_producers b ON b.result_id=g.result_id
             JOIN graph_producer_versions v ON v.result_id=b.producer_result_id
             JOIN graph_producer_scopes s ON s.scope_id=v.scope_id
             WHERE g.result_id=? AND g.commit_revision=? AND r.tenant_id=?
                AND r.commit_revision=g.commit_revision AND s.producer_kind=0
                AND v.commit_revision=g.commit_revision AND (CAST(? AS VARCHAR) IS NULL OR v.result_id=?)
                ORDER BY s.call_id LIMIT 1",
                params![result.result_id, result.commit_revision, tenant.as_slice(),expected_call,expected_call],
                |row| Ok((row.get(0)?, row.get(1)?,row.get(2)?,row.get(3)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph captured owner",
            })?;
        let (record, revision) = Self::managed_meta_from(reader, tenant, &call)?;
        let (attempt, spec) = Self::managed_call_owner(reader, tenant, &call, revision, &record)?;
        if call_cut != Some(attempt.capture.revision)
            || metadata_cut != Some(attempt.capture.revision)
        {
            return Err(Code::Invalid.error("Graph captured native cut"));
        }
        if reference.is_some_and(|reference| {
            reference.0.capture != attempt.capture
                || reference.1.spec != spec
                || reference.0.receipt != attempt.receipt
                || reference.0.request.id != attempt.request.id
        }) {
            return Err(Code::Conflict.error("Graph captured reference"));
        }
        let ManagedDestination::Graph {
            source: declared,
            calls,
            ..
        } = &spec.destination
        else {
            return Err(Code::Invalid.error("Graph captured destination"));
        };
        if declared.key() != source
            || !calls.contains(&record.call)
            || attempt
                .receipt
                .as_ref()
                .and_then(|receipt| receipt.graph.as_ref())
                != Some(result)
            || attempt.capture.revision >= result.commit_revision
        {
            return Err(Code::Invalid.error("Graph captured receipt"));
        }
        crate::analysis::graph_rows::GraphRows::call_scope(
            reader,
            &spec,
            record.call,
            &PackageResultRefV1 {
                result_id: call,
                commit_revision: revision,
            },
        )?;
        Ok(attempt.capture.revision)
    }

    pub(super) fn managed_call_owner(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
        revision: u64,
        record: &Record,
    ) -> Result<(Attempt, ManagedSpec)> {
        let attempt =
            Self::managed_attempt_from(reader, tenant, &record.instance, &record.attempt)?
                .ok_or_else(|| Code::Missing.error("managed result attempt"))?;
        if attempt.terminal.is_some()
            || attempt.receipt.as_ref().is_none_or(|receipt| {
                receipt.instance != record.instance
                    || receipt.attempt != record.attempt
                    || receipt.commit_revision != revision
                    || receipt.results.get(&record.call).is_none_or(|result| {
                        result.result_id != id || result.commit_revision != revision
                    })
            })
        {
            return Err(Code::Invalid.error("retained managed result owner"));
        }
        let spec = Self::managed_version_from(
            reader,
            tenant,
            &record.instance,
            attempt.capture.generation,
        )?;
        Ok((attempt, spec))
    }

    pub(super) fn validate_managed_header(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
        record: &Record,
        revision: u64,
    ) -> Result<(sdk::Package, Attempt, ManagedSpec)> {
        Self::validate_managed_header_on(reader, tenant, id, record, revision, &mut |_, _| Ok(()))
    }

    pub(super) fn validate_managed_header_on(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
        record: &Record,
        revision: u64,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<(sdk::Package, Attempt, ManagedSpec)> {
        let (attempt, spec) = Self::managed_call_owner(reader, tenant, id, revision, record)?;
        attempt.capture.grant.validate()?;
        if attempt.capture.grant.selection
            != Self::managed_scope_from(
                reader,
                tenant,
                &record.instance,
                attempt.capture.generation,
            )?
        {
            return Err(Code::Invalid.error("retained managed result contract"));
        }
        let receipt = attempt
            .receipt
            .as_ref()
            .ok_or_else(|| Code::Invalid.error("unpublished managed result"))?;
        let (metadata, selected): (Vec<u8>, u64) = reader
            .query_row(
                "SELECT request_meta, commit_revision FROM analysis_results
             WHERE tenant_id = ? AND result_id = ? AND processor_id = 'managed-definition-v1'",
                params![tenant.as_slice(), receipt.selected.result_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read managed result evidence owner",
            })?;
        let step: Step = ManagedCodec::decode(&metadata).context(crate::ManagedDecodingSnafu)?;
        Self::check_source_evidence(reader, &attempt, &step)?;
        let descriptor = Self::validate_call_header(
            reader, tenant, id, record, revision, &step, selected, &attempt, &spec, charge,
        )?;
        Ok((descriptor, attempt, spec))
    }

    pub(super) fn validate_call_header(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
        record: &Record,
        revision: u64,
        step: &Step,
        selected: u64,
        attempt: &Attempt,
        spec: &ManagedSpec,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<sdk::Package> {
        let declaration = spec
            .manifest
            .calls
            .get(&record.call)
            .ok_or_else(|| Code::Invalid.error("retained managed call"))?;
        let receipt = attempt
            .receipt
            .as_ref()
            .ok_or_else(|| Code::Invalid.error("unpublished managed result"))?;
        if attempt.terminal.is_some()
            || receipt.instance != record.instance
            || receipt.attempt != record.attempt
            || receipt.commit_revision != revision
            || receipt
                .results
                .get(&record.call)
                .is_none_or(|result| result.result_id != id || result.commit_revision != revision)
            || record.context.context.id != attempt.request.id
            || record.context.context.time_utc_ns != attempt.request.time_utc_ns as i64
            || record.context.context.seed != attempt.request.seed
        {
            return Err(Code::Invalid.error("retained managed result contract"));
        }
        if selected != receipt.selected.commit_revision
            || selected != receipt.commit_revision
            || step.instance != record.instance
            || step.attempt != record.attempt
            || record.witnesses.windows(2).any(|pair| {
                (&pair[0].identity, pair[0].cursor) >= (&pair[1].identity, pair[1].cursor)
            })
            || record
                .contexts
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
            || record.witnesses.iter().any(|value| {
                step.witnesses
                    .binary_search_by(|witness| {
                        (&witness.identity, witness.cursor).cmp(&(&value.identity, value.cursor))
                    })
                    .ok()
                    .is_none_or(|index| step.witnesses[index] != *value)
            })
            || record.contexts.iter().any(|value| {
                step.contexts
                    .binary_search_by(|reference| reference.key.cmp(&value.key))
                    .ok()
                    .is_none_or(|index| step.contexts[index] != *value)
            })
            || record
                .derived
                .iter()
                .any(|value| !step.derived.contains(value))
            || record
                .origins
                .iter()
                .any(|value| !step.origins.contains(value))
        {
            return Err(Code::Invalid.error("managed result source evidence"));
        }
        Self::check_source_pins(
            reader,
            id,
            &record.witnesses,
            &Self::join_contexts(&record.contexts, &record.derived)?,
        )?;
        Self::check_source_proofs(
            reader,
            id,
            (&record.witnesses, &record.derived, &record.proofs),
            attempt.capture.revision,
        )?;
        Self::check_derived_refs(
            reader,
            &attempt,
            &record.derived,
            &record.origins,
            &record.contexts,
            &record.witnesses,
            revision,
            id,
        )?;
        let descriptor = Self::managed_contract(reader, tenant, declaration)?;
        let model = descriptor
            .exports
            .iter()
            .find(|model| model.name == declaration.export)
            .ok_or_else(|| Code::Missing.error("retained managed model"))?;
        if record.context.target != declaration.target
            || record.context.artifact != declaration.artifact
            || record.context.inputs.len() != model.inputs.len()
            || record.context.input_coverage.len() != model.inputs.len()
            || record.context.coverage
                != crate::ResultContext::coverage(&record.context.input_coverage)
        {
            return Err(Code::Invalid.error("retained managed evaluation context"));
        }
        Self::check_change_record(reader, tenant, record, declaration, model, &attempt)?;
        Self::check_graph_result(
            reader,
            &spec,
            id,
            record.call,
            revision,
            model.graph.is_some(),
        )?;
        Self::check_graph_proof(reader, &attempt, record, model.graph.is_some(), charge)?;
        let mut dependencies = attempt.capture.dependencies.clone();
        dependencies.extend(
            declaration
                .dependencies
                .iter()
                .filter_map(|call| receipt.results.get(call).cloned()),
        );
        dependencies.sort_by(|left, right| left.result_id.cmp(&right.result_id));
        dependencies.dedup();
        if dependencies != record.dependencies {
            return Err(Code::Invalid.error("retained managed dependencies"));
        }
        Ok(descriptor)
    }
}

impl AnalysisStore {
    pub(in crate::analysis) fn managed_edges(
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
