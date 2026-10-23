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
        grant: &crate::PackageGrantV1,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        spec.validate()?;
        grant.validate()?;
        if grant.selection.tenant_id != spec.tenant {
            return Err(Code::Invalid.error("managed instance grant"));
        }
        let bytes = serde_json::to_vec(spec).context(crate::PackageEncodingSnafu)?;
        let grant_bytes = serde_json::to_vec(grant).context(crate::PackageEncodingSnafu)?;
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin managed admission",
            })?;
        Self::check_managed_images(&transaction, spec)?;
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
                    serde_json::to_vec(&grant.selection).context(crate::PackageEncodingSnafu)?
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
        self.check_logical(&transaction, spec.tenant, false)?;
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
        let row = reader.query_row("SELECT v.spec, i.authority, i.generation, i.progress, i.running, i.removed, i.lifecycle FROM managed_instances i JOIN managed_versions v USING (tenant_id, instance_id, generation) WHERE i.tenant_id = ? AND i.instance_id = ?", params![tenant.as_slice(), id], |row|
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, u64>(2)?, row.get::<_, u64>(3)?, row.get::<_, bool>(4)?, row.get::<_, bool>(5)?, row.get::<_, u64>(6)?)))
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
            serde_json::from_slice(&bytes).context(crate::PackageEncodingSnafu)?;
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
            serde_json::from_slice(&bytes).context(crate::PackageEncodingSnafu)?;
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
            serde_json::from_slice(&bytes).context(crate::PackageEncodingSnafu)?;
        let grant = serde_json::from_slice(&grant).context(crate::PackageEncodingSnafu)?;
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
        let definition =
            serde_json::to_vec(&spec.definition).context(crate::PackageEncodingSnafu)?;
        let saved: Option<Vec<u8>> = reader.query_row("SELECT definition FROM discovery_definitions WHERE tenant_id = ? AND name = ? AND revision = ?",
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
            if completed > instance.progress {
                let bytes: Vec<u8> = reader.query_row(
                    "SELECT contract FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? AND completed = ?",
                    params![tenant.as_slice(), id, completed], |row| row.get(0),
                ).context(AnalysisDatabaseSnafu { operation: "read managed terminal frontier" })?;
                let attempt: Attempt = serde_json::from_slice(&bytes)
                    .context(crate::PackageEncodingSnafu)?;
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
                            return Ok(ManagedResume { instance, frontier: Some(frontier), completed });
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
                let attempt: Attempt = serde_json::from_slice(&bytes)
                    .context(crate::PackageEncodingSnafu)?;
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
            Ok(ManagedResume { instance, frontier, completed })
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

    pub fn managed_result(
        &self,
        instance: &ManagedInstance,
        id: &str,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<ManagedResult> {
        let ManagedOutput::Call { result, data } =
            self.managed_output(instance, id, now, control)?
        else {
            return Err(Code::Unsupported.error("selected package result"));
        };
        Ok(ManagedResult {
            context: result.context,
            output: data,
            commit_revision: result.commit_revision,
            current: result.current,
        })
    }

    pub fn managed_output(
        &self,
        instance: &ManagedInstance,
        id: &str,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<ManagedOutput> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            self.managed_output_from(reader, instance, id, now, control)
        })
    }

    pub fn managed_query_output(
        &self,
        selection: &crate::AnalysisSelectionV1,
        instance: &str,
        id: Option<&str>,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<ManagedOutput> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let mut current = Self::managed_instance_from(reader, selection.tenant_id, instance)?
                .ok_or_else(|| Code::Missing.error("managed instance"))?;
            let selected;
            let id = match id {
                Some(id) => id,
                None => {
                    current.grant.permitted_by(selection)?;
                    if current.progress == 0 {
                        return Err(Code::Missing.error("managed current result"));
                    }
                    let key: String = reader.query_row(
                        "SELECT attempt_id FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? AND generation = ? AND completed = ?",
                        params![selection.tenant_id.as_slice(), instance, current.generation, current.progress],
                        |row| row.get(0),
                    ).optional().context(AnalysisDatabaseSnafu { operation: "read current managed receipt" })?
                        .ok_or_else(|| Code::Invalid.error("managed current receipt"))?;
                    let attempt = Self::managed_attempt_from(reader, selection.tenant_id, instance, &key)?
                        .ok_or_else(|| Code::Invalid.error("managed current receipt"))?;
                    let receipt = attempt.receipt.as_ref().filter(|receipt| {
                        attempt.capture.generation == current.generation
                            && attempt.terminal.is_none()
                            && receipt.instance == instance
                            && receipt.attempt == key
                            && receipt.commit_revision == current.progress
                            && receipt.selected.commit_revision == current.progress
                            && !receipt.selected.result_id.is_empty()
                    }).ok_or_else(|| Code::Invalid.error("managed current receipt"))?;
                    selected = receipt.selected.result_id.clone();
                    let (step, _, revision) = Self::managed_step_header(reader, selection.tenant_id, &selected)?;
                    if step.instance != instance || step.attempt != key || revision != current.progress {
                        return Err(Code::Invalid.error("managed current receipt"));
                    }
                    &selected
                }
            };
            current.grant.selection = selection.clone();
            self.managed_output_from(reader, &current, id, now, control)
        })
    }

    fn managed_output_from(
        &self,
        reader: &Connection,
        instance: &ManagedInstance,
        id: &str,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<ManagedOutput> {
        if Self::managed_version_from(
            reader,
            instance.spec.tenant,
            &instance.spec.id,
            instance.generation,
        )? != instance.spec
        {
            return Err(Code::Denied.error("managed result scope"));
        }
        let processor: Option<String> = reader
            .query_row(
                "SELECT processor_id FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
                params![instance.spec.tenant.as_slice(), id],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read managed result kind",
            })?;
        match processor.as_deref() {
            Some("managed-package-v1") => {}
            Some("managed-definition-v1") => {
                let (step, packet, revision) =
                    Self::managed_step_header(reader, instance.spec.tenant, id)?;
                if step.instance != instance.spec.id {
                    return Err(Code::Denied.error("managed result scope"));
                }
                let (attempt, schema) = Self::validate_selected_header(
                    reader,
                    instance.spec.tenant,
                    id,
                    &step,
                    revision,
                )?;
                attempt
                    .capture
                    .grant
                    .permitted_by(&instance.grant.selection)?;
                let packet = Self::managed_step_payload(reader, id, packet)?;
                let data = Self::decode_selected_record(&packet, &schema, step.rows)?;
                return Ok(ManagedOutput::Selected { packet, data });
            }
            _ => return Err(Code::Missing.error("managed result")),
        }
        let (record, output, commit_revision) =
            Self::managed_header_from(reader, instance.spec.tenant, id)?;
        if record.instance != instance.spec.id {
            return Err(Code::Denied.error("managed result scope"));
        }
        let (descriptor, attempt) = Self::validate_managed_header(
            reader,
            instance.spec.tenant,
            id,
            &record,
            commit_revision,
        )?;
        attempt
            .capture
            .grant
            .permitted_by(&instance.grant.selection)?;
        let (record, output, commit_revision) =
            Self::managed_payload_from(reader, id, (record, output, commit_revision))?;
        let data = Self::decode_managed_record(&descriptor, &record, &output)?;
        let current =
            self.managed_current(reader, &instance.spec, id, commit_revision, now, control)?;
        Ok(ManagedOutput::Call {
            result: Box::new(crate::InstanceResultV1 {
                instance_id: instance.spec.id.clone(),
                result_id: id.to_owned(),
                image: record.declaration.image,
                package: record.declaration.package,
                export: record.declaration.export,
                context: record.context,
                commit_revision,
                current,
                output,
            }),
            data,
        })
    }

    pub(super) fn managed_record_from(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<(Record, sdk::wire::Output, u64)> {
        let header = Self::managed_header_from(reader, tenant, id)?;
        Self::managed_payload_from(reader, id, header)
    }

    fn managed_payload_from(
        reader: &Connection,
        id: &str,
        (mut record, mut output, revision): (Record, sdk::wire::Output, u64),
    ) -> Result<(Record, sdk::wire::Output, u64)> {
        let mut blobs = reader
            .prepare(
                "SELECT role, slot, ipc FROM managed_arrow WHERE result_id = ? AND role <> 'input' ORDER BY role, slot",
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
        Ok((record, output, revision))
    }

    pub(super) fn managed_header_from(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<(Record, sdk::wire::Output, u64)> {
        let (metadata, body, revision): (Vec<u8>, Vec<u8>, u64) = reader.query_row("SELECT request_meta, body, commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ? AND processor_id = 'managed-package-v1'",
            params![tenant.as_slice(), id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .context(AnalysisDatabaseSnafu { operation: "read complete managed result" })?;
        let record: Record =
            serde_json::from_slice(&metadata).context(crate::PackageEncodingSnafu)?;
        let output: sdk::wire::Output =
            serde_json::from_slice(&body).context(crate::PackageEncodingSnafu)?;
        if Self::managed_edges(reader, tenant, id)? != record.dependencies {
            return Err(Code::Invalid.error("managed result edges"));
        }
        let (count, invalid): (usize, usize) = reader.query_row(
            "SELECT count(*), count(*) FILTER (WHERE slot >= ? OR octet_length(ipc) = 0) FROM managed_arrow WHERE result_id = ? AND role = 'input'",
            params![record.inputs.len(), id], |row| Ok((row.get(0)?, row.get(1)?)),
        ).context(AnalysisDatabaseSnafu { operation: "validate managed input slots" })?;
        if invalid != 0 || count > record.inputs.len() {
            return Err(Code::Invalid.error("managed input payload count"));
        }
        if count < record.inputs.len() {
            return Err(Code::Missing.error("managed input payload"));
        }
        Ok((record, output, revision))
    }

    fn retained_call_from(
        &self,
        reader: &Connection,
        spec: &ManagedSpec,
        record: &Record,
        id: &str,
        revision: u64,
    ) -> Result<Option<Attempt>> {
        if !matches!(
            &spec.destination,
            ManagedDestination::Graph {
                operation: ManagedGraphOperation::Evaluate,
                ..
            }
        ) {
            return Ok(None);
        }
        let Some(current) = Self::managed_instance_from(reader, spec.tenant, &spec.id)? else {
            return Ok(None);
        };
        if current.removed || current.spec != *spec || current.progress <= revision {
            return Ok(None);
        }
        let key: String = reader.query_row(
            "SELECT attempt_id FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? AND generation = ? AND completed = ?",
            params![spec.tenant.as_slice(), spec.id, current.generation, current.progress], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "read retained Graph call attestation" })?;
        let attempt = Self::managed_attempt_from(reader, spec.tenant, &spec.id, &key)?
            .ok_or_else(|| Code::Invalid.error("retained Graph call attestation"))?;
        let reference = crate::analysis::PackageResultRefV1 {
            result_id: id.into(),
            commit_revision: revision,
        };
        if !attempt.retains(spec, record.call, &reference) {
            return Ok(None);
        }
        let receipt = attempt
            .receipt
            .as_ref()
            .filter(|receipt| {
                receipt.commit_revision == current.progress
                    && receipt.results.get(&record.call) == Some(&reference)
                    && attempt.terminal.is_none()
            })
            .ok_or_else(|| Code::Invalid.error("retained Graph call attestation"))?;
        let (step, _, saved) =
            Self::managed_step_header(reader, spec.tenant, &receipt.selected.result_id)?;
        Self::validate_selected_header(
            reader,
            spec.tenant,
            &receipt.selected.result_id,
            &step,
            saved,
        )?;
        Self::validate_managed_header(reader, spec.tenant, id, record, revision)?;
        Ok(Some(attempt))
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
        self.managed_source_current(reader, spec, (id, revision), now, control, None)
    }

    pub(super) fn managed_source_current(
        &self,
        reader: &Connection,
        spec: &ManagedSpec,
        (id, revision): (&str, u64),
        now: u64,
        control: &AnalysisReadControl,
        mut output: Option<&mut crate::AnalysisExtractionV1>,
    ) -> Result<bool> {
        let mut statement = reader.prepare("WITH RECURSIVE needed(result_id, revision) AS (
            SELECT ?::VARCHAR, ?::UBIGINT UNION
            SELECT e.dependency_id, e.commit_revision FROM managed_edges e
                JOIN needed n ON n.result_id = e.result_id
                JOIN analysis_results parent ON parent.result_id = e.result_id
                    AND parent.tenant_id = e.tenant_id AND parent.commit_revision = n.revision
                WHERE e.tenant_id = ? AND parent.processor_id
                    IN ('managed-package-v1', 'managed-definition-v1'))
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
            let attempt = if processor == "managed-package-v1" {
                if instance.as_deref() != Some(spec.id.as_str()) {
                    return Ok(false);
                }
                let metadata: Vec<u8> = reader.query_row("SELECT request_meta FROM analysis_results WHERE tenant_id = ? AND result_id = ?", params![spec.tenant.as_slice(), id], |row| row.get(0)).context(AnalysisDatabaseSnafu { operation: "read managed freshness metadata" })?;
                let record: Record =
                    serde_json::from_slice(&metadata).context(crate::PackageEncodingSnafu)?;
                match self.retained_call_from(reader, spec, &record, &id, revision)? {
                    Some(attested) => attested,
                    None => {
                        Self::managed_attempt_from(reader, spec.tenant, &spec.id, &record.attempt)?
                            .ok_or_else(|| Code::Missing.error("managed result attempt"))?
                    }
                }
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
            } else {
                if processor == "analysis-package" {
                    return Err(Code::Unsupported.error("legacy activation input"));
                }
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
            if let Some(output) = output.as_deref_mut() {
                for trace in &capture.traces {
                    if !output.trace_reads.contains(trace) {
                        let added = crate::AnalysisExtractionV1::grow(
                            &mut output.trace_reads,
                            output.input_bytes,
                            output.limits.input_bytes,
                        )?;
                        output.charge(added)?;
                        output.trace_reads.push(*trace);
                    }
                }
            }
            if capture
                .witnesses
                .iter()
                .any(|witness| witness.expires_utc_ns <= now)
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
            if step.instance != instance
                || step.attempt != attempt.request.id
                || receipt.selected.commit_revision != revision
            {
                return Err(Code::Invalid.error("managed selected result rows"));
            }
            let (_, schema) = Self::validate_selected_header(
                reader,
                tenant,
                &receipt.selected.result_id,
                &step,
                revision,
            )?;
            let data = Self::decode_selected_record(&packet, &schema, step.rows)?;
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
        let (step, packet, revision) = Self::managed_step_header(reader, tenant, id)?;
        Ok((
            step,
            Self::managed_step_payload(reader, id, packet)?,
            revision,
        ))
    }

    fn managed_step_header(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<(Step, sdk::wire::Dataset, u64)> {
        let (metadata, body, revision): (Vec<u8>, Vec<u8>, u64) = reader.query_row(
            "SELECT request_meta, body, commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ? AND processor_id = 'managed-definition-v1'",
            params![tenant.as_slice(), id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .context(AnalysisDatabaseSnafu { operation: "read managed selected relation" })?;
        let step: Step = serde_json::from_slice(&metadata).context(crate::PackageEncodingSnafu)?;
        let packet: sdk::wire::Dataset =
            serde_json::from_slice(&body).context(crate::PackageEncodingSnafu)?;
        if !packet.arrow_ipc.is_empty() {
            return Err(Code::Invalid.error("managed selected header"));
        }
        if Self::managed_edges(reader, tenant, id)? != step.dependencies {
            return Err(Code::Invalid.error("managed selected edges"));
        }
        Ok((step, packet, revision))
    }

    fn managed_step_payload(
        reader: &Connection,
        id: &str,
        mut packet: sdk::wire::Dataset,
    ) -> Result<sdk::wire::Dataset> {
        let blobs = reader.query_row("SELECT count(*), count(*) FILTER (WHERE role = 'selected' AND slot = 0) FROM managed_arrow WHERE result_id = ?", params![id], |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)))
            .context(AnalysisDatabaseSnafu { operation: "validate selected Arrow role" })?;
        if blobs != (1, 1) {
            return Err(Code::Invalid.error("managed selected payload"));
        }
        packet.arrow_ipc = reader.query_row("SELECT ipc FROM managed_arrow WHERE result_id = ? AND role = 'selected' AND slot = 0", params![id], |row| row.get(0))
            .context(AnalysisDatabaseSnafu { operation: "read selected Arrow payload" })?;
        Ok(packet)
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
        let (descriptor, _) = Self::validate_managed_header(reader, tenant, id, record, revision)?;
        Self::decode_managed_record(&descriptor, record, packet)
    }

    fn decode_managed_record(
        descriptor: &sdk::Package,
        record: &Record,
        packet: &sdk::wire::Output,
    ) -> Result<sdk::Output> {
        let model = descriptor
            .exports
            .iter()
            .find(|model| model.name == record.declaration.export)
            .ok_or_else(|| Code::Missing.error("retained managed model"))?;
        match (&record.parameters, model.parameters.fields().is_empty()) {
            (None, true) => {}
            (Some(packet), false) => {
                let data = packet
                    .decode(&model.parameters)
                    .context(crate::AnalysisContractSnafu)?;
                if packet.name != "parameters" || data.batches.len() != 1 || data.rows() != 1 {
                    return Err(Code::Invalid.error("retained managed parameters"));
                }
                data.validate(&sdk::Port::new("parameters", model.parameters.clone()))
                    .context(crate::AnalysisContractSnafu)?;
            }
            _ => return Err(Code::Invalid.error("retained managed parameters")),
        }
        packet
            .decode_retained(
                descriptor,
                &record.declaration.export,
                &record
                    .inputs
                    .iter()
                    .map(|input| (input.name.clone(), input.rows))
                    .collect(),
            )
            .context(crate::AnalysisContractSnafu)
    }

    pub(super) fn validate_managed_header(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
        record: &Record,
        revision: u64,
    ) -> Result<(sdk::Package, Attempt)> {
        let attempt =
            Self::managed_attempt_from(reader, tenant, &record.instance, &record.attempt)?
                .ok_or_else(|| Code::Missing.error("managed result attempt"))?;
        let spec = Self::managed_version_from(
            reader,
            tenant,
            &record.instance,
            attempt.capture.generation,
        )?;
        let receipt = attempt
            .receipt
            .as_ref()
            .ok_or_else(|| Code::Invalid.error("unpublished managed result"))?;
        attempt.capture.grant.validate()?;
        if attempt.capture.grant.selection
            != Self::managed_scope_from(
                reader,
                tenant,
                &record.instance,
                attempt.capture.generation,
            )?
            || spec.manifest.calls.get(&record.call) != Some(&record.declaration)
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
            || record.inputs.len() != model.inputs.len()
            || record
                .inputs
                .iter()
                .map(|input| &input.name)
                .collect::<std::collections::BTreeSet<_>>()
                != model.inputs.iter().map(|port| &port.port.name).collect()
            || record.context.coverage
                != crate::ResultContext::coverage(&record.context.input_coverage)
        {
            return Err(Code::Invalid.error("retained managed evaluation context"));
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
        Ok((descriptor, attempt))
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
