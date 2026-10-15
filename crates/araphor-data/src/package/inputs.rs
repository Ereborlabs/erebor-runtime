use araphor_analysis_sdk as sdk;

use crate::analysis::{PackageActivationV1, PackageResultRefV1};
use crate::{
    AnalysisContextRefV1, AnalysisReadControl, AnalysisWitnessV1, QuerySql, Result, SqlModelInputV1,
};

use super::admission::ModelRef;
use super::evaluation::ResultContext;
use super::owner::InstalledContext;
use super::{
    AnalysisPackageOwner, PackageArtifactV1, PackageErrorCodeV1 as Code, PackageOutputV1,
    PackageRefV1,
};

pub(super) struct ModelInputs {
    pub inputs: Vec<sdk::Input>,
    pub dependencies: Vec<PackageResultRefV1>,
    pub source_revisions: Vec<(String, u64)>,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub contexts: Vec<AnalysisContextRefV1>,
    pub _sources: Vec<SqlModelInputV1>,
}

pub(super) struct InputRequest<'a> {
    pub activation: &'a PackageActivationV1,
    pub artifact: &'a PackageArtifactV1,
    pub model: &'a sdk::Model,
    pub context: &'a InstalledContext,
    pub now: u64,
    pub action: super::PackageActionV1,
}

impl AnalysisPackageOwner {
    pub(super) fn inputs(
        &self,
        request: InputRequest<'_>,
        control: &AnalysisReadControl,
    ) -> Result<ModelInputs> {
        self.inputs_with_sql(request, control, None)
    }

    pub(super) fn inputs_with_sql(
        &self,
        request: InputRequest<'_>,
        control: &AnalysisReadControl,
        mut operation: Option<&mut crate::query::SqlOperation<'_>>,
    ) -> Result<ModelInputs> {
        let InputRequest {
            activation,
            artifact,
            model,
            context,
            now,
            action,
        } = request;
        let sources = artifact
            .implementation(&model.name)?
            .bindings()
            .ok_or_else(|| Code::Missing.error("host-prepared inputs"))?;
        let mut selected = ModelInputs {
            inputs: Vec::new(),
            dependencies: Vec::new(),
            source_revisions: Vec::new(),
            witnesses: Vec::new(),
            contexts: Vec::new(),
            _sources: Vec::new(),
        };
        for port in &model.inputs {
            control.check()?;
            self.check(&context.grant, action)?;
            if let Some(sql) = sources.get(&port.name) {
                let request = crate::SqlModelInputRequestV1 {
                    selection: context.grant.selection.clone(),
                    sql: QuerySql::admit(sql, Vec::new(), false)?,
                    port,
                    limits: model.limits,
                    now_ns: now,
                };
                let mut input = match operation.as_deref_mut() {
                    Some(operation) => operation.model_input(request, control)?,
                    None => self.query.model_input(request, control)?,
                };
                for witness in &mut input.witnesses {
                    if witness.expires_utc_ns == 0 {
                        witness.expires_utc_ns =
                            now.saturating_add(7 * 24 * 60 * 60 * 1_000_000_000);
                    }
                }
                selected.dependencies.extend(
                    self.store
                        .package_result_refs(activation.key.tenant_id, &input.result_ids)?,
                );
                let (witnesses, contexts) = self
                    .store
                    .package_evidence(activation.key.tenant_id, &input.result_ids)?;
                selected.witnesses.extend(witnesses);
                selected.contexts.extend(contexts);
                selected.witnesses.extend(input.witnesses.iter().cloned());
                selected.contexts.extend(input.contexts.iter().cloned());
                selected.inputs.push(input.input.clone());
                selected
                    .source_revisions
                    .extend(input.source_revisions.iter().cloned());
                selected._sources.push(input);
            } else {
                let dependency = artifact
                    .descriptor
                    .dependencies
                    .iter()
                    .find(|dependency| {
                        dependency.model == model.name && dependency.input == port.name
                    })
                    .ok_or_else(|| Code::Incomplete.error("input binding"))?;
                self.dependency(
                    activation,
                    context,
                    dependency,
                    port,
                    model.limits,
                    &mut selected,
                )?;
            }
            selected.check(model.limits)?;
        }
        selected
            .dependencies
            .sort_by(|left, right| left.result_id.cmp(&right.result_id));
        selected.dependencies.dedup();
        selected.source_revisions.sort();
        selected
            .source_revisions
            .dedup_by(|right, left| right.0 == left.0);
        Self::normalize_refs(&mut selected);
        if selected
            .witnesses
            .iter()
            .any(|witness| witness.expires_utc_ns <= now)
        {
            for input in &mut selected.inputs {
                input.coverage.state = sdk::CoverageState::Unknown;
                input
                    .coverage
                    .limits
                    .push("source evidence retention expired".into());
            }
            selected
                .witnesses
                .retain(|witness| witness.expires_utc_ns > now);
        }
        Ok(selected)
    }

    fn dependency(
        &self,
        activation: &PackageActivationV1,
        context: &InstalledContext,
        dependency: &sdk::Dependency,
        port: &sdk::Port,
        limits: sdk::Limits,
        selected: &mut ModelInputs,
    ) -> Result<()> {
        let model = ModelRef {
            package: PackageRefV1 {
                package_id: dependency.package.clone(),
                revision: dependency.revision.clone(),
            },
            export: dependency.export.clone(),
        };
        let key = Self::key(&context.grant, &activation.key.scope_id, &model);
        let active = self
            .store
            .package_activation(&key)?
            .filter(|active| active.active && active.revision == dependency.revision)
            .ok_or_else(|| Code::Incomplete.error("dependency activation"))?;
        let id = active
            .result_id
            .ok_or_else(|| Code::Incomplete.error("dependency result"))?;
        let result = self
            .store
            .package_result(key.tenant_id, &id)?
            .filter(|result| !result.stale && result.revision == dependency.revision)
            .ok_or_else(|| Code::Incomplete.error("dependency freshness"))?;
        let installed: InstalledContext = Self::decode(&result.activation.metadata)?;
        Self::permits(&context.grant, &installed.grant)?;
        let packet: PackageOutputV1 = Self::decode(&result.datasets)?;
        let dataset = packet
            .datasets
            .iter()
            .find(|dataset| dataset.name == dependency.output)
            .ok_or_else(|| Code::Invalid.error("dependency dataset"))?;
        let mut data = dataset.decode(&port.schema, limits)?;
        data.name = port.name.clone();
        let metadata: ResultContext = Self::decode(&result.metadata)?;
        selected.inputs.push(sdk::Input {
            data,
            revision: sdk::Revision {
                owner: format!("{}.{}", dependency.package, dependency.export),
                id: format!("{}:{}", result.result_id, result.commit_revision),
                window: None,
            },
            coverage: metadata.coverage,
        });
        selected.dependencies.push(PackageResultRefV1 {
            result_id: result.result_id.clone(),
            commit_revision: result.commit_revision,
        });
        let (witnesses, contexts) = self
            .store
            .package_evidence(key.tenant_id, &[result.result_id])?;
        selected.witnesses.extend(witnesses);
        selected.contexts.extend(contexts);
        Ok(())
    }

    fn normalize_refs(inputs: &mut ModelInputs) {
        inputs.witnesses.sort_by(|left, right| {
            left.identity
                .cmp(&right.identity)
                .then(left.cursor.cmp(&right.cursor))
                .then(left.expires_utc_ns.cmp(&right.expires_utc_ns))
        });
        inputs
            .witnesses
            .dedup_by(|right, left| right.identity == left.identity && right.cursor == left.cursor);
        inputs.contexts.sort_by(|left, right| {
            left.key
                .cmp(&right.key)
                .then(left.commit_revision.cmp(&right.commit_revision))
        });
        inputs.contexts.dedup();
    }
}

impl ModelInputs {
    fn check(&self, limits: sdk::Limits) -> Result<()> {
        let batches = self.inputs.iter().flat_map(|input| &input.data.batches);
        let (mut rows, mut bytes, mut count) = (0_u64, 0_u64, 0_u64);
        for batch in batches {
            rows = rows.saturating_add(batch.num_rows() as u64);
            bytes = bytes.saturating_add(batch.get_array_memory_size() as u64);
            count += 1;
        }
        if rows > limits.max_rows
            || bytes > limits.max_bytes.min(64 * 1024 * 1024)
            || count > u64::from(limits.max_batches)
            || self.witnesses.len() > 8192
            || self.contexts.len() > 256
            || self.dependencies.len() > 64
        {
            return Err(Code::Limit.error("selected model inputs"));
        }
        Ok(())
    }
}
