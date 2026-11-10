use std::collections::BTreeSet;

use super::{results::ResultBody, results::StoredResult, CallHead, InstanceRecord, Records};
use crate::analysis::native::{DataView, NativeStore};
use crate :: { AnalysisReadControl , InstanceResultKindV1 , InstanceResultV1 , ManagedAttempt , ManagedInstance , ManagedSpec , PackageErrorCodeV1 as Code , Result } ;

impl NativeStore {
    pub fn managed_changes(
        &self,
        reference: &ManagedAttempt,
        call: u64,
        control: &AnalysisReadControl,
    ) -> Result<Option<crate::ManagedChanges>> {
        let instance = reference.instance();
        let receipt = reference
            .receipt()
            .ok_or_else(|| Code::Invalid.error("managed change receipt"))?;
        let result = receipt
            .results
            .get(&call)
            .ok_or_else(|| Code::Missing.error("managed change call"))?;
        if reference.terminal().is_some()
            || result.commit_revision != receipt.commit_revision
            || receipt.selected.commit_revision != receipt.commit_revision
        {
            return Err(Code::Conflict.error("managed change publication"));
        }
        let view = self.view()?;
        let (id, stored, owner) = view.result_owner(
            instance.spec.tenant,
            &result.result_id,
            control,
            &mut |_| control.check(),
        )?;
        let ResultBody::Call(record) = stored.body else {
            return Err(Code::Invalid.error("managed change call kind"));
        };
        if stored.revision != result.commit_revision
            || record.call != call
            || record.instance != instance.spec.id
            || record.attempt != reference.request().id
        {
            return Err(Code::Conflict.error("managed change reference"));
        }
        if owner.0 != reference.0 || owner.instance().spec != instance.spec {
            return Err(Code::Conflict.error("managed change owner"));
        }
        view.check_dependencies(id, instance.spec.tenant, &record.dependencies, control)?;
        owner
            .0
            .capture
            .grant
            .permitted_by(&instance.grant.selection)?;
        control.check()?;
        Ok(record
            .changes
            .map(|changes| crate::ManagedChanges { base: changes.base }))
    }

    pub fn managed_reference(
        &self,
        instance: &ManagedInstance,
        id: &str,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<(ManagedAttempt, Option<u64>, bool)> {
        self.managed_reference_at(self.view()?.as_ref(), instance, id, now, control)
    }

    pub fn managed_reference_at(
        &self,
        view: &DataView,
        instance: &ManagedInstance,
        id: &str,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<(ManagedAttempt, Option<u64>, bool)> {
        let (stored, attempt, current) =
            self.resolve_managed_result(view, instance, id, now, control)?;
        let call = match stored.body {
            ResultBody::Call(record) => Some(record.call),
            ResultBody::Selected(_) => None,
        };
        Ok((attempt, call, current))
    }

    pub fn managed_result(
        &self,
        instance: &ManagedInstance,
        id: &str,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<InstanceResultV1> {
        self.managed_result_at(self.view()?.as_ref(), instance, id, now, control)
    }

    pub fn managed_result_at(
        &self,
        view: &DataView,
        instance: &ManagedInstance,
        id: &str,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<InstanceResultV1> {
        let (stored, reference, current) =
            self.resolve_managed_result(view, instance, id, now, control)?;
        let captured = &reference.0.capture;
        let receipt = reference
            .receipt()
            .cloned()
            .ok_or_else(|| Code::Invalid.error("managed result receipt"))?;
        let (result, kind) = match stored.body {
            ResultBody::Call(record) => {
                let result = receipt
                    .results
                    .get(&record.call)
                    .cloned()
                    .ok_or_else(|| Code::Invalid.error("managed result reference"))?;
                let declaration = &reference.1.spec.manifest.calls[&record.call];
                (
                    result,
                    InstanceResultKindV1::Call {
                        call: record.call,
                        image: declaration.image.clone(),
                        package: declaration.package.clone(),
                        export: declaration.export.clone(),
                        context: record.context,
                    },
                )
            }
            ResultBody::Selected(_) => (receipt.selected.clone(), InstanceResultKindV1::Selected),
        };
        reference.instance().spec.definition.validate()?;
        if reference.instance().spec.manifest.definition == 0 {
            return Err(Code::Invalid.error("definition revision"));
        }
        Ok(InstanceResultV1 {
            instance_id: instance.spec.id.clone(),
            result,
            definition_revision: reference.instance().spec.manifest.definition.to_string(),
            generation: captured.generation,
            source: reference.source_meta(),
            time_utc_ns: captured.time_utc_ns,
            prior: captured.prior.clone(),
            receipt,
            current,
            kind,
        })
    }

    fn resolve_managed_result(
        &self,
        view: &DataView,
        instance: &ManagedInstance,
        name: &str,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<(StoredResult, ManagedAttempt, bool)> {
        control.check()?;
        if view.store_uuid != self.view()?.store_uuid {
            return Err(Code::Conflict.error("managed result store"));
        }
        let (_, stored) = StoredResult::load(
            instance.spec.tenant,
            name,
            |key| Records::read(key, &view.snapshot),
            &mut |_| control.check(),
        )?
        .ok_or_else(|| Code::Missing.error("managed result"))?;
        if view.managed_version(
            instance.spec.tenant,
            &instance.spec.id,
            instance.generation,
            control,
        )? != instance.spec
            || stored.owner().0 != instance.spec.id
        {
            return Err(Code::Denied.error("managed result scope"));
        }
        let attempt = view
            .managed_attempt(
                instance.spec.tenant,
                &instance.spec.id,
                stored.owner().1,
                control,
            )?
            .ok_or_else(|| Code::Missing.error("managed result attempt"))?;
        attempt
            .0
            .capture
            .grant
            .permitted_by(&instance.grant.selection)?;
        stored.check_identity(instance.spec.tenant, name, view.metadata_revision)?;
        stored.check(&attempt.0, &attempt.1.spec)?;
        self.check_captured_progress(&attempt.0.capture)?;
        let current = match &stored.body {
            ResultBody::Call(_) => {
                view.managed_current(&instance.spec, &stored, &attempt, now, control)?
            }
            ResultBody::Selected(_) => view
                .managed_instance(instance.spec.tenant, &instance.spec.id, control)?
                .is_some_and(|saved| saved.progress == stored.revision),
        };
        control.check()?;
        Ok((stored, attempt, current))
    }
}

impl DataView {
    fn managed_current(
        &self,
        spec: &ManagedSpec,
        root: &StoredResult,
        attempt: &ManagedAttempt,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<bool> {
        let mut needed = Vec::new();
        let mut seen = BTreeSet::from([(root.id.clone(), root.revision)]);
        if !self.result_current(spec, root, attempt, now, control, &mut needed)? {
            return Ok(false);
        }
        while let Some((name, revision)) = needed.pop() {
            control.check()?;
            if !seen.insert((name.clone(), revision)) {
                continue;
            }
            let Some((_, stored)) = StoredResult::read(
                spec.tenant,
                &name,
                self.metadata_revision,
                |key| Records::read(key, &self.snapshot),
                &mut |_| control.check(),
            )?
            else {
                return Ok(false);
            };
            if stored.revision != revision || stored.owner().0 != spec.id {
                return Ok(false);
            }
            let attempt = self
                .managed_attempt(spec.tenant, &spec.id, stored.owner().1, control)?
                .ok_or_else(|| Code::Missing.error("managed result attempt"))?;
            stored.check(&attempt.0, &attempt.1.spec)?;
            if !self.result_current(spec, &stored, &attempt, now, control, &mut needed)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn result_current(
        &self,
        spec: &ManagedSpec,
        stored: &StoredResult,
        attempt: &ManagedAttempt,
        now: u64,
        control: &AnalysisReadControl,
        needed: &mut Vec<(String, u64)>,
    ) -> Result<bool> {
        let (dependencies, witnesses, contexts) = match &stored.body {
            ResultBody::Call(record) => {
                let owner =
                    Records::find(&InstanceRecord::identity(spec.tenant, &spec.id)?, |key| {
                        Records::read(key, &self.snapshot)
                    })?
                    .ok_or_else(|| Code::Missing.error("managed current instance"))?;
                let head =
                    Records::payload(&InstanceRecord::call_key(owner, record.call), |key| {
                        Records::read(key, &self.snapshot)
                    })?
                    .map(|bytes| Records::decode::<CallHead>(&bytes))
                    .transpose()?;
                if head.is_none_or(|head| {
                    head.revision != stored.revision
                        || head.result.as_deref() != Some(stored.id.as_str())
                }) {
                    return Ok(false);
                }
                (
                    &record.dependencies,
                    &record.witnesses,
                    crate::AnalysisContextRefV1::join(&record.contexts, &record.derived)?,
                )
            }
            ResultBody::Selected(step) => {
                if self
                    .managed_instance(spec.tenant, &step.instance, control)?
                    .is_none_or(|current| current.progress != stored.revision)
                {
                    return Ok(false);
                }
                (
                    &step.dependencies,
                    &step.witnesses,
                    crate::AnalysisContextRefV1::join(&step.contexts, &step.derived)?,
                )
            }
        };
        if attempt
            .0
            .request
            .frontier
            .as_ref()
            .and_then(|frontier| frontier.next_change)
            .is_some_and(|deadline| deadline <= now)
            || !self.sources_current(&attempt.0.capture.sources, control)?
            || witnesses
                .iter()
                .any(|witness| witness.expires_utc_ns <= now)
        {
            return Ok(false);
        }
        self.check_trace_reads(attempt.0.capture.tenant, &attempt.0.capture.traces, control)?;
        for reference in &contexts {
            control.check()?;
            if self
                .context(&reference.key)?
                .is_none_or(|(_, saved)| saved != reference.commit_revision)
            {
                return Ok(false);
            }
        }
        needed.extend(
            dependencies
                .iter()
                .map(|reference| (reference.result_id.clone(), reference.commit_revision)),
        );
        Ok(true)
    }
}
