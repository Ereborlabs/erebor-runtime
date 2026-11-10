use super::{attempts::Attempts, results::ResultBody, InstanceRecord, Records};
use crate::analysis::managed::Attempt;
use crate::analysis::native::{DataView, NativeStore};
use crate::{
    AnalysisExtractionV1, AnalysisReadControl, ManagedAttempt, ManagedInstance, ManagedPrior,
    ManagedSourceRef, PackageErrorCodeV1 as Code, Result, StorePositionV1,
};

impl DataView {
    pub(super) fn managed_prior(
        &self,
        instance: &ManagedInstance,
        call: u64,
        name: &str,
        revision: u64,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<ManagedPrior> {
        let declaration = instance
            .spec
            .manifest
            .calls
            .get(&call)
            .ok_or_else(|| Code::Invalid.error("managed prior call"))?;
        let (id, stored, attempt) =
            self.result_owner(instance.spec.tenant, name, control, &mut |bytes| {
                output.charge(bytes)
            })?;
        let ResultBody::Call(record) = stored.body else {
            return Err(Code::Invalid.error("managed prior kind"));
        };
        if stored.revision != revision
            || record.instance != instance.spec.id
            || record.call != call
            || attempt.1.spec.manifest.calls.get(&call) != Some(declaration)
            || record.context.target != declaration.target
            || record.context.artifact != declaration.artifact
        {
            return Err(Code::Invalid.error("managed prior contract"));
        }
        let descriptor =
            self.managed_contract_charged(&instance.spec, declaration, &mut |bytes| {
                output.charge(bytes)
            })?;
        let model = descriptor
            .exports
            .iter()
            .find(|model| model.name == declaration.export)
            .ok_or_else(|| Code::Missing.error("managed prior model"))?;
        let packet = self.result_checkpoint(id, &mut |bytes| output.charge(bytes))?;
        let checkpoint = ManagedPrior::decode_checkpoint(packet.as_ref(), model, output, control)?;
        let source = ManagedSourceRef {
            result: attempt
                .receipt()
                .ok_or_else(|| Code::Invalid.error("managed prior receipt"))?
                .selected
                .clone(),
            position: StorePositionV1 {
                commit_revision: attempt.captured_revision(),
                ordinal: u32::MAX,
            },
        };
        output.charge(source.result.result_id.capacity())?;
        Ok(ManagedPrior {
            revision,
            result: name.into(),
            source,
            context: record.context,
            parameters: None,
            checkpoint,
            retained: None,
        })
    }

    pub(super) fn managed_source_at(
        &self,
        instance: &ManagedInstance,
        control: &AnalysisReadControl,
    ) -> Result<Option<(ManagedSourceRef, Attempt)>> {
        if instance.progress == 0 {
            return Ok(None);
        }
        let owner = Records::find(
            &InstanceRecord::identity(instance.spec.tenant, &instance.spec.id)?,
            |key| Records::read(key, &self.snapshot),
        )?
        .ok_or_else(|| Code::Missing.error("managed source instance"))?;
        let id = Records::read(&Attempts::ended(owner, instance.progress), &self.snapshot)?
            .ok_or_else(|| Code::Missing.error("managed successful outcome"))?;
        let id = NativeStore::number(&id)?;
        let bytes = Records::payload(&Records::key(b'a', id), |key| {
            Records::read(key, &self.snapshot)
        })?
        .ok_or_else(|| Code::Missing.error("managed successful attempt"))?;
        let attempt: Attempt = Records::decode(&bytes)?;
        let receipt = attempt
            .receipt
            .as_ref()
            .filter(|receipt| {
                attempt.terminal.is_none()
                    && receipt.commit_revision == instance.progress
                    && receipt.selected.commit_revision == instance.progress
                    && attempt.capture.tenant == instance.spec.tenant
                    && attempt.capture.instance == instance.spec.id
                    && attempt.capture.generation == instance.generation
            })
            .ok_or_else(|| Code::Invalid.error("managed successful progress"))?;
        let (_, stored, saved) = self.result_owner(
            instance.spec.tenant,
            &receipt.selected.result_id,
            control,
            &mut |_| Ok(()),
        )?;
        let ResultBody::Selected(step) = stored.body else {
            return Err(Code::Invalid.error("managed source selected kind"));
        };
        if saved.0 != attempt
            || stored.revision != instance.progress
            || step.instance != instance.spec.id
            || step.attempt != attempt.request.id
        {
            return Err(Code::Invalid.error("managed source selected owner"));
        }
        let source = ManagedSourceRef {
            result: receipt.selected.clone(),
            position: StorePositionV1 {
                commit_revision: attempt.capture.revision,
                ordinal: u32::MAX,
            },
        };
        Ok(Some((source, attempt)))
    }
}

impl NativeStore {
    pub(super) fn check_captured_progress(
        &self,
        capture: &crate::analysis::managed::Capture,
    ) -> Result<()> {
        let historical = self.read_at(capture.revision)?;
        let instance = historical
            .managed_instance(
                capture.tenant,
                &capture.instance,
                &AnalysisReadControl::default(),
            )?
            .ok_or_else(|| Code::Missing.error("managed captured progress"))?;
        let owner = Records::find(
            &InstanceRecord::identity(capture.tenant, &capture.instance)?,
            |key| Records::read(key, &historical.snapshot),
        )?
        .ok_or_else(|| Code::Missing.error("managed captured instance"))?;
        if instance.generation != capture.expected_generation
            || instance.progress != capture.progress
            || historical.managed_completed(owner, capture.expected_generation)?
                != capture.completed
            || capture.progress > capture.completed
            || capture.completed > capture.revision
        {
            return Err(Code::Invalid.error("managed captured progress"));
        }
        Ok(())
    }

    pub fn managed_parent(
        &self,
        reference: &ManagedAttempt,
        control: &AnalysisReadControl,
    ) -> Result<Option<ManagedSourceRef>> {
        let capture = &reference.0.capture;
        self.check_captured_progress(capture)?;
        if capture.progress == 0
            || capture.rebuild
            || capture.generation != capture.expected_generation
        {
            return Ok(None);
        }
        let mut instance = reference.instance().clone();
        instance.generation = capture.expected_generation;
        instance.progress = capture.progress;
        let (source, parent) = self
            .view()?
            .managed_source_at(&instance, control)?
            .ok_or_else(|| Code::Missing.error("managed source parent"))?;
        if parent.capture.store != capture.store
            || parent.capture.schema != capture.schema
            || parent.capture.recovery == 0
            || parent.capture.recovery > capture.recovery
            || parent.capture.grant.selection != capture.grant.selection
            || source.result.commit_revision > capture.revision
        {
            return Err(Code::Conflict.error("managed source parent basis"));
        }
        Ok(Some(source))
    }
}
