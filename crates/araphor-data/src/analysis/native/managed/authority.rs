use super::{attempts::Attempts, CallHead, InstanceRecord, Records};
use crate::analysis::managed::Capture;
use crate::analysis::native::{DataView, NativeStore};
use crate::{
    AnalysisConflictSnafu, AnalysisReadControl, AnalysisStoreMetaV1, ManagedAttempt,
    ManagedInstance, ManagedSpec, PackageErrorCodeV1 as Code, Result,
};

impl Capture {
    pub(super) fn check_native_owner(
        &self,
        current: &ManagedInstance,
        spec: &ManagedSpec,
        meta: &AnalysisStoreMetaV1,
        completed: u64,
    ) -> Result<()> {
        self.check_follow_mode(spec)?;
        if meta.store_uuid != self.store
            || meta.schema_version != self.schema
            || meta.recovery_epoch != self.recovery
            || meta.commit_revision < self.revision
            || self
                .sources
                .iter()
                .any(|(_, revision)| *revision > self.revision)
            || current.generation != self.expected_generation
            || current.grant != self.grant
            || current.lifecycle != self.lifecycle
            || current.running != self.running
            || current.progress != self.progress
            || completed != self.completed
            || self.prior.keys().ne(spec.manifest.calls.keys())
        {
            return AnalysisConflictSnafu.fail();
        }
        Ok(())
    }

    pub(super) fn check_native_heads(
        &self,
        current: &ManagedInstance,
        spec: &ManagedSpec,
        owner: u64,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<()> {
        for (call, prior) in &self.prior {
            if !spec.same_call(&current.spec, *call) {
                if prior.is_some() {
                    return AnalysisConflictSnafu.fail();
                }
                continue;
            }
            let bytes = Records::payload(&InstanceRecord::call_key(owner, *call), |key| get(key))?
                .ok_or_else(|| Code::Missing.error("managed call head"))?;
            let head: CallHead = Records::decode(&bytes)?;
            if prior
                .as_ref()
                .map(|prior| (prior.commit_revision, Some(prior.result_id.as_str())))
                .unwrap_or((0, None))
                != (head.revision, head.result.as_deref())
            {
                return AnalysisConflictSnafu.fail();
            }
        }
        Ok(())
    }
}

impl NativeStore {
    pub(super) fn live_attempt(
        &self,
        supplied: &ManagedAttempt,
        control: &AnalysisReadControl,
    ) -> Result<std::sync::Arc<DataView>> {
        self.check_managed_claim(supplied)?;
        supplied.1.grant.remaining()?;
        let view = self.view()?;
        let spec = &supplied.1.spec;
        let (_, saved) = Attempts::read(spec.tenant, &spec.id, &supplied.0.request.id, |key| {
            Records::read(key, &view.snapshot)
        })?
        .ok_or_else(|| Code::Missing.error("managed live attempt"))?;
        if saved != supplied.0
            || saved.receipt.is_some()
            || saved.terminal.is_some()
            || view.managed_version(spec.tenant, &spec.id, saved.capture.generation, control)?
                != *spec
        {
            return AnalysisConflictSnafu.fail();
        }
        let current = view
            .managed_instance(spec.tenant, &spec.id, control)?
            .ok_or_else(|| Code::Missing.error("managed live instance"))?;
        let capture = &saved.capture;
        let instance = Records::find(&InstanceRecord::identity(spec.tenant, &spec.id)?, |key| {
            Records::read(key, &view.snapshot)
        })?
        .ok_or_else(|| Code::Missing.error("managed live instance"))?;
        let completed = view.managed_completed(instance, capture.expected_generation)?;
        capture.check_native_owner(&current, spec, &view.meta(), completed)?;
        capture.check_native_heads(&current, spec, instance, |key| {
            Records::read(key, &view.snapshot)
        })?;
        if !capture.follow && !view.sources_current(&capture.sources, control)? {
            return crate::AnalysisSourceChangedSnafu.fail();
        }
        if !capture.traces.is_empty() || !capture.dependencies.is_empty() {
            return Err(Code::Unsupported.error("native managed dependency owner"));
        }
        for reference in &capture.contexts {
            control.check()?;
            if view
                .context(&reference.key)?
                .is_none_or(|(_, revision)| revision != reference.commit_revision)
            {
                return AnalysisConflictSnafu.fail();
            }
        }
        if capture.witnesses.iter().any(|witness| {
            witness.identity.tenant() != spec.tenant
                || witness.cursor == 0
                || witness.expires_utc_ns <= supplied.request().time_utc_ns
        }) {
            return Err(Code::Incomplete.error("managed witness lifetime"));
        }
        control.check()?;
        Ok(view)
    }
}
