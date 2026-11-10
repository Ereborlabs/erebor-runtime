use std::collections::BTreeMap;

use snafu::ResultExt as _;

use super::super::{DataView, DataWrite, NativeStore};
use super::{InstanceRecord, Records};
use crate::analysis::managed::{Attempt, Capture, ManagedAttempt};
use crate::{
    AnalysisConflictSnafu, AnalysisReadControl, ManagedCapture, ManagedInstance, ManagedRequest,
    NativeStateSnafu, NativeStorageSnafu, PackageErrorCodeV1 as Code, Result,
};

pub(super) struct Attempts;

impl Attempts {
    pub(super) fn identity(tenant: [u8; 16], instance: &str, id: &str) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(b'a', tenant, instance, id)).context(crate::ManagedEncodingSnafu)
    }

    pub(super) fn pending(owner: u64, generation: u64) -> Vec<u8> {
        [Records::key(b'p', owner), generation.to_be_bytes().to_vec()].concat()
    }

    pub(super) fn outcome(owner: u64, generation: u64) -> Vec<u8> {
        [Records::key(b'o', owner), generation.to_be_bytes().to_vec()].concat()
    }

    pub(super) fn read(
        tenant: [u8; 16],
        instance: &str,
        name: &str,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<Option<(u64, Attempt)>> {
        Self::read_charged(tenant, instance, name, get, &mut |_| Ok(()))
    }

    fn read_charged(
        tenant: [u8; 16],
        instance: &str,
        name: &str,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<(u64, Attempt)>> {
        let Some(id) = Records::find(&Self::identity(tenant, instance, name)?, &mut get)? else {
            return Ok(None);
        };
        let Some(bytes) = Records::charged_payload(&Records::key(b'a', id), &mut get, charge)?
        else {
            return Ok(None);
        };
        let attempt: Attempt = Records::decode(&bytes)?;
        if attempt.capture.tenant != tenant
            || attempt.capture.instance != instance
            || attempt.request.id != name
        {
            return Err(Code::Invalid.error("managed attempt key"));
        }
        Ok(Some((id, attempt)))
    }

    pub(super) fn validate_request(request: &ManagedRequest) -> Result<()> {
        if request.id.is_empty()
            || request.id.chars().any(char::is_control)
            || request.time_utc_ns == 0
            || i64::try_from(request.time_utc_ns).is_err()
            || request
                .frontier
                .as_ref()
                .is_some_and(|frontier| frontier.cursor.is_empty() || frontier.pending)
        {
            return Err(Code::Invalid.error("managed attempt request"));
        }
        Ok(())
    }
}

impl DataView {
    pub(super) fn managed_completed(&self, owner: u64, generation: u64) -> Result<u64> {
        let Some(bytes) = Records::read(&Attempts::outcome(owner, generation), &self.snapshot)?
        else {
            return Ok(0);
        };
        if bytes.len() != 16 {
            return NativeStateSnafu {
                field: "managed outcome head",
            }
            .fail();
        }
        NativeStore::number(&bytes[..8])
    }

    pub fn managed_attempt(
        &self,
        tenant: [u8; 16],
        instance: &str,
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<Option<ManagedAttempt>> {
        self.managed_attempt_charged(tenant, instance, id, control, &mut |_| Ok(()))
    }

    pub(super) fn managed_attempt_charged(
        &self,
        tenant: [u8; 16],
        instance: &str,
        id: &str,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<ManagedAttempt>> {
        control.check()?;
        let Some((_, attempt)) = Attempts::read_charged(
            tenant,
            instance,
            id,
            |key| Records::read(key, &self.snapshot),
            charge,
        )?
        else {
            return Ok(None);
        };
        let owner = Records::find(&InstanceRecord::identity(tenant, instance)?, |key| {
            Records::read(key, &self.snapshot)
        })?
        .ok_or_else(|| Code::Missing.error("managed version"))?;
        let instance = ManagedInstance {
            spec: super::VersionRecord::read_charged(
                owner,
                tenant,
                instance,
                attempt.capture.generation,
                self.metadata_revision,
                |key| Records::read(key, &self.snapshot),
                charge,
            )?
            .spec,
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
            BTreeMap::new(),
            None,
            None,
        )))
    }
}

impl NativeStore {
    pub fn managed_attempt(
        &self,
        tenant: [u8; 16],
        instance: &str,
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<Option<ManagedAttempt>> {
        self.view()?.managed_attempt(tenant, instance, id, control)
    }

    pub(super) fn check_managed_claim(&self, attempt: &ManagedAttempt) -> Result<()> {
        let claim = attempt
            .2
            .as_ref()
            .ok_or_else(|| Code::Incomplete.error("managed pending attempt capture"))?;
        if !claim.same_channel(&self.revision.subscribe()) {
            return AnalysisConflictSnafu.fail();
        }
        Ok(())
    }

    pub fn register_managed_attempt(
        &self,
        captured: &ManagedCapture,
        request: &ManagedRequest,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedAttempt> {
        Attempts::validate_request(request)?;
        let capture = captured.request_capture(request)?;
        let spec = &captured.instance.spec;
        let mut tx = self.write()?;
        if let Some((_, saved)) = Attempts::read(spec.tenant, &spec.id, &request.id, |key| {
            Records::staged(key, &tx.transaction)
        })? {
            if saved.capture != capture || saved.request != *request {
                return AnalysisConflictSnafu.fail();
            }
            if saved.receipt.is_none() && saved.terminal.is_none() {
                return Err(Code::Incomplete.error("managed pending attempt"));
            }
            check()?;
            return Ok(ManagedAttempt(
                saved,
                captured.instance.clone(),
                None,
                BTreeMap::new(),
                None,
                None,
            ));
        }
        let owner = Records::find(&InstanceRecord::identity(spec.tenant, &spec.id)?, |key| {
            Records::staged(key, &tx.transaction)
        })?
        .ok_or_else(|| Code::Missing.error("managed capture instance"))?;
        if request.frontier.is_some() {
            tx.check_pending(owner, capture.expected_generation)?;
        }
        tx.check_capture(&capture, request.time_utc_ns)?;
        self.resolve_witnesses(&capture.witnesses, capture.revision)?;
        let attempt = Attempt {
            request: request.clone(),
            capture,
            registered: tx.revision,
            receipt: None,
            terminal: None,
        };
        let id = Records::intern(
            &mut tx.transaction,
            &Attempts::identity(spec.tenant, &spec.id, &request.id)?,
        )?;
        Records::stage(
            &mut tx.transaction,
            Records::key(b'a', id),
            Records::named(&attempt)?,
        );
        let pending = [
            Attempts::pending(owner, attempt.capture.generation),
            id.to_be_bytes().to_vec(),
        ]
        .concat();
        tx.transaction
            .insert(pending, attempt.registered.to_be_bytes());
        tx.dirty = true;
        check()?;
        tx.commit([])?;
        Ok(ManagedAttempt(
            attempt,
            captured.instance.clone(),
            Some(self.revision.subscribe()),
            captured.prior.clone(),
            captured.execution.clone(),
            captured.source.clone(),
        ))
    }

    pub(super) fn resolve_witnesses(
        &self,
        witnesses: &[crate::AnalysisWitnessV1],
        revision: u64,
    ) -> Result<Vec<u64>> {
        let mut segments = Vec::with_capacity(witnesses.len());
        let mut cached = Vec::<crate::AnalysisRecordV1>::new();
        let mut source = None;
        let mut segment = 0;
        for witness in witnesses {
            if source != Some(&witness.identity)
                || cached
                    .first()
                    .is_none_or(|record| witness.cursor < record.cursor)
                || cached
                    .last()
                    .is_none_or(|record| witness.cursor > record.cursor)
            {
                let ranges = self
                    .raw
                    .lock()
                    .map_err(|_| {
                        NativeStateSnafu {
                            field: "raw owner lock",
                        }
                        .build()
                    })?
                    .select_ranges(
                        &witness.identity,
                        witness.cursor,
                        witness.cursor,
                        revision,
                        None,
                        2,
                    )?;
                if ranges.len() != 1 {
                    return crate::AnalysisStore::reject_path(
                        &self.root,
                        "the result witness is not retained exactly once",
                    );
                }
                cached = ranges[0].read(&self.root)?.0;
                segment = ranges[0].segment_id;
                source = Some(&witness.identity);
            }
            cached
                .binary_search_by_key(&witness.cursor, |record| record.cursor)
                .map_err(|_| {
                    NativeStateSnafu {
                        field: "result witness is not retained",
                    }
                    .build()
                })?;
            segments.push(segment);
        }
        Ok(segments)
    }
}

impl DataWrite<'_> {
    pub(super) fn check_pending(&self, owner: u64, generation: u64) -> Result<()> {
        if self
            .transaction
            .prefix(Attempts::pending(owner, generation))
            .next()
            .transpose()
            .context(NativeStorageSnafu {
                operation: "read managed pending attempts",
            })?
            .is_some()
        {
            return Err(Code::Incomplete.error("managed pending attempt"));
        }
        Ok(())
    }

    pub(super) fn check_capture(&mut self, capture: &Capture, now: u64) -> Result<()> {
        let current = self
            .managed_instance(capture.tenant, &capture.instance)?
            .ok_or_else(|| Code::Missing.error("managed capture instance"))?;
        let view = self.store.view()?;
        let spec = view.managed_version(
            capture.tenant,
            &capture.instance,
            capture.generation,
            &AnalysisReadControl::default(),
        )?;
        capture.check_follow_mode(&spec)?;
        let owner = Records::find(
            &InstanceRecord::identity(capture.tenant, &capture.instance)?,
            |key| Records::staged(key, &self.transaction),
        )?
        .ok_or_else(|| Code::Missing.error("managed capture instance"))?;
        let completed = self
            .transaction
            .get(Attempts::outcome(owner, capture.expected_generation))
            .context(NativeStorageSnafu {
                operation: "read managed completed outcome",
            })?
            .map(|bytes| NativeStore::number(bytes.get(..8).unwrap_or_default()))
            .transpose()?
            .unwrap_or(0);
        capture.check_native_owner(&current, &spec, &view.meta(), completed)?;
        capture.check_native_heads(&current, &spec, owner, |key| {
            Records::staged(key, &self.transaction)
        })?;
        let control = AnalysisReadControl::default();
        if !capture.follow && !self.sources_current(&capture.sources, &control)? {
            return crate::AnalysisSourceChangedSnafu.fail();
        }
        if !capture.traces.is_empty() || !capture.dependencies.is_empty() {
            return Err(Code::Unsupported.error("native managed dependency owner"));
        }
        for reference in &capture.contexts {
            if !self.check_context_ref(reference)? {
                return AnalysisConflictSnafu.fail();
            }
        }
        if capture.witnesses.iter().any(|witness| {
            witness.identity.tenant() != capture.tenant
                || witness.cursor == 0
                || witness.expires_utc_ns <= now
        }) {
            return Err(Code::Incomplete.error("managed witness lifetime"));
        }
        Ok(())
    }
}
