use snafu::ResultExt as _;

use super::super::{DataWrite, NativeStore};
use super::{attempts::Attempts, InstanceRecord, Records};
use crate::analysis::managed::{Attempt, Failure, FailureOrigin};
use crate :: { AnalysisConflictSnafu , AnalysisReadControl , ManagedAttempt , ManagedExit , ManagedTerminal , NativeStateSnafu , NativeStorageSnafu , PackageErrorCodeV1 as Code , Result } ;

impl Attempts {
    pub(super) fn ended(owner: u64, revision: u64) -> Vec<u8> {
        [Records::key(b'E', owner), revision.to_be_bytes().to_vec()].concat()
    }
}

impl NativeStore {
    /// Stop and join the original execution before this call.
    /// A loaded pending attempt cannot end the original execution claim.
    pub fn finish_managed(
        &self,
        supplied: &ManagedAttempt,
        exit: ManagedExit,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedTerminal> {
        let spec = &supplied.1.spec;
        let mut tx = self.write()?;
        let (id, mut attempt) =
            Attempts::read(spec.tenant, &spec.id, &supplied.0.request.id, |key| {
                Records::staged(key, &tx.transaction)
            })?
            .ok_or_else(|| Code::Missing.error("managed terminal attempt"))?;
        if supplied.0.request != attempt.request
            || supplied.0.capture != attempt.capture
            || supplied.0.registered != attempt.registered
            || attempt.receipt.is_some()
        {
            return AnalysisConflictSnafu.fail();
        }
        if let Some(terminal) = &attempt.terminal {
            if terminal.exit != exit {
                return AnalysisConflictSnafu.fail();
            }
            check()?;
            return Ok(terminal.clone());
        }
        self.check_managed_claim(supplied)?;
        let view = self.view()?;
        if view.store_uuid != attempt.capture.store
            || view.schema_version != attempt.capture.schema
            || view.recovery_epoch != attempt.capture.recovery
            || view.managed_version(
                spec.tenant,
                &spec.id,
                attempt.capture.generation,
                &AnalysisReadControl::default(),
            )? != *spec
        {
            return AnalysisConflictSnafu.fail();
        }
        let mut instance = tx
            .managed_instance(spec.tenant, &spec.id)?
            .ok_or_else(|| Code::Missing.error("managed terminal instance"))?;
        let failure = match exit {
            ManagedExit::Failed(code)
                if instance.generation == attempt.capture.generation
                    && instance.generation == attempt.capture.expected_generation
                    && instance.running == attempt.capture.running
                    && instance.lifecycle == attempt.capture.lifecycle
                    && instance.progress == attempt.capture.progress =>
            {
                Some(Failure {
                    origin: FailureOrigin::Attempt,
                    code,
                    progress: instance.progress,
                    revision: tx.revision,
                })
            }
            _ => None,
        };
        let suspended =
            exit == ManagedExit::Failed(Code::Denied) && instance.running && failure.is_some();
        let owner = Records::find(&InstanceRecord::identity(spec.tenant, &spec.id)?, |key| {
            Records::staged(key, &tx.transaction)
        })?
        .ok_or_else(|| Code::Missing.error("managed terminal instance"))?;
        let terminal = tx.end_attempt(owner, id, &mut attempt, exit, suspended)?;
        if let Some(failure) = failure {
            Records::stage(
                &mut tx.transaction,
                Records::key(b'Y', owner),
                Records::named(&failure)?,
            );
            if suspended {
                instance.running = false;
                instance.lifecycle = tx.revision;
                tx.stage_instance(&instance)?;
            }
        }
        check()?;
        tx.commit([])?;
        Ok(terminal)
    }

    pub(in crate::analysis::native) fn recover_managed_startup(&self) -> Result<()> {
        let view = self.view()?;
        let control = AnalysisReadControl::default();
        let mut pending = Vec::new();
        for row in view.snapshot.prefix(b"\0data/p") {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "read interrupted managed attempts",
            })?;
            if key.len() != 31 {
                return NativeStateSnafu {
                    field: "managed pending key",
                }
                .fail();
            }
            let owner = Self::number(&key[7..15])?;
            let id = Self::number(&key[23..])?;
            let bytes = Records::payload(&Records::key(b'a', id), |key| {
                Records::read(key, &view.snapshot)
            })?
            .ok_or_else(|| Code::Missing.error("managed recovery attempt"))?;
            let attempt: Attempt = Records::decode(&bytes)?;
            let instance = view
                .managed_instance(attempt.capture.tenant, &attempt.capture.instance, &control)?
                .ok_or_else(|| Code::Missing.error("managed recovery instance"))?;
            if attempt.request.frontier.is_some()
                && attempt.capture.generation == instance.generation
            {
                pending.push((owner, id, attempt));
            }
        }
        if pending.is_empty() {
            return Ok(());
        }
        let mut tx = self.write_access()?;
        for (owner, id, mut attempt) in pending {
            tx.end_attempt(owner, id, &mut attempt, ManagedExit::Cancelled, false)?;
        }
        tx.commit([])?;
        Ok(())
    }
}

impl DataWrite<'_> {
    fn end_attempt(
        &mut self,
        owner: u64,
        id: u64,
        attempt: &mut Attempt,
        exit: ManagedExit,
        suspended: bool,
    ) -> Result<ManagedTerminal> {
        if attempt.receipt.is_some() || attempt.terminal.is_some() {
            return AnalysisConflictSnafu.fail();
        }
        let terminal = ManagedTerminal {
            instance: attempt.capture.instance.clone(),
            attempt: attempt.request.id.clone(),
            revision: self.revision,
            exit,
            suspended,
        };
        attempt.terminal = Some(terminal.clone());
        Records::stage(
            &mut self.transaction,
            Records::key(b'a', id),
            Records::named(attempt)?,
        );
        let pending = [
            Attempts::pending(owner, attempt.capture.generation),
            id.to_be_bytes().to_vec(),
        ]
        .concat();
        self.transaction.remove(pending);
        self.transaction.insert(
            Attempts::outcome(owner, attempt.capture.generation),
            [self.revision.to_be_bytes(), id.to_be_bytes()].concat(),
        );
        self.transaction
            .insert(Attempts::ended(owner, self.revision), id.to_be_bytes());
        self.dirty = true;
        Ok(terminal)
    }
}
