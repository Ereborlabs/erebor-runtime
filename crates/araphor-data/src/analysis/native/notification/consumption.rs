use std::{collections::BTreeSet, sync::Arc};

use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::super::{inputs::InputRecord, records::Records, DataView, DataWrite, NativeStore};
use crate::analysis::inputs::{InputCapture, InputCut};
use crate::{
    AnalysisContextRefV1, AnalysisExtractLimits, AnalysisPositionPageV1, AnalysisReadControl,
    AnalysisSelectionV1, AnalysisTableRead, InputSubscription, ManagedDestination, ManagedInstance,
    NativeStorageSnafu, PackageErrorCodeV1 as Code, Result, NOTIFICATION_STATE_OWNER,
};

pub struct NotificationCapture {
    view: Arc<DataView>,
    instance: ManagedInstance,
    input: InputCapture,
}

impl NotificationCapture {
    pub fn metadata_bytes(&self) -> usize {
        self.instance
            .allocation_bytes()
            .unwrap_or(usize::MAX)
            .saturating_add(std::mem::size_of::<Self>())
    }
}

#[derive(Deserialize, PartialEq, Serialize)]
pub(in crate::analysis::native) struct NotificationCompletion {
    input: InputCapture,
    lifecycle: u64,
    revision: u64,
    contexts: Vec<AnalysisContextRefV1>,
}

impl NativeStore {
    pub fn read_notification_subscribed(
        &self,
        inputs: &InputSubscription,
        selection: &AnalysisSelectionV1,
        instance: &ManagedInstance,
        read: AnalysisTableRead<'_>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        owners: Option<&BTreeSet<String>>,
    ) -> Result<(AnalysisPositionPageV1, NotificationCapture)> {
        if instance.spec.destination != ManagedDestination::Notification {
            return Err(Code::Invalid.error("notification consumer destination"));
        }
        instance.grant.remaining()?;
        let view = self.view()?;
        if !instance.running || instance.removed {
            return Err(Code::Conflict.error("notification consumer lifecycle"));
        }
        read.check_scope(selection, &instance.grant.selection)?;
        let (mut page, current) = self.read_tables_with(
            &view,
            selection,
            &instance.grant.selection,
            read,
            limits,
            control,
            owners,
            None,
            Some(instance),
            |output| {
                output.charge(
                    instance
                        .allocation_bytes()
                        .and_then(|bytes| bytes.checked_mul(2))
                        .and_then(|bytes| {
                            bytes.checked_add(std::mem::size_of::<NotificationCapture>())
                        })
                        .ok_or_else(|| Code::Limit.error("notification capture memory"))?,
                )?;
                view.managed_instance(instance.spec.tenant, &instance.spec.id, control)?
                    .filter(|current| current == instance)
                    .ok_or_else(|| Code::Conflict.error("notification consumer lifecycle"))
            },
        )?;
        let input = inputs
            .capture_notification(self, &view, instance, selection, &read, &mut page, owners)?;
        Ok((
            page,
            NotificationCapture {
                view,
                instance: current,
                input,
            },
        ))
    }
}

impl DataWrite<'_> {
    pub fn commit_notifications(
        mut self,
        capture: &NotificationCapture,
        references: &[AnalysisContextRefV1],
    ) -> Result<(u64, bool)> {
        let instance = &capture.instance;
        let current = self.store.view()?;
        if capture.view.store_uuid != current.store_uuid
            || capture.view.schema_version != current.schema_version
            || capture.view.recovery_epoch != current.recovery_epoch
            || InputCut::capture(&capture.view)? != capture.input.cut
            || instance.spec.destination != ManagedDestination::Notification
            || !instance.running
            || instance.removed
            || self
                .managed_instance(instance.spec.tenant, &instance.spec.id)?
                .as_ref()
                != Some(instance)
        {
            return Err(Code::Conflict.error("notification completion capture"));
        }
        instance.grant.remaining()?;
        let record =
            current.check_consumer(&capture.input, instance.spec.tenant, &instance.spec.id)?;
        for reference in references {
            if reference.key.tenant_id != instance.spec.tenant
                || reference.key.owner_id != NOTIFICATION_STATE_OWNER
                || reference.commit_revision > self.revision
                || !self.check_context_ref(reference)?
            {
                return Err(Code::Invalid.error("notification completion context"));
            }
        }
        let completed = self.consume_capture(
            &capture.input,
            instance.spec.tenant,
            &instance.spec.id,
            true,
        )?;
        if completed.is_some() {
            let receipt = NotificationCompletion {
                input: capture.input.clone(),
                lifecycle: instance.lifecycle,
                revision: self.revision,
                contexts: references.to_vec(),
            };
            Records::stage(
                &mut self.transaction,
                NotificationCompletion::key(&capture.input),
                Records::named(&receipt)?,
            );
            self.dirty = true;
        }
        let consumed = capture.input.exhaustive
            && (completed.is_some() || record.completed_through >= capture.input.cut.position());
        let revision = if self.dirty {
            self.revision
        } else {
            current.revision
        };
        self.commit_published([], move || {
            if let Some((delivery, position)) = completed {
                delivery.complete(position);
            }
        })?;
        Ok((revision, consumed))
    }
}

impl NotificationCompletion {
    pub(in crate::analysis::native) const PREFIX: &'static [u8] =
        b"\0data/notification-completion/";

    fn key(input: &InputCapture) -> Vec<u8> {
        [
            Self::PREFIX,
            &input.owner.to_be_bytes(),
            &input.generation.to_be_bytes(),
            &input.version.to_be_bytes(),
        ]
        .concat()
    }
}

impl DataView {
    pub(in crate::analysis::native) fn notification_completions(
        &self,
        branch: &fjall::Branch,
        completed: &mut std::collections::BTreeMap<(u64, u64, u64), u64>,
    ) -> Result<()> {
        let control = AnalysisReadControl::default();
        for item in self.snapshot.prefix(NotificationCompletion::PREFIX) {
            let (key, _) = item.context(NativeStorageSnafu {
                operation: "validate notification completions",
            })?;
            if key.len() == NotificationCompletion::PREFIX.len() + 32 {
                continue;
            }
            let bytes = Records::payload(&key, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| Code::Missing.error("notification completion"))?;
            let receipt: NotificationCompletion = Records::decode(&bytes)?;
            let input = &receipt.input;
            if key.as_ref() != NotificationCompletion::key(input)
                || !input.exhaustive
                || receipt.revision <= input.cut.revision
                || receipt.revision > self.metadata_revision
            {
                return Err(Code::Invalid.error("notification completion record"));
            }
            let consumer = InputRecord::read(input.owner, input.generation, |key| {
                Records::read(key, &self.snapshot)
            })?
            .ok_or_else(|| Code::Missing.error("notification completion consumer"))?;
            let at = NativeStore::cut_at(branch, self, input.cut.revision)?;
            let instance = at
                .managed_instance(consumer.tenant, &consumer.instance, &control)?
                .ok_or_else(|| Code::Missing.error("notification captured instance"))?;
            at.check_consumer(input, consumer.tenant, &consumer.instance)?;
            if instance.generation != input.generation
                || instance.lifecycle != receipt.lifecycle
                || !instance.running
                || instance.removed
                || instance.spec.destination != ManagedDestination::Notification
            {
                return Err(Code::Invalid.error("notification completion lifecycle"));
            }
            let committed = NativeStore::cut_at(branch, self, receipt.revision)?;
            let saved = Records::payload(&key, |key| Records::read(key, &committed.snapshot))?
                .map(|bytes| Records::decode::<NotificationCompletion>(&bytes))
                .transpose()?;
            let saved_consumer =
                committed.check_consumer(input, consumer.tenant, &consumer.instance)?;
            if saved.as_ref() != Some(&receipt)
                || saved_consumer.completed_through != input.cut.position()
                || committed
                    .managed_instance(consumer.tenant, &consumer.instance, &control)?
                    .as_ref()
                    != Some(&instance)
            {
                return Err(Code::Invalid.error("notification completion commit"));
            }
            for reference in &receipt.contexts {
                if reference.key.tenant_id != consumer.tenant
                    || reference.key.owner_id != NOTIFICATION_STATE_OWNER
                    || reference.commit_revision > receipt.revision
                    || committed
                        .context(&reference.key)?
                        .is_none_or(|(_, revision)| revision != reference.commit_revision)
                {
                    return Err(Code::Invalid.error("notification completion context"));
                }
            }
            if completed
                .insert(
                    (input.owner, input.generation, input.version),
                    input.cut.revision,
                )
                .is_some()
            {
                return Err(Code::Invalid.error("notification completion destination"));
            }
        }
        Ok(())
    }
}
