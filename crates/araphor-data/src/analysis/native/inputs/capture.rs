use super::{InputRecord, Wake};
use crate::analysis::{
    inputs::{InputCapture, InputCut},
    managed::Capture,
    native::{records::Records, DataView, DataWrite, NativeStore},
};
use crate::{
    AnalysisPositionPageV1, AnalysisReadModeV1, AnalysisSelectionV1, AnalysisTableRead,
    InputSubscription, ManagedRead, PackageErrorCodeV1 as Code, Result,
};
use std::collections::BTreeSet;

impl InputSubscription {
    pub(in crate::analysis::native) fn capture_inputs(
        &self,
        store: &NativeStore,
        view: &DataView,
        request: &ManagedRead,
        selection: &AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        page: &mut AnalysisPositionPageV1,
        owners: Option<&BTreeSet<String>>,
    ) -> Result<InputCapture> {
        self.native
            .as_ref()
            .ok_or_else(|| Code::Conflict.error("native input subscription"))?
            .capture_inputs(
                store,
                view,
                &request.instance,
                request.source.as_ref(),
                selection,
                read,
                page,
                owners,
            )
    }
    pub(in crate::analysis::native) fn capture_notification(
        &self,
        store: &NativeStore,
        view: &DataView,
        instance: &crate::ManagedInstance,
        selection: &AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        page: &mut AnalysisPositionPageV1,
        owners: Option<&BTreeSet<String>>,
    ) -> Result<InputCapture> {
        self.native
            .as_ref()
            .ok_or_else(|| Code::Conflict.error("native input subscription"))?
            .capture_inputs(store, view, instance, None, selection, read, page, owners)
    }
}

impl Wake {
    fn capture_inputs(
        &self,
        store: &NativeStore,
        view: &DataView,
        instance: &crate::ManagedInstance,
        source: Option<&crate::ManagedSourceRead>,
        selection: &AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        page: &mut AnalysisPositionPageV1,
        owners: Option<&BTreeSet<String>>,
    ) -> Result<InputCapture> {
        let (consumer, _) = self
            .consumer
            .as_ref()
            .filter(|(consumer, source)| {
                std::ptr::eq(source.as_ptr(), store)
                    && std::sync::Arc::ptr_eq(&self.coordinator, &store.inputs)
                    && consumer.delivery.active()
            })
            .ok_or_else(|| Code::Conflict.error("input consumer store"))?;
        let interest = &consumer.registration.watch.interest;
        let record = InputRecord::read_charged(
            consumer.owner,
            consumer.generation,
            |key| Records::read(key, &view.snapshot),
            &mut |bytes| page.extraction.charge(bytes),
        )?
        .ok_or_else(|| Code::Missing.error("input capture consumer"))?;
        if instance.generation != consumer.generation
            || record.version != consumer.version
            || record.tenant != instance.spec.tenant
            || record.instance != instance.spec.id
        {
            return Err(Code::Conflict.error("input capture binding"));
        }
        read.check_scope(selection, &interest.original)?;
        let cut = InputCut::capture(view)?;
        let exhaustive = page.exhausted
            && page.scanned_through == cut.position()
            && interest.covers_read(selection, read.requests, owners, read.event_ranges)?
            && (!matches!(read.mode, AnalysisReadModeV1::Metadata) || !read.reads_raw())
            && match read.mode {
                AnalysisReadModeV1::Complete | AnalysisReadModeV1::Metadata => true,
                AnalysisReadModeV1::Changes(after) => {
                    let consumed = record.completed_through.commit_revision != 0
                        && after <= record.cut.position();
                    let replayed = match (source, &self.replay) {
                        (Some(crate::ManagedSourceRead::Changes(parent)), Some(replay))
                            if parent.position == after =>
                        {
                            replay.matches(parent)?
                        }
                        _ => false,
                    };
                    consumed || replayed
                }
                _ => false,
            };
        Ok(InputCapture {
            owner: consumer.owner,
            generation: consumer.generation,
            version: consumer.version,
            cut,
            exhaustive,
        })
    }
}

impl DataView {
    pub(in crate::analysis::native) fn check_input_token(&self, capture: &Capture) -> Result<()> {
        let Some(input) = &capture.input else {
            return Ok(());
        };
        self.check_consumer(input, capture.tenant, &capture.instance)?;
        if input.cut.revision != capture.revision || input.generation != capture.generation {
            return Err(Code::Invalid.error("input capture token"));
        }
        Ok(())
    }
    pub(in crate::analysis::native) fn check_consumer(
        &self,
        input: &InputCapture,
        tenant: [u8; 16],
        instance: &str,
    ) -> Result<InputRecord> {
        input.cut.check(self)?;
        let record = InputRecord::read(input.owner, input.generation, |key| {
            Records::read(key, &self.snapshot)
        })?
        .ok_or_else(|| Code::Missing.error("input capture consumer"))?;
        let owner = Records::find(
            &super::super::managed::InstanceRecord::identity(tenant, instance)?,
            |key| Records::read(key, &self.snapshot),
        )?;
        if record.version != input.version
            || record.tenant != tenant
            || record.instance != instance
            || owner != Some(input.owner)
            || record.version > input.cut.revision
        {
            return Err(Code::Invalid.error("input capture token"));
        }
        Ok(record)
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn check_input_capture(
        &self,
        capture: &Capture,
    ) -> Result<Option<InputRecord>> {
        let Some(input) = &capture.input else {
            return Ok(None);
        };
        if input.cut.revision != capture.revision || input.generation != capture.generation {
            return Err(Code::Invalid.error("input capture token"));
        }
        self.check_live_consumer(input, capture.tenant, &capture.instance)
            .map(Some)
    }

    pub(in crate::analysis::native) fn consume_inputs(
        &mut self,
        capture: &Capture,
        completed: bool,
    ) -> Result<Option<(std::sync::Arc<super::Delivery>, crate::StorePositionV1)>> {
        let Some(input) = &capture.input else {
            return Ok(None);
        };
        let Some(record) = self.check_input_capture(capture)? else {
            return Ok(None);
        };
        self.advance_input(input, record, completed)
    }

    fn check_live_consumer(
        &self,
        input: &InputCapture,
        tenant: [u8; 16],
        instance: &str,
    ) -> Result<InputRecord> {
        let view = self.store.view()?;
        view.check_consumer(input, tenant, instance)?;
        let record = InputRecord::read(input.owner, input.generation, |key| {
            Records::staged(key, &self.transaction)
        })?
        .ok_or_else(|| Code::Missing.error("input capture consumer"))?;
        if record.version != input.version
            || record.tenant != tenant
            || record.instance != instance
            || !record.active(input.owner, &view)?
        {
            return Err(Code::Conflict.error("input capture consumer"));
        }
        Ok(record)
    }

    pub(in crate::analysis::native) fn consume_capture(
        &mut self,
        input: &InputCapture,
        tenant: [u8; 16],
        instance: &str,
        completed: bool,
    ) -> Result<Option<(std::sync::Arc<super::Delivery>, crate::StorePositionV1)>> {
        let record = self.check_live_consumer(input, tenant, instance)?;
        self.advance_input(input, record, completed)
    }

    fn advance_input(
        &mut self,
        input: &InputCapture,
        mut record: InputRecord,
        completed: bool,
    ) -> Result<Option<(std::sync::Arc<super::Delivery>, crate::StorePositionV1)>> {
        if completed && input.exhaustive && input.cut.position() > record.completed_through {
            if input.cut.revision > record.cut.revision {
                record.cut = input.cut.clone();
            }
            record.completed_through = input.cut.position();
            Records::stage(
                &mut self.transaction,
                InputRecord::key(input.owner, input.generation),
                Records::named(&record)?,
            );
            self.dirty = true;
            let scan = self.store.inputs.scan.lock().map_err(|_| {
                crate::NativeStateSnafu {
                    field: "input journal reader lock",
                }
                .build()
            })?;
            let consumer = scan
                .consumers
                .get(&(input.owner, input.generation))
                .ok_or_else(|| Code::Missing.error("live input consumer"))?;
            return Ok(Some((
                std::sync::Arc::clone(&consumer.delivery),
                record.completed_through,
            )));
        }
        Ok(None)
    }
}
