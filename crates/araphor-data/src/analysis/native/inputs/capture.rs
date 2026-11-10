use super::{InputRecord, Wake};
use crate::analysis::{
    inputs::{InputCapture, InputCut},
    managed::Capture,
    native::{records::Records, DataView, DataWrite, NativeStore},
};
use crate::{
    AnalysisPositionPageV1, AnalysisReadModeV1, AnalysisSelectionV1, AnalysisTableRead,
    InputSubscription, ManagedInstance, PackageErrorCodeV1 as Code, Result,
};
use std::collections::BTreeSet;

impl InputSubscription {
    pub(in crate::analysis::native) fn capture_inputs(
        &self,
        store: &NativeStore,
        view: &DataView,
        instance: &ManagedInstance,
        selection: &AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        page: &AnalysisPositionPageV1,
        owners: Option<&BTreeSet<String>>,
    ) -> Result<InputCapture> {
        self.native
            .as_ref()
            .ok_or_else(|| Code::Conflict.error("native input subscription"))?
            .capture_inputs(store, view, instance, selection, read, page, owners)
    }
}

impl Wake {
    fn capture_inputs(
        &self,
        store: &NativeStore,
        view: &DataView,
        instance: &ManagedInstance,
        selection: &AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        page: &AnalysisPositionPageV1,
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
        let record = InputRecord::read(consumer.owner, consumer.generation, |key| {
            Records::read(key, &view.snapshot)
        })?
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
            && *selection == interest.original.project(read.requests)?
            && interest.requests == *read.requests
            && (owners.is_none()
                || interest
                    .owners
                    .as_ref()
                    .zip(owners)
                    .is_some_and(|(watched, captured)| watched.is_subset(captured)))
            && owners.is_none_or(|owners| {
                [
                    ("targets", "mithril-control/target"),
                    ("compiled_policies", "mithril-control/compiled-policy"),
                    ("notification_routes", crate::NOTIFICATION_ROUTE_OWNER),
                ]
                .iter()
                .all(|(table, owner)| {
                    !read.requests.contains_key(*table) || owners.contains(*owner)
                })
            })
            && read
                .event_ranges
                .is_none_or(|ranges| ranges == [(0, u64::MAX)])
            && (!matches!(read.mode, AnalysisReadModeV1::Metadata) || !read.reads_raw())
            && match read.mode {
                AnalysisReadModeV1::Complete | AnalysisReadModeV1::Metadata => true,
                AnalysisReadModeV1::Changes(after) => {
                    record.completed_through.commit_revision != 0 && after <= record.cut.position()
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
        input.cut.check(self)?;
        let record = InputRecord::read(input.owner, input.generation, |key| {
            Records::read(key, &self.snapshot)
        })?
        .ok_or_else(|| Code::Missing.error("input capture consumer"))?;
        let owner = Records::find(
            &super::super::managed::InstanceRecord::identity(capture.tenant, &capture.instance)?,
            |key| Records::read(key, &self.snapshot),
        )?;
        if input.cut.revision != capture.revision
            || input.generation != capture.generation
            || record.version != input.version
            || record.tenant != capture.tenant
            || record.instance != capture.instance
            || owner != Some(input.owner)
            || record.version > capture.revision
        {
            return Err(Code::Invalid.error("input capture token"));
        }
        Ok(())
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
        let view = self.store.view()?;
        view.check_input_token(capture)?;
        let record = InputRecord::read(input.owner, input.generation, |key| {
            Records::staged(key, &self.transaction)
        })?
        .ok_or_else(|| Code::Missing.error("input capture consumer"))?;
        if input.cut.revision != capture.revision
            || input.generation != capture.generation
            || record.version != input.version
            || record.tenant != capture.tenant
            || record.instance != capture.instance
            || !record.active(input.owner, &view)?
        {
            return Err(Code::Conflict.error("input capture consumer"));
        }
        Ok(Some(record))
    }

    pub(in crate::analysis::native) fn consume_inputs(
        &mut self,
        capture: &Capture,
        completed: bool,
    ) -> Result<Option<(std::sync::Arc<super::Delivery>, crate::StorePositionV1)>> {
        let Some(mut record) = self.check_input_capture(capture)? else {
            return Ok(None);
        };
        let input = capture
            .input
            .as_ref()
            .ok_or_else(|| Code::Missing.error("input capture"))?;
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
