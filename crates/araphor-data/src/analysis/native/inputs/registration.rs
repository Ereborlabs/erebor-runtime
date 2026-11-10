use std::{collections::BTreeSet, sync::Arc};

use super::{InputRecord, Wake};
use crate::analysis::{
    inputs::{InputCut, InputInterest},
    managed::PreparedMemory,
    native::{managed::InstanceRecord, records::Records, NativeStore},
};
use crate::{
    AnalysisReadControl, AnalysisSelectionV1, AnalysisTableRequests, InputSubscription,
    ManagedBudget, ManagedInstance, NativeStateSnafu, PackageErrorCodeV1 as Code, Result,
    StorePositionV1,
};

impl NativeStore {
    pub fn subscribe_managed_inputs(
        self: &Arc<Self>,
        instance: &ManagedInstance,
        selection: &AnalysisSelectionV1,
        requests: &AnalysisTableRequests,
        owners: Option<&BTreeSet<String>>,
        control: &AnalysisReadControl,
        budget: &dyn ManagedBudget,
    ) -> Result<InputSubscription> {
        instance.grant.remaining()?;
        let memory = PreparedMemory::new(control, budget)?;
        let lease = memory.reserve(InputInterest::allocation_bytes(selection, requests, owners))?;
        let interest = InputInterest::new(selection.clone(), requests.clone(), owners.cloned())?;
        let spec = interest.spec();
        let scope = instance
            .spec
            .destination
            .selection(&instance.grant.selection)?;
        crate::AnalysisTableRead {
            requests,
            event_ranges: None,
            mode: crate::AnalysisReadModeV1::Complete,
            now: 0,
        }
        .check_scope(&selection.project(requests)?, &scope)?;
        let mut tx = self.write()?;
        let current = tx
            .managed_instance(instance.spec.tenant, &instance.spec.id)?
            .filter(|current| current == instance && !current.removed)
            .ok_or_else(|| Code::Conflict.error("input consumer generation"))?;
        let owner = Records::find(
            &InstanceRecord::identity(current.spec.tenant, &current.spec.id)?,
            |key| Records::staged(key, &tx.transaction),
        )?
        .ok_or_else(|| Code::Missing.error("input consumer instance"))?;
        if let Some(record) = InputRecord::read(owner, current.generation, |key| {
            Records::staged(key, &tx.transaction)
        })? {
            if record.interest != spec {
                return Err(Code::Conflict.error("input consumer interest"));
            }
        } else {
            let view = self.view()?;
            let cut = InputCut::capture(&view)?;
            let record = InputRecord {
                tenant: current.spec.tenant,
                instance: current.spec.id.clone(),
                generation: current.generation,
                version: tx.revision,
                interest: spec,
                cut,
                completed_through: StorePositionV1 {
                    commit_revision: 0,
                    ordinal: 0,
                },
            };
            Records::stage(
                &mut tx.transaction,
                InputRecord::key(owner, current.generation),
                Records::named(&record)?,
            );
            tx.dirty = true;
        }
        memory.check()?;
        tx.commit([])?;
        let mut scan = self.inputs.scan.lock().map_err(|_| {
            NativeStateSnafu {
                field: "input journal reader lock",
            }
            .build()
        })?;
        let view = self.inputs.view()?;
        self.inputs.refresh(
            &mut scan,
            &InputRecord::key(owner, current.generation),
            &view,
        )?;
        self.inputs.read(&mut scan, &view)?;
        let consumer = scan
            .consumers
            .get(&(owner, current.generation))
            .cloned()
            .ok_or_else(|| Code::Conflict.error("input consumer registration"))?;
        let mut allocation = consumer
            .memory
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if allocation.is_none() {
            *allocation = Some(lease);
        }
        drop(allocation);
        let mut receiver = consumer.registration.watch.changes.subscribe();
        if *receiver.borrow() > consumer.delivery.completed() {
            receiver.mark_changed();
        }
        Ok(InputSubscription {
            _registration: Arc::clone(&consumer.registration),
            changes: receiver,
            meta: view.meta(),
            native: Some(Wake {
                coordinator: Arc::clone(&self.inputs),
                revision: self.revision.subscribe(),
                consumer: Some((consumer, Arc::downgrade(self))),
            }),
        })
    }
}
