use snafu::ResultExt as _;
use std::sync::Arc;

use super::{Consumer, Coordinator, Delivery, InputRecord, InputWatch, Scan};
use crate::analysis::{
    inputs::InputInterest,
    native::{managed::InstanceRecord, records::Records, DataView, NativeStore},
};
use crate::{
    AnalysisReadControl, NativeStateSnafu, NativeStorageSnafu, PackageErrorCodeV1 as Code, Result,
};

impl InputRecord {
    pub(super) fn identity(key: &[u8]) -> Result<Option<(u64, u64)>> {
        if !key.starts_with(Self::PREFIX) || key.len() == Self::PREFIX.len() + 24 {
            return Ok(None);
        }
        if key.len() != Self::PREFIX.len() + 16 {
            return NativeStateSnafu {
                field: "input consumer key",
            }
            .fail();
        }
        Ok(Some((
            NativeStore::number(&key[Self::PREFIX.len()..Self::PREFIX.len() + 8])?,
            NativeStore::number(&key[Self::PREFIX.len() + 8..])?,
        )))
    }

    pub(super) fn active(&self, owner: u64, view: &DataView) -> Result<bool> {
        self.check(view)?;
        if Records::find(
            &InstanceRecord::identity(self.tenant, &self.instance)?,
            |key| Records::read(key, &view.snapshot),
        )? != Some(owner)
        {
            return Err(Code::Invalid.error("input consumer owner"));
        }
        let control = AnalysisReadControl::default();
        view.managed_version(self.tenant, &self.instance, self.generation, &control)?;
        let current = view
            .managed_instance(self.tenant, &self.instance, &control)?
            .ok_or_else(|| Code::Missing.error("input consumer instance"))?;
        Ok(!current.removed && current.generation == self.generation)
    }
}

impl Coordinator {
    pub(super) fn restore(&self, view: &DataView) -> Result<()> {
        let mut scan = self.scan.lock().map_err(|_| {
            NativeStateSnafu {
                field: "input journal reader lock",
            }
            .build()
        })?;
        for entry in view.snapshot.prefix(InputRecord::PREFIX) {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "restore input consumers",
            })?;
            self.refresh(&mut scan, &key, view)?;
        }
        Ok(())
    }

    pub(super) fn refresh(&self, scan: &mut Scan, key: &[u8], view: &DataView) -> Result<()> {
        let Some((owner, generation)) = InputRecord::identity(key)? else {
            return Ok(());
        };
        let record =
            InputRecord::read(owner, generation, |key| Records::read(key, &view.snapshot))?;
        let Some(record) = record else {
            if let Some(consumer) = scan.consumers.remove(&(owner, generation)) {
                consumer.delivery.retire();
            }
            return Ok(());
        };
        if !record.active(owner, view)? {
            if let Some(consumer) = scan.consumers.remove(&(owner, generation)) {
                consumer.delivery.retire();
            }
            return Ok(());
        }
        if let Some(consumer) = scan.consumers.get(&(owner, generation)) {
            if consumer.version != record.version
                || consumer.registration.watch.interest.spec() != record.interest
            {
                return Err(Code::Conflict.error("input consumer binding"));
            }
            consumer.delivery.complete(record.completed_through);
            return Ok(());
        }
        record.cut.read(&self.branch, view)?;
        let interest = InputInterest::new(
            record.interest.selection.clone(),
            record.interest.requests.clone(),
            record.interest.owners.clone(),
        )?;
        let delivery = Arc::new(Delivery::new(record.completed_through));
        let changes = tokio::sync::watch::channel(record.completed_through).0;
        let watch = Arc::new(InputWatch {
            interest,
            changes,
            after: record.cut.revision,
            delivery: Some(Arc::clone(&delivery)),
            _memory: Box::new(()),
        });
        let empty = self.is_empty();
        let consumer = Arc::new(Consumer {
            owner,
            generation,
            version: record.version,
            registration: self.readers.register(&watch),
            delivery,
            memory: std::sync::Mutex::new(None),
        });
        scan.consumers.insert((owner, generation), consumer);
        if empty || Some(record.cut.cursor()) < scan.native.cursor() {
            scan.native = self
                .database
                .inner()
                .journal_feed(Some(record.cut.cursor()))
                .context(NativeStorageSnafu {
                    operation: "resume durable input cursor",
                })?;
        }
        scan.raw = if empty {
            record.cut.revision
        } else {
            scan.raw.min(record.cut.revision)
        };
        Ok(())
    }
}

impl DataView {
    pub(in crate::analysis::native) fn check_input_completions(
        &self,
        completed: &std::collections::BTreeMap<(u64, u64, u64), u64>,
    ) -> Result<()> {
        for row in self.snapshot.prefix(InputRecord::PREFIX) {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "validate input completions",
            })?;
            let Some((owner, generation)) = InputRecord::identity(&key)? else {
                continue;
            };
            let record =
                InputRecord::read(owner, generation, |key| Records::read(key, &self.snapshot))?
                    .ok_or_else(|| Code::Missing.error("input completion consumer"))?;
            record.check(self)?;
            if record.completed_through.commit_revision
                != completed
                    .get(&(owner, generation, record.version))
                    .copied()
                    .unwrap_or(0)
            {
                return Err(Code::Invalid.error("input completion outcome"));
            }
        }
        Ok(())
    }
}
