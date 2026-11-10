use super::InputRecord;
use crate::analysis::{
    inputs::InputCut,
    native::{records::Records, DataWrite, NativeStore},
};
use crate::{NativeStateSnafu, Result};

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn checkpoint_inputs(&mut self) -> Result<()> {
        let mut scan = self.store.inputs.scan.lock().map_err(|_| {
            NativeStateSnafu {
                field: "input journal reader lock",
            }
            .build()
        })?;
        if scan.consumers.is_empty() {
            return Ok(());
        }
        let view = self.store.inputs.view()?;
        self.store.inputs.read(&mut scan, &view)?;
        for consumer in scan.consumers.values() {
            let Some(mut record) = InputRecord::read(consumer.owner, consumer.generation, |key| {
                Records::staged(key, &self.transaction)
            })?
            else {
                continue;
            };
            let through = consumer
                .delivery
                .safe_after(scan.last_real, record.completed_through);
            if through > record.cut.revision {
                let at = NativeStore::cut_at(&self.store.branch, &view, through)?;
                record.cut = InputCut::capture(&at)?;
                Records::stage(
                    &mut self.transaction,
                    InputRecord::key(consumer.owner, consumer.generation),
                    Records::named(&record)?,
                );
                self.dirty = true;
            }
        }
        Ok(())
    }
}

impl NativeStore {
    pub fn checkpoint_inputs(&self) -> Result<()> {
        let mut tx = self.write()?;
        tx.checkpoint_inputs()?;
        tx.commit([])?;
        Ok(())
    }
}
