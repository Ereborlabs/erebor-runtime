use fjall::Readable;
use serde::{Deserialize, Serialize};

use super::{AnalysisSourceReceiptV1, Result, Tables};

#[derive(Deserialize, Serialize)]
pub(super) struct State {
    pub head: u64,
    pub events: u64,
    pub receipts: u64,
    pub bindings: u64,
    pub consumed: u64,
    pub next_source: u64,
}

impl Default for State {
    fn default() -> Self {
        Self {
            head: 0,
            events: 0,
            receipts: 0,
            bindings: 0,
            consumed: 0,
            next_source: 1,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub(super) struct Receipt {
    pub cpu_id: u32,
    pub contiguous_cursor: u64,
    pub coverage_revision: u64,
    pub retained_floor: u64,
}

impl Tables {
    pub(super) fn state(&self, tx: &impl Readable) -> Result<State> {
        Ok(tx
            .get(&self.state, b"head")?
            .map(|bytes| rmp_serde::from_slice(&bytes))
            .transpose()?
            .unwrap_or_default())
    }

    pub(super) fn receipt(&self, tx: &impl Readable) -> Result<Option<AnalysisSourceReceiptV1>> {
        if self.metadata {
            let Some(prefix) = self.prefix.as_deref() else {
                return Ok(None);
            };
            let receipt = tx
                .get(&self.receipts, prefix)?
                .map(|bytes| rmp_serde::from_slice::<Receipt>(&bytes))
                .transpose()?;
            Ok(receipt.map(|receipt| AnalysisSourceReceiptV1 {
                identity: self.source.clone(),
                cpu_id: receipt.cpu_id,
                contiguous_cursor: receipt.contiguous_cursor,
                coverage_revision: receipt.coverage_revision,
                retained_floor: receipt.retained_floor,
            }))
        } else {
            Ok(tx
                .get(&self.receipts, self.source.key())?
                .map(|bytes| rmp_serde::from_slice(&bytes))
                .transpose()?)
        }
    }
}
