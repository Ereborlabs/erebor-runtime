use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use super::super::{records::Records, DataView};
use crate::analysis::inputs::{InputCut, InputRegistration, InputSpec};
use crate::{NativeStateSnafu, Result, StorePositionV1};

#[derive(Clone, Deserialize, Serialize)]
pub(in crate::analysis::native) struct InputRecord {
    pub tenant: [u8; 16],
    pub instance: String,
    pub generation: u64,
    pub version: u64,
    pub interest: InputSpec,
    pub cut: InputCut,
    pub completed_through: StorePositionV1,
}

pub(super) struct Consumer {
    pub owner: u64,
    pub generation: u64,
    pub version: u64,
    pub registration: Arc<InputRegistration>,
    pub delivery: Arc<Delivery>,
}

pub(in crate::analysis) struct Delivery(Mutex<Progress>);

struct Progress {
    active: bool,
    completed: StorePositionV1,
    highest: StorePositionV1,
    first: Option<u64>,
}

impl Delivery {
    pub(super) fn new(completed: StorePositionV1) -> Self {
        Self(Mutex::new(Progress {
            active: true,
            completed,
            highest: completed,
            first: None,
        }))
    }

    pub(in crate::analysis) fn record(&self, position: StorePositionV1) -> bool {
        let mut progress = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if !progress.active || position <= progress.completed {
            return false;
        }
        progress.highest = progress.highest.max(position);
        progress.first = Some(progress.first.map_or(position.commit_revision, |first| {
            first.min(position.commit_revision)
        }));
        true
    }

    pub(super) fn completed(&self) -> StorePositionV1 {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .completed
    }

    pub(super) fn active(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .active
    }

    pub(super) fn retire(&self) {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .active = false;
    }

    pub(in crate::analysis::native) fn complete(&self, completed: StorePositionV1) {
        let mut progress = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if completed <= progress.completed {
            return;
        }
        progress.completed = completed;
        progress.first = if progress.highest <= completed {
            None
        } else {
            Some(
                progress
                    .first
                    .unwrap_or(completed.commit_revision.saturating_add(1))
                    .max(completed.commit_revision.saturating_add(1)),
            )
        };
    }

    pub(super) fn safe_after(&self, through: u64, completed: StorePositionV1) -> u64 {
        let progress = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if progress.highest <= completed {
            through
        } else {
            progress.first.map_or(through, |first| {
                through.min(
                    first
                        .max(completed.commit_revision.saturating_add(1))
                        .saturating_sub(1),
                )
            })
        }
    }
}

impl InputRecord {
    pub(in crate::analysis::native) const PREFIX: &'static [u8] = b"\0data/input/";

    pub(in crate::analysis::native) fn key(owner: u64, generation: u64) -> Vec<u8> {
        [
            Self::PREFIX,
            &owner.to_be_bytes(),
            &generation.to_be_bytes(),
        ]
        .concat()
    }

    pub(in crate::analysis::native) fn read(
        owner: u64,
        generation: u64,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<Option<Self>> {
        Self::read_charged(owner, generation, get, &mut |_| Ok(()))
    }

    pub(super) fn read_charged(
        owner: u64,
        generation: u64,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<Self>> {
        Records::charged_payload(&Self::key(owner, generation), get, charge)?
            .map(|bytes| {
                let record: Self = Records::decode(&bytes)?;
                if record.generation != generation {
                    return NativeStateSnafu {
                        field: "input generation key",
                    }
                    .fail();
                }
                Ok(record)
            })
            .transpose()
    }

    pub(super) fn check(&self, view: &DataView) -> Result<()> {
        self.cut.check(view)?;
        if self.tenant == [0; 16]
            || self.instance.is_empty()
            || self.interest.selection.tenant_id != self.tenant
            || self.generation == 0
            || self.generation > self.version
            || self.generation > self.cut.revision
            || self.version > view.metadata_revision
            || self.completed_through.commit_revision > self.cut.revision
            || self.completed_through.commit_revision == 0 && self.completed_through.ordinal != 0
            || self.completed_through.commit_revision != 0
                && self.completed_through.ordinal != u32::MAX
        {
            return NativeStateSnafu {
                field: "input consumer record",
            }
            .fail();
        }
        Ok(())
    }
}
