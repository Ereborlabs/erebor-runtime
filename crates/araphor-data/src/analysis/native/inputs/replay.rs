use std :: { any :: Any , sync :: { Arc , Mutex } } ;

use super::{InputRecord, Wake};
use crate::analysis::{native::records::Records, PackageResultRefV1};
use crate :: { AnalysisReadControl , InputSubscription , ManagedBudget , ManagedSourceFrame , ManagedSourceRead , ManagedSourceRef , NativeStateSnafu , Result , StorePositionV1 } ;

pub(super) struct Replay {
    head: Mutex<Option<Head>>,
    _memory: Box<dyn Any + Send + Sync>,
}

struct Head {
    proof: Arc<PackageResultRefV1>,
    position: StorePositionV1,
    _memory: Box<dyn Any + Send + Sync>,
}

impl Replay {
    pub(super) fn new(
        control: &AnalysisReadControl,
        budget: &dyn ManagedBudget,
    ) -> Result<Arc<Self>> {
        control.check()?;
        budget.check()?;
        let memory = budget.reserve(size_of::<Self>() + 4 * size_of::<usize>())?;
        Ok(Arc::new(Self {
            head: Mutex::new(None),
            _memory: memory,
        }))
    }

    pub(super) fn matches(&self, parent: &ManagedSourceRef) -> Result<bool> {
        let head = self.head.lock().map_err(|_| {
            NativeStateSnafu {
                field: "input replay lock",
            }
            .build()
        })?;
        Ok(head
            .as_ref()
            .is_some_and(|head| head.position == parent.position && *head.proof == parent.result))
    }

    fn observe(
        &self,
        frame: &ManagedSourceFrame,
        control: &AnalysisReadControl,
        budget: &dyn ManagedBudget,
    ) -> Result<()> {
        let Some(proof) = frame.proof() else {
            return Ok(());
        };
        control.check()?;
        budget.check()?;
        if !self.can_observe(frame)? {
            return Ok(());
        }
        let memory = budget
            .reserve(size_of::<Head>() + proof.result_id.capacity() + 4 * size_of::<usize>())?;
        let mut head = self.head.lock().map_err(|_| {
            NativeStateSnafu {
                field: "input replay lock",
            }
            .build()
        })?;
        if Self::advances(head.as_ref(), frame) {
            *head = Some(Head {
                proof: Arc::clone(proof),
                position: frame.position(),
                _memory: memory,
            });
        }
        Ok(())
    }

    fn can_observe(&self, frame: &ManagedSourceFrame) -> Result<bool> {
        let head = self.head.lock().map_err(|_| {
            NativeStateSnafu {
                field: "input replay lock",
            }
            .build()
        })?;
        Ok(frame.proof().is_some() && Self::advances(head.as_ref(), frame))
    }

    fn advances(head: Option<&Head>, frame: &ManagedSourceFrame) -> bool {
        if head.is_some_and(|head| head.position >= frame.position()) {
            return false;
        }
        match frame.read() {
            ManagedSourceRead::Initial => true,
            ManagedSourceRead::Changes(parent) => head.is_some_and(|head| {
                head.position == parent.position && *head.proof == parent.result
            }),
        }
    }
}

impl InputSubscription {
    pub fn observe_source(
        &self,
        frame: &ManagedSourceFrame,
        control: &AnalysisReadControl,
        budget: &dyn ManagedBudget,
    ) -> Result<()> {
        let Some(wake) = &self.native else {
            return Ok(());
        };
        wake.observe_source(frame, control, budget)
    }
}

impl Wake {
    fn observe_source(
        &self,
        frame: &ManagedSourceFrame,
        control: &AnalysisReadControl,
        budget: &dyn ManagedBudget,
    ) -> Result<()> {
        control.check()?;
        let Some((consumer, _)) = &self.consumer else {
            return Ok(());
        };
        let Some(replay) = &self.replay else {
            return Ok(());
        };
        if !consumer.delivery.active() {
            return Ok(());
        }
        if !replay.can_observe(frame)? {
            return Ok(());
        }
        let view = self.coordinator.view()?;
        let mut memory = crate::analysis::managed::PreparedMemory::new(control, budget)?;
        let Some(record) = InputRecord::read_charged(
            consumer.owner,
            consumer.generation,
            |key| Records::read(key, &view.snapshot),
            &mut |bytes| memory.charge(bytes),
        )?
        else {
            return Ok(());
        };
        if record.version != consumer.version
            || !frame.covers_inputs(
                &view.meta(),
                &consumer.registration.watch.interest,
                &record.instance,
                record.generation,
            )?
        {
            return Ok(());
        }
        replay.observe(frame, control, budget)
    }
}
