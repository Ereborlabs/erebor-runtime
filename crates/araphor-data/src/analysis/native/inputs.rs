use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound::{Excluded, Included},
    sync::{atomic::Ordering, Arc, Mutex, RwLock, Weak},
};

use fjall::{cdc::Feed, Branch, SingleWriterTxDatabase};
use snafu::ResultExt as _;
use tokio::sync::watch;

use super::{DataView, NativeStore};
use crate::analysis::inputs::{InputChanges, InputInterest, InputWatch};
use crate::{
    AnalysisReadControl, AnalysisSelectionV1, AnalysisTableRequests, InputSubscription,
    ManagedBudget, NativeStateSnafu, NativeStorageSnafu, Result, StorePositionV1,
};

mod capture;
mod checkpoint;
mod consumer;
mod cut;
mod records;
mod recovery;
mod registration;

pub(in crate::analysis) use consumer::Delivery;
use consumer::{Consumer, InputRecord};

pub(super) struct Coordinator {
    database: SingleWriterTxDatabase,
    branch: Branch,
    published: Arc<RwLock<Arc<DataView>>>,
    ready: Arc<std::sync::atomic::AtomicBool>,
    readers: InputChanges,
    scan: Mutex<Scan>,
}

struct Scan {
    native: Feed,
    raw: u64,
    consumers: BTreeMap<(u64, u64), Arc<Consumer>>,
    last_real: u64,
}

#[derive(Clone)]
pub(in crate::analysis) struct Wake {
    coordinator: Arc<Coordinator>,
    revision: watch::Receiver<u64>,
    consumer: Option<(Arc<Consumer>, Weak<NativeStore>)>,
}

impl Coordinator {
    pub(super) fn new(
        database: SingleWriterTxDatabase,
        branch: Branch,
        published: Arc<RwLock<Arc<DataView>>>,
        ready: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Self> {
        let view = published.read().map_err(|_| {
            NativeStateSnafu {
                field: "input publication lock",
            }
            .build()
        })?;
        let cursor = view.snapshot.cursor().context(NativeStorageSnafu {
            operation: "capture input journal cut",
        })?;
        let native = database
            .inner()
            .journal_feed(cursor)
            .context(NativeStorageSnafu {
                operation: "open input journal reader",
            })?;
        let raw = view.revision;
        let recovered = Arc::clone(&view);
        drop(view);
        let owner = Self {
            database,
            branch,
            published,
            ready,
            readers: InputChanges::default(),
            scan: Mutex::new(Scan {
                native,
                raw,
                consumers: BTreeMap::new(),
                last_real: 0,
            }),
        };
        owner.restore(&recovered)?;
        Ok(owner)
    }

    fn view(&self) -> Result<Arc<DataView>> {
        if !self.ready.load(Ordering::Acquire) {
            return NativeStateSnafu {
                field: "input store requires reopen",
            }
            .fail();
        }
        self.published
            .read()
            .map(|view| Arc::clone(&view))
            .map_err(|_| {
                NativeStateSnafu {
                    field: "input publication lock",
                }
                .build()
            })
    }

    fn catch_up(&self) -> Result<()> {
        let mut scan = self.scan.lock().map_err(|_| {
            NativeStateSnafu {
                field: "input journal reader lock",
            }
            .build()
        })?;
        let view = self.view()?;
        self.read(&mut scan, &view)
    }

    fn read(&self, scan: &mut Scan, view: &DataView) -> Result<()> {
        let end = view.snapshot.cursor().context(NativeStorageSnafu {
            operation: "capture input journal end",
        })?;
        while scan.native.cursor() < end {
            let before = scan.native.cursor();
            let routed = (|| {
                let batch = scan
                    .native
                    .next_batch()
                    .context(NativeStorageSnafu {
                        operation: "read original input journal",
                    })?
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "input journal ends before Data cut",
                        }
                        .build()
                    })?;
                if Some(batch.cursor) > end {
                    return NativeStateSnafu {
                        field: "input journal exceeds Data cut",
                    }
                    .fail();
                }
                self.records(&batch, view, scan)
            })();
            if let Err(error) = routed {
                scan.native = self
                    .database
                    .inner()
                    .journal_feed(before.min(scan.native.cursor()))
                    .context(NativeStorageSnafu {
                        operation: "restore failed input journal read",
                    })?;
                return Err(error);
            }
        }
        for (_, entry) in view
            .raw
            .entries
            .range((Excluded(scan.raw), Included(view.revision)))
        {
            self.readers.raw(entry);
            scan.last_real = scan.last_real.max(entry.commit.revision);
        }
        scan.raw = view.revision;
        Ok(())
    }
}

impl Wake {
    pub(in crate::analysis) fn needs_initial(&self) -> bool {
        self.consumer
            .as_ref()
            .is_some_and(|(consumer, _)| consumer.delivery.completed().commit_revision == 0)
    }

    pub(in crate::analysis) async fn changed(
        &mut self,
        changes: &mut watch::Receiver<StorePositionV1>,
    ) -> Result<()> {
        loop {
            let coordinator = Arc::clone(&self.coordinator);
            tokio::task::spawn_blocking(move || coordinator.catch_up())
                .await
                .map_err(|_| {
                    NativeStateSnafu {
                        field: "input journal reader task",
                    }
                    .build()
                })??;
            if self
                .consumer
                .as_ref()
                .is_some_and(|(consumer, _)| !consumer.delivery.active())
            {
                return Err(crate::PackageErrorCodeV1::Conflict.error("input consumer retired"));
            }
            if changes.has_changed().map_err(|_| {
                NativeStateSnafu {
                    field: "input change receiver",
                }
                .build()
            })? {
                let position = *changes.borrow_and_update();
                if self
                    .consumer
                    .as_ref()
                    .is_none_or(|(consumer, _)| position > consumer.delivery.completed())
                {
                    return Ok(());
                }
                continue;
            }
            self.revision.changed().await.map_err(|_| {
                NativeStateSnafu {
                    field: "input publication receiver",
                }
                .build()
            })?;
        }
    }
}

impl NativeStore {
    pub fn subscribe_inputs(
        &self,
        selection: &AnalysisSelectionV1,
        requests: &AnalysisTableRequests,
        owners: Option<&BTreeSet<String>>,
        control: &AnalysisReadControl,
        budget: &dyn ManagedBudget,
    ) -> Result<InputSubscription> {
        let view = self.view()?;
        self.subscribe_inputs_at(&view, selection, requests, owners, control, budget)
    }

    pub fn subscribe_inputs_at(
        &self,
        after: &DataView,
        selection: &AnalysisSelectionV1,
        requests: &AnalysisTableRequests,
        owners: Option<&BTreeSet<String>>,
        control: &AnalysisReadControl,
        budget: &dyn ManagedBudget,
    ) -> Result<InputSubscription> {
        control.check()?;
        let memory = crate::analysis::managed::PreparedMemory::new(control, budget)?;
        let lease = memory.reserve(InputInterest::allocation_bytes(selection, requests, owners))?;
        let interest = InputInterest::new(selection.clone(), requests.clone(), owners.cloned())?;
        let mut scan = self.inputs.scan.lock().map_err(|_| {
            NativeStateSnafu {
                field: "input journal reader lock",
            }
            .build()
        })?;
        let current = self.inputs.view()?;
        if after.store_uuid != current.store_uuid || after.revision > current.revision {
            return NativeStateSnafu {
                field: "input saved Data cut",
            }
            .fail();
        }
        let cursor = after.snapshot.cursor().context(NativeStorageSnafu {
            operation: "capture saved input journal cut",
        })?;
        if cursor.is_none() {
            return NativeStateSnafu {
                field: "saved input journal is not retained",
            }
            .fail();
        }
        if let Some((revision, entry)) = after.raw.entries.range(..=after.revision).next_back() {
            if current.raw.entries.get(revision).is_none_or(|retained| {
                retained.reference.id != entry.reference.id
                    || retained.reference.offset != entry.reference.offset
            }) {
                return NativeStateSnafu {
                    field: "saved raw input footer is not retained",
                }
                .fail();
            }
        }
        let empty = self.inputs.readers.is_empty();
        if empty || cursor < scan.native.cursor() {
            scan.native =
                self.inputs
                    .database
                    .inner()
                    .journal_feed(cursor)
                    .context(NativeStorageSnafu {
                        operation: "resume original input journal",
                    })?;
        }
        scan.raw = if empty {
            after.revision
        } else {
            scan.raw.min(after.revision)
        };
        let (changes, receiver) = watch::channel(StorePositionV1 {
            commit_revision: 0,
            ordinal: 0,
        });
        let owner = Arc::new(InputWatch {
            interest,
            changes,
            after: after.revision,
            delivery: None,
            _memory: lease,
        });
        let registration = self.inputs.readers.register(&owner);
        self.inputs.read(&mut scan, &current)?;
        Ok(InputSubscription {
            _registration: registration,
            changes: receiver,
            meta: current.meta(),
            native: Some(Wake {
                coordinator: Arc::clone(&self.inputs),
                revision: self.revision.subscribe(),
                consumer: None,
            }),
        })
    }
}
