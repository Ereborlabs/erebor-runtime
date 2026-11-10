use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::watch;

use super::*;

mod head;
mod interest;

pub(super) struct InputInterest {
    original: AnalysisSelectionV1,
    selection: AnalysisSelectionV1,
    requests: AnalysisTableRequests,
    owners: Option<BTreeSet<String>>,
}

pub(super) enum InputChange<'a> {
    Raw {
        identity: &'a AnalysisStreamIdentityV1,
        range: Option<(u64, u64, u64)>,
    },
    Removal {
        identity: &'a AnalysisStreamIdentityV1,
        range: Option<(u64, u64, Option<u64>)>,
    },
    Context(&'a AnalysisContextKeyV1),
    Processor(&'a ProcessorScopeV1),
    Profile {
        scope: &'a ProcessorScopeV1,
        result: &'a str,
    },
    Notice {
        scope: &'a ProcessorScopeV1,
        result: &'a str,
    },
    Graph {
        tenant: [u8; 16],
        result: &'a str,
        source: Option<&'a EvidenceIntakeIdentityV1>,
        witnesses: &'a [AnalysisWitnessV1],
    },
    Publication {
        tenant: [u8; 16],
        result: &'a str,
        owners: &'a managed::CommittedOwners,
    },
    Trace {
        tenant: [u8; 16],
        request: [u8; 16],
        bindings: &'a [TraceBindingV1],
    },
}

#[derive(Clone, Default)]
pub(super) struct InputChanges {
    readers: Arc<Mutex<BTreeMap<[u8; 16], BTreeMap<usize, Arc<InputWatch>>>>>,
}

pub(in crate::analysis) struct InputWatch {
    pub(in crate::analysis) interest: InputInterest,
    pub(in crate::analysis) changes: watch::Sender<StorePositionV1>,
    pub(in crate::analysis) after: u64,
    pub(in crate::analysis) _memory: Box<dyn std::any::Any + Send + Sync>,
}

pub(in crate::analysis) struct InputRegistration {
    readers: Weak<Mutex<BTreeMap<[u8; 16], BTreeMap<usize, Arc<InputWatch>>>>>,
    watch: Arc<InputWatch>,
}

impl Drop for InputRegistration {
    fn drop(&mut self) {
        let Some(readers) = self.readers.upgrade() else {
            return;
        };
        let mut readers = readers.lock().unwrap_or_else(|error| error.into_inner());
        let tenant = self.watch.interest.selection.tenant_id;
        if let Some(subscriptions) = readers.get_mut(&tenant) {
            subscriptions.remove(&(Arc::as_ptr(&self.watch) as usize));
            if subscriptions.is_empty() {
                readers.remove(&tenant);
            }
        }
    }
}

#[derive(Clone)]
pub struct InputSubscription {
    pub(in crate::analysis) _registration: Arc<InputRegistration>,
    pub(in crate::analysis) changes: watch::Receiver<StorePositionV1>,
    pub(in crate::analysis) meta: AnalysisStoreMetaV1,
    #[cfg(feature = "native-store")]
    pub(in crate::analysis) native: Option<super::native::inputs::Wake>,
}

impl InputSubscription {
    pub fn meta(&self) -> &AnalysisStoreMetaV1 {
        &self.meta
    }

    pub fn observed_meta(&mut self, meta: &AnalysisStoreMetaV1, publication: u64) {
        let revision = self
            .meta
            .commit_revision
            .max(meta.commit_revision)
            .max(publication);
        self.meta = meta.clone();
        self.meta.commit_revision = revision;
    }

    pub fn position(&self) -> StorePositionV1 {
        *self.changes.borrow()
    }

    pub fn observe(&mut self) -> StorePositionV1 {
        *self.changes.borrow_and_update()
    }

    pub async fn changed(&mut self) -> Result<StorePositionV1> {
        #[cfg(feature = "native-store")]
        if let Some(native) = &mut self.native {
            native.changed(&mut self.changes).await?;
            return Ok(self.observe());
        }
        self.changes
            .changed()
            .await
            .map_err(|_| crate::PackageErrorCodeV1::Incomplete.error("input journal progress"))?;
        Ok(self.observe())
    }
}

impl InputChanges {
    #[cfg(feature = "native-store")]
    pub(in crate::analysis) fn is_empty(&self) -> bool {
        self.readers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_empty()
    }

    #[cfg(feature = "native-store")]
    pub(in crate::analysis) fn interested(&self, change: InputChange<'_>) -> bool {
        self.readers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&change.tenant())
            .is_some_and(|readers| {
                readers
                    .values()
                    .any(|reader| reader.interest.matches(&change))
            })
    }

    #[cfg(feature = "native-store")]
    pub(in crate::analysis) fn raw(&self, entry: &super::raw::RawEntry) {
        let readers = self
            .readers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(readers) = readers.get(&entry.identity.tenant()) {
            for reader in readers.values() {
                for span in &entry.commit.spans {
                    if let Some(position) = reader.interest.raw_position(entry, span) {
                        reader.advance(position);
                    }
                }
            }
        }
    }

    pub(super) fn metadata(&self, revision: u64, change: InputChange<'_>) {
        self.publish(
            StorePositionV1 {
                commit_revision: revision,
                ordinal: u32::MAX,
            },
            change,
        );
    }

    pub(super) fn contexts(&self, revision: u64, references: &[AnalysisContextRefV1]) {
        for reference in references
            .iter()
            .filter(|reference| reference.commit_revision == revision)
        {
            self.metadata(revision, InputChange::Context(&reference.key));
        }
    }

    pub(in crate::analysis) fn register(&self, owner: &Arc<InputWatch>) -> Arc<InputRegistration> {
        self.readers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entry(owner.interest.selection.tenant_id)
            .or_default()
            .insert(Arc::as_ptr(owner) as usize, Arc::clone(owner));
        Arc::new(InputRegistration {
            readers: Arc::downgrade(&self.readers),
            watch: Arc::clone(owner),
        })
    }

    pub(super) fn publish(&self, position: StorePositionV1, change: InputChange<'_>) {
        let tenant = change.tenant();
        let readers = self
            .readers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(readers) = readers.get(&tenant) {
            for reader in readers.values() {
                if reader.interest.matches(&change) {
                    reader.advance(position);
                }
            }
        }
    }
}

impl InputWatch {
    fn advance(&self, position: StorePositionV1) {
        if position.commit_revision > self.after {
            self.changes.send_if_modified(|current| {
                if position > *current {
                    *current = position;
                    true
                } else {
                    false
                }
            });
        }
    }
}

impl AnalysisStore {
    pub fn subscribe_inputs(
        &self,
        selection: &AnalysisSelectionV1,
        requests: &AnalysisTableRequests,
        owners: Option<&BTreeSet<String>>,
        control: &AnalysisReadControl,
        budget: &dyn crate::ManagedBudget,
    ) -> Result<InputSubscription> {
        let memory = managed::PreparedMemory::new(control, budget)?;
        let lease = memory.reserve(InputInterest::allocation_bytes(selection, requests, owners))?;
        let interest = InputInterest::new(selection.clone(), requests.clone(), owners.cloned())?;
        let (changes, receiver) = watch::channel(StorePositionV1 {
            commit_revision: 0,
            ordinal: 0,
        });
        let owner = Arc::new(InputWatch {
            interest,
            changes,
            after: 0,
            _memory: lease,
        });
        let registration = self.inputs.register(&owner);
        let (meta, position) = owner.interest.head(self, control, &memory)?;
        owner.changes.send_if_modified(|current| {
            if position > *current {
                *current = position;
                true
            } else {
                false
            }
        });
        Ok(InputSubscription {
            _registration: registration,
            changes: receiver,
            meta,
            #[cfg(feature = "native-store")]
            native: None,
        })
    }
}

impl InputChange<'_> {
    fn tenant(&self) -> [u8; 16] {
        match self {
            Self::Raw { identity, .. } | Self::Removal { identity, .. } => identity.tenant(),
            Self::Context(key) => key.tenant_id,
            Self::Processor(scope) | Self::Profile { scope, .. } | Self::Notice { scope, .. } => {
                scope.identity.tenant_id
            }
            Self::Graph { tenant, .. }
            | Self::Publication { tenant, .. }
            | Self::Trace { tenant, .. } => *tenant,
        }
    }
}
