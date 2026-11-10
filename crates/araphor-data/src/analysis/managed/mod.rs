mod budget;
mod capture;
mod changes;
mod codec;
mod commit;
mod contract;
mod execution;
pub(in crate::analysis) mod graph;
mod history;
mod lifecycle;
mod model;
mod packet;
#[cfg(feature = "native-store")]
pub(in crate::analysis) use packet::Packet;
mod prepare;
pub use prepare::PreparedManagedCommit;
mod read;
mod reader;
pub(in crate::analysis) use reader::{CommittedOwners, OwnerRead};
mod reference;
mod removal;
mod schema;
mod selected;
pub(in crate::analysis) mod source;
mod status;
#[cfg(feature = "native-store")]
pub(in crate::analysis) use status::{Failure, FailureOrigin};
mod version;

pub use budget::ManagedBudget;
pub(in crate::analysis) use budget::PreparedMemory;
pub use execution::ManagedExecution;
pub use graph::{ManagedGraphJournal, ManagedGraphTransaction};
pub use lifecycle::ManagedLease;
pub use model::*;
pub(in crate::analysis) use source::publication::SourcePublication;
pub use source::{
    ManagedDerivedSource, ManagedInputSelection, ManagedSourceBlock, ManagedSourceFrame,
    ManagedSourceHistory, ManagedSourceRead, ManagedSourceRef, ManagedSourceRows, SourceScope,
};

#[cfg(test)]
mod tests;

mod terminal;
