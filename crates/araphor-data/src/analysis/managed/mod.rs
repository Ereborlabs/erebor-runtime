mod budget;
mod capture;
mod changes;
mod codec;

mod contract;
mod execution;
pub(in crate::analysis) mod graph;


mod model;
mod packet;

pub(in crate::analysis) use packet::Packet;





mod reference;


mod selected;
pub(in crate::analysis) mod source;
mod status;

pub(in crate::analysis) use status::{Failure, FailureOrigin};


pub use budget::ManagedBudget;
pub(in crate::analysis) use budget::PreparedMemory;
pub use execution::ManagedExecution;


pub use model::*;
pub use source :: { InputProof , ManagedDerivedSource , ManagedInputSelection , ManagedSourceBlock , ManagedSourceFrame , ManagedSourceHistory , ManagedSourceRead , ManagedSourceRef , ManagedSourceRows , ResolvedInput , SourceScope } ;

#[cfg(test)]
mod tests;


