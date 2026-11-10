#[cfg(feature = "native-store")]
pub(crate) use araphor_data::analysis::native::{
    ActivationSubscription, ManagedCommit, ManagedLease, ManagedReturn,
    NativeStore as AnalysisStore,
};
#[cfg(not(feature = "native-store"))]
pub(crate) use araphor_data::{AnalysisStore, ManagedCommit, ManagedLease, ManagedReturn};
#[cfg(not(feature = "native-store"))]
pub(crate) type ActivationSubscription = tokio::sync::watch::Receiver<u64>;
