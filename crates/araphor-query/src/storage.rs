#[cfg(feature = "native-store")]
pub(crate) use araphor_data::analysis::native::{
    ManagedGraphJournal, ManagedGraphTransaction, NativeStore as AnalysisStore,
};
#[cfg(not(feature = "native-store"))]
pub(crate) use araphor_data::{AnalysisStore, ManagedGraphJournal, ManagedGraphTransaction};
