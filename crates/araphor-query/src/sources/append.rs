use crate::storage::AnalysisStore;
use std::sync::{Arc, Mutex};

use araphor_data::{
    AnalysisAppendRead, AnalysisExtractLimits, AnalysisPositionPageV1, AnalysisReadControl,
    AnalysisSelectionV1, AnalysisStoreMetaV1, AnalysisTableRead, StorePositionV1,
};
use datafusion::common::{DataFusionError, Result};
use datafusion::execution::memory_pool::MemoryReservation;

pub(crate) struct AppendRead {
    state: Mutex<(AnalysisAppendRead, Option<MemoryReservation>)>,
    _metadata: MemoryReservation,
}

impl AppendRead {
    pub(crate) fn new(memory: &Arc<crate::memory::Memory>) -> Result<Arc<Self>> {
        let metadata = memory.reserve_input(std::mem::size_of::<Self>())?;
        Ok(Arc::new(Self {
            state: Mutex::new((AnalysisAppendRead::default(), None)),
            _metadata: metadata,
        }))
    }

    #[expect(clippy::too_many_arguments)]
    pub(super) fn read(
        &self,
        store: &AnalysisStore,
        selection: &AnalysisSelectionV1,
        scope: &AnalysisSelectionV1,
        read: AnalysisTableRead<'_>,
        after: Option<StorePositionV1>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        reservation: &MemoryReservation,
        data_error: impl Fn(araphor_data::Error) -> DataFusionError,
    ) -> Result<(AnalysisPositionPageV1, AnalysisStoreMetaV1)> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DataFusionError::Internal("the append reader is poisoned".into()))?;
        let (cursor, retained) = &mut *state;
        store
            .read_append_tables_filtered(
                selection,
                scope,
                read,
                after,
                limits,
                control,
                cursor,
                &mut |bytes| {
                    if limits.input_bytes == usize::MAX {
                        reservation.grow(bytes.saturating_sub(reservation.size()));
                    }
                    if bytes > reservation.size() {
                        return Err(araphor_data::Error::AnalysisInputTooLarge {
                            resource: "selected input bytes",
                            location: snafu::location!(),
                        });
                    }
                    *retained = (bytes != 0).then(|| reservation.split(bytes));
                    Ok(())
                },
            )
            .map_err(data_error)
    }
}
