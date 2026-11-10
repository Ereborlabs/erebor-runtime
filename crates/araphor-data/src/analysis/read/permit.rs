use std::sync::Arc;

pub(crate) struct ReadPermit {
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    capacity: tokio::sync::watch::Sender<()>,
}

impl ReadPermit {
    pub(in crate::analysis) fn acquire(
        limit: Option<usize>,
        slots: Option<&Arc<tokio::sync::Semaphore>>,
        capacity: &tokio::sync::watch::Sender<()>,
    ) -> crate::Result<Self> {
        if limit == Some(0) {
            return crate::StorageCapacitySnafu {
                resource: "reader admissions",
            }
            .fail();
        }
        let permit = slots
            .map(|slots| {
                Arc::clone(slots)
                    .try_acquire_owned()
                    .map_err(|_| crate::AnalysisBusySnafu { resource: "reader" }.build())
            })
            .transpose()?;
        Ok(Self {
            permit,
            capacity: capacity.clone(),
        })
    }
}

impl Drop for ReadPermit {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.capacity.send_replace(());
    }
}
