use super::NativeStore;
use crate::analysis::read::ReadPermit;
use crate::analysis::TraceReadPermit;
use crate::{AnalysisReadControl, Result};

impl NativeStore {
    pub(crate) fn reserve_reader(&self) -> Result<ReadPermit> {
        self.check()?;
        ReadPermit::acquire(
            self.storage.reader_admissions,
            self.read_slots.as_ref(),
            &self.capacity,
        )
    }

    pub fn reserve_trace_read(&self) -> Result<TraceReadPermit> {
        self.reserve_reader().map(TraceReadPermit)
    }

    pub fn subscribe_capacity(&self) -> tokio::sync::watch::Receiver<()> {
        self.capacity.subscribe()
    }

    pub async fn wait_capacity(&self) -> Result<()> {
        let mut capacity = self.subscribe_capacity();
        loop {
            capacity.borrow_and_update();
            match self.reserve_reader() {
                Ok(permit) => {
                    drop(permit);
                    return Ok(());
                }
                Err(crate::Error::AnalysisBusy {
                    resource: "reader", ..
                }) => (),
                Err(error) => return Err(error),
            }
            capacity.changed().await.map_err(|_| {
                crate::NativeStateSnafu {
                    field: "reader capacity channel",
                }
                .build()
            })?;
        }
    }

    pub fn check_trace_reads(
        &self,
        tenant: [u8; 16],
        requests: &[[u8; 16]],
        control: &AnalysisReadControl,
        _permit: TraceReadPermit,
    ) -> Result<()> {
        self.check_trace_authority(tenant, requests, control)
    }

    pub(in crate::analysis::native) fn check_trace_authority(
        &self,
        tenant: [u8; 16],
        requests: &[[u8; 16]],
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if requests.is_empty() {
            return control.check();
        }
        self.view()?.check_trace_reads(tenant, requests, control)
    }
}
