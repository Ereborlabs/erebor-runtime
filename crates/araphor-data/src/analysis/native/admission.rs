use super::NativeStore;
use crate::{AnalysisReadControl, Result};

impl NativeStore {
    pub fn check_trace_reads(
        &self,
        tenant: [u8; 16],
        requests: &[[u8; 16]],
        control: &AnalysisReadControl,
    ) -> Result<()> {
        self.check()?;
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
