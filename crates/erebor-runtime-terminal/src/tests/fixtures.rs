use erebor_runtime_core::{ProcessExecInterceptionRequest, SurfaceMediationDecision};

use crate::TerminalProcessMediationCapability;

pub(crate) struct TestMediationCapability;

impl TerminalProcessMediationCapability for TestMediationCapability {
    fn mediate_process_exec(
        &self,
        _request: &ProcessExecInterceptionRequest<'_>,
        handler: &erebor_runtime_core::ProcessMediationHandlerConfig,
    ) -> Result<SurfaceMediationDecision, String> {
        Ok(SurfaceMediationDecision::new(
            handler.kind().as_str(),
            "browser_cdp",
            "ws://127.0.0.1:9222/",
        ))
    }
}
