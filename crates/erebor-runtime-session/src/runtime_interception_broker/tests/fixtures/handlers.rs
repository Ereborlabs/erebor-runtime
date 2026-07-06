use erebor_runtime_core::{
    FileInterceptionRequest, FileOperationSurfaceHandler, ProcessExecInterceptionRequest,
    ProcessExecSurfaceHandler, SocketConnectInterceptionRequest, SocketConnectSurfaceHandler,
    SurfaceInterceptionDecision, SurfaceMediationDecision,
};

pub(crate) struct TestProcessExecHandler;

pub(crate) struct TestProcessExecDecisionHandler;

pub(crate) struct TestProcessExecMediationHandler;

pub(crate) struct MatchedHandlerProcessExecHandler;

pub(crate) struct TestFileHandler;

pub(crate) struct TestSocketConnectHandler;

impl ProcessExecSurfaceHandler for TestProcessExecHandler {
    fn surface(&self) -> &str {
        "terminal"
    }

    fn decide_process_exec(
        &self,
        _request: &ProcessExecInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        SurfaceInterceptionDecision::deny("test-process-exec-deny", "dangerous process execution")
    }
}

impl ProcessExecSurfaceHandler for TestProcessExecDecisionHandler {
    fn surface(&self) -> &str {
        "terminal"
    }

    fn decide_process_exec(
        &self,
        request: &ProcessExecInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        match request.matched_handler_id() {
            "allow-tool" => SurfaceInterceptionDecision::allow("allow-tool", "safe tool"),
            "deny-tool" => SurfaceInterceptionDecision::deny("deny-tool", "dangerous tool"),
            "approve-tool" => {
                SurfaceInterceptionDecision::require_approval("approve-tool", "needs approval")
            }
            "mediate-tool" => SurfaceInterceptionDecision::mediate(
                "mediate-tool",
                "route to replacement surface",
                SurfaceMediationDecision::new("future_api", "browser_cdp", "local://replacement"),
            ),
            handler_id => SurfaceInterceptionDecision::deny(
                "test-process-exec-unknown-handler",
                format!("unexpected handler id `{handler_id}`"),
            ),
        }
    }
}

impl ProcessExecSurfaceHandler for TestProcessExecMediationHandler {
    fn surface(&self) -> &str {
        "terminal"
    }

    fn decide_process_exec(
        &self,
        _request: &ProcessExecInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        SurfaceInterceptionDecision::mediate(
            "test-process-exec-mediate",
            "process execution mediated by surface handler",
            SurfaceMediationDecision::new(
                "managed_browser_cdp",
                "browser_cdp",
                "ws://127.0.0.1:9222/",
            )
            .with_lease_id("surface-lease")
            .with_print_line("DevTools listening on ws://127.0.0.1:9222/devtools/browser/surface")
            .with_keepalive(true),
        )
    }
}

impl ProcessExecSurfaceHandler for MatchedHandlerProcessExecHandler {
    fn surface(&self) -> &str {
        "terminal"
    }

    fn decide_process_exec(
        &self,
        request: &ProcessExecInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        SurfaceInterceptionDecision::deny(
            "matched-handler-id-visible",
            request.matched_handler_id(),
        )
    }
}

impl FileOperationSurfaceHandler for TestFileHandler {
    fn surface(&self) -> &str {
        "filesystem"
    }

    fn decide_file_operation(
        &self,
        request: &FileInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        SurfaceInterceptionDecision::deny(
            "filesystem-file-read-visible",
            format!("{}@{}:{}", request.path(), request.cwd(), request.pid()),
        )
    }
}

impl SocketConnectSurfaceHandler for TestSocketConnectHandler {
    fn surface(&self) -> &str {
        "network"
    }

    fn decide_socket_connect(
        &self,
        request: &SocketConnectInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        SurfaceInterceptionDecision::deny(
            "network-socket-connect-visible",
            format!(
                "{}://{}:{}",
                request.scheme(),
                request.host(),
                request.port()
            ),
        )
    }
}
