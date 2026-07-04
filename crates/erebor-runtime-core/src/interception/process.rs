use super::SurfaceInterceptionDecision;

#[derive(Clone, Copy, Debug)]
pub struct ProcessExecInterceptionRequest<'a> {
    executable: &'a str,
    argv: &'a [String],
    matched_handler_id: &'a str,
}

impl<'a> ProcessExecInterceptionRequest<'a> {
    #[must_use]
    pub const fn new(executable: &'a str, argv: &'a [String], matched_handler_id: &'a str) -> Self {
        Self {
            executable,
            argv,
            matched_handler_id,
        }
    }

    #[must_use]
    pub const fn executable(&self) -> &'a str {
        self.executable
    }

    #[must_use]
    pub const fn argv(&self) -> &'a [String] {
        self.argv
    }

    #[must_use]
    pub const fn matched_handler_id(&self) -> &'a str {
        self.matched_handler_id
    }
}

pub trait ProcessExecSurfaceHandler: Send + Sync {
    fn surface(&self) -> &str;
    fn decide_process_exec(
        &self,
        request: &ProcessExecInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision;
}
