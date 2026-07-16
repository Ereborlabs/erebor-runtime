use erebor_runtime_core::ProcessInterceptionHandlerConfig;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FileOperationInterceptionInput {
    pub(crate) open: bool,
    pub(crate) read: bool,
    pub(crate) mutation: bool,
}

impl FileOperationInterceptionInput {
    pub(crate) const fn new(open: bool, read: bool, mutation: bool) -> Self {
        Self {
            open,
            read,
            mutation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessExecMediationMode {
    Shim,
}

pub(crate) struct ProcessExecMediationInput<'a> {
    enabled: bool,
    mode: ProcessExecMediationMode,
    handlers: &'a [ProcessInterceptionHandlerConfig],
}

impl<'a> ProcessExecMediationInput<'a> {
    pub(crate) const fn new(
        enabled: bool,
        mode: ProcessExecMediationMode,
        handlers: &'a [ProcessInterceptionHandlerConfig],
    ) -> Self {
        Self {
            enabled,
            mode,
            handlers,
        }
    }

    pub(crate) const fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) const fn ensure_supported_mode(&self) {
        match self.mode {
            ProcessExecMediationMode::Shim => {}
        }
    }

    pub(crate) fn handlers(&self) -> &[ProcessInterceptionHandlerConfig] {
        self.handlers
    }
}

pub(crate) struct ProcessExecInterceptionInput<'a> {
    mediation: ProcessExecMediationInput<'a>,
    tty: bool,
}

impl<'a> ProcessExecInterceptionInput<'a> {
    pub(crate) fn new(mediation: ProcessExecMediationInput<'a>, tty: bool) -> Self {
        Self { mediation, tty }
    }

    pub(crate) const fn mediation(&self) -> &ProcessExecMediationInput<'a> {
        &self.mediation
    }

    pub(crate) const fn tty(&self) -> bool {
        self.tty
    }
}
