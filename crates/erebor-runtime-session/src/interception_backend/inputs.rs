use erebor_runtime_core::{AuditCommandLogLevel, ProcessInterceptionHandlerConfig};

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
    audit_level: AuditCommandLogLevel,
    audit_debug_commands: Vec<String>,
    tty: bool,
}

impl<'a> ProcessExecInterceptionInput<'a> {
    pub(crate) fn new(
        mediation: ProcessExecMediationInput<'a>,
        audit_level: AuditCommandLogLevel,
        audit_debug_commands: Vec<String>,
        tty: bool,
    ) -> Self {
        Self {
            mediation,
            audit_level,
            audit_debug_commands,
            tty,
        }
    }

    pub(crate) const fn mediation(&self) -> &ProcessExecMediationInput<'a> {
        &self.mediation
    }

    pub(crate) const fn audit_level(&self) -> AuditCommandLogLevel {
        self.audit_level
    }

    pub(crate) fn audit_debug_commands(&self) -> &[String] {
        &self.audit_debug_commands
    }

    pub(crate) const fn tty(&self) -> bool {
        self.tty
    }
}
