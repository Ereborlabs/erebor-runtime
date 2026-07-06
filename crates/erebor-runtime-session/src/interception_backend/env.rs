use erebor_runtime_core::{
    AuditCommandLogLevel, ProcessInterceptionHandlerConfig, ProcessInterceptionHandlerKind,
};

pub(crate) fn audit_command_level_env(level: AuditCommandLogLevel) -> &'static str {
    match level {
        AuditCommandLogLevel::All => "all",
        AuditCommandLogLevel::Signal => "signal",
        AuditCommandLogLevel::NonAllow => "non_allow",
    }
}

pub(crate) fn process_interception_executable_env(
    handler: &ProcessInterceptionHandlerConfig,
) -> Vec<String> {
    if !handler.environment().executable_env().is_empty() {
        return handler.environment().executable_env().to_vec();
    }

    match handler.kind() {
        ProcessInterceptionHandlerKind::ManagedBrowserCdp => [
            "CHROME_PATH",
            "BROWSER",
            "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH",
            "PUPPETEER_EXECUTABLE_PATH",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    }
}

pub(crate) fn interception_env_field(value: impl AsRef<str>) -> String {
    value
        .as_ref()
        .chars()
        .map(|character| match character {
            '\t' | '\n' | '\r' => ' ',
            character => character,
        })
        .collect()
}
