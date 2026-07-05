use erebor_runtime_core::{
    AuditCommandLogLevel, AuditRecord, BrowserCdpAuditSurfaceLoggingConfig,
    DesktopAuditSurfaceLoggingConfig, FilesystemAuditSurfaceLoggingConfig,
    InternalSystemAuditSurfaceLoggingConfig, McpAuditSurfaceLoggingConfig,
    NetworkAuditSurfaceLoggingConfig, RuntimeAuditSurfaceLoggingConfig,
    SaaSAuditSurfaceLoggingConfig, TerminalAuditSurfaceLoggingConfig,
};
use erebor_runtime_events::ExecutionSurface;

use super::matcher::AuditDebugMatcher;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuditSurfaceFilter<'a> {
    surfaces: &'a RuntimeAuditSurfaceLoggingConfig,
}

impl<'a> AuditSurfaceFilter<'a> {
    pub(super) const fn new(surfaces: &'a RuntimeAuditSurfaceLoggingConfig) -> Self {
        Self { surfaces }
    }

    pub(super) fn should_record(self, record: &AuditRecord) -> bool {
        let matcher = AuditDebugMatcher::new(record);
        if matcher.is_signal_decision() {
            return true;
        }

        match record.event.surface {
            ExecutionSurface::BrowserCdp => self.browser_cdp(record, self.surfaces.browser_cdp()),
            ExecutionSurface::Mcp => self.mcp(record, self.surfaces.mcp()),
            ExecutionSurface::Terminal => self.terminal(record, self.surfaces.terminal()),
            ExecutionSurface::Filesystem => self.filesystem(record, self.surfaces.filesystem()),
            ExecutionSurface::Network => self.network(record, self.surfaces.network()),
            ExecutionSurface::SaaS => self.saas(record, self.surfaces.saas()),
            ExecutionSurface::Desktop => self.desktop(record, self.surfaces.desktop()),
            ExecutionSurface::InternalSystem => {
                self.internal_system(record, self.surfaces.internal_system())
            }
        }
    }

    fn terminal(self, record: &AuditRecord, logging: &TerminalAuditSurfaceLoggingConfig) -> bool {
        match logging.level() {
            AuditCommandLogLevel::All => true,
            AuditCommandLogLevel::NonAllow => false,
            AuditCommandLogLevel::Signal => {
                !AuditDebugMatcher::new(record).matches_terminal_command(logging.debug_commands())
            }
        }
    }

    fn browser_cdp(
        self,
        record: &AuditRecord,
        logging: &BrowserCdpAuditSurfaceLoggingConfig,
    ) -> bool {
        match logging.level() {
            AuditCommandLogLevel::All => true,
            AuditCommandLogLevel::NonAllow => false,
            AuditCommandLogLevel::Signal => !AuditDebugMatcher::new(record)
                .matches_browser_cdp(logging.debug_methods(), logging.debug_actions()),
        }
    }

    fn mcp(self, record: &AuditRecord, logging: &McpAuditSurfaceLoggingConfig) -> bool {
        match logging.level() {
            AuditCommandLogLevel::All => true,
            AuditCommandLogLevel::NonAllow => false,
            AuditCommandLogLevel::Signal => !AuditDebugMatcher::new(record)
                .matches_mcp(logging.debug_tools(), logging.debug_actions()),
        }
    }

    fn filesystem(
        self,
        record: &AuditRecord,
        logging: &FilesystemAuditSurfaceLoggingConfig,
    ) -> bool {
        self.operation(
            record,
            logging.level(),
            logging.debug_operations(),
            logging.debug_actions(),
        )
    }

    fn network(self, record: &AuditRecord, logging: &NetworkAuditSurfaceLoggingConfig) -> bool {
        self.operation(
            record,
            logging.level(),
            logging.debug_operations(),
            logging.debug_actions(),
        )
    }

    fn saas(self, record: &AuditRecord, logging: &SaaSAuditSurfaceLoggingConfig) -> bool {
        self.operation(
            record,
            logging.level(),
            logging.debug_operations(),
            logging.debug_actions(),
        )
    }

    fn desktop(self, record: &AuditRecord, logging: &DesktopAuditSurfaceLoggingConfig) -> bool {
        match logging.level() {
            AuditCommandLogLevel::All => true,
            AuditCommandLogLevel::NonAllow => false,
            AuditCommandLogLevel::Signal => {
                !AuditDebugMatcher::new(record).matches_action(logging.debug_actions())
            }
        }
    }

    fn internal_system(
        self,
        record: &AuditRecord,
        logging: &InternalSystemAuditSurfaceLoggingConfig,
    ) -> bool {
        self.operation(
            record,
            logging.level(),
            logging.debug_operations(),
            logging.debug_actions(),
        )
    }

    fn operation(
        self,
        record: &AuditRecord,
        level: AuditCommandLogLevel,
        debug_operations: &[String],
        debug_actions: &[String],
    ) -> bool {
        match level {
            AuditCommandLogLevel::All => true,
            AuditCommandLogLevel::NonAllow => false,
            AuditCommandLogLevel::Signal => {
                !AuditDebugMatcher::new(record).matches_operation(debug_operations, debug_actions)
            }
        }
    }
}
