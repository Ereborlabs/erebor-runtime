use std::env;

const MAX_HANDLERS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InterceptionHandler {
    pub(super) id: String,
    executables: Vec<String>,
}

impl InterceptionHandler {
    pub(super) fn new(id: String, executables: Vec<String>) -> Self {
        Self { id, executables }
    }

    fn matches_executable(&self, invoked: &str) -> bool {
        self.executables
            .iter()
            .any(|executable| executable == invoked)
    }
}

pub(super) struct InterceptionHandlers {
    handlers: Vec<InterceptionHandler>,
}

impl InterceptionHandlers {
    pub(super) fn from_environment() -> Self {
        let source = env::var("EREBOR_PROCESS_INTERCEPTION_HANDLERS").unwrap_or_default();
        Self::parse(&source)
    }

    fn parse(source: &str) -> Self {
        let handlers = source
            .lines()
            .take(MAX_HANDLERS)
            .filter_map(Self::parse_line)
            .collect();
        Self { handlers }
    }

    fn parse_line(line: &str) -> Option<InterceptionHandler> {
        let fields = line.split('\t').collect::<Vec<_>>();
        let id = fields.first().copied().unwrap_or_default();
        if id.is_empty() {
            return None;
        }
        let executables = match fields.as_slice() {
            // Current format: id<TAB>executable[,executable]
            [_id, executables] => Self::split_csv(executables),
            // Compatibility format: id<TAB>decision<TAB>kind<TAB>executables...
            [_id, _decision, _kind, executables, ..] => Self::split_csv(executables),
            _ => Vec::new(),
        };
        if executables.is_empty() {
            return None;
        }

        Some(InterceptionHandler::new(id.to_owned(), executables))
    }

    fn split_csv(source: &str) -> Vec<String> {
        source
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    }

    pub(super) fn matching(&self, invoked: &str) -> Option<&InterceptionHandler> {
        self.handlers
            .iter()
            .find(|handler| handler.matches_executable(invoked))
    }
}

#[cfg(test)]
mod tests {
    use super::InterceptionHandlers;

    #[test]
    fn parses_process_interception_handler_environment_format_for_matching_only() {
        let handlers = InterceptionHandlers::parse(
            "managed-browser-cdp\tgoogle-chrome,chromium\nlegacy\tmediate\tmanaged_browser_cdp\tchrome\t9222\tws://127.0.0.1:9222/\ttrue\tfalse\n",
        );

        assert_eq!(handlers.handlers.len(), 2);
        assert_eq!(handlers.handlers[0].id, "managed-browser-cdp");
        assert_eq!(
            handlers.handlers[0].executables,
            vec![String::from("google-chrome"), String::from("chromium")]
        );
        assert_eq!(handlers.handlers[1].id, "legacy");
        assert_eq!(
            handlers.handlers[1].executables,
            vec![String::from("chrome")]
        );
    }
}
