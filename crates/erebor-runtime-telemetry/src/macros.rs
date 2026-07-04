#[macro_export]
macro_rules! log {
    ($level:expr, $($arg:tt)+) => {{
        $crate::tracing::event!($level, $($arg)+)
    }};
}

#[macro_export]
macro_rules! error {
    (%$err:expr; $message:literal $(, $field:ident = %$value:expr)* $(,)?) => {{
        $crate::log!(
            $crate::tracing::Level::ERROR,
            error = %$err,
            $($field = %$value,)*
            $message
        )
    }};

    ($err:expr; $message:literal $(, $field:ident = %$value:expr)* $(,)?) => {{
        $crate::log!(
            $crate::tracing::Level::ERROR,
            error = ?$err,
            $($field = %$value,)*
            $message
        )
    }};

    ($message:literal $(, $field:ident = %$value:expr)+ $(,)?) => {{
        $crate::log!(
            $crate::tracing::Level::ERROR,
            $($field = %$value,)*
            $message
        )
    }};

    ($($arg:tt)+) => {{
        $crate::log!($crate::tracing::Level::ERROR, $($arg)+)
    }};
}

#[macro_export]
macro_rules! warn {
    ($err:expr; $message:literal $(, $field:ident = %$value:expr)* $(,)?) => {{
        $crate::log!(
            $crate::tracing::Level::WARN,
            error = ?$err,
            $($field = %$value,)*
            $message
        )
    }};

    ($message:literal $(, $field:ident = %$value:expr)+ $(,)?) => {{
        $crate::log!(
            $crate::tracing::Level::WARN,
            $($field = %$value,)*
            $message
        )
    }};

    ($($arg:tt)+) => {{
        $crate::log!($crate::tracing::Level::WARN, $($arg)+)
    }};
}

#[macro_export]
macro_rules! info {
    ($message:literal $(, $field:ident = %$value:expr)+ $(,)?) => {{
        $crate::log!(
            $crate::tracing::Level::INFO,
            $($field = %$value,)*
            $message
        )
    }};

    ($($arg:tt)+) => {{
        $crate::log!($crate::tracing::Level::INFO, $($arg)+)
    }};
}

#[macro_export]
macro_rules! debug {
    ($message:literal $(, $field:ident = %$value:expr)+ $(,)?) => {{
        $crate::log!(
            $crate::tracing::Level::DEBUG,
            $($field = %$value,)*
            $message
        )
    }};

    ($($arg:tt)+) => {{
        $crate::log!($crate::tracing::Level::DEBUG, $($arg)+)
    }};
}

#[macro_export]
macro_rules! trace {
    ($message:literal $(, $field:ident = %$value:expr)+ $(,)?) => {{
        $crate::log!(
            $crate::tracing::Level::TRACE,
            $($field = %$value,)*
            $message
        )
    }};

    ($($arg:tt)+) => {{
        $crate::log!($crate::tracing::Level::TRACE, $($arg)+)
    }};
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fmt;

    #[derive(Debug)]
    struct TestError;

    impl fmt::Display for TestError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("test error")
        }
    }

    impl Error for TestError {}

    #[test]
    fn error_macro_supports_message_fields_and_error_fields() {
        let err = TestError;
        let value = 42;

        crate::error!("plain error message", field = %value);
        crate::error!(err; "debug error message", field = %value);
        crate::error!(%err; "display error message", field = %value);
    }

    #[test]
    fn warn_macro_supports_message_fields_and_error_fields() {
        let err = TestError;
        let value = "value";

        crate::warn!("warning message", field = %value);
        crate::warn!(err; "warning with error", field = %value);
    }

    #[test]
    fn level_macros_support_message_fields() {
        let value = "value";

        crate::info!("info message", field = %value);
        crate::debug!("debug message", field = %value);
        crate::trace!("trace message", field = %value);
    }
}
