use std::fmt;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u32)]
pub enum StatusCode {
    Success = 0,
    Unknown = 1000,
    Unsupported = 1001,
    Unexpected = 1002,
    Internal = 1003,
    InvalidArguments = 1004,
    InvalidSyntax = 1005,
    NotFound = 1006,
    AlreadyExists = 1007,
    PolicyDenied = 1008,
    PermissionDenied = 1009,
    Cancelled = 1010,
    DeadlineExceeded = 1011,
    IllegalState = 1012,
    Unavailable = 1013,
    External = 1014,
}

impl StatusCode {
    pub const ALL: [Self; 16] = [
        Self::Success,
        Self::Unknown,
        Self::Unsupported,
        Self::Unexpected,
        Self::Internal,
        Self::InvalidArguments,
        Self::InvalidSyntax,
        Self::NotFound,
        Self::AlreadyExists,
        Self::PolicyDenied,
        Self::PermissionDenied,
        Self::Cancelled,
        Self::DeadlineExceeded,
        Self::IllegalState,
        Self::Unavailable,
        Self::External,
    ];

    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn is_success(code: u32) -> bool {
        Self::Success as u32 == code
    }

    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Success),
            1000 => Some(Self::Unknown),
            1001 => Some(Self::Unsupported),
            1002 => Some(Self::Unexpected),
            1003 => Some(Self::Internal),
            1004 => Some(Self::InvalidArguments),
            1005 => Some(Self::InvalidSyntax),
            1006 => Some(Self::NotFound),
            1007 => Some(Self::AlreadyExists),
            1008 => Some(Self::PolicyDenied),
            1009 => Some(Self::PermissionDenied),
            1010 => Some(Self::Cancelled),
            1011 => Some(Self::DeadlineExceeded),
            1012 => Some(Self::IllegalState),
            1013 => Some(Self::Unavailable),
            1014 => Some(Self::External),
            _ => None,
        }
    }

    #[must_use]
    pub const fn should_log_error(self) -> bool {
        matches!(
            self,
            Self::Unknown
                | Self::Unexpected
                | Self::Internal
                | Self::Cancelled
                | Self::DeadlineExceeded
                | Self::IllegalState
                | Self::Unavailable
                | Self::External
        )
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "Success",
            Self::Unknown => "Unknown",
            Self::Unsupported => "Unsupported",
            Self::Unexpected => "Unexpected",
            Self::Internal => "Internal",
            Self::InvalidArguments => "InvalidArguments",
            Self::InvalidSyntax => "InvalidSyntax",
            Self::NotFound => "NotFound",
            Self::AlreadyExists => "AlreadyExists",
            Self::PolicyDenied => "PolicyDenied",
            Self::PermissionDenied => "PermissionDenied",
            Self::Cancelled => "Cancelled",
            Self::DeadlineExceeded => "DeadlineExceeded",
            Self::IllegalState => "IllegalState",
            Self::Unavailable => "Unavailable",
            Self::External => "External",
        }
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::StatusCode;

    #[test]
    fn status_code_round_trips_from_u32() {
        for code in StatusCode::ALL {
            assert_eq!(StatusCode::from_u32(code.as_u32()), Some(code));
        }

        assert_eq!(StatusCode::from_u32(9999), None);
    }

    #[test]
    fn success_detection_uses_success_code_only() {
        assert!(StatusCode::is_success(StatusCode::Success.as_u32()));
        assert!(!StatusCode::is_success(StatusCode::Unknown.as_u32()));
        assert!(!StatusCode::is_success(1));
    }

    #[test]
    fn status_code_display_uses_variant_name() {
        assert_eq!(StatusCode::Success.to_string(), "Success");
        assert_eq!(StatusCode::PolicyDenied.to_string(), "PolicyDenied");
        assert_eq!(StatusCode::InvalidArguments.to_string(), "InvalidArguments");
    }

    #[test]
    fn expected_user_statuses_do_not_request_error_logs() {
        assert!(!StatusCode::PolicyDenied.should_log_error());
        assert!(!StatusCode::InvalidArguments.should_log_error());
        assert!(!StatusCode::PermissionDenied.should_log_error());
        assert!(StatusCode::Internal.should_log_error());
        assert!(StatusCode::External.should_log_error());
    }
}
