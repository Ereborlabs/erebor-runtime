use snafu::ensure;

use crate::{error::InvalidSessionWorkIdSnafu, Result};

const SESSION_WORK_REF_PREFIX: &str = "erebor/session-work";

#[derive(Clone, Copy)]
pub(super) struct SessionWorkSessionId<'a> {
    value: &'a str,
}

impl<'a> SessionWorkSessionId<'a> {
    pub(super) fn new(value: &'a str) -> Result<Self> {
        SessionWorkIdValidator::new("session id", value).validate()?;
        Ok(Self { value })
    }

    pub(super) const fn as_str(self) -> &'a str {
        self.value
    }

    pub(super) fn ref_prefix(self) -> String {
        format!("{SESSION_WORK_REF_PREFIX}/{}", self.value)
    }

    pub(super) fn transaction_id(self, sequence: u64) -> String {
        format!("{}.work-{sequence:06}", self.value)
    }
}

#[derive(Clone, Copy)]
pub(super) struct SessionWorkTransactionId<'a> {
    value: &'a str,
}

impl<'a> SessionWorkTransactionId<'a> {
    pub(super) fn new(value: &'a str) -> Result<Self> {
        SessionWorkIdValidator::new("transaction id", value).validate()?;
        Ok(Self { value })
    }

    pub(super) fn manifest_ref(self, session_id: SessionWorkSessionId<'_>) -> String {
        format!(
            "{SESSION_WORK_REF_PREFIX}/{}/{}/manifest",
            session_id.as_str(),
            self.value
        )
    }

    pub(super) fn sequence(self, session_id: SessionWorkSessionId<'_>) -> Option<u64> {
        self.value
            .strip_prefix(session_id.as_str())?
            .strip_prefix(".work-")?
            .parse()
            .ok()
    }
}

pub(super) struct SessionWorkRefParser<'a> {
    session_id: SessionWorkSessionId<'a>,
}

impl<'a> SessionWorkRefParser<'a> {
    pub(super) const fn new(session_id: SessionWorkSessionId<'a>) -> Self {
        Self { session_id }
    }

    pub(super) fn transaction_id_from_manifest_ref(&self, ref_name: &str) -> Option<String> {
        ref_name
            .strip_prefix(&format!("{}/", self.session_id.ref_prefix()))?
            .strip_suffix("/manifest")
            .map(ToOwned::to_owned)
    }
}

struct SessionWorkIdValidator<'a> {
    field: &'static str,
    value: &'a str,
}

impl<'a> SessionWorkIdValidator<'a> {
    const fn new(field: &'static str, value: &'a str) -> Self {
        Self { field, value }
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            !self.value.is_empty(),
            InvalidSessionWorkIdSnafu {
                field: self.field,
                value: self.value.to_owned(),
                reason: String::from("must not be empty"),
            }
        );
        ensure!(
            self.value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            InvalidSessionWorkIdSnafu {
                field: self.field,
                value: self.value.to_owned(),
                reason: String::from(
                    "must contain only ASCII letters, digits, dot, underscore, or dash",
                ),
            }
        );
        Ok(())
    }
}
