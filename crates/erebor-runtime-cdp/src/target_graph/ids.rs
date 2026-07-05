use serde::Serialize;

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct BrowserTargetId(String);

impl BrowserTargetId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct ClientSessionId(String);

impl ClientSessionId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct FrameId(String);

impl FrameId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}
