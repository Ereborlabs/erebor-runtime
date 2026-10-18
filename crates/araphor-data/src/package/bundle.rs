use crate::{PackageBundleV1, Result};

pub struct PackageBundleRef<'a> {
    value: &'a PackageBundleV1,
    digest: std::borrow::Cow<'a, str>,
}

impl<'a> PackageBundleRef<'a> {
    pub fn new(value: &'a PackageBundleV1) -> Result<Self> {
        Ok(Self {
            value,
            digest: value.digest()?.into(),
        })
    }

    pub fn bundle(&self) -> &PackageBundleV1 {
        self.value
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn retained(value: &'a PackageBundleV1, digest: &'a str) -> Self {
        Self {
            value,
            digest: digest.into(),
        }
    }
}
