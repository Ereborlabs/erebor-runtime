use std::sync::Arc;

use tokio::sync::watch;

use crate::{AnalysisSelectionV1, Result};

#[derive(Clone, Debug)]
pub struct QueryGrant {
    pub principal: String,
    pub revision: u64,
    pub selection: AnalysisSelectionV1,
}

/// Control checks current identity and tenant permission. This interface grants no authority.
pub trait QueryAuthorization: Send + Sync + 'static {
    fn check(&self, grant: &QueryGrant) -> Result<()>;
    fn changes(&self) -> watch::Receiver<u64>;
    fn expires_ns(&self) -> Option<u64>;
}

#[derive(Clone)]
pub(super) struct QuerySession {
    pub authority: Arc<dyn QueryAuthorization>,
    pub grant: Arc<QueryGrant>,
}

impl QuerySession {
    pub(super) fn check(&self) -> Result<()> {
        self.authority.check(&self.grant)
    }
}

impl QueryGrant {
    pub(super) fn validate(&self) -> Result<()> {
        if self.principal.is_empty()
            || self.principal.len() > 256
            || self.principal.chars().any(char::is_control)
            || !self.selection.valid()
        {
            return crate::QueryDeniedSnafu.fail();
        }
        Ok(())
    }
}
