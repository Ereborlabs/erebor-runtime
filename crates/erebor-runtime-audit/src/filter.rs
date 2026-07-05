mod matcher;
mod surfaces;
#[cfg(test)]
mod tests;

use erebor_runtime_core::{AuditError, AuditRecord, AuditSink, RuntimeAuditConfig};

use surfaces::AuditSurfaceFilter;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditFilter<'a> {
    audit: &'a RuntimeAuditConfig,
}

impl<'a> AuditFilter<'a> {
    #[must_use]
    pub const fn new(audit: &'a RuntimeAuditConfig) -> Self {
        Self { audit }
    }

    #[must_use]
    pub fn should_record(self, record: &AuditRecord) -> bool {
        AuditSurfaceFilter::new(self.audit.surfaces()).should_record(record)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilteredAuditSink<S> {
    inner: S,
    audit: RuntimeAuditConfig,
}

impl<S> FilteredAuditSink<S> {
    #[must_use]
    pub const fn new(inner: S, audit: RuntimeAuditConfig) -> Self {
        Self { inner, audit }
    }

    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    #[must_use]
    pub const fn audit(&self) -> &RuntimeAuditConfig {
        &self.audit
    }

    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> AuditSink for FilteredAuditSink<S>
where
    S: AuditSink,
{
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        if AuditFilter::new(&self.audit).should_record(record) {
            self.inner.record(record)?;
        }
        Ok(())
    }
}
