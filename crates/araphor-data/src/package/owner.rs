use std::sync::Arc;

use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;
use tokio::sync::watch;

use crate::{AnalysisReadControl, AnalysisStore, PackageEncodingSnafu, QueryOwner, Result};

use super::{
    AnalysisPackageOwner, PackageActionV1, PackageAuthorization, PackageErrorCodeV1 as Code,
    PackageGrantV1, PackageReadinessV1, PackageRefV1, PackageRequestV1, PackageResponseV1,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum ClockDependency {
    None,
    Inputs,
    Model,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct InstalledContext {
    pub grant: PackageGrantV1,
    pub root: PackageRefV1,
    pub parameters: Option<serde_json::Value>,
    pub readiness: PackageReadinessV1,
    pub status_checkpoint: u64,
    pub prepared: bool,
    pub clock: ClockDependency,
}

pub(super) struct PackageTask {
    pub control: Arc<AnalysisReadControl>,
}

impl Drop for PackageTask {
    fn drop(&mut self) {
        let _cancelled = self.control.cancel();
    }
}

impl AnalysisPackageOwner {
    pub(super) const RECONCILE_INTERVAL: std::time::Duration =
        std::time::Duration::from_millis(500);

    pub fn new(
        store: Arc<AnalysisStore>,
        query: Arc<QueryOwner>,
        authority: Arc<dyn PackageAuthorization>,
    ) -> Result<Self> {
        {
            let _lifecycle = store
                .package_lifecycle
                .lock()
                .map_err(|_| Code::Conflict.error("package lifecycle lock"))?;
            store.collect_package_admissions()?;
        }
        let wasm = super::wasm::WasmExecution::new(*query.wasm_limits())?;
        let native = super::native::NativeExecution::new(query.native_limits())?;
        Ok(Self {
            lifecycle: store.package_lifecycle.clone(),
            store,
            query,
            authority,
            operations: Arc::new(tokio::sync::Semaphore::new(4)),
            wasm,
            native,
        })
    }

    pub async fn execute(
        self: &Arc<Self>,
        grant: PackageGrantV1,
        request: PackageRequestV1,
        control: Arc<AnalysisReadControl>,
    ) -> Result<PackageResponseV1> {
        let action = request.action();
        self.check(&grant, action)?;
        let control = Self::grant_control(&grant, control)?;
        let permit = self.operation()?;
        let owner = self.clone();
        let saved = grant.clone();
        let stage = control.clone();
        let task = PackageTask { control };
        let mut changes = self.authority.changes();
        let mut run = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            owner.execute_sync(saved, request, &stage)
        });
        tokio::select! {
            result = &mut run => {
                let result = result.context(crate::QueryExecutionSnafu)??;
                self.check(&grant, action)?;
                Ok(result)
            }
            _change = changes.changed() => {
                task.control.cancel()?;
                Err(Code::Denied.error("package authority changed"))
            }
            () = tokio::time::sleep(task.control.remaining()?) => {
                self.check(&grant, action)?;
                task.control.check()?;
                Err(crate::AnalysisReadDeadlineSnafu.build())
            }
        }
    }

    pub(crate) fn execute_sync(
        &self,
        grant: PackageGrantV1,
        request: PackageRequestV1,
        control: &AnalysisReadControl,
    ) -> Result<PackageResponseV1> {
        control.check()?;
        let _lifecycle = if matches!(
            &request,
            PackageRequestV1::Install { .. }
                | PackageRequestV1::Update { .. }
                | PackageRequestV1::Rollback { .. }
                | PackageRequestV1::Remove { .. }
        ) {
            Some(
                self.lifecycle
                    .lock()
                    .map_err(|_| Code::Conflict.error("package lifecycle lock"))?,
            )
        } else {
            None
        };
        control.check()?;
        match request {
            PackageRequestV1::Install {
                scope_id,
                bundle,
                parameters,
            } => self.install(&grant, &scope_id, &bundle, parameters, false, control),
            PackageRequestV1::Update { scope_id, bundle } => {
                self.install(&grant, &scope_id, &bundle, None, true, control)
            }
            PackageRequestV1::Inspect {
                scope_id,
                package_id,
            } => self.inspect(&grant, &scope_id, &package_id, None, control),
            PackageRequestV1::Run {
                scope_id,
                package_id,
                export,
                evaluation_id,
                parameters,
            } => self.run(
                &grant,
                super::evaluation::PackageRun {
                    scope: &scope_id,
                    package: &package_id,
                    export: export.as_deref(),
                    id: &evaluation_id,
                    parameters,
                },
                control,
            ),
            PackageRequestV1::Rollback {
                scope_id,
                package_id,
                revision,
            } => {
                let root = PackageRefV1 {
                    package_id,
                    revision,
                };
                let bundle = self.load_bundle(grant.selection.tenant_id, &root)?;
                self.install(&grant, &scope_id, &bundle, None, true, control)
            }
            PackageRequestV1::Remove {
                scope_id,
                package_id,
            } => self.remove(&grant, &scope_id, &package_id, control),
            PackageRequestV1::Test {
                scope_id,
                package_id,
                fixture,
            } => self.test_package(&grant, &scope_id, &package_id, fixture.as_deref(), control),
            PackageRequestV1::Query {
                scope_id,
                package_id,
                export,
                result_id,
                sql,
            } => self.query_output(
                &grant,
                super::inspect::PackageQuery {
                    scope: &scope_id,
                    package: &package_id,
                    export: &export,
                    id: result_id.as_deref(),
                    sql: &sql,
                },
                control,
            ),
        }
    }

    pub(super) fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> Result<()> {
        if grant.principal.is_empty()
            || grant.principal.len() > 256
            || grant.revision == 0
            || !grant.selection.valid()
            || grant
                .expires_utc_ns
                .is_some_and(|expires| expires <= Self::now())
        {
            return Err(Code::Denied.error("package grant"));
        }
        self.authority.check(grant, action)
    }

    pub(super) fn now() -> u64 {
        u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos()).unwrap_or(0)
    }

    pub(super) fn grant_control(
        grant: &PackageGrantV1,
        control: Arc<AnalysisReadControl>,
    ) -> Result<Arc<AnalysisReadControl>> {
        let Some(expiry) = grant.expires_utc_ns else {
            return Ok(control);
        };
        let remaining = std::time::Duration::from_nanos(expiry.saturating_sub(Self::now()).max(1));
        Ok(Arc::new(
            control.within(remaining.min(control.remaining()?))?,
        ))
    }

    pub(super) fn operation(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        self.operations.clone().try_acquire_owned().map_err(|_| {
            crate::AnalysisBusySnafu {
                resource: "package operation capacity",
            }
            .build()
        })
    }

    pub(super) fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
        serde_json::to_vec(value).context(PackageEncodingSnafu)
    }

    pub(super) fn authorize_commit<T>(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &super::PackageBundleRef<'_>,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let mut operation = Some(operation);
        let mut result = None;
        self.authority.commit(grant, action, bundle, &mut || {
            let operation = operation
                .take()
                .ok_or_else(|| Code::Invalid.error("commit callback"))?;
            result = Some(operation()?);
            Ok(())
        })?;
        result.ok_or_else(|| Code::Denied.error("commit authority"))
    }

    pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        serde_json::from_slice(bytes).context(PackageEncodingSnafu)
    }

    pub async fn serve(self: Arc<Self>, mut stop: watch::Receiver<bool>) -> Result<()> {
        let mut sources = self.store.subscribe_revision();
        let mut authority = self.authority.changes();
        let mut admitted = None;
        let mut checked = None;
        loop {
            if *stop.borrow() {
                return Ok(());
            }
            let revision = *authority.borrow_and_update();
            let source_revision = *sources.borrow_and_update();
            let (complete, deadline) = self
                .reconcile_until(
                    &mut stop,
                    admitted != Some(revision),
                    checked != Some(source_revision),
                )
                .await?;
            if complete {
                admitted = Some(revision);
                checked = Some(source_revision);
            }
            if *stop.borrow() || stop.has_changed().is_err() {
                return Ok(());
            }
            let wakeup = async {
                if deadline == u64::MAX {
                    std::future::pending::<()>().await;
                } else {
                    tokio::time::sleep(std::time::Duration::from_nanos(
                        deadline.saturating_sub(Self::now()),
                    ))
                    .await;
                }
            };
            tokio::select! {
                changed = stop.changed() => { if changed.is_err() { return Ok(()); } }
                changed = sources.changed() => { if changed.is_err() { return Ok(()); } }
                changed = authority.changed() => { if changed.is_err() { return Ok(()); } }
                () = wakeup => {}
            }
        }
    }
}
