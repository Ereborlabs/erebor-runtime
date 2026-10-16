use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use erebor_runtime_error::{ErrorExt as _, StatusCode};
use snafu::IntoError as _;

use crate::analysis::PackageActivationV1;
use crate::{AnalysisReadControl, Result};

use super::installed::snapshot::InstalledBundle;
use super::owner::{InstalledContext, PackageTask};
use super::{
    AnalysisPackageOwner, PackageActionV1 as Action, PackageErrorCodeV1 as Code, PackageReadinessV1,
};

#[cfg(test)]
mod tests;

impl AnalysisPackageOwner {
    #[cfg(test)]
    pub(super) async fn reconcile(self: &Arc<Self>) -> Result<()> {
        let (_stop, mut receiver) = tokio::sync::watch::channel(false);
        self.reconcile_until(&mut receiver, true, true)
            .await
            .map(|_| ())
    }

    pub(super) async fn reconcile_until(
        self: &Arc<Self>,
        stop: &mut tokio::sync::watch::Receiver<bool>,
        refresh: bool,
        changed: bool,
    ) -> Result<(bool, u64)> {
        let (mut complete, mut deadline) = (true, u64::MAX);
        let mut after = None;
        loop {
            if *stop.borrow() || stop.has_changed().is_err() {
                return Ok((false, deadline));
            }
            let store = self.store.clone();
            let cursor = after.clone();
            let page =
                tokio::task::spawn_blocking(move || store.package_activation_page(cursor.as_ref()))
                    .await
                    .map_err(|source| crate::AnalysisExecutionSnafu.into_error(source))??;
            if page.is_empty() {
                break;
            }
            after = page.last().map(|active| active.key.clone());
            let mut groups = BTreeMap::new();
            for active in page {
                let context: InstalledContext = Self::decode(&active.metadata)?;
                groups
                    .entry((
                        active.key.tenant_id,
                        active.key.scope_id.clone(),
                        context.root,
                    ))
                    .or_insert_with(Vec::new)
                    .push(active);
            }
            for group in groups.into_values() {
                if *stop.borrow() || stop.has_changed().is_err() {
                    return Ok((false, deadline));
                }
                let owner = self.clone();
                let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(
                    30 * (group.len() as u64 + 1),
                ))?);
                let _task = PackageTask {
                    control: control.clone(),
                };
                let stage = control.clone();
                let mut changes = self.authority.changes();
                let mut run = tokio::task::spawn_blocking(move || {
                    owner.reconcile_group(group, refresh, changed, &stage)
                });
                let result = tokio::select! {
                    result = &mut run => result.map_err(|source| crate::AnalysisExecutionSnafu.into_error(source))?,
                    _changed = stop.changed() => {
                        control.cancel()?;
                        let _result = run.await.map_err(|source| crate::AnalysisExecutionSnafu.into_error(source))?;
                        return Ok((false, deadline));
                    }
                    _changed = changes.changed() => {
                        control.cancel()?;
                        let _result = run.await.map_err(|source| crate::AnalysisExecutionSnafu.into_error(source))?;
                        return Ok((false, Self::now()));
                    }
                };
                match result {
                    Ok((admitted, next)) => {
                        complete &= admitted;
                        deadline = deadline.min(next);
                    }
                    Err(_) => {
                        complete = false;
                        deadline = deadline.min(
                            Self::now().saturating_add(Self::RECONCILE_INTERVAL.as_nanos() as u64),
                        );
                    }
                }
            }
        }
        Ok((complete, deadline))
    }

    fn reconcile_group(
        &self,
        group: Vec<PackageActivationV1>,
        refresh: bool,
        changed: bool,
        control: &AnalysisReadControl,
    ) -> Result<(bool, u64)> {
        control.check()?;
        self.prune_orphans(&group[0])?;
        let (mut complete, mut deadline) = (true, u64::MAX);
        let mut bundle = None::<Arc<InstalledBundle>>;
        for selected in group {
            control.check()?;
            let Some(active) = self
                .store
                .package_activation(&selected.key)?
                .filter(|active| active.active)
            else {
                continue;
            };
            let context: InstalledContext = Self::decode(&active.metadata)?;
            let now = Self::now();
            let stage = Arc::new(control.within(Duration::from_secs(30))?);
            let result = (|| -> Result<()> {
                self.check(&context.grant, Action::Run)?;
                if let Some(expires) = context.grant.expires_utc_ns {
                    deadline = deadline.min(expires);
                }
                if !context.prepared {
                    let (current, next) =
                        self.inputs_current(&active, context.clock, now, changed, &stage)?;
                    deadline = deadline.min(next);
                    if !refresh && current {
                        return Ok(());
                    }
                } else if !refresh {
                    return Ok(());
                }
                let _permit = self.operation()?;
                if bundle
                    .as_ref()
                    .is_none_or(|bundle| bundle.value.root != context.root)
                {
                    bundle = None;
                    bundle = Some(self.load_installed(active.key.tenant_id, &context.root)?);
                }
                let bundle = bundle
                    .as_ref()
                    .ok_or_else(|| Code::Missing.error("installed bundle"))?;
                let admission = bundle.admission();
                self.authority.admit(&context.grant, &admission)?;
                stage.check()?;
                let artifact = bundle.value.artifact(&super::PackageRefV1 {
                    package_id: active.key.package_id.clone(),
                    revision: active.revision.clone(),
                })?;
                let model = artifact
                    .descriptor
                    .exports
                    .iter()
                    .find(|model| model.name == active.key.export)
                    .ok_or_else(|| Code::Missing.error("installed export"))?;
                if context.prepared != artifact.prepared(&active.key.export)
                    || context.clock != bundle.clock(artifact, model)?
                {
                    return Err(Code::Invalid.error("activation model flags").into());
                }
                if !context.prepared {
                    let stage = Self::grant_control(&context.grant, stage.clone())?;
                    self.evaluate_active(&active, "automatic", true, bundle, &stage)?;
                }
                Ok(())
            })();
            if let Err(error) = result {
                stage.check()?;
                complete &= error.status_code() == StatusCode::PermissionDenied;
                deadline =
                    deadline.min(now.saturating_add(Self::RECONCILE_INTERVAL.as_nanos() as u64));
                if !error.is_busy() {
                    self.failed(&active, &error, &stage)?;
                    if error.status_code() == StatusCode::PermissionDenied {
                        let _lifecycle = self
                            .lifecycle
                            .lock()
                            .map_err(|_| Code::Conflict.error("package lifecycle lock"))?;
                        self.store
                            .suspend_package(&active.key, active.generation, || stage.check())?;
                    }
                }
            }
        }
        Ok((complete, deadline))
    }

    pub(super) fn failed(
        &self,
        active: &PackageActivationV1,
        error: &crate::Error,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let mut context: InstalledContext = Self::decode(&active.metadata)?;
        let code = error.package_code();
        context.readiness = PackageReadinessV1::Failed {
            code,
            field: "model evaluation".into(),
        };
        context.status_checkpoint = active.checkpoint_revision;
        self.store
            .fail_package(active, &Self::encode(&context)?, || control.check())
            .map_err(Into::into)
    }
}
