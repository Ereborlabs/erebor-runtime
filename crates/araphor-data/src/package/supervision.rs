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
    ) -> Result<bool> {
        let mut complete = true;
        let mut after = None;
        loop {
            if *stop.borrow() || stop.has_changed().is_err() {
                return Ok(false);
            }
            let store = self.store.clone();
            let cursor = after.clone();
            let page =
                tokio::task::spawn_blocking(move || store.package_activation_page(cursor.as_ref()))
                    .await
                    .map_err(|source| crate::QueryExecutionSnafu.into_error(source))??;
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
                    return Ok(false);
                }
                let owner = self.clone();
                let selected = group[0].clone();
                tokio::task::spawn_blocking(move || owner.prune_orphans(&selected))
                    .await
                    .map_err(|source| crate::QueryExecutionSnafu.into_error(source))??;
                let mut bundle = None::<Arc<InstalledBundle>>;
                for selected in group {
                    if *stop.borrow() || stop.has_changed().is_err() {
                        return Ok(false);
                    }
                    let permit = match self.operation() {
                        Ok(permit) => permit,
                        Err(crate::Error::AnalysisBusy { .. }) => return Ok(false),
                        Err(error) => return Err(error),
                    };
                    let owner = self.clone();
                    let control =
                        Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?);
                    let _task = PackageTask {
                        control: control.clone(),
                    };
                    let mut changes = self.authority.changes();
                    let stage = control.clone();
                    let known = bundle.take();
                    let mut run = tokio::task::spawn_blocking(
                        move || -> Result<(Option<Arc<InstalledBundle>>, bool)> {
                            let _permit = permit;
                            stage.check()?;
                            let Some(active) = owner
                                .store
                                .package_activation(&selected.key)?
                                .filter(|active| active.active)
                            else {
                                return Ok((known, true));
                            };
                            let context: InstalledContext = Self::decode(&active.metadata)?;
                            let checked = owner.check(&context.grant, Action::Run).and_then(|()| {
                                if !refresh
                                    && (context.prepared
                                        || owner.inputs_current(
                                            &active,
                                            context.clock,
                                            Self::now(),
                                            changed,
                                            &stage,
                                        )?)
                                {
                                    return Ok(known);
                                }
                                let bundle = match known {
                                    Some(bundle) if bundle.value.root == context.root => bundle,
                                    _ => InstalledBundle::new(
                                        &owner.query,
                                        owner.load_bundle(active.key.tenant_id, &context.root)?,
                                    )?,
                                };
                                stage.check()?;
                                let admission = bundle.admission();
                                owner.authority.admit(&context.grant, &admission)?;
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
                                    || context.clock != artifact.clock_dependency(model)?
                                {
                                    return Err(Code::Invalid.error("activation model flags"));
                                }
                                stage.check()?;
                                if !context.prepared {
                                    let stage = Self::grant_control(&context.grant, stage.clone())?;
                                    owner.evaluate_active(
                                        &active,
                                        "automatic",
                                        true,
                                        Some(&admission),
                                        &stage,
                                    )?;
                                }
                                Ok(Some(bundle))
                            });
                            match checked {
                                Ok(bundle) => Ok((bundle, true)),
                                Err(error) => {
                                    stage.check()?;
                                    owner.failed(&active, &error, &stage)?;
                                    if error.status_code() == StatusCode::PermissionDenied {
                                        let _lifecycle = owner.lifecycle.lock().map_err(|_| {
                                            Code::Conflict.error("package lifecycle lock")
                                        })?;
                                        owner.store.suspend_package(
                                            &active.key,
                                            active.generation,
                                            || stage.check(),
                                        )?;
                                    }
                                    Ok((None, error.status_code() == StatusCode::PermissionDenied))
                                }
                            }
                        },
                    );
                    tokio::select! {
                        result = &mut run => {
                            match result.map_err(|source| crate::QueryExecutionSnafu.into_error(source))? {
                                Ok((retained, admitted)) => { bundle = retained; complete &= admitted; }
                                Err(_) => complete = false,
                            }
                        }
                        _changed = stop.changed() => {
                            let cancelled = control.cancel();
                            let _result = run.await.map_err(|source| crate::QueryExecutionSnafu.into_error(source))?;
                            cancelled?;
                            if *stop.borrow() || stop.has_changed().is_err() { return Ok(false); }
                            complete = false;
                        }
                        _changed = changes.changed() => {
                            let cancelled = control.cancel();
                            let _result = run.await.map_err(|source| crate::QueryExecutionSnafu.into_error(source))?;
                            cancelled?;
                            complete = false;
                        }
                    }
                }
            }
        }
        Ok(complete)
    }

    pub(super) fn failed(
        &self,
        active: &PackageActivationV1,
        error: &crate::Error,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let mut context: InstalledContext = Self::decode(&active.metadata)?;
        let code = match error {
            crate::Error::Package { code, .. }
            | crate::Error::PackageWasm { code, .. }
            | crate::Error::PackageNative { code, .. } => *code,
            crate::Error::QueryLimit { .. } | crate::Error::AnalysisInputTooLarge { .. } => {
                Code::Limit
            }
            crate::Error::AnalysisContract { source, .. }
                if source.code() == araphor_analysis_sdk::ErrorCode::Limit =>
            {
                Code::Limit
            }
            _ => match error.status_code() {
                StatusCode::PermissionDenied => Code::Denied,
                StatusCode::Unsupported => Code::Unsupported,
                StatusCode::NotFound => Code::Missing,
                StatusCode::Unavailable | StatusCode::Cancelled | StatusCode::DeadlineExceeded => {
                    Code::Incomplete
                }
                StatusCode::AlreadyExists => Code::Conflict,
                _ => Code::Invalid,
            },
        };
        context.readiness = PackageReadinessV1::Failed {
            code,
            field: "model evaluation".into(),
        };
        context.status_checkpoint = active.checkpoint_revision;
        self.store
            .fail_package(active, &Self::encode(&context)?, || control.check())
    }
}
