use std::sync::Arc;
use std::time::Duration;

use erebor_runtime_error::{ErrorExt as _, StatusCode};
use snafu::IntoError as _;

use crate::analysis::PackageActivationV1;
use crate::{AnalysisReadControl, Result};

use super::owner::{InstalledContext, PackageTask};
use super::{
    AnalysisPackageOwner, PackageActionV1 as Action, PackageErrorCodeV1 as Code, PackageReadinessV1,
};

impl AnalysisPackageOwner {
    pub(super) async fn reconcile(self: &Arc<Self>) -> Result<()> {
        let mut after = None;
        loop {
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
            for active in page {
                let owner = self.clone();
                let Some(active) =
                    tokio::task::spawn_blocking(move || owner.prune_orphans(&active))
                        .await
                        .map_err(|source| crate::QueryExecutionSnafu.into_error(source))??
                else {
                    continue;
                };
                if !active.active {
                    continue;
                }
                let permit = match self.operation() {
                    Ok(permit) => permit,
                    Err(crate::Error::AnalysisBusy { .. }) => return Ok(()),
                    Err(error) => return Err(error),
                };
                let context: InstalledContext = Self::decode(&active.metadata)?;
                let owner = self.clone();
                let check = self.check(&context.grant, Action::Run).and_then(|()| {
                    let bundle = self.load_bundle(active.key.tenant_id, &context.root)?;
                    self.authority.admit(&context.grant, &bundle)?;
                    Ok(bundle)
                });
                let bundle = match check {
                    Ok(bundle) => bundle,
                    Err(error) => {
                        self.failed(&active, &error)?;
                        if error.status_code() == StatusCode::PermissionDenied {
                            let _lifecycle = self
                                .lifecycle
                                .lock()
                                .map_err(|_| Code::Conflict.error("package lifecycle lock"))?;
                            self.store.suspend_package(
                                &active.key,
                                active.generation,
                                || Ok(()),
                            )?;
                        }
                        continue;
                    }
                };
                if bundle
                    .artifact(&super::PackageRefV1 {
                        package_id: active.key.package_id.clone(),
                        revision: active.revision.clone(),
                    })?
                    .prepared(&active.key.export)
                {
                    continue;
                }
                let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?);
                let control = Self::grant_control(&context.grant, control)?;
                let _task = PackageTask {
                    control: control.clone(),
                };
                let mut changes = self.authority.changes();
                let stage = control.clone();
                let mut run = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    owner.evaluate_active(&active, "automatic", true, Some(&bundle), &stage)
                });
                tokio::select! {
                    result = &mut run => { let _result = result.map_err(|source| crate::QueryExecutionSnafu.into_error(source))?; }
                    _changed = changes.changed() => { control.cancel()?; }
                }
            }
        }
        Ok(())
    }

    pub(super) fn failed(&self, active: &PackageActivationV1, error: &crate::Error) -> Result<()> {
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
            .fail_package(active, &Self::encode(&context)?, || Ok(()))
    }
}
