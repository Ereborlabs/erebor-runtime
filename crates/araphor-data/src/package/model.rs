use std::time::{Duration, SystemTime, UNIX_EPOCH};

use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::{AnalysisSelectionV1, Result};

use super::{PackageBundleRef, PackageBundleV1};

mod request;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageErrorCodeV1 {
    Invalid,
    Limit,
    Denied,
    Conflict,
    Missing,
    Unsupported,
    Incomplete,
}

impl PackageErrorCodeV1 {
    pub fn error(self, field: &'static str) -> crate::Error {
        crate::PackageSnafu { code: self, field }.build()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageArtifactIdentityV1 {
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closure_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

impl PackageArtifactIdentityV1 {
    pub fn allocated_bytes(&self) -> usize {
        self.digest.capacity()
            + self.closure_digest.as_ref().map_or(0, String::capacity)
            + self.platform.as_ref().map_or(0, String::capacity)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageGrantV1 {
    pub principal: String,
    pub revision: u64,
    pub selection: AnalysisSelectionV1,
    pub expires_utc_ns: Option<u64>,
    pub authorization_id: Option<String>,
}

impl PackageGrantV1 {
    pub fn remaining(&self) -> Result<Option<Duration>> {
        if self.principal.is_empty()
            || self.principal.len() > 256
            || self.revision == 0
            || !self.selection.valid()
        {
            return Err(PackageErrorCodeV1::Denied.error("package grant"));
        }
        let Some(expiry) = self.expires_utc_ns else {
            return Ok(None);
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| u64::try_from(time.as_nanos()).ok())
            .ok_or_else(|| PackageErrorCodeV1::Incomplete.error("system time"))?;
        let remaining = expiry
            .checked_sub(now)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(|| PackageErrorCodeV1::Denied.error("package grant"))?;
        Ok(Some(Duration::from_nanos(remaining)))
    }

    pub fn permitted_by(&self, selection: &AnalysisSelectionV1) -> Result<()> {
        if *selection != self.selection
            && *selection != AnalysisSelectionV1::tenant(self.selection.tenant_id)
        {
            return Err(PackageErrorCodeV1::Denied.error("whole package scope"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ClockDependency {
    None,
    Inputs,
    Model,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstalledContext {
    pub grant: PackageGrantV1,
    pub root: super::PackageRefV1,
    pub parameters: Option<serde_json::Value>,
    pub readiness: PackageReadinessV1,
    pub status_checkpoint: u64,
    pub prepared: bool,
    pub clock: ClockDependency,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResultContext {
    #[serde(default = "ResultContext::sql_target")]
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<PackageArtifactIdentityV1>,
    pub context: sdk::EvaluationContext,
    pub inputs: Vec<sdk::Revision>,
    pub input_coverage: Vec<sdk::Coverage>,
    pub coverage: sdk::Coverage,
}

impl ResultContext {
    fn sql_target() -> String {
        "sql".into()
    }

    pub fn matches(&self, inputs: &[sdk::Input]) -> bool {
        self.inputs
            .iter()
            .eq(inputs.iter().map(|input| &input.revision))
            && self
                .input_coverage
                .iter()
                .eq(inputs.iter().map(|input| &input.coverage))
    }

    pub fn new(id: &str, now: u64, model: &sdk::Model, inputs: &[sdk::Input]) -> Self {
        let input_coverage: Vec<_> = inputs.iter().map(|input| input.coverage.clone()).collect();
        let (mut state, mut limits) = (sdk::CoverageState::Complete, Vec::new());
        for coverage in &input_coverage {
            if coverage.state == sdk::CoverageState::Unknown
                || (coverage.state == sdk::CoverageState::Gapped
                    && state == sdk::CoverageState::Complete)
            {
                state = coverage.state;
            }
            limits.extend(coverage.limits.iter().cloned());
        }
        limits.sort();
        limits.dedup();
        Self {
            target: Self::sql_target(),
            artifact: None,
            context: sdk::EvaluationContext {
                id: id.into(),
                time_utc_ns: now as i64,
                seed: None,
                limits: model.limits,
            },
            inputs: inputs.iter().map(|input| input.revision.clone()).collect(),
            input_coverage,
            coverage: sdk::Coverage { state, limits },
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageActionV1 {
    Inspect,
    Install,
    Run,
    Update,
    Rollback,
    Remove,
    Test,
}

pub trait PackageAuthorization: Send + Sync + 'static {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> Result<()>;
    fn admit(&self, grant: &PackageGrantV1, bundle: &PackageBundleRef<'_>) -> Result<()>;
    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &PackageBundleRef<'_>,
        operation: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()>;
    fn changes(&self) -> watch::Receiver<u64>;

    fn changes_for(&self, _grant: &PackageGrantV1) -> watch::Receiver<u64> {
        self.changes()
    }

    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, &PackageBundleRef<'_>)],
        action: PackageActionV1,
        operation: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let [(grant, bundle)] = grants else {
            return Err(PackageErrorCodeV1::Unsupported.error("atomic package authority set"));
        };
        self.commit(grant, action, bundle, operation)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum PackageRequestV1 {
    Install {
        scope_id: String,
        #[serde(skip_serializing)]
        bundle: PackageBundleV1,
        parameters: Option<serde_json::Value>,
    },
    Inspect {
        scope_id: String,
        package_id: String,
    },
    Run {
        scope_id: String,
        package_id: String,
        export: Option<String>,
        evaluation_id: String,
        parameters: Option<serde_json::Value>,
    },
    Update {
        scope_id: String,
        #[serde(skip_serializing)]
        bundle: PackageBundleV1,
    },
    Rollback {
        scope_id: String,
        package_id: String,
        revision: String,
    },
    Remove {
        scope_id: String,
        package_id: String,
    },
    Test {
        scope_id: String,
        package_id: String,
        fixture: Option<String>,
    },
    Query {
        scope_id: String,
        package_id: String,
        export: String,
        result_id: Option<String>,
        sql: String,
    },
}

impl PackageRequestV1 {
    pub fn action(&self) -> PackageActionV1 {
        match self {
            Self::Install { .. } => PackageActionV1::Install,
            Self::Inspect { .. } | Self::Query { .. } => PackageActionV1::Inspect,
            Self::Run { .. } => PackageActionV1::Run,
            Self::Update { .. } => PackageActionV1::Update,
            Self::Rollback { .. } => PackageActionV1::Rollback,
            Self::Remove { .. } => PackageActionV1::Remove,
            Self::Test { .. } => PackageActionV1::Test,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageResponseV1 {
    pub scope_id: String,
    pub package_id: String,
    pub exports: Vec<PackageExportStatusV1>,
    pub tests: Vec<PackageTestResultV1>,
    pub output: Option<sdk::wire::Output>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageExportStatusV1 {
    pub descriptor: sdk::Model,
    pub revision: String,
    pub targets: Vec<String>,
    pub readiness: PackageReadinessV1,
    pub active: bool,
    pub activation_revision: u64,
    pub results: Vec<PackageReceiptV1>,
    pub fixtures: Vec<String>,
}

impl PackageExportStatusV1 {
    pub fn new(
        artifact: &super::PackageArtifactV1,
        model: &sdk::Model,
        active: &crate::analysis::PackageActivationV1,
        readiness: PackageReadinessV1,
        results: Vec<PackageReceiptV1>,
    ) -> Self {
        Self {
            descriptor: model.clone(),
            revision: active.revision.clone(),
            targets: artifact
                .implementations
                .iter()
                .filter(|target| target.implements(&model.name))
                .map(|target| target.target().into())
                .collect(),
            readiness,
            active: active.active,
            activation_revision: active.generation,
            results,
            fixtures: artifact
                .fixtures
                .iter()
                .filter(|fixture| fixture.export == model.name)
                .map(|fixture| fixture.name.clone())
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PackageReadinessV1 {
    Ready,
    Inactive,
    MissingInput {
        input: String,
    },
    Unsupported {
        target: String,
    },
    Failed {
        code: PackageErrorCodeV1,
        field: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageReceiptV1 {
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<PackageArtifactIdentityV1>,
    pub result_id: String,
    pub commit_revision: u64,
    pub input_revisions: Vec<sdk::Revision>,
    pub coverage: sdk::Coverage,
    pub stale: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageTestResultV1 {
    pub fixture: String,
    pub passed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> PackageGrantV1 {
        PackageGrantV1 {
            principal: "fixture".into(),
            revision: 1,
            selection: AnalysisSelectionV1::tenant([1; 16]),
            expires_utc_ns: None,
            authorization_id: None,
        }
    }

    #[test]
    fn grant_has_optional_deadline() -> Result<()> {
        let mut grant = grant();
        assert_eq!(grant.remaining()?, None);
        grant.principal = "x".repeat(256);
        grant.expires_utc_ns = Some(u64::MAX);
        assert!(grant
            .remaining()?
            .is_some_and(|remaining| !remaining.is_zero()));
        Ok(())
    }

    #[test]
    fn grant_rejects_invalid_shapes() {
        for case in 0..4 {
            let mut grant = grant();
            match case {
                0 => grant.principal.clear(),
                1 => grant.principal = "x".repeat(257),
                2 => grant.revision = 0,
                _ => grant.selection.tenant_id = [0; 16],
            }
            assert!(matches!(
                grant.remaining(),
                Err(crate::Error::Package {
                    code: PackageErrorCodeV1::Denied,
                    field: "package grant",
                    ..
                })
            ));
        }
    }

    #[test]
    fn grant_rejects_expired_deadline() {
        let mut grant = grant();
        for expired in [0, 1] {
            grant.expires_utc_ns = Some(expired);
            assert!(matches!(
                grant.remaining(),
                Err(crate::Error::Package {
                    code: PackageErrorCodeV1::Denied,
                    field: "package grant",
                    ..
                })
            ));
        }
    }
}
