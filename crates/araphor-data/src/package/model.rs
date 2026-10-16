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
