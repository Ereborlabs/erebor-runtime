use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

use erebor_runtime_core::{AgentAdapterDescriptor, ImmutableIdentity, SessionSpec};
use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel};
use erebor_runtime_packages::{
    AgentPackageManifest, CanonicalEncoding, CodexPackageDefinition, ContentDigest,
    InstallationRecord, PolicyPackageRevision, PolicySetRevision, VerifiedLocalArtifact,
};
use erebor_runtime_policy::LocalPolicy;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{
    config::{RootCuratedAdmission, RootCuratedCodexPackage},
    error::{InvalidRequestSnafu, IoSnafu},
    DaemonPaths, Result,
};

/// Root-owned content reference indexes. A session lease keeps every immutable
/// identity named by a durable session reachable until that session is removed.
pub(crate) struct DaemonLocalStore {
    packages: PathBuf,
    users: PathBuf,
    write_lock: Mutex<()>,
}

/// Immutable package, installation, adapter, and policy-set facts resolved for
/// one session admission. The daemon derives these facts from its own store;
/// client-supplied digests merely select an already admitted record.
pub(crate) struct LocalAdmission {
    package: AgentPackageManifest,
    package_digest: String,
    installation_digest: String,
    adapter_digest: String,
    policy_set_digest: String,
    policy_input_digests: Vec<String>,
}

/// The exact root-curated Codex release selected before an explicit local
/// installation is enrolled. It is stored separately from the vendor binary
/// so no raw path can become a trusted package definition.
pub(crate) struct LocalCodexPackage {
    package: AgentPackageManifest,
    package_digest: String,
    definition: CodexPackageDefinition,
}

impl LocalCodexPackage {
    pub(crate) const fn package(&self) -> &AgentPackageManifest {
        &self.package
    }

    pub(crate) fn package_digest(&self) -> &str {
        &self.package_digest
    }

    pub(crate) const fn definition(&self) -> &CodexPackageDefinition {
        &self.definition
    }
}

/// One caller-owned, descriptor-verified Codex installation resolved from the
/// daemon store. Its embedded artifact facts must be re-proved from a held
/// descriptor before the daemon admits or starts a workload.
pub(crate) struct LocalCodexInstallation {
    package: LocalCodexPackage,
    installation: InstallationRecord,
    installation_digest: String,
    entrypoint: String,
}

impl LocalCodexInstallation {
    pub(crate) const fn package(&self) -> &LocalCodexPackage {
        &self.package
    }

    pub(crate) const fn installation(&self) -> &InstallationRecord {
        &self.installation
    }

    pub(crate) fn installation_digest(&self) -> &str {
        &self.installation_digest
    }

    pub(crate) fn entrypoint(&self) -> &str {
        &self.entrypoint
    }
}

pub(crate) struct BuiltInAdmission {
    package_digest: String,
    installation_digest: String,
    adapter_digest: String,
    policy_set_digest: String,
}

pub(crate) struct StoredPolicyPackage {
    name: String,
}

impl StoredPolicyPackage {
    fn new(revision: &PolicyPackageRevision) -> Self {
        Self {
            name: revision.manifest().name().to_owned(),
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

pub(crate) struct StoredPolicySet {
    name: String,
}

impl StoredPolicySet {
    fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

pub(crate) struct StoredSurface {
    name: String,
    surface_type: String,
}

impl StoredSurface {
    fn new(name: impl Into<String>, surface_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            surface_type: surface_type.into(),
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn surface_type(&self) -> &str {
        &self.surface_type
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct StaticSessionAdmission {
    session_name: String,
    agent_name: String,
    policy_set_name: String,
    surface_names: Vec<String>,
    agent_adapter: String,
    agent_integrity_digest: String,
    policy_set_integrity_digest: String,
    policy_package_integrity_digests: Vec<String>,
    surface_integrity_digests: Vec<String>,
}

impl StaticSessionAdmission {
    pub(crate) fn session_name(&self) -> &str {
        &self.session_name
    }

    pub(crate) fn agent_adapter(&self) -> &str {
        &self.agent_adapter
    }

    fn resource_spec(&self) -> StaticSessionResourceSpec {
        StaticSessionResourceSpec {
            agent: self.agent_name.clone(),
            policy_set: self.policy_set_name.clone(),
            surfaces: self.surface_names.clone(),
        }
    }

    fn resolution(&self) -> StaticSessionResolution {
        StaticSessionResolution {
            agent_integrity_digest: self.agent_integrity_digest.clone(),
            policy_set_integrity_digest: self.policy_set_integrity_digest.clone(),
            policy_package_integrity_digests: self.policy_package_integrity_digests.clone(),
            surface_integrity_digests: self.surface_integrity_digests.clone(),
        }
    }
}

pub(crate) struct StoredStaticSession {
    name: String,
    agent_name: String,
    policy_set_name: String,
    surface_names: Vec<String>,
}

impl StoredStaticSession {
    fn from_record(record: NamedResourceRecord) -> Result<Self> {
        let name = record.metadata.name.clone();
        let integrity_digest = record.validate("Session", &name)?;
        let NamedResourceSpec::Session(spec) = record.spec else {
            return InvalidRequestSnafu {
                reason: String::from("Session resource has an invalid spec"),
            }
            .fail();
        };
        let _integrity_digest = integrity_digest;
        Ok(Self {
            name,
            agent_name: spec.agent,
            policy_set_name: spec.policy_set,
            surface_names: spec.surfaces,
        })
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn agent_name(&self) -> &str {
        &self.agent_name
    }

    pub(crate) fn policy_set_name(&self) -> &str {
        &self.policy_set_name
    }

    pub(crate) fn surface_names(&self) -> &[String] {
        &self.surface_names
    }
}

struct SurfaceRegistry;

impl SurfaceRegistry {
    fn require_registered(surface: &ExecutionSurface, field: &str) -> Result<()> {
        if matches!(
            surface,
            ExecutionSurface::Terminal
                | ExecutionSurface::Filesystem
                | ExecutionSurface::Network
                | ExecutionSurface::BrowserCdp
        ) {
            return Ok(());
        }
        InvalidRequestSnafu {
            reason: format!(
                "{field} selects unregistered Surface `{}`",
                Self::surface_name(surface)
            ),
        }
        .fail()
    }

    fn validate_named_surface_type(surface_type: &str) -> Result<()> {
        match surface_type {
            "browser_cdp" => Ok(()),
            "terminal" | "filesystem" | "network" => InvalidRequestSnafu {
                reason: format!(
                    "Surface spec.type `{surface_type}` is intrinsic and has no named Surface record"
                ),
            }
            .fail(),
            _ => InvalidRequestSnafu {
                reason: format!("Surface spec.type `{surface_type}` is not registered"),
            }
            .fail(),
        }
    }

    fn surface_name(surface: &ExecutionSurface) -> &'static str {
        match surface {
            ExecutionSurface::Terminal => "terminal",
            ExecutionSurface::Filesystem => "filesystem",
            ExecutionSurface::BrowserCdp => "browser_cdp",
            ExecutionSurface::Mcp => "mcp",
            ExecutionSurface::Network => "network",
            ExecutionSurface::SaaS => "saas",
            ExecutionSurface::Desktop => "desktop",
            ExecutionSurface::InternalSystem => "internal_system",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedResourceRecord {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    metadata: NamedResourceMetadata,
    spec: NamedResourceSpec,
    integrity_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedResourceMetadata {
    name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
enum NamedResourceSpec {
    Agent(AgentResourceSpec),
    PolicyPackage(PolicyPackageResourceSpec),
    PolicySet(PolicySetResourceSpec),
    Surface(SurfaceResourceSpec),
    Session(StaticSessionResourceSpec),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentResourceSpec {
    adapter: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyPackageResourceSpec {
    rules: Vec<PolicyPackageRule>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyPackageRuleDocument {
    rules: Vec<PolicyPackageRule>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyPackageRule {
    id: String,
    #[serde(rename = "match")]
    matcher: PolicyPackageRuleMatch,
    decision: PolicyPackageDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mediation: Option<PolicyPackageMediation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyPackageRuleMatch {
    surface: Option<ExecutionSurface>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<ActionKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_contains: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_contains: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command_contains: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk_at_least: Option<RiskLevel>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PolicyPackageDecision {
    Allow,
    Deny,
    RequireApproval,
    Mediate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyPackageMediation {
    kind: PolicyPackageMediationKind,
    replacement_surface: ExecutionSurface,
    return_endpoint: PolicyPackageMediationReturnEndpoint,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PolicyPackageMediationKind {
    ManagedBrowserCdp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PolicyPackageMediationReturnEndpoint {
    RequestedPort,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicySetResourceSpec {
    packages: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SurfaceResourceSpec {
    #[serde(rename = "type")]
    surface_type: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticSessionResourceSpec {
    agent: String,
    #[serde(rename = "policySet")]
    policy_set: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    surfaces: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticSessionResolution {
    agent_integrity_digest: String,
    policy_set_integrity_digest: String,
    policy_package_integrity_digests: Vec<String>,
    surface_integrity_digests: Vec<String>,
}

struct ResolvedNamedAgent {
    adapter: String,
    integrity_digest: ContentDigest,
}

impl NamedResourceRecord {
    const API_VERSION: &'static str = "erebor.dev/v1";

    fn agent(name: &str, integrity_digest: &ContentDigest, adapter: &str) -> Result<Self> {
        if adapter.is_empty() {
            return InvalidRequestSnafu {
                reason: String::from("Agent spec.adapter must be explicit"),
            }
            .fail();
        }
        Ok(Self {
            api_version: Self::API_VERSION.to_owned(),
            kind: String::from("Agent"),
            metadata: NamedResourceMetadata {
                name: name.to_owned(),
            },
            spec: NamedResourceSpec::Agent(AgentResourceSpec {
                adapter: adapter.to_owned(),
            }),
            integrity_digest: integrity_digest.as_str().to_owned(),
        })
    }

    fn policy_package(
        name: &str,
        integrity_digest: &ContentDigest,
        spec: PolicyPackageResourceSpec,
    ) -> Result<Self> {
        spec.validate()?;
        Ok(Self {
            api_version: Self::API_VERSION.to_owned(),
            kind: String::from("PolicyPackage"),
            metadata: NamedResourceMetadata {
                name: name.to_owned(),
            },
            spec: NamedResourceSpec::PolicyPackage(spec),
            integrity_digest: integrity_digest.as_str().to_owned(),
        })
    }

    fn policy_set(
        name: &str,
        integrity_digest: &ContentDigest,
        packages: Vec<String>,
    ) -> Result<Self> {
        let spec = PolicySetResourceSpec { packages };
        spec.validate()?;
        Ok(Self {
            api_version: Self::API_VERSION.to_owned(),
            kind: String::from("PolicySet"),
            metadata: NamedResourceMetadata {
                name: name.to_owned(),
            },
            spec: NamedResourceSpec::PolicySet(spec),
            integrity_digest: integrity_digest.as_str().to_owned(),
        })
    }

    fn surface(name: &str, surface_type: &str) -> Result<Self> {
        let spec = SurfaceResourceSpec {
            surface_type: surface_type.to_owned(),
        };
        spec.validate()?;
        Ok(Self {
            api_version: Self::API_VERSION.to_owned(),
            kind: String::from("Surface"),
            metadata: NamedResourceMetadata {
                name: name.to_owned(),
            },
            integrity_digest: Self::integrity_digest_for_spec(&spec)?,
            spec: NamedResourceSpec::Surface(spec),
        })
    }

    fn session(name: &str, spec: StaticSessionResourceSpec) -> Result<Self> {
        spec.validate()?;
        Ok(Self {
            api_version: Self::API_VERSION.to_owned(),
            kind: String::from("Session"),
            metadata: NamedResourceMetadata {
                name: name.to_owned(),
            },
            integrity_digest: Self::integrity_digest_for_spec(&spec)?,
            spec: NamedResourceSpec::Session(spec),
        })
    }

    fn integrity_digest_for_spec(spec: &impl Serialize) -> Result<String> {
        let encoded = serde_json::to_vec(spec).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("encoding a named resource specification failed: {error}"),
            }
            .build()
        })?;
        Ok(ContentDigest::from_canonical_bytes(&encoded)
            .as_str()
            .to_owned())
    }

    fn validate(&self, expected_kind: &str, requested_name: &str) -> Result<ContentDigest> {
        if self.api_version != Self::API_VERSION
            || self.kind != expected_kind
            || self.metadata.name != requested_name
            || !DaemonLocalStore::is_path_component(&self.metadata.name)
        {
            return InvalidRequestSnafu {
                reason: format!(
                    "named resource does not match required apiVersion, kind, and metadata.name for {expected_kind}"
                ),
            }
            .fail();
        }
        match (expected_kind, &self.spec) {
            ("Agent", NamedResourceSpec::Agent(spec)) if !spec.adapter.is_empty() => {}
            ("PolicyPackage", NamedResourceSpec::PolicyPackage(spec)) => spec.validate()?,
            ("PolicySet", NamedResourceSpec::PolicySet(spec)) => spec.validate()?,
            ("Surface", NamedResourceSpec::Surface(spec)) => spec.validate()?,
            ("Session", NamedResourceSpec::Session(spec)) => spec.validate()?,
            ("Agent", NamedResourceSpec::Agent(_)) => {
                return InvalidRequestSnafu {
                    reason: String::from("Agent resource is missing explicit spec.adapter"),
                }
                .fail()
            }
            _ => {
                return InvalidRequestSnafu {
                    reason: format!("{expected_kind} resource has an invalid spec"),
                }
                .fail()
            }
        }
        DaemonLocalStore::parse_digest(&self.integrity_digest, expected_kind)
    }
}

impl SurfaceResourceSpec {
    fn validate(&self) -> Result<()> {
        SurfaceRegistry::validate_named_surface_type(&self.surface_type)
    }
}

impl StaticSessionResourceSpec {
    fn validate(&self) -> Result<()> {
        DaemonLocalStore::require_resource_name(&self.agent, "Session spec.agent")?;
        DaemonLocalStore::require_resource_name(&self.policy_set, "Session spec.policySet")?;
        let mut names = BTreeSet::new();
        for surface in &self.surfaces {
            if !DaemonLocalStore::is_path_component(surface) || !names.insert(surface.as_str()) {
                return InvalidRequestSnafu {
                    reason: format!(
                        "Session spec.surfaces name `{surface}` is invalid or duplicated"
                    ),
                }
                .fail();
            }
        }
        Ok(())
    }
}

impl PolicyPackageResourceSpec {
    fn from_revision(policy: &PolicyPackageRevision) -> Result<Self> {
        let mut rules = Vec::new();
        for (source_name, source) in policy.rules() {
            let document: PolicyPackageRuleDocument = serde_json::from_slice(source).map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!(
                        "policy package `{}` rule document `{source_name}` does not match the Phase 5.1 rule schema: {error}",
                        policy.manifest().name()
                    ),
                }
                .build()
            })?;
            rules.extend(document.rules);
        }
        let spec = Self { rules };
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<()> {
        if self.rules.is_empty() {
            return InvalidRequestSnafu {
                reason: String::from("PolicyPackage spec.rules must be non-empty"),
            }
            .fail();
        }
        let mut ids = BTreeSet::new();
        for rule in &self.rules {
            rule.validate()?;
            if !ids.insert(rule.id.as_str()) {
                return InvalidRequestSnafu {
                    reason: format!("PolicyPackage rule id `{}` is duplicated", rule.id),
                }
                .fail();
            }
        }
        Ok(())
    }
}

impl PolicyPackageRule {
    fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return InvalidRequestSnafu {
                reason: String::from("PolicyPackage rule id must be non-empty"),
            }
            .fail();
        }
        let surface = self.matcher.surface.as_ref().ok_or_else(|| {
            InvalidRequestSnafu {
                reason: format!(
                    "PolicyPackage rule `{}` must declare match.surface",
                    self.id
                ),
            }
            .build()
        })?;
        SurfaceRegistry::require_registered(
            surface,
            &format!("PolicyPackage rule `{}` match.surface", self.id),
        )?;
        if self.reason.as_deref().is_some_and(str::is_empty) {
            return InvalidRequestSnafu {
                reason: format!("PolicyPackage rule `{}` has an empty reason", self.id),
            }
            .fail();
        }
        match (self.decision, &self.mediation) {
            (PolicyPackageDecision::Mediate, Some(mediation)) => {
                mediation.validate(&self.id, surface, self.matcher.action.as_ref())
            }
            (PolicyPackageDecision::Mediate, None) => InvalidRequestSnafu {
                reason: format!("PolicyPackage rule `{}` requires mediation", self.id),
            }
            .fail(),
            (_, Some(_)) => InvalidRequestSnafu {
                reason: format!(
                    "PolicyPackage rule `{}` may use mediation only with decision mediate",
                    self.id
                ),
            }
            .fail(),
            (_, None) => Ok(()),
        }
    }
}

impl PolicyPackageMediation {
    fn validate(
        &self,
        rule_id: &str,
        source_surface: &ExecutionSurface,
        action: Option<&ActionKind>,
    ) -> Result<()> {
        SurfaceRegistry::require_registered(
            &self.replacement_surface,
            &format!("PolicyPackage rule `{rule_id}` mediation.replacement_surface"),
        )?;
        if !matches!(self.kind, PolicyPackageMediationKind::ManagedBrowserCdp)
            || self.replacement_surface != ExecutionSurface::BrowserCdp
            || !matches!(
                self.return_endpoint,
                PolicyPackageMediationReturnEndpoint::RequestedPort
            )
            || source_surface != &ExecutionSurface::Terminal
            || action != Some(&ActionKind::ProcessExec)
        {
            return InvalidRequestSnafu {
                reason: format!(
                    "PolicyPackage rule `{rule_id}` must use managed_browser_cdp from terminal process_exec to browser_cdp with requested_port",
                ),
            }
            .fail();
        }
        Ok(())
    }
}

impl PolicySetResourceSpec {
    fn validate(&self) -> Result<()> {
        if self.packages.is_empty() {
            return InvalidRequestSnafu {
                reason: String::from("PolicySet spec.packages must be non-empty"),
            }
            .fail();
        }
        let mut names = BTreeSet::new();
        for name in &self.packages {
            if !DaemonLocalStore::is_path_component(name) || !names.insert(name.as_str()) {
                return InvalidRequestSnafu {
                    reason: format!("PolicySet package name `{name}` is invalid or duplicated"),
                }
                .fail();
            }
        }
        Ok(())
    }
}

impl BuiltInAdmission {
    pub(crate) fn package_digest(&self) -> &str {
        &self.package_digest
    }

    pub(crate) fn installation_digest(&self) -> &str {
        &self.installation_digest
    }

    pub(crate) fn adapter_digest(&self) -> &str {
        &self.adapter_digest
    }

    pub(crate) fn policy_set_digest(&self) -> &str {
        &self.policy_set_digest
    }
}

impl LocalAdmission {
    pub(crate) const fn package(&self) -> &AgentPackageManifest {
        &self.package
    }

    pub(crate) fn package_digest(&self) -> &str {
        &self.package_digest
    }

    pub(crate) fn installation_digest(&self) -> &str {
        &self.installation_digest
    }

    pub(crate) fn adapter_digest(&self) -> &str {
        &self.adapter_digest
    }

    pub(crate) fn policy_set_digest(&self) -> &str {
        &self.policy_set_digest
    }

    pub(crate) fn policy_input_digests(&self) -> &[String] {
        &self.policy_input_digests
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionLease {
    session_id: String,
    owner_uid: u32,
    package_digest: Option<String>,
    installation_digest: Option<String>,
    adapter_digest: Option<String>,
    policy_set_digest: String,
    policy_input_digests: Vec<String>,
}

impl DaemonLocalStore {
    pub(crate) fn installed(paths: &DaemonPaths) -> Result<Self> {
        let packages = paths.packages_state_path();
        let users = paths.users_state_path();
        Self::require_safe_directory(&packages)?;
        Self::require_safe_directory(&users)?;
        Ok(Self {
            packages,
            users,
            write_lock: Mutex::new(()),
        })
    }

    pub(crate) fn seed_root_curated(&self, admissions: &[RootCuratedAdmission]) -> Result<()> {
        for admission in admissions {
            for policy in admission.policies() {
                self.validate_policy_package(policy)?;
                let policy_digest = policy.canonical_digest().map_err(Self::invalid_model)?;
                self.write_immutable(
                    &self.policy_package_path(&policy_digest),
                    &policy.canonical_bytes().map_err(Self::invalid_model)?,
                )?;
            }
            let package = admission.package();
            let package_digest = package.canonical_digest().map_err(Self::invalid_model)?;
            self.write_immutable(
                &self.package_manifest_path(&package_digest),
                &package.canonical_bytes().map_err(Self::invalid_model)?,
            )?;

            let installation = admission.installation();
            let installation_digest = installation
                .canonical_digest()
                .map_err(Self::invalid_model)?;
            self.write_immutable(
                &self.installation_path(installation.owner_uid(), &installation_digest),
                &installation
                    .canonical_bytes()
                    .map_err(Self::invalid_model)?,
            )?;

            let policy_set = admission.policy_set();
            let policy_set_digest = policy_set.canonical_digest().map_err(Self::invalid_model)?;
            self.write_immutable(
                &self.policy_set_path(installation.owner_uid(), &policy_set_digest),
                &policy_set.canonical_bytes().map_err(Self::invalid_model)?,
            )?;
        }
        Ok(())
    }

    pub(crate) fn seed_root_curated_codex_packages(
        &self,
        packages: &[RootCuratedCodexPackage],
    ) -> Result<()> {
        for curated in packages {
            let package = curated.package();
            let package_digest = package.canonical_digest().map_err(Self::invalid_model)?;
            self.write_immutable(
                &self.package_manifest_path(&package_digest),
                &package.canonical_bytes().map_err(Self::invalid_model)?,
            )?;
            let definition = curated.definition();
            let definition_digest = definition.canonical_digest().map_err(Self::invalid_model)?;
            if package.config_digest() != &definition_digest {
                return InvalidRequestSnafu {
                    reason: String::from(
                        "root-curated Codex package does not bind its exact definition digest",
                    ),
                }
                .fail();
            }
            self.write_immutable(
                &self.codex_definition_path(&package_digest),
                &definition.canonical_bytes().map_err(Self::invalid_model)?,
            )?;
        }
        Ok(())
    }

    pub(crate) fn seed_builtin_generic_content(&self) -> Result<()> {
        let (package, policy) = Self::builtin_generic_content()?;
        let package_digest = package.canonical_digest().map_err(Self::invalid_model)?;
        self.write_immutable(
            &self.package_manifest_path(&package_digest),
            &package.canonical_bytes().map_err(Self::invalid_model)?,
        )?;
        self.validate_policy_package(&policy)?;
        let policy_digest = policy.canonical_digest().map_err(Self::invalid_model)?;
        self.write_immutable(
            &self.policy_package_path(&policy_digest),
            &policy.canonical_bytes().map_err(Self::invalid_model)?,
        )
    }

    pub(crate) fn ensure_builtin_admission(&self, owner_uid: u32) -> Result<BuiltInAdmission> {
        self.seed_builtin_generic_content()?;
        let (package, policy) = Self::builtin_generic_content()?;
        let package_digest = package.canonical_digest().map_err(Self::invalid_model)?;
        let installation = InstallationRecord::new(owner_uid, package_digest.clone(), 0);
        let installation_digest = installation
            .canonical_digest()
            .map_err(Self::invalid_model)?;
        self.write_immutable(
            &self.installation_path(owner_uid, &installation_digest),
            &installation
                .canonical_bytes()
                .map_err(Self::invalid_model)?,
        )?;
        let policy_digest = policy.canonical_digest().map_err(Self::invalid_model)?;
        let policy_set =
            PolicySetRevision::new(vec![policy_digest]).map_err(Self::invalid_model)?;
        let policy_set_digest = policy_set.canonical_digest().map_err(Self::invalid_model)?;
        self.write_immutable(
            &self.policy_set_path(owner_uid, &policy_set_digest),
            &policy_set.canonical_bytes().map_err(Self::invalid_model)?,
        )?;
        Ok(BuiltInAdmission {
            package_digest: package_digest.as_str().to_owned(),
            installation_digest: installation_digest.as_str().to_owned(),
            adapter_digest: package.adapter_digest().as_str().to_owned(),
            policy_set_digest: policy_set_digest.as_str().to_owned(),
        })
    }

    fn builtin_generic_content() -> Result<(AgentPackageManifest, PolicyPackageRevision)> {
        let descriptor = AgentAdapterDescriptor::generic_process_v1().map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("built-in generic adapter descriptor is invalid: {error}"),
            }
            .build()
        })?;
        let package = AgentPackageManifest::new(
            "generic-process",
            descriptor.id(),
            env!("CARGO_PKG_VERSION"),
            vec![String::from("<argv>")],
            ContentDigest::new(descriptor.sha256().map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("built-in generic adapter digest is invalid: {error}"),
                }
                .build()
            })?)
            .map_err(Self::invalid_model)?,
            Vec::new(),
        )
        .map_err(Self::invalid_model)?;
        let policy = PolicyPackageRevision::new(
            "generic-host-minimum",
            b"name = \"generic-host-minimum\"\n".to_vec(),
            std::collections::BTreeMap::from([
                (
                    String::from("filesystem.json"),
                    br#"{"rules":[{"id":"generic-host-allow-filesystem","match":{"surface":"filesystem"},"decision":"allow"}]}"#.to_vec(),
                ),
                (
                    String::from("terminal.json"),
                    br#"{"rules":[{"id":"generic-host-allow-terminal","match":{"surface":"terminal"},"decision":"allow"}]}"#.to_vec(),
                ),
                (
                    String::from("network.json"),
                    br#"{"rules":[{"id":"generic-host-allow-network","match":{"surface":"network"},"decision":"allow"}]}"#.to_vec(),
                ),
            ]),
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::from([
                (String::from("filesystem.json"), br#"{}"#.to_vec()),
                (String::from("network.json"), br#"{}"#.to_vec()),
                (String::from("terminal.json"), br#"{}"#.to_vec()),
            ]),
            b"# Built-in generic host minimum\n".to_vec(),
        )
        .map_err(Self::invalid_model)?;
        Ok((package, policy))
    }

    pub(crate) fn resolve_admission(
        &self,
        owner_uid: u32,
        package_digest: &str,
        installation_digest: &str,
        adapter_digest: &str,
        policy_set_digest: &str,
    ) -> Result<LocalAdmission> {
        let package_digest = Self::parse_digest(package_digest, "package")?;
        let installation_digest = Self::parse_digest(installation_digest, "installation")?;
        let adapter_digest = Self::parse_digest(adapter_digest, "adapter")?;
        let policy_set_digest = Self::parse_digest(policy_set_digest, "policy set")?;

        let package: AgentPackageManifest = self.read_canonical(
            &self.package_manifest_path(&package_digest),
            &package_digest,
            "agent package",
        )?;
        if package.adapter_digest() != &adapter_digest {
            return InvalidRequestSnafu {
                reason: String::from(
                    "package adapter identity does not match the requested adapter",
                ),
            }
            .fail();
        }
        let installation: InstallationRecord = self.read_canonical(
            &self.installation_path(owner_uid, &installation_digest),
            &installation_digest,
            "installation",
        )?;
        installation.validate().map_err(Self::invalid_model)?;
        if installation.owner_uid() != owner_uid || installation.package_digest() != &package_digest
        {
            return InvalidRequestSnafu {
                reason: String::from(
                    "installation does not belong to the caller or selected package",
                ),
            }
            .fail();
        }

        let policy_set: PolicySetRevision = self.read_canonical(
            &self.policy_set_path(owner_uid, &policy_set_digest),
            &policy_set_digest,
            "policy set",
        )?;
        policy_set.validate().map_err(Self::invalid_model)?;
        for policy_digest in policy_set.policy_input_digests() {
            self.read_policy_package(owner_uid, policy_digest)?;
        }
        let policy_input_digests = policy_set
            .policy_input_digests()
            .into_iter()
            .map(|digest| digest.as_str().to_owned())
            .collect();

        Ok(LocalAdmission {
            package,
            package_digest: package_digest.as_str().to_owned(),
            installation_digest: installation_digest.as_str().to_owned(),
            adapter_digest: adapter_digest.as_str().to_owned(),
            policy_set_digest: policy_set_digest.as_str().to_owned(),
            policy_input_digests,
        })
    }

    pub(crate) fn resolve_codex_package(&self, package_digest: &str) -> Result<LocalCodexPackage> {
        let package_digest = Self::parse_digest(package_digest, "Codex package")?;
        let package: AgentPackageManifest = self.read_canonical(
            &self.package_manifest_path(&package_digest),
            &package_digest,
            "Codex agent package",
        )?;
        if package.adapter_id() != "codex-v1" {
            return InvalidRequestSnafu {
                reason: String::from("selected package is not a root-curated codex-v1 package"),
            }
            .fail();
        }
        let definition: CodexPackageDefinition = self.read_canonical(
            &self.codex_definition_path(&package_digest),
            package.config_digest(),
            "Codex package definition",
        )?;
        definition.validate().map_err(Self::invalid_model)?;
        Ok(LocalCodexPackage {
            package,
            package_digest: package_digest.as_str().to_owned(),
            definition,
        })
    }

    pub(crate) fn resolve_codex_package_name(&self, name: &str) -> Result<LocalCodexPackage> {
        Self::require_resource_name(name, "AgentPackage")?;
        let mut matches = Vec::new();
        for entry in
            self.directory_entries(&self.packages, "listing root-curated Codex packages")?
        {
            let path = entry.path();
            let file_type = entry.file_type().context(IoSnafu {
                action: "inspecting root-curated Codex package directory",
                path: &path,
            })?;
            if file_type.is_symlink() || !file_type.is_dir() {
                continue;
            }
            let Some(digest) = entry
                .file_name()
                .to_str()
                .and_then(|value| ContentDigest::new(value).ok())
            else {
                continue;
            };
            if !path.join("codex-v1.json").exists() {
                continue;
            }
            let package = self.resolve_codex_package(digest.as_str())?;
            if package.package().name() == name {
                matches.push(package);
            }
        }
        match matches.len() {
            1 => Ok(matches.remove(0)),
            0 => InvalidRequestSnafu {
                reason: format!("no root-curated Codex package is named `{name}`"),
            }
            .fail(),
            _ => InvalidRequestSnafu {
                reason: format!("root-curated Codex package name `{name}` is ambiguous"),
            }
            .fail(),
        }
    }

    pub(crate) fn store_codex_installation(
        &self,
        owner_uid: u32,
        agent_name: &str,
        package_digest: &str,
        installed_at_unix_ms: u64,
        artifact: VerifiedLocalArtifact,
    ) -> Result<LocalCodexInstallation> {
        Self::require_resource_name(agent_name, "Agent")?;
        let package = self.resolve_codex_package(package_digest)?;
        if artifact.sha256() != package.definition().executable_sha256() {
            return InvalidRequestSnafu {
                reason: String::from(
                    "the held Codex executable digest does not match the root-curated release",
                ),
            }
            .fail();
        }
        let package_digest =
            ContentDigest::new(package.package_digest()).map_err(Self::invalid_model)?;
        let installation = InstallationRecord::enrolled_local(
            owner_uid,
            package_digest,
            installed_at_unix_ms,
            artifact,
        )
        .map_err(Self::invalid_model)?;
        let installation_digest = installation
            .canonical_digest()
            .map_err(Self::invalid_model)?;
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_error| crate::error::StateLockSnafu.build())?;
        self.write_immutable(
            &self.installation_path(owner_uid, &installation_digest),
            &installation
                .canonical_bytes()
                .map_err(Self::invalid_model)?,
        )?;
        let record = NamedResourceRecord::agent(
            agent_name,
            &installation_digest,
            package.package().adapter_id(),
        )?;
        let encoded =
            serde_json::to_vec(&record).map_err(|source| crate::DaemonError::InvalidConfig {
                path: self.agent_path(owner_uid, agent_name),
                source,
                location: snafu::Location::default(),
            })?;
        self.write_immutable(&self.agent_path(owner_uid, agent_name), &encoded)?;
        self.resolve_codex_installation(
            owner_uid,
            package.package_digest(),
            installation_digest.as_str(),
            Some("codex"),
        )
    }

    pub(crate) fn resolve_codex_agent(
        &self,
        owner_uid: u32,
        name: &str,
        entrypoint: &str,
    ) -> Result<LocalCodexInstallation> {
        let installation_digest =
            self.read_named_resource(owner_uid, "Agent", name, self.agent_path(owner_uid, name))?;
        let installation: InstallationRecord = self.read_canonical(
            &self.installation_path(owner_uid, &installation_digest),
            &installation_digest,
            "Codex installation",
        )?;
        self.resolve_codex_installation(
            owner_uid,
            installation.package_digest().as_str(),
            installation_digest.as_str(),
            Some(entrypoint),
        )
    }

    pub(crate) fn resolve_codex_installation(
        &self,
        owner_uid: u32,
        package_digest: &str,
        installation_digest: &str,
        entrypoint: Option<&str>,
    ) -> Result<LocalCodexInstallation> {
        let package = self.resolve_codex_package(package_digest)?;
        let installation_digest = Self::parse_digest(installation_digest, "Codex installation")?;
        let installation: InstallationRecord = self.read_canonical(
            &self.installation_path(owner_uid, &installation_digest),
            &installation_digest,
            "Codex installation",
        )?;
        installation.validate().map_err(Self::invalid_model)?;
        if installation.owner_uid() != owner_uid
            || installation.package_digest().as_str() != package.package_digest()
        {
            return InvalidRequestSnafu {
                reason: String::from(
                    "Codex installation does not belong to the caller or its selected package",
                ),
            }
            .fail();
        }
        if installation.local_artifact().is_none() {
            return InvalidRequestSnafu {
                reason: String::from(
                    "Codex installation has no descriptor-verified local executable artifact",
                ),
            }
            .fail();
        }
        let entrypoint = entrypoint.unwrap_or("codex");
        if package.definition().entrypoint(entrypoint).is_none() {
            return InvalidRequestSnafu {
                reason: format!(
                    "Codex package does not certify the `{entrypoint}` entrypoint for this installation"
                ),
            }
            .fail();
        }
        Ok(LocalCodexInstallation {
            package,
            installation,
            installation_digest: installation_digest.as_str().to_owned(),
            entrypoint: entrypoint.to_owned(),
        })
    }

    pub(crate) fn validate_session_spec(&self, spec: &SessionSpec) -> Result<LocalAdmission> {
        let package = spec.package().ok_or_else(|| {
            InvalidRequestSnafu {
                reason: String::from("session has no admitted agent package identity"),
            }
            .build()
        })?;
        let installation = spec.installation().ok_or_else(|| {
            InvalidRequestSnafu {
                reason: String::from("session has no admitted installation identity"),
            }
            .build()
        })?;
        let adapter = spec.adapter().ok_or_else(|| {
            InvalidRequestSnafu {
                reason: String::from("session has no admitted adapter identity"),
            }
            .build()
        })?;
        let configuration = spec.package_configuration().ok_or_else(|| {
            InvalidRequestSnafu {
                reason: String::from("session has no admitted package configuration identity"),
            }
            .build()
        })?;
        let admission = self.resolve_admission(
            spec.owner().uid(),
            package.sha256(),
            installation.sha256(),
            adapter.sha256(),
            spec.policy_set().sha256(),
        )?;
        if configuration.sha256() != admission.package().config_digest().as_str() {
            return InvalidRequestSnafu {
                reason: String::from(
                    "session package configuration identity no longer matches its package manifest",
                ),
            }
            .fail();
        }
        Ok(admission)
    }

    pub(crate) fn policy_packages_for_session(
        &self,
        spec: &SessionSpec,
    ) -> Result<Vec<PolicyPackageRevision>> {
        let admission = self.validate_session_spec(spec)?;
        admission
            .policy_input_digests()
            .iter()
            .map(|digest| {
                let digest = Self::parse_digest(digest, "policy package")?;
                self.read_policy_package(spec.owner().uid(), &digest)
            })
            .collect()
    }

    /// Proves that every immutable package selected for an admission has an
    /// explicit rule for each intrinsic Surface required by that execution
    /// contract. Wildcard rules do not satisfy this check: the policy package
    /// must visibly participate in the relevant governance boundary.
    pub(crate) fn require_admission_surface_coverage(
        &self,
        owner_uid: u32,
        admission: &LocalAdmission,
        required_surfaces: &[ExecutionSurface],
    ) -> Result<()> {
        for digest in admission.policy_input_digests() {
            let digest = Self::parse_digest(digest, "policy package")?;
            let revision = self.read_policy_package(owner_uid, &digest)?;
            let policies = revision
                .rules()
                .values()
                .map(|source| {
                    let source = std::str::from_utf8(source).map_err(|error| {
                        InvalidRequestSnafu {
                            reason: format!(
                                "policy package `{}` has non-UTF-8 rule bytes: {error}",
                                revision.manifest().name()
                            ),
                        }
                        .build()
                    })?;
                    LocalPolicy::from_json_str(source).map_err(|error| {
                        InvalidRequestSnafu {
                            reason: format!(
                                "policy package `{}` has an invalid rule: {error}",
                                revision.manifest().name()
                            ),
                        }
                        .build()
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            for surface in required_surfaces {
                if !policies.iter().any(|policy| policy.covers_surface(surface)) {
                    return InvalidRequestSnafu {
                        reason: format!(
                            "admitted PolicySet has no explicit `{}` coverage in mandatory package `{}`",
                            SurfaceRegistry::surface_name(surface),
                            revision.manifest().name(),
                        ),
                    }
                    .fail();
                }
            }
        }
        Ok(())
    }

    pub(crate) fn store_user_policy_package(
        &self,
        owner_uid: u32,
        policy: &PolicyPackageRevision,
        maximum_stored_bytes: u64,
    ) -> Result<ContentDigest> {
        self.validate_policy_package(policy)?;
        let digest = policy.canonical_digest().map_err(Self::invalid_model)?;
        let name = policy.manifest().name();
        Self::require_resource_name(name, "PolicyPackage")?;
        let name_record = NamedResourceRecord::policy_package(
            name,
            &digest,
            PolicyPackageResourceSpec::from_revision(policy)?,
        )?;
        let name_path = self.policy_package_name_path(owner_uid, name);
        let name_record_encoded = serde_json::to_vec(&name_record).map_err(|source| {
            crate::DaemonError::InvalidConfig {
                path: name_path.clone(),
                source,
                location: snafu::Location::default(),
            }
        })?;
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_error| crate::error::StateLockSnafu.build())?;
        for existing in self.list_policy_packages(owner_uid)? {
            if existing.name() == name {
                let existing_digest =
                    self.resolve_policy_package_name(owner_uid, existing.name())?;
                if existing_digest != digest {
                    return InvalidRequestSnafu {
                        reason: format!(
                            "PolicyPackage name `{}` already identifies a different immutable revision",
                            name
                        ),
                    }
                    .fail();
                }
            }
        }
        let policy_encoded = policy.canonical_bytes().map_err(Self::invalid_model)?;
        let path = self.user_policy_package_path(owner_uid, &digest);
        if !path.exists()
            && self
                .user_policy_package_bytes(owner_uid)?
                .saturating_add(policy_encoded.len() as u64)
                > maximum_stored_bytes
        {
            return crate::error::InvalidRequestSnafu {
                reason: format!(
                    "owner UID {owner_uid} would exceed the {maximum_stored_bytes}-byte stored policy limit",
                ),
            }
                .fail();
        }
        self.write_immutable(&path, &policy_encoded)?;
        self.write_immutable(&name_path, &name_record_encoded)?;
        Ok(digest)
    }

    pub(crate) fn list_policy_packages(&self, owner_uid: u32) -> Result<Vec<StoredPolicyPackage>> {
        let mut packages = BTreeMap::new();
        self.collect_root_policy_packages(&mut packages)?;
        self.collect_user_policy_packages(owner_uid, &mut packages)?;
        Ok(packages.into_values().collect())
    }

    pub(crate) fn inspect_policy_package(
        &self,
        owner_uid: u32,
        name: &str,
    ) -> Result<StoredPolicyPackage> {
        let digest = self.resolve_policy_package_name(owner_uid, name)?;
        let policy = self.read_policy_package(owner_uid, &digest)?;
        self.validate_policy_package(&policy)?;
        Ok(StoredPolicyPackage::new(&policy))
    }

    pub(crate) fn create_user_policy_set(
        &self,
        owner_uid: u32,
        name: &str,
        package_names: &[String],
    ) -> Result<StoredPolicySet> {
        Self::require_resource_name(name, "PolicySet")?;
        let mut package_digests = Vec::with_capacity(package_names.len());
        for package_name in package_names {
            let digest = self.resolve_policy_package_name(owner_uid, package_name)?;
            package_digests.push(digest);
        }
        let revision = PolicySetRevision::new(package_digests).map_err(Self::invalid_model)?;
        let digest = revision.canonical_digest().map_err(Self::invalid_model)?;
        let name_record = NamedResourceRecord::policy_set(name, &digest, package_names.to_vec())?;
        let encoded = serde_json::to_vec(&name_record).map_err(|source| {
            crate::DaemonError::InvalidConfig {
                path: self.policy_set_name_path(owner_uid, name),
                source,
                location: snafu::Location::default(),
            }
        })?;
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_error| crate::error::StateLockSnafu.build())?;
        self.write_immutable(
            &self.policy_set_path(owner_uid, &digest),
            &revision.canonical_bytes().map_err(Self::invalid_model)?,
        )?;
        self.write_immutable(&self.policy_set_name_path(owner_uid, name), &encoded)?;
        Ok(StoredPolicySet::new(name))
    }

    pub(crate) fn resolve_policy_set_name(
        &self,
        owner_uid: u32,
        name: &str,
    ) -> Result<ContentDigest> {
        let digest = self.read_named_resource(
            owner_uid,
            "PolicySet",
            name,
            self.policy_set_name_path(owner_uid, name),
        )?;
        let policy_set: PolicySetRevision = self.read_canonical(
            &self.policy_set_path(owner_uid, &digest),
            &digest,
            "policy set",
        )?;
        policy_set.validate().map_err(Self::invalid_model)?;
        Ok(digest)
    }

    pub(crate) fn list_policy_sets(&self, owner_uid: u32) -> Result<Vec<StoredPolicySet>> {
        self.list_named_resources(
            owner_uid,
            "PolicySet",
            self.policy_set_names_directory(owner_uid),
        )
        .map(|names| names.into_iter().map(StoredPolicySet::new).collect())
    }

    pub(crate) fn inspect_policy_set(&self, owner_uid: u32, name: &str) -> Result<StoredPolicySet> {
        let digest = self.resolve_policy_set_name(owner_uid, name)?;
        let revision: PolicySetRevision = self.read_canonical(
            &self.policy_set_path(owner_uid, &digest),
            &digest,
            "policy set",
        )?;
        revision.validate().map_err(Self::invalid_model)?;
        for policy_digest in revision.policy_input_digests() {
            self.read_policy_package(owner_uid, policy_digest)?;
        }
        Ok(StoredPolicySet::new(name))
    }

    pub(crate) fn create_user_surface(
        &self,
        owner_uid: u32,
        name: &str,
        surface_type: &str,
    ) -> Result<StoredSurface> {
        Self::require_resource_name(name, "Surface")?;
        let record = NamedResourceRecord::surface(name, surface_type)?;
        let path = self.surface_path(owner_uid, name);
        let encoded =
            serde_json::to_vec(&record).map_err(|source| crate::DaemonError::InvalidConfig {
                path: path.clone(),
                source,
                location: snafu::Location::default(),
            })?;
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_error| crate::error::StateLockSnafu.build())?;
        self.write_immutable(&path, &encoded)?;
        Ok(StoredSurface::new(name, surface_type))
    }

    pub(crate) fn list_surfaces(&self, owner_uid: u32) -> Result<Vec<StoredSurface>> {
        let mut surfaces = Vec::new();
        for name in
            self.list_named_resources(owner_uid, "Surface", self.surface_directory(owner_uid))?
        {
            surfaces.push(self.inspect_surface(owner_uid, &name)?);
        }
        Ok(surfaces)
    }

    pub(crate) fn inspect_surface(&self, owner_uid: u32, name: &str) -> Result<StoredSurface> {
        let record = self.read_named_resource_record(
            owner_uid,
            "Surface",
            name,
            self.surface_path(owner_uid, name),
        )?;
        let NamedResourceSpec::Surface(spec) = record.spec else {
            return InvalidRequestSnafu {
                reason: String::from("Surface resource has an invalid spec"),
            }
            .fail();
        };
        Ok(StoredSurface::new(name, spec.surface_type))
    }

    pub(crate) fn prepare_static_session_admission(
        &self,
        owner_uid: u32,
        session_name: &str,
        agent_name: &str,
        policy_set_name: &str,
        surface_names: &[String],
    ) -> Result<StaticSessionAdmission> {
        Self::require_resource_name(session_name, "Session")?;
        let agent = self.resolve_named_agent(owner_uid, agent_name)?;
        let (policy_set_digest, policy_packages) =
            self.resolve_policy_set_for_static_session(owner_uid, policy_set_name)?;

        let required_source_surfaces = policy_packages
            .iter()
            .flat_map(|(_digest, spec)| spec.rules.iter())
            .filter_map(|rule| rule.matcher.surface.as_ref())
            .map(SurfaceRegistry::surface_name)
            .collect::<BTreeSet<_>>();
        for required_surface in &required_source_surfaces {
            if policy_packages.iter().any(|(_digest, spec)| {
                !spec.rules.iter().any(|rule| {
                    rule.matcher.surface.as_ref().is_some_and(|surface| {
                        SurfaceRegistry::surface_name(surface) == *required_surface
                    })
                })
            }) {
                return InvalidRequestSnafu {
                    reason: format!(
                        "PolicySet `{policy_set_name}` has no mandatory-package coverage for `{required_surface}`"
                    ),
                }
                .fail();
            }
        }

        let mut normalized_surface_names = surface_names.to_vec();
        normalized_surface_names.sort();
        let session_spec = StaticSessionResourceSpec {
            agent: agent_name.to_owned(),
            policy_set: policy_set_name.to_owned(),
            surfaces: normalized_surface_names.clone(),
        };
        session_spec.validate()?;

        let requires_browser_cdp = policy_packages.iter().any(|(_digest, spec)| {
            spec.rules.iter().any(|rule| {
                rule.matcher.surface == Some(ExecutionSurface::BrowserCdp)
                    || rule.mediation.as_ref().is_some_and(|mediation| {
                        mediation.replacement_surface == ExecutionSurface::BrowserCdp
                    })
            })
        });

        let mut surface_types = BTreeSet::new();
        let mut surface_integrity_digests = Vec::with_capacity(normalized_surface_names.len());
        for surface_name in &normalized_surface_names {
            let record = self.read_named_resource_record(
                owner_uid,
                "Surface",
                surface_name,
                self.surface_path(owner_uid, surface_name),
            )?;
            let integrity_digest = record.validate("Surface", surface_name)?;
            let NamedResourceSpec::Surface(spec) = record.spec else {
                return InvalidRequestSnafu {
                    reason: format!("Surface `{surface_name}` has an invalid spec"),
                }
                .fail();
            };
            if !surface_types.insert(spec.surface_type.clone()) {
                return InvalidRequestSnafu {
                    reason: format!(
                        "Session may name at most one Surface implementing `{}`",
                        spec.surface_type
                    ),
                }
                .fail();
            }
            surface_integrity_digests.push(integrity_digest.as_str().to_owned());
        }

        if requires_browser_cdp {
            if surface_types != BTreeSet::from([String::from("browser_cdp")]) {
                return InvalidRequestSnafu {
                    reason: String::from(
                        "Session PolicySet requires browser_cdp; name exactly one browser_cdp Surface",
                    ),
                }
                .fail();
            }
        } else if !surface_types.is_empty() {
            return InvalidRequestSnafu {
                reason: String::from(
                    "Session names a Surface, but its PolicySet has no browser_cdp requirement",
                ),
            }
            .fail();
        }

        Ok(StaticSessionAdmission {
            session_name: session_name.to_owned(),
            agent_name: agent_name.to_owned(),
            policy_set_name: policy_set_name.to_owned(),
            surface_names: normalized_surface_names,
            agent_adapter: agent.adapter,
            agent_integrity_digest: agent.integrity_digest.as_str().to_owned(),
            policy_set_integrity_digest: policy_set_digest.as_str().to_owned(),
            policy_package_integrity_digests: policy_packages
                .into_iter()
                .map(|(digest, _spec)| digest.as_str().to_owned())
                .collect(),
            surface_integrity_digests,
        })
    }

    pub(crate) fn create_static_session(
        &self,
        owner_uid: u32,
        admission: &StaticSessionAdmission,
    ) -> Result<StoredStaticSession> {
        let record =
            NamedResourceRecord::session(admission.session_name(), admission.resource_spec())?;
        let record_path = self.static_session_path(owner_uid, admission.session_name());
        let record_encoded =
            serde_json::to_vec(&record).map_err(|source| crate::DaemonError::InvalidConfig {
                path: record_path.clone(),
                source,
                location: snafu::Location::default(),
            })?;
        let resolution_path =
            self.static_session_resolution_path(owner_uid, admission.session_name());
        let resolution_encoded = serde_json::to_vec(&admission.resolution()).map_err(|source| {
            crate::DaemonError::InvalidConfig {
                path: resolution_path.clone(),
                source,
                location: snafu::Location::default(),
            }
        })?;
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_error| crate::error::StateLockSnafu.build())?;
        self.write_immutable(&resolution_path, &resolution_encoded)?;
        self.write_immutable(&record_path, &record_encoded)?;
        StoredStaticSession::from_record(record)
    }

    pub(crate) fn inspect_static_session(
        &self,
        owner_uid: u32,
        name: &str,
    ) -> Result<Option<StoredStaticSession>> {
        Self::require_resource_name(name, "Session")?;
        let path = self.static_session_path(owner_uid, name);
        if !path.exists() {
            return Ok(None);
        }
        let record = self.read_named_resource_record(owner_uid, "Session", name, path)?;
        let stored = StoredStaticSession::from_record(record)?;
        let resolution: StaticSessionResolution = self.read_json_record(
            &self.static_session_resolution_path(owner_uid, name),
            "static Session resolution",
        )?;
        Self::parse_digest(
            &resolution.agent_integrity_digest,
            "Session agent resolution",
        )?;
        Self::parse_digest(
            &resolution.policy_set_integrity_digest,
            "Session PolicySet resolution",
        )?;
        for digest in resolution
            .policy_package_integrity_digests
            .iter()
            .chain(resolution.surface_integrity_digests.iter())
        {
            Self::parse_digest(digest, "Session resolution")?;
        }
        Ok(Some(stored))
    }

    pub(crate) fn list_static_sessions(&self, owner_uid: u32) -> Result<Vec<StoredStaticSession>> {
        let mut sessions = Vec::new();
        for name in self.list_named_resources(
            owner_uid,
            "Session",
            self.static_session_directory(owner_uid),
        )? {
            if let Some(session) = self.inspect_static_session(owner_uid, &name)? {
                sessions.push(session);
            }
        }
        Ok(sessions)
    }

    pub(crate) fn record_session_lease(&self, spec: &SessionSpec) -> Result<()> {
        self.record_lease(SessionLease::from_spec(spec))
    }

    /// A removed session retains its immutable dependencies until its bounded
    /// output/evidence retention is pruned. Only that final retention step can
    /// release the corresponding content lease.
    pub(crate) fn release_session_lease(&self, owner_uid: u32, session_id: &str) -> Result<()> {
        if !Self::is_path_component(session_id) {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("session lease id is not a safe path component"),
            }
            .fail();
        }
        let path = self.lease_path(session_id);
        let encoded = match fs::read(&path) {
            Ok(encoded) => encoded,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(crate::DaemonError::Io {
                    action: "reading session content lease before release",
                    path,
                    source,
                    location: snafu::Location::default(),
                })
            }
        };
        let lease: SessionLease = serde_json::from_slice(&encoded).map_err(|source| {
            crate::DaemonError::InvalidConfig {
                path: path.clone(),
                source,
                location: snafu::Location::default(),
            }
        })?;
        if lease.session_id != session_id || lease.owner_uid != owner_uid {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("session content lease does not match the pruning owner"),
            }
            .fail();
        }
        let parent = path.parent().ok_or_else(|| {
            crate::error::UnsafePathSnafu {
                path: path.clone(),
                reason: String::from("session content lease has no parent directory"),
            }
            .build()
        })?;
        Self::require_safe_directory(parent)?;
        fs::remove_file(&path).context(IoSnafu {
            action: "releasing pruned session content lease",
            path: &path,
        })?;
        File::open(parent)
            .context(IoSnafu {
                action: "opening session content lease directory",
                path: parent,
            })?
            .sync_all()
            .context(IoSnafu {
                action: "syncing released session content lease directory",
                path: parent,
            })
    }

    fn record_lease(&self, lease: SessionLease) -> Result<()> {
        if !Self::is_path_component(&lease.session_id) {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("session lease id is not a safe path component"),
            }
            .fail();
        }
        let encoded =
            serde_json::to_vec(&lease).map_err(|source| crate::DaemonError::InvalidConfig {
                path: self.lease_path(&lease.session_id),
                source,
                location: snafu::Location::default(),
            })?;
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_error| crate::error::StateLockSnafu.build())?;
        self.write_immutable(&self.lease_path(&lease.session_id), &encoded)
    }

    fn lease_path(&self, session_id: &str) -> PathBuf {
        self.packages
            .join("leases")
            .join("sessions")
            .join(format!("{session_id}.json"))
    }

    fn package_manifest_path(&self, digest: &ContentDigest) -> PathBuf {
        self.packages.join(digest.as_str()).join("manifest.json")
    }

    fn codex_definition_path(&self, digest: &ContentDigest) -> PathBuf {
        self.packages.join(digest.as_str()).join("codex-v1.json")
    }

    fn agent_path(&self, owner_uid: u32, name: &str) -> PathBuf {
        self.users
            .join(owner_uid.to_string())
            .join("agents")
            .join(format!("{name}.json"))
    }

    fn surface_directory(&self, owner_uid: u32) -> PathBuf {
        self.users.join(owner_uid.to_string()).join("surfaces")
    }

    fn surface_path(&self, owner_uid: u32, name: &str) -> PathBuf {
        self.surface_directory(owner_uid)
            .join(format!("{name}.json"))
    }

    fn static_session_directory(&self, owner_uid: u32) -> PathBuf {
        self.users
            .join(owner_uid.to_string())
            .join("static-sessions")
    }

    fn static_session_path(&self, owner_uid: u32, name: &str) -> PathBuf {
        self.static_session_directory(owner_uid)
            .join(format!("{name}.json"))
    }

    fn static_session_resolution_directory(&self, owner_uid: u32) -> PathBuf {
        self.users
            .join(owner_uid.to_string())
            .join("static-session-resolutions")
    }

    fn static_session_resolution_path(&self, owner_uid: u32, name: &str) -> PathBuf {
        self.static_session_resolution_directory(owner_uid)
            .join(format!("{name}.json"))
    }

    fn installation_path(&self, owner_uid: u32, digest: &ContentDigest) -> PathBuf {
        self.users
            .join(owner_uid.to_string())
            .join("installations")
            .join(format!("{}.json", digest.as_str()))
    }

    fn policy_set_path(&self, owner_uid: u32, digest: &ContentDigest) -> PathBuf {
        self.users
            .join(owner_uid.to_string())
            .join("policy-sets")
            .join(format!("{}.json", digest.as_str()))
    }

    fn policy_set_names_directory(&self, owner_uid: u32) -> PathBuf {
        self.users
            .join(owner_uid.to_string())
            .join("policy-set-names")
    }

    fn policy_package_names_directory(&self, owner_uid: u32) -> PathBuf {
        self.users
            .join(owner_uid.to_string())
            .join("policy-package-names")
    }

    fn policy_package_name_path(&self, owner_uid: u32, name: &str) -> PathBuf {
        self.policy_package_names_directory(owner_uid)
            .join(format!("{name}.json"))
    }

    fn policy_set_name_path(&self, owner_uid: u32, name: &str) -> PathBuf {
        self.policy_set_names_directory(owner_uid)
            .join(format!("{name}.json"))
    }

    fn policy_package_path(&self, digest: &ContentDigest) -> PathBuf {
        self.packages
            .join(digest.as_str())
            .join("policy-package.json")
    }

    fn user_policy_package_path(&self, owner_uid: u32, digest: &ContentDigest) -> PathBuf {
        self.users
            .join(owner_uid.to_string())
            .join("policy-packages")
            .join(format!("{}.json", digest.as_str()))
    }

    fn read_policy_package(
        &self,
        owner_uid: u32,
        digest: &ContentDigest,
    ) -> Result<PolicyPackageRevision> {
        let user_path = self.user_policy_package_path(owner_uid, digest);
        if user_path.exists() {
            return self.read_canonical(&user_path, digest, "user policy package");
        }
        self.read_canonical(
            &self.policy_package_path(digest),
            digest,
            "root policy package",
        )
    }

    fn collect_root_policy_packages(
        &self,
        packages: &mut BTreeMap<String, StoredPolicyPackage>,
    ) -> Result<()> {
        let entries = self.directory_entries(&self.packages, "listing root policy packages")?;
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().context(IoSnafu {
                action: "inspecting root package directory",
                path: &path,
            })?;
            if file_type.is_symlink() || !file_type.is_dir() {
                continue;
            }
            Self::require_safe_directory(&path)?;
            let digest = match entry.file_name().to_str() {
                Some(value) => match ContentDigest::new(value) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                None => continue,
            };
            let policy_path = path.join("policy-package.json");
            if !policy_path.exists() {
                continue;
            }
            let revision: PolicyPackageRevision =
                self.read_canonical(&policy_path, &digest, "root policy package")?;
            self.validate_policy_package(&revision)?;
            packages.insert(
                digest.as_str().to_owned(),
                StoredPolicyPackage::new(&revision),
            );
        }
        Ok(())
    }

    fn collect_user_policy_packages(
        &self,
        owner_uid: u32,
        packages: &mut BTreeMap<String, StoredPolicyPackage>,
    ) -> Result<()> {
        for name in self.list_named_resources(
            owner_uid,
            "PolicyPackage",
            self.policy_package_names_directory(owner_uid),
        )? {
            let digest = self.read_named_resource(
                owner_uid,
                "PolicyPackage",
                &name,
                self.policy_package_name_path(owner_uid, &name),
            )?;
            let revision = self.read_policy_package(owner_uid, &digest)?;
            self.validate_policy_package(&revision)?;
            packages.insert(
                digest.as_str().to_owned(),
                StoredPolicyPackage::new(&revision),
            );
        }
        Ok(())
    }

    fn user_policy_package_bytes(&self, owner_uid: u32) -> Result<u64> {
        let directory = self
            .users
            .join(owner_uid.to_string())
            .join("policy-packages");
        let mut total = 0_u64;
        for (digest, _policy) in self.canonical_records_in_flat_directory::<PolicyPackageRevision>(
            &directory,
            "policy package",
        )? {
            let path = self.user_policy_package_path(owner_uid, &digest);
            let metadata = fs::metadata(&path).context(IoSnafu {
                action: "measuring immutable user policy package",
                path: &path,
            })?;
            total = total.saturating_add(metadata.len());
        }
        Ok(total)
    }

    fn canonical_records_in_flat_directory<T>(
        &self,
        directory: &Path,
        record_kind: &str,
    ) -> Result<Vec<(ContentDigest, T)>>
    where
        T: CanonicalEncoding + DeserializeOwned,
    {
        let entries =
            self.directory_entries(directory, "listing immutable daemon store records")?;
        let mut records = Vec::new();
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().context(IoSnafu {
                action: "inspecting immutable daemon store record entry",
                path: &path,
            })?;
            if file_type.is_symlink() || !file_type.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            let Some(name) = file_name
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
            else {
                continue;
            };
            let digest = match ContentDigest::new(name) {
                Ok(value) => value,
                Err(_) => continue,
            };
            records.push((
                digest.clone(),
                self.read_canonical(&path, &digest, record_kind)?,
            ));
        }
        records.sort_by(|(left, _), (right, _)| left.as_str().cmp(right.as_str()));
        Ok(records)
    }

    fn resolve_policy_package_name(&self, owner_uid: u32, name: &str) -> Result<ContentDigest> {
        Self::require_resource_name(name, "PolicyPackage")?;
        let mut candidates = Vec::new();
        let user_name_path = self.policy_package_name_path(owner_uid, name);
        if user_name_path.exists() {
            candidates.push(self.read_named_resource(
                owner_uid,
                "PolicyPackage",
                name,
                user_name_path,
            )?);
        }
        for entry in
            self.directory_entries(&self.packages, "listing root policy packages by name")?
        {
            let path = entry.path();
            let file_type = entry.file_type().context(IoSnafu {
                action: "inspecting root policy package directory",
                path: &path,
            })?;
            if file_type.is_symlink() || !file_type.is_dir() {
                continue;
            }
            let Some(digest) = entry
                .file_name()
                .to_str()
                .and_then(|value| ContentDigest::new(value).ok())
            else {
                continue;
            };
            let policy_path = path.join("policy-package.json");
            if !policy_path.exists() {
                continue;
            }
            let package: PolicyPackageRevision =
                self.read_canonical(&policy_path, &digest, "root policy package")?;
            if package.manifest().name() == name {
                candidates.push(digest);
            }
        }
        candidates.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        candidates.dedup();
        match candidates.as_slice() {
            [digest] => Ok(digest.clone()),
            [] => InvalidRequestSnafu {
                reason: format!("no PolicyPackage is named `{name}`"),
            }
            .fail(),
            _ => InvalidRequestSnafu {
                reason: format!("PolicyPackage name `{name}` is ambiguous"),
            }
            .fail(),
        }
    }

    fn resolve_named_agent(&self, owner_uid: u32, name: &str) -> Result<ResolvedNamedAgent> {
        let record = self.read_named_resource_record(
            owner_uid,
            "Agent",
            name,
            self.agent_path(owner_uid, name),
        )?;
        let integrity_digest = record.validate("Agent", name)?;
        let NamedResourceSpec::Agent(spec) = record.spec else {
            return InvalidRequestSnafu {
                reason: String::from("Agent resource has an invalid spec"),
            }
            .fail();
        };
        let installation: InstallationRecord = self.read_canonical(
            &self.installation_path(owner_uid, &integrity_digest),
            &integrity_digest,
            "Agent installation",
        )?;
        installation.validate().map_err(Self::invalid_model)?;
        if installation.owner_uid() != owner_uid {
            return InvalidRequestSnafu {
                reason: String::from("Agent installation does not belong to the caller"),
            }
            .fail();
        }
        let package: AgentPackageManifest = self.read_canonical(
            &self.package_manifest_path(installation.package_digest()),
            installation.package_digest(),
            "Agent package",
        )?;
        if package.adapter_id() != spec.adapter {
            return InvalidRequestSnafu {
                reason: String::from(
                    "Agent resource adapter does not match its immutable package revision",
                ),
            }
            .fail();
        }
        Ok(ResolvedNamedAgent {
            adapter: spec.adapter,
            integrity_digest,
        })
    }

    fn resolve_policy_set_for_static_session(
        &self,
        owner_uid: u32,
        name: &str,
    ) -> Result<(
        ContentDigest,
        Vec<(ContentDigest, PolicyPackageResourceSpec)>,
    )> {
        let record = self.read_named_resource_record(
            owner_uid,
            "PolicySet",
            name,
            self.policy_set_name_path(owner_uid, name),
        )?;
        let policy_set_digest = record.validate("PolicySet", name)?;
        let NamedResourceSpec::PolicySet(spec) = record.spec else {
            return InvalidRequestSnafu {
                reason: String::from("PolicySet resource has an invalid spec"),
            }
            .fail();
        };
        let revision: PolicySetRevision = self.read_canonical(
            &self.policy_set_path(owner_uid, &policy_set_digest),
            &policy_set_digest,
            "policy set",
        )?;
        revision.validate().map_err(Self::invalid_model)?;
        if spec.packages.len() != revision.policy_input_digests().len() {
            return InvalidRequestSnafu {
                reason: String::from(
                    "PolicySet package names do not match its immutable package revision",
                ),
            }
            .fail();
        }
        let mut packages = Vec::with_capacity(spec.packages.len());
        for (package_name, revision_digest) in spec
            .packages
            .iter()
            .zip(revision.policy_input_digests().iter())
        {
            let digest = self.resolve_policy_package_name(owner_uid, package_name)?;
            if digest.as_str() != revision_digest.as_str() {
                return InvalidRequestSnafu {
                    reason: format!(
                        "PolicySet package `{package_name}` no longer matches its immutable membership"
                    ),
                }
                .fail();
            }
            let policy = self.read_policy_package(owner_uid, &digest)?;
            packages.push((digest, PolicyPackageResourceSpec::from_revision(&policy)?));
        }
        Ok((policy_set_digest, packages))
    }

    fn read_named_resource(
        &self,
        owner_uid: u32,
        kind: &str,
        name: &str,
        path: PathBuf,
    ) -> Result<ContentDigest> {
        self.read_named_resource_record(owner_uid, kind, name, path)
            .and_then(|record| record.validate(kind, name))
    }

    fn read_named_resource_record(
        &self,
        owner_uid: u32,
        kind: &str,
        name: &str,
        path: PathBuf,
    ) -> Result<NamedResourceRecord> {
        Self::require_resource_name(name, kind)?;
        let record: NamedResourceRecord = self.read_json_record(&path, "named resource")?;
        record.validate(kind, name)?;
        let _owner_uid = owner_uid;
        Ok(record)
    }

    fn list_named_resources(
        &self,
        owner_uid: u32,
        kind: &str,
        directory: PathBuf,
    ) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in self.directory_entries(&directory, "listing named resources")? {
            let path = entry.path();
            let file_type = entry.file_type().context(IoSnafu {
                action: "inspecting named resource entry",
                path: &path,
            })?;
            if file_type.is_symlink() || !file_type.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            let Some(name) = file_name
                .to_str()
                .and_then(|value| value.strip_suffix(".json"))
            else {
                continue;
            };
            let _digest = self.read_named_resource(owner_uid, kind, name, path)?;
            names.push(name.to_owned());
        }
        names.sort();
        Ok(names)
    }

    fn directory_entries(
        &self,
        directory: &Path,
        action: &'static str,
    ) -> Result<Vec<fs::DirEntry>> {
        match fs::read_dir(directory) {
            Ok(entries) => {
                Self::require_safe_directory(directory)?;
                entries
                    .map(|entry| {
                        entry.context(IoSnafu {
                            action,
                            path: directory,
                        })
                    })
                    .collect()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(source) => Err(crate::DaemonError::Io {
                action,
                path: directory.to_path_buf(),
                source,
                location: snafu::Location::default(),
            }),
        }
    }

    fn read_canonical<T>(
        &self,
        path: &Path,
        expected_digest: &ContentDigest,
        record_kind: &str,
    ) -> Result<T>
    where
        T: CanonicalEncoding + DeserializeOwned,
    {
        let metadata = fs::symlink_metadata(path).context(IoSnafu {
            action: "inspecting immutable daemon store record",
            path,
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return crate::error::UnsafePathSnafu {
                path: path.to_path_buf(),
                reason: String::from(
                    "must be an effective-owner-controlled non-symlink non-writable file",
                ),
            }
            .fail();
        }
        let bytes = fs::read(path).context(IoSnafu {
            action: "reading immutable daemon store record",
            path,
        })?;
        let record = serde_json::from_slice::<T>(&bytes).map_err(|source| {
            crate::DaemonError::InvalidConfig {
                path: path.to_path_buf(),
                source,
                location: snafu::Location::default(),
            }
        })?;
        let canonical = record.canonical_bytes().map_err(Self::invalid_model)?;
        if canonical != bytes || ContentDigest::from_canonical_bytes(&canonical) != *expected_digest
        {
            return InvalidRequestSnafu {
                reason: format!("stored {record_kind} does not match its canonical digest"),
            }
            .fail();
        }
        Ok(record)
    }

    fn read_json_record<T>(&self, path: &Path, _record_kind: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let metadata = fs::symlink_metadata(path).context(IoSnafu {
            action: "inspecting named daemon store record",
            path,
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return crate::error::UnsafePathSnafu {
                path: path.to_path_buf(),
                reason: String::from(
                    "must be an effective-owner-controlled non-symlink non-writable file",
                ),
            }
            .fail();
        }
        let bytes = fs::read(path).context(IoSnafu {
            action: "reading named daemon store record",
            path,
        })?;
        serde_json::from_slice::<T>(&bytes).map_err(|source| crate::DaemonError::InvalidConfig {
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        })
    }

    fn write_immutable(&self, path: &Path, encoded: &[u8]) -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| crate::DaemonError::UnsafePath {
                path: path.to_path_buf(),
                reason: String::from("immutable store record has no parent directory"),
                location: snafu::Location::default(),
            })?;
        fs::create_dir_all(parent).context(IoSnafu {
            action: "creating immutable store directory",
            path: parent,
        })?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).context(IoSnafu {
            action: "securing immutable store directory",
            path: parent,
        })?;
        Self::require_safe_directory(parent)?;
        match fs::read(path) {
            Ok(existing) if existing == encoded => return Ok(()),
            Ok(_) => {
                return crate::error::InvalidRequestSnafu {
                    reason: format!(
                        "immutable daemon store record `{}` conflicts with an earlier value",
                        path.display()
                    ),
                }
                .fail()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(crate::DaemonError::Io {
                    action: "reading immutable store record",
                    path: path.to_path_buf(),
                    source,
                    location: snafu::Location::default(),
                })
            }
        }
        let temporary = path.with_extension("json.tmp");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .context(IoSnafu {
                action: "writing immutable store temporary record",
                path: &temporary,
            })?;
        file.write_all(encoded).context(IoSnafu {
            action: "writing immutable store temporary record",
            path: &temporary,
        })?;
        file.sync_all().context(IoSnafu {
            action: "syncing immutable store temporary record",
            path: &temporary,
        })?;
        fs::rename(&temporary, path).context(IoSnafu {
            action: "publishing immutable store record",
            path,
        })?;
        File::open(parent)
            .context(IoSnafu {
                action: "opening immutable store directory",
                path: parent,
            })?
            .sync_all()
            .context(IoSnafu {
                action: "syncing immutable store directory",
                path: parent,
            })
    }

    fn require_safe_directory(path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(path).context(IoSnafu {
            action: "inspecting immutable store directory",
            path,
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return crate::error::UnsafePathSnafu {
                path: path.to_path_buf(),
                reason: String::from(
                    "must be an effective-owner-controlled non-symlink non-writable directory",
                ),
            }
            .fail();
        }
        Ok(())
    }

    fn is_path_component(value: &str) -> bool {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }

    fn require_resource_name(name: &str, kind: &str) -> Result<()> {
        if Self::is_path_component(name) {
            return Ok(());
        }
        InvalidRequestSnafu {
            reason: format!("{kind} metadata.name is not a safe immutable resource name"),
        }
        .fail()
    }

    fn parse_digest(value: &str, kind: &str) -> Result<ContentDigest> {
        ContentDigest::new(value).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("{kind} digest is invalid: {error}"),
            }
            .build()
        })
    }

    fn invalid_model(error: erebor_runtime_packages::PackageError) -> crate::DaemonError {
        InvalidRequestSnafu {
            reason: error.to_string(),
        }
        .build()
    }

    fn validate_policy_package(&self, policy: &PolicyPackageRevision) -> Result<()> {
        PolicyPackageResourceSpec::from_revision(policy)?;
        std::str::from_utf8(policy.policy_config()).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!(
                    "policy package `{}` has non-UTF-8 policy.toml: {error}",
                    policy.manifest().name()
                ),
            }
            .build()
        })?;
        for (name, source) in policy.rules() {
            let source = std::str::from_utf8(source).map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!(
                        "policy package `{}` rule `{name}` is not UTF-8: {error}",
                        policy.manifest().name()
                    ),
                }
                .build()
            })?;
            LocalPolicy::from_json_str(source).map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!(
                        "policy package `{}` rule `{name}` is invalid: {error}",
                        policy.manifest().name()
                    ),
                }
                .build()
            })?;
        }
        Ok(())
    }
}

impl SessionLease {
    fn from_spec(spec: &SessionSpec) -> Self {
        Self {
            session_id: spec.session_id().as_str().to_owned(),
            owner_uid: spec.owner().uid(),
            package_digest: spec
                .package()
                .map(ImmutableIdentity::sha256)
                .map(str::to_owned),
            installation_digest: spec
                .installation()
                .map(ImmutableIdentity::sha256)
                .map(str::to_owned),
            adapter_digest: spec
                .adapter()
                .map(ImmutableIdentity::sha256)
                .map(str::to_owned),
            policy_set_digest: spec.policy_set().sha256().to_owned(),
            policy_input_digests: spec
                .policy_inputs()
                .iter()
                .map(ImmutableIdentity::sha256)
                .map(str::to_owned)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use erebor_runtime_packages::{
        AgentPackageManifest, CanonicalEncoding, ContentDigest, InstallationRecord,
        PolicyPackageRevision, PolicySetRevision,
    };

    use super::{DaemonLocalStore, NamedResourceRecord, SessionLease};
    use crate::{config::RootCuratedAdmission, DaemonPaths};

    const ADAPTER_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn store_named_generic_agent(
        store: &DaemonLocalStore,
        owner_uid: u32,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let package = AgentPackageManifest::new(
            "generic-process",
            "generic-process-v1",
            "0.1.0",
            vec![String::from("<argv>")],
            ContentDigest::new(ADAPTER_DIGEST)?,
            Vec::new(),
        )?;
        let package_digest = package.canonical_digest()?;
        store.write_immutable(
            &store.package_manifest_path(&package_digest),
            &package.canonical_bytes()?,
        )?;
        let installation = InstallationRecord::new(owner_uid, package_digest, 1);
        let installation_digest = installation.canonical_digest()?;
        store.write_immutable(
            &store.installation_path(owner_uid, &installation_digest),
            &installation.canonical_bytes()?,
        )?;
        let record = NamedResourceRecord::agent(name, &installation_digest, "generic-process-v1")?;
        store.write_immutable(
            &store.agent_path(owner_uid, name),
            &serde_json::to_vec(&record)?,
        )?;
        Ok(())
    }

    fn browser_mediation_package(
        name: &str,
    ) -> Result<PolicyPackageRevision, Box<dyn std::error::Error>> {
        Ok(PolicyPackageRevision::new(
            name,
            format!("name = \"{name}\"\n").into_bytes(),
            BTreeMap::from([(
                String::from("terminal.json"),
                br#"{"rules":[{"id":"mediate-managed-browser-launch","match":{"surface":"terminal","action":"process_exec","command_contains":"--remote-debugging-port"},"decision":"mediate","reason":"replace raw browser debug launches","mediation":{"kind":"managed_browser_cdp","replacement_surface":"browser_cdp","return_endpoint":"requested_port"}},{"id":"allow-terminal","match":{"surface":"terminal"},"decision":"allow"}]}"#.to_vec(),
            )]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            format!("# {name}\n").into_bytes(),
        )?)
    }

    fn single_surface_package(
        name: &str,
        surface: &str,
    ) -> Result<PolicyPackageRevision, Box<dyn std::error::Error>> {
        Ok(PolicyPackageRevision::new(
            name,
            format!("name = \"{name}\"\n").into_bytes(),
            BTreeMap::from([(
                String::from("rules.json"),
                format!(
                    r#"{{"rules":[{{"id":"allow-{surface}","match":{{"surface":"{surface}"}},"decision":"allow"}}]}}"#
                )
                .into_bytes(),
            )]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("rules.json"), br#"{}"#.to_vec())]),
            format!("# {name}\n").into_bytes(),
        )?)
    }

    #[test]
    fn session_leases_are_crash_safe_idempotent_and_immutable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        let lease = SessionLease {
            session_id: String::from("session-1"),
            owner_uid: 1000,
            package_digest: Some(String::from("package")),
            installation_digest: Some(String::from("installation")),
            adapter_digest: Some(String::from("adapter")),
            policy_set_digest: String::from("policy-set"),
            policy_input_digests: vec![String::from("policy-a"), String::from("policy-b")],
        };
        store.record_lease(lease.clone())?;
        store.record_lease(lease)?;
        assert!(store
            .record_lease(SessionLease {
                session_id: String::from("session-1"),
                owner_uid: 1000,
                package_digest: Some(String::from("different-package")),
                installation_digest: Some(String::from("installation")),
                adapter_digest: Some(String::from("adapter")),
                policy_set_digest: String::from("policy-set"),
                policy_input_digests: vec![String::from("policy-a"), String::from("policy-b")],
            })
            .is_err());
        store.release_session_lease(1000, "session-1")?;
        assert!(!store.lease_path("session-1").exists());
        store.release_session_lease(1000, "session-1")?;
        Ok(())
    }

    #[test]
    fn named_resource_envelopes_are_versioned_and_never_retargeted(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        let first = ContentDigest::new(ADAPTER_DIGEST)?;
        let second =
            ContentDigest::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?;
        let path = store.agent_path(1000, "local-codex");
        let record = NamedResourceRecord::agent("local-codex", &first, "codex-v1")?;
        let encoded = serde_json::to_vec(&record)?;
        store.write_immutable(&path, &encoded)?;
        assert_eq!(
            store.read_named_resource(1000, "Agent", "local-codex", path.clone())?,
            first
        );
        let replacement = NamedResourceRecord::agent("local-codex", &second, "codex-v1")?;
        assert!(store
            .write_immutable(&path, &serde_json::to_vec(&replacement)?)
            .is_err());

        let mut unknown_version = record;
        unknown_version.api_version = String::from("erebor.dev/v2");
        assert!(unknown_version.validate("Agent", "local-codex").is_err());
        assert!(replacement.validate("PolicySet", "local-codex").is_err());

        let mut agent_json = serde_json::to_value(NamedResourceRecord::agent(
            "local-codex-2",
            &first,
            "codex-v1",
        )?)?;
        agent_json["spec"]["policy"] = serde_json::Value::String(String::from("fixture"));
        assert!(serde_json::from_value::<NamedResourceRecord>(agent_json).is_err());
        Ok(())
    }

    #[test]
    fn root_curated_records_are_immutable_and_resolved_per_owner(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;

        let package = AgentPackageManifest::new(
            "generic-process",
            "generic-process-v1",
            "0.1.0",
            vec![String::from("<argv>")],
            ContentDigest::new(ADAPTER_DIGEST)?,
            Vec::new(),
        )?;
        let package_digest = package.canonical_digest()?;
        let installation = InstallationRecord::new(1000, package_digest.clone(), 1);
        let installation_digest = installation.canonical_digest()?;
        let policy = PolicyPackageRevision::new(
            "host-minimum",
            b"name = \"host-minimum\"\n".to_vec(),
            BTreeMap::from([(
                String::from("terminal.json"),
                br#"{"rules":[{"id":"allow-terminal","match":{"surface":"terminal"},"decision":"allow"}]}"#.to_vec(),
            )]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Host minimum\n".to_vec(),
        )?;
        let policy_digest = policy.canonical_digest()?;
        let policy_set = PolicySetRevision::new(vec![policy_digest.clone()])?;
        let policy_set_digest = policy_set.canonical_digest()?;
        store.seed_root_curated(&[RootCuratedAdmission::new(
            package,
            installation,
            policy_set,
            vec![policy],
        )])?;

        let admission = store.resolve_admission(
            1000,
            package_digest.as_str(),
            installation_digest.as_str(),
            ADAPTER_DIGEST,
            policy_set_digest.as_str(),
        )?;
        assert_eq!(admission.package_digest(), package_digest.as_str());
        assert_eq!(
            admission.installation_digest(),
            installation_digest.as_str()
        );
        assert_eq!(admission.adapter_digest(), ADAPTER_DIGEST);
        assert_eq!(admission.policy_set_digest(), policy_set_digest.as_str());
        assert_eq!(
            admission.policy_input_digests(),
            &[policy_digest.as_str().to_owned()]
        );
        assert!(store
            .resolve_admission(
                1001,
                package_digest.as_str(),
                installation_digest.as_str(),
                ADAPTER_DIGEST,
                policy_set_digest.as_str(),
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn policy_catalogs_are_daemon_owned_and_revalidate_canonical_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        let _admission = store.ensure_builtin_admission(1000)?;

        let packages = store.list_policy_packages(1000)?;
        let package = packages
            .iter()
            .find(|package| package.name() == "generic-host-minimum")
            .ok_or("built-in host policy package was not listed")?;
        let inspected_package = store.inspect_policy_package(1000, package.name())?;
        assert_eq!(inspected_package.name(), "generic-host-minimum");

        let policy_set = store.create_user_policy_set(
            1000,
            "company-workspace",
            &[String::from("generic-host-minimum")],
        )?;
        let policy_sets = store.list_policy_sets(1000)?;
        assert!(policy_sets
            .iter()
            .any(|listed| listed.name() == policy_set.name()));
        assert_eq!(
            store.inspect_policy_set(1000, "company-workspace")?.name(),
            "company-workspace"
        );
        assert!(store.list_policy_sets(1001)?.is_empty());
        Ok(())
    }

    #[test]
    fn builtin_generic_host_policy_covers_intrinsic_effect_surfaces(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_package, policy) = DaemonLocalStore::builtin_generic_content()?;
        for surface in ["filesystem", "network", "terminal"] {
            let rule_name = format!("{surface}.json");
            let rule = std::str::from_utf8(
                policy
                    .rules()
                    .get(&rule_name)
                    .ok_or("built-in policy rule is missing")?,
            )?;
            assert!(rule.contains(&format!("\"surface\":\"{surface}\"")));
            assert!(policy.tests().contains_key(&rule_name));
        }
        crate::runtime_interception::policy::RuntimePolicyImage::compile(
            "builtin-generic-host",
            vec![policy],
        )?;
        Ok(())
    }

    #[test]
    fn malformed_root_policy_is_rejected_before_it_reaches_the_store(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        let package = AgentPackageManifest::new(
            "generic-process",
            "generic-process-v1",
            "0.1.0",
            vec![String::from("<argv>")],
            ContentDigest::new(ADAPTER_DIGEST)?,
            Vec::new(),
        )?;
        let installation = InstallationRecord::new(1000, package.canonical_digest()?, 1);
        let policy = PolicyPackageRevision::new(
            "host-minimum",
            b"name = \"host-minimum\"\n".to_vec(),
            BTreeMap::from([(String::from("terminal.json"), b"not-json".to_vec())]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Host minimum\n".to_vec(),
        )?;
        let policy_set = PolicySetRevision::new(vec![policy.canonical_digest()?])?;
        assert!(store
            .seed_root_curated(&[RootCuratedAdmission::new(
                package,
                installation,
                policy_set,
                vec![policy],
            )])
            .is_err());
        Ok(())
    }

    #[test]
    fn policy_sets_compose_ordered_named_user_policy_packages_without_a_root_special_case(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        let baseline = PolicyPackageRevision::new(
            "company-baseline",
            b"name = \"company-baseline\"\n".to_vec(),
            BTreeMap::from([(
                String::from("terminal.json"),
                br#"{"rules":[{"id":"baseline-allow","match":{"surface":"terminal"},"decision":"allow"}]}"#.to_vec(),
            )]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Company baseline\n".to_vec(),
        )?;
        let workspace = PolicyPackageRevision::new(
            "workspace-write",
            b"name = \"workspace-write\"\n".to_vec(),
            BTreeMap::from([(
                String::from("terminal.json"),
                br#"{"rules":[{"id":"workspace-deny","match":{"surface":"terminal"},"decision":"deny"}]}"#.to_vec(),
            )]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Workspace write policy\n".to_vec(),
        )?;
        let baseline_digest = store.store_user_policy_package(1000, &baseline, u64::MAX)?;
        let workspace_digest = store.store_user_policy_package(1000, &workspace, u64::MAX)?;
        let forward = store.create_user_policy_set(
            1000,
            "workspace-policy",
            &[
                String::from("company-baseline"),
                String::from("workspace-write"),
            ],
        )?;
        let reverse = store.create_user_policy_set(
            1000,
            "workspace-policy-reversed",
            &[
                String::from("workspace-write"),
                String::from("company-baseline"),
            ],
        )?;
        assert!(store
            .create_user_policy_set(
                1000,
                "duplicate-package",
                &[
                    String::from("company-baseline"),
                    String::from("company-baseline")
                ],
            )
            .is_err());

        let forward_digest = store.resolve_policy_set_name(1000, forward.name())?;
        let forward_revision: PolicySetRevision = store.read_canonical(
            &store.policy_set_path(1000, &forward_digest),
            &forward_digest,
            "policy set",
        )?;
        assert_eq!(
            forward_revision
                .policy_input_digests()
                .iter()
                .map(|digest| digest.as_str())
                .collect::<Vec<_>>(),
            vec![baseline_digest.as_str(), workspace_digest.as_str()]
        );
        assert_ne!(
            forward_digest,
            store.resolve_policy_set_name(1000, reverse.name())?
        );
        Ok(())
    }

    #[test]
    fn policy_package_schema_requires_surface_coverage_and_persists_the_typed_resource(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        let policy = PolicyPackageRevision::new(
            "fixture-baseline",
            b"name = \"fixture-baseline\"\n".to_vec(),
            BTreeMap::from([(
                String::from("terminal.json"),
                br#"{"rules":[{"id":"mediate-managed-browser-launch","match":{"surface":"terminal","action":"process_exec","command_contains":"--remote-debugging-port"},"decision":"mediate","reason":"replace raw browser debug launches","mediation":{"kind":"managed_browser_cdp","replacement_surface":"browser_cdp","return_endpoint":"requested_port"}},{"id":"deny-destructive-fixture-command","match":{"surface":"terminal","action":"process_exec","command_contains":"rm -rf"},"decision":"deny","reason":"destructive recursive removal is denied"},{"id":"allow-fixture-processes","match":{"surface":"terminal","action":"process_exec"},"decision":"allow"}]}"#.to_vec(),
            )]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Fixture baseline\n".to_vec(),
        )?;
        let digest = store.store_user_policy_package(1000, &policy, u64::MAX)?;
        let record: NamedResourceRecord = serde_json::from_slice(&std::fs::read(
            store.policy_package_name_path(1000, "fixture-baseline"),
        )?)?;
        assert_eq!(record.api_version, "erebor.dev/v1");
        assert_eq!(record.kind, "PolicyPackage");
        assert_eq!(record.metadata.name, "fixture-baseline");
        assert_eq!(record.integrity_digest, digest.as_str());
        assert!(matches!(
            record.spec,
            super::NamedResourceSpec::PolicyPackage(super::PolicyPackageResourceSpec { ref rules })
                if rules.len() == 3
        ));

        let restarted = DaemonLocalStore::installed(&paths)?;
        assert_eq!(
            restarted
                .inspect_policy_package(1000, "fixture-baseline")?
                .name(),
            "fixture-baseline"
        );
        assert_eq!(
            restarted
                .list_policy_packages(1000)?
                .iter()
                .map(|package| package.name())
                .collect::<Vec<_>>(),
            vec!["fixture-baseline"]
        );

        let missing_surface = PolicyPackageRevision::new(
            "missing-surface",
            b"name = \"missing-surface\"\n".to_vec(),
            BTreeMap::from([(
                String::from("terminal.json"),
                br#"{"rules":[{"id":"missing-surface","match":{"action":"process_exec"},"decision":"allow"}]}"#.to_vec(),
            )]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Missing surface\n".to_vec(),
        )?;
        assert!(restarted
            .store_user_policy_package(1000, &missing_surface, u64::MAX)
            .is_err());
        Ok(())
    }

    #[test]
    fn policy_storage_quota_rejects_before_a_new_immutable_record_is_written(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        let policy = PolicyPackageRevision::new(
            "bounded-user-policy",
            b"name = \"bounded-user-policy\"\n".to_vec(),
            BTreeMap::from([(
                String::from("terminal.json"),
                br#"{"rules":[{"id":"allow-terminal","match":{"surface":"terminal"},"decision":"allow"}]}"#.to_vec(),
            )]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Bounded user policy\n".to_vec(),
        )?;
        let bytes = policy.canonical_bytes()?.len() as u64;
        assert!(store
            .store_user_policy_package(1000, &policy, bytes.saturating_sub(1))
            .is_err());
        assert!(store.list_policy_packages(1000)?.is_empty());
        assert!(store
            .store_user_policy_package(1000, &policy, bytes)
            .is_ok());
        Ok(())
    }

    #[test]
    fn daemon_installed_builtin_generic_content_is_canonical_and_idempotent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        store.seed_builtin_generic_content()?;
        store.seed_builtin_generic_content()?;
        let descriptor = erebor_runtime_core::AgentAdapterDescriptor::generic_process_v1()?;
        let package = AgentPackageManifest::new(
            "generic-process",
            descriptor.id(),
            env!("CARGO_PKG_VERSION"),
            vec![String::from("<argv>")],
            ContentDigest::new(descriptor.sha256()?)?,
            Vec::new(),
        )?;
        let digest = package.canonical_digest()?;
        let stored: AgentPackageManifest = store.read_canonical(
            &store.package_manifest_path(&digest),
            &digest,
            "built-in package",
        )?;
        assert_eq!(stored, package);
        let first = store.ensure_builtin_admission(1000)?;
        let second = store.ensure_builtin_admission(1000)?;
        assert_eq!(first.package_digest(), digest.as_str());
        assert_eq!(first.package_digest(), second.package_digest());
        assert_eq!(first.installation_digest(), second.installation_digest());
        assert_eq!(first.adapter_digest(), second.adapter_digest());
        assert_eq!(first.policy_set_digest(), second.policy_set_digest());
        let resolved = store.resolve_admission(
            1000,
            first.package_digest(),
            first.installation_digest(),
            first.adapter_digest(),
            first.policy_set_digest(),
        )?;
        assert_eq!(resolved.package_digest(), first.package_digest());
        Ok(())
    }

    #[test]
    fn static_sessions_join_named_resources_without_creating_a_runtime(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        store_named_generic_agent(&store, 1000, "local-agent")?;
        let first_policy = browser_mediation_package("browser-policy-first")?;
        let second_policy = browser_mediation_package("browser-policy-second")?;
        let first_policy_digest = store.store_user_policy_package(1000, &first_policy, u64::MAX)?;
        let second_policy_digest =
            store.store_user_policy_package(1000, &second_policy, u64::MAX)?;
        store.create_user_policy_set(
            1000,
            "browser-policyset",
            &[
                String::from("browser-policy-first"),
                String::from("browser-policy-second"),
            ],
        )?;
        store.create_user_surface(1000, "engineering-browser", "browser_cdp")?;

        let admission = store.prepare_static_session_admission(
            1000,
            "session-static-1",
            "local-agent",
            "browser-policyset",
            &[String::from("engineering-browser")],
        )?;
        let session = store.create_static_session(1000, &admission)?;
        assert_eq!(session.name(), "session-static-1");
        assert_eq!(session.agent_name(), "local-agent");
        assert_eq!(session.policy_set_name(), "browser-policyset");
        assert_eq!(
            session.surface_names(),
            &[String::from("engineering-browser")]
        );
        assert!(store
            .static_session_resolution_path(1000, "session-static-1")
            .exists());
        assert_eq!(
            store
                .inspect_static_session(1000, "session-static-1")?
                .ok_or("static Session is missing")?
                .name(),
            "session-static-1"
        );
        assert_eq!(
            store
                .list_static_sessions(1000)?
                .iter()
                .map(|session| session.name())
                .collect::<Vec<_>>(),
            vec!["session-static-1"]
        );
        let record: NamedResourceRecord = serde_json::from_slice(&std::fs::read(
            store.static_session_path(1000, "session-static-1"),
        )?)?;
        assert_eq!(record.api_version, "erebor.dev/v1");
        assert_eq!(record.kind, "Session");
        assert_eq!(record.metadata.name, "session-static-1");
        let resolution: super::StaticSessionResolution = serde_json::from_slice(&std::fs::read(
            store.static_session_resolution_path(1000, "session-static-1"),
        )?)?;
        assert_eq!(
            resolution.policy_package_integrity_digests,
            vec![first_policy_digest.as_str(), second_policy_digest.as_str(),]
        );
        assert!(!paths
            .session_state_path()
            .join("users/1000/sessions/session-static-1")
            .exists());
        assert!(!paths
            .session_runtime_path()
            .join("session-static-1")
            .exists());
        Ok(())
    }

    #[test]
    fn static_sessions_require_exact_named_browser_configuration_and_owner_scope(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        store_named_generic_agent(&store, 1000, "local-agent")?;
        let policy = browser_mediation_package("browser-policy")?;
        store.store_user_policy_package(1000, &policy, u64::MAX)?;
        store.create_user_policy_set(
            1000,
            "browser-policyset",
            &[String::from("browser-policy")],
        )?;
        store.create_user_surface(1000, "engineering-browser", "browser_cdp")?;
        assert!(store
            .prepare_static_session_admission(
                1000,
                "session-without-browser",
                "local-agent",
                "browser-policyset",
                &[],
            )
            .is_err());
        assert!(store
            .prepare_static_session_admission(
                1000,
                "session-duplicate-browser",
                "local-agent",
                "browser-policyset",
                &[
                    String::from("engineering-browser"),
                    String::from("engineering-browser"),
                ],
            )
            .is_err());
        assert!(store
            .prepare_static_session_admission(
                1001,
                "session-cross-owner",
                "local-agent",
                "browser-policyset",
                &[String::from("engineering-browser")],
            )
            .is_err());
        assert!(store
            .create_user_surface(1000, "intrinsic-filesystem", "filesystem")
            .is_err());
        assert!(store
            .create_user_surface(1000, "intrinsic-network", "network")
            .is_err());
        Ok(())
    }

    #[test]
    fn static_sessions_require_each_policy_package_to_cover_each_source_surface(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        store_named_generic_agent(&store, 1000, "local-agent")?;
        let terminal = single_surface_package("terminal-policy", "terminal")?;
        let filesystem = single_surface_package("filesystem-policy", "filesystem")?;
        store.store_user_policy_package(1000, &terminal, u64::MAX)?;
        store.store_user_policy_package(1000, &filesystem, u64::MAX)?;
        store.create_user_policy_set(
            1000,
            "incomplete-coverage",
            &[
                String::from("terminal-policy"),
                String::from("filesystem-policy"),
            ],
        )?;
        assert!(store
            .prepare_static_session_admission(
                1000,
                "session-incomplete-coverage",
                "local-agent",
                "incomplete-coverage",
                &[],
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn surface_and_policy_envelopes_reject_reverse_references_and_unregistered_surfaces(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        let mut surface = serde_json::to_value(NamedResourceRecord::surface(
            "engineering-browser",
            "browser_cdp",
        )?)?;
        surface["spec"]["policySet"] = serde_json::Value::String(String::from("policy"));
        assert!(serde_json::from_value::<NamedResourceRecord>(surface).is_err());
        let mut unknown_version = NamedResourceRecord::surface("second-browser", "browser_cdp")?;
        unknown_version.api_version = String::from("erebor.dev/v2");
        assert!(unknown_version
            .validate("Surface", "second-browser")
            .is_err());
        assert!(unknown_version
            .validate("Session", "second-browser")
            .is_err());

        let unregistered = PolicyPackageRevision::new(
            "mcp-policy",
            b"name = \"mcp-policy\"\n".to_vec(),
            BTreeMap::from([(
                String::from("mcp.json"),
                br#"{"rules":[{"id":"allow-mcp","match":{"surface":"mcp"},"decision":"allow"}]}"#
                    .to_vec(),
            )]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("mcp.json"), br#"{}"#.to_vec())]),
            b"# MCP\n".to_vec(),
        )?;
        assert!(store
            .store_user_policy_package(1000, &unregistered, u64::MAX)
            .is_err());
        Ok(())
    }
}
