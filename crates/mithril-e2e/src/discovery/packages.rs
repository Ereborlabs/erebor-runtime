use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use araphor_data::{PackageBundleV1, PackageRequestV1, PackageResponseV1};
use mithril_control::{ClientAuth, PackageTrustPinV1};
use serde_json::json;

use crate::control_fixture::{oidc::OidcFixture, MtlsFixture};

mod bundle;
mod fixture;
mod native;
mod wasm;

use bundle::Denials;
use fixture::Fixture;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct AnalysisPackageQualification {
    output: PathBuf,
}

impl AnalysisPackageQualification {
    pub fn new(output: PathBuf) -> Self {
        Self { output }
    }

    pub async fn run(&self) -> Result<()> {
        self.run_case(false).await
    }

    pub async fn run_native(&self) -> Result<()> {
        self.run_case(true).await
    }

    async fn run_case(&self, native: bool) -> Result<()> {
        if native {
            for executable in ["python", "python3"] {
                let error = match std::process::Command::new(executable)
                    .arg("--version")
                    .output()
                {
                    Err(error) => error,
                    Ok(_) => {
                        return Err(
                            "native qualification requires Python unavailable on PATH".into()
                        )
                    }
                };
                self.check(
                    error.kind() == std::io::ErrorKind::NotFound,
                    "Python availability check did not return NotFound",
                )?;
            }
        }
        self.check(
            !self.output.exists(),
            "the qualification output already exists",
        )?;
        let tls = MtlsFixture::new(false)?;
        let oidc = OidcFixture::start(&tls.files, "package-operator").await?;
        let mut config = oidc.auth(
            "https://localhost:44444",
            Some([1; 16]),
            tls.files.ca.clone(),
        );
        config
            .service
            .as_mut()
            .ok_or("the qualification service configuration is absent")?
            .max_age_seconds = 300;
        config.package_managers = config.investigators.clone();
        let managers = config.package_managers.clone();
        let bundles = [
            Denials::bundle("1", 3, false),
            Denials::bundle("bad", 3, true),
            Denials::bundle("2", 2, false),
        ];
        let wasm_bundle = wasm::bundle();
        let native_bundle = native.then(native::detector_bundle).transpose()?;
        let native_bundles = if native {
            native::bundles()?
        } else {
            Vec::new()
        };
        let required = araphor_data::AnalysisPackageOwner::required_bundles();
        config.package_trust = bundles
            .iter()
            .chain(std::iter::once(&wasm_bundle))
            .chain(native_bundle.iter())
            .chain(native_bundles.iter())
            .chain(required.iter())
            .map(|bundle| {
                Ok(PackageTrustPinV1 {
                    tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
                    bundle_digest: bundle.digest()?,
                })
            })
            .collect::<araphor_data::Result<_>>()?;
        let auth = Arc::new(ClientAuth::load(&config).await?);
        let root = tls.path().join("package-control");
        let wasm = wasm::run(
            &tls.path().join("wasm-control"),
            &tls,
            auth.clone(),
            &wasm_bundle,
            &config,
            self,
        )
        .await?;
        let native_detector = if let Some(bundle) = &native_bundle {
            Some(
                wasm::run(
                    &tls.path().join("native-control"),
                    &tls,
                    auth.clone(),
                    bundle,
                    &config,
                    self,
                )
                .await?,
            )
        } else {
            None
        };
        let first = self.initial(&root, auth.clone(), &bundles[0]).await?;
        let original = Self::result_id(&first)?;
        // The token fixture sets expiry in whole seconds.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let fixture = Fixture::open(&root, auth.clone())?;
        let retry = fixture.run("initial").await?;
        self.check_retry(&first, &retry)?;
        self.check(
            fixture.checkpoint().await? == 2,
            "restart retry changed the saved checkpoint",
        )?;
        let (corrected, empty) = self.replacements(&fixture, &bundles).await?;
        auth.replace_package_managers(Vec::new())?;
        let denied = fixture.run("revoked").await;
        self.check(denied.is_err(), "revoked package manager ran an export")?;
        auth.replace_package_managers(managers)?;
        self.removal(&fixture, &original).await?;
        fs::create_dir(&self.output)?;
        super::write_json(
            &self.output.join("result.json"),
            &json!({
                "schema_version":1,"case":if native {"analysis-packages-native"} else {"analysis-packages"},"result":"PASS","mode":"LIGHTWEIGHT",
                "production_owners":["AraphorClient","ClientAuth","ClientListener","ClientGrpcOwner","AnalysisPackageOwner","QueryOwner","AnalysisStore","EffectObservationStore","EvidenceIntakeOwner","GraphAndFindingOwner"],
                "offline_directory_digest":bundles[0].digest()?,"original_result":original,
                "initial":first,"corrected":corrected,"empty":empty,
                "installed_wasm_detector":wasm,
                "installed_native_detector":native_detector,
                "python_unavailable":native,
                "restart_retry_receipt_equal":true,"credential_renewal_advances_activation":true,"stale_source_visible":true,"automatic_source_replacement":true,
                "checkpoint_runs":{"initial":2,"restart_retry":2,"corrected":1},
                "failed_upgrade_preserved_active":true,
                "rollback_restored_threshold":true,"revocation_denied_run":true,"removal_preserved_history":true,
                "source":"Versioned external denial facts with a complete-window marker.",
                "physical_action_attempted":false,"cross_node_qualified":false,"performance_claim":false
            }),
        )?;
        oidc.shutdown().await?;
        Ok(())
    }

    async fn initial(
        &self,
        root: &Path,
        auth: Arc<ClientAuth>,
        bundle: &PackageBundleV1,
    ) -> Result<PackageResponseV1> {
        let fixture = Fixture::open(root, auth)?;
        fixture.window(1, 3)?;
        let directory = root.join("built-package");
        fs::create_dir(&directory)?;
        bundle.write_layout(&directory)?;
        let local = PackageBundleV1::read(&directory)?;
        self.check(
            local.digest()? == bundle.digest()?,
            "local directory changed the admitted bundle",
        )?;
        let installed = fixture
            .operation(PackageRequestV1::Install {
                scope_id: "qualified".into(),
                bundle: local,
                parameters: None,
            })
            .await?;
        self.check(
            installed.exports.iter().all(|export| export.active),
            "SQL package was not activated",
        )?;
        let first = fixture.run("initial").await?;
        self.check(
            fixture.counts(None).await? == json!([{"count":3}]),
            "three denied events did not produce count3",
        )?;
        self.check(
            fixture.checkpoint().await? == 2,
            "initial run did not commit checkpoint2",
        )?;
        Ok(first)
    }

    async fn replacements(
        &self,
        fixture: &Fixture,
        bundles: &[PackageBundleV1; 3],
    ) -> Result<(PackageResponseV1, PackageResponseV1)> {
        fixture.window(2, 2)?;
        let stale = fixture.inspect().await?;
        self.check(
            stale
                .exports
                .iter()
                .flat_map(|export| &export.results)
                .any(|result| result.stale),
            "changed source was presented as current",
        )?;
        let mut worker = fixture.worker()?;
        let corrected = fixture
            .wait_current(&Self::result_id(&stale)?, &mut worker)
            .await?;
        worker.stop().await?;
        self.check(
            fixture.checkpoint().await? == 1,
            "source correction did not rebuild the checkpoint",
        )?;
        self.check(
            fixture.counts(None).await? == json!([]),
            "corrected source window retained a removed report",
        )?;
        self.upgrades(fixture, bundles).await?;
        fixture.window(3, 0)?;
        let empty = fixture.run("empty").await?;
        self.check(
            fixture.counts(None).await? == json!([]),
            "empty source window retained a report",
        )?;
        self.check(
            empty
                .exports
                .iter()
                .flat_map(|export| &export.results)
                .all(|result| {
                    result.coverage.state == araphor_analysis_sdk::CoverageState::Unknown
                }),
            "an empty result claimed complete source coverage",
        )?;
        Ok((corrected, empty))
    }

    async fn removal(&self, fixture: &Fixture, original: &str) -> Result<()> {
        let removed = fixture
            .operation(PackageRequestV1::Remove {
                scope_id: "qualified".into(),
                package_id: "denials.repeated".into(),
            })
            .await?;
        self.check(
            removed.exports.iter().all(|export| !export.active),
            "removal left an active export",
        )?;
        self.check(
            fixture.counts(Some(original.to_owned())).await? == json!([{"count":3}]),
            "removal lost referenced historical output",
        )?;
        Ok(())
    }

    async fn upgrades(&self, fixture: &Fixture, bundles: &[PackageBundleV1; 3]) -> Result<()> {
        let before = fixture.inspect().await?;
        self.check(
            fixture
                .operation(PackageRequestV1::Update {
                    scope_id: "qualified".into(),
                    bundle: bundles[1].clone(),
                })
                .await
                .is_err(),
            "invalid SQL upgrade succeeded",
        )?;
        let after = fixture.inspect().await?;
        self.check(
            Self::result_id(&before)? == Self::result_id(&after)?
                && after.exports.iter().all(|export| export.revision == "1"),
            "failed upgrade replaced active revision or result",
        )?;
        fixture
            .operation(PackageRequestV1::Update {
                scope_id: "qualified".into(),
                bundle: bundles[2].clone(),
            })
            .await?;
        self.check(
            fixture.counts(None).await? == json!([{"count":2}]),
            "successful upgrade did not apply threshold2",
        )?;
        fixture
            .operation(PackageRequestV1::Rollback {
                scope_id: "qualified".into(),
                package_id: "denials.repeated".into(),
                revision: "1".into(),
            })
            .await?;
        self.check(
            fixture.counts(None).await? == json!([]),
            "rollback did not restore threshold3",
        )
    }

    fn check_retry(&self, original: &PackageResponseV1, retry: &PackageResponseV1) -> Result<()> {
        self.check(
            original.scope_id == retry.scope_id
                && original.package_id == retry.package_id
                && original.exports.len() == retry.exports.len(),
            "restart retry changed its package scope",
        )?;
        for (before, after) in original.exports.iter().zip(&retry.exports) {
            self.check(
                before.activation_revision < after.activation_revision,
                "renewed credential did not advance activation authority",
            )?;
            self.check(
                serde_json::to_value(&before.results)? == serde_json::to_value(&after.results)?,
                "restart retry changed the original receipts",
            )?;
            self.check(
                before.active == after.active
                    && before.revision == after.revision
                    && serde_json::to_value(&before.descriptor)?
                        == serde_json::to_value(&after.descriptor)?
                    && serde_json::to_value(&before.readiness)?
                        == serde_json::to_value(&after.readiness)?,
                "restart retry changed the export status",
            )?;
        }
        Ok(())
    }

    fn result_id(response: &PackageResponseV1) -> Result<String> {
        response
            .exports
            .iter()
            .find(|export| export.descriptor.name == "repeated")
            .and_then(|export| {
                export
                    .results
                    .iter()
                    .max_by_key(|result| result.commit_revision)
            })
            .map(|result| result.result_id.clone())
            .ok_or_else(|| "repeated result is absent".into())
    }

    fn check(&self, passed: bool, reason: &str) -> Result<()> {
        if !passed {
            return Err(crate::error::InvalidInputSnafu {
                path: &self.output,
                reason,
            }
            .build()
            .into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn analysis_packages_contract() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("proof");
        let qualification = AnalysisPackageQualification::new(output.clone());
        qualification.run().await?;
        let before = fs::read(output.join("result.json"))?;
        let result: serde_json::Value = serde_json::from_slice(&before)?;
        assert_eq!(result["result"], "PASS");
        assert_eq!(result["physical_action_attempted"], false);
        assert!(qualification.run().await.is_err());
        assert_eq!(fs::read(output.join("result.json"))?, before);
        Ok(())
    }
}
