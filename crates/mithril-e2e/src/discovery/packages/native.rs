use std::{path::Path, sync::Arc, time::Duration};

use araphor_analysis_back::{AnalysisPackageOwner, GraphAndFindingOwner, InstalledAnalysis};
use araphor_analysis_builtins::graph::Detector;
use araphor_data::{
    native::Qualification, AnalysisReadControl, AnalysisSelectionV1, AnalysisStore,
    GraphReplayInputV1, GraphSnapshotV1, PackageActionV1, PackageArtifactV1, PackageBundleV1,
    PackageImplementationV1, PackageRequestV1,
};
use araphor_detector_example::BurstDetector;
use araphor_query::execution::{Engine, Limits};
use mithril_control::ClientAuth;
use serde_json::json;

use super::Result;

pub(super) fn detector_bundle() -> Result<PackageBundleV1> {
    bundle(BurstDetector::package(), "detector")
}

pub(super) fn bundles() -> Result<Vec<PackageBundleV1>> {
    [
        (Detector::Process, "process"),
        (Detector::Credentials, "credentials"),
        (Detector::Kubernetes, "kubernetes"),
    ]
    .into_iter()
    .map(|(detector, filename)| bundle(detector.descriptor(), filename))
    .collect()
}

fn bundle(descriptor: araphor_analysis_sdk::Package, filename: &str) -> Result<PackageBundleV1> {
    let directory =
        std::env::var_os("ARAPHOR_NATIVE_DIR").ok_or("ARAPHOR_NATIVE_DIR is required")?;
    let target = std::env::var("ARAPHOR_NATIVE_TARGET")?;
    let artifact = std::fs::read(
        Path::new(&directory).join(format!("{filename}.{}", std::env::consts::DLL_EXTENSION)),
    )?;
    let exports = descriptor
        .exports
        .iter()
        .map(|model| model.name.clone())
        .collect::<Vec<_>>();
    let qualification = Qualification::inspect(&artifact, exports.clone(), target)?;
    let artifact = PackageArtifactV1 {
        descriptor,
        implementations: vec![PackageImplementationV1::Native {
            export: exports[0].clone(),
            artifact,
            qualification: Some(qualification),
        }],
        fixtures: Vec::new(),
    };
    Ok(PackageBundleV1 {
        schema_version: 1,
        root: artifact.reference(),
        artifacts: vec![artifact],
    })
}

impl super::AnalysisPackageQualification {
    pub(super) async fn native_algorithms(
        &self,
        root: &Path,
        auth: Arc<ClientAuth>,
        detector: &PackageBundleV1,
        replay: &GraphReplayInputV1,
        expected: &GraphSnapshotV1,
    ) -> Result<serde_json::Value> {
        let store = Arc::new(AnalysisStore::open(root.join("native-algorithms"))?);
        let query = Engine::new(store, Limits::default())?;
        let owner = Arc::new(AnalysisPackageOwner::new(query, auth.clone())?);
        let mut metadata = tonic::metadata::MetadataMap::new();
        metadata.insert("authorization", "Bearer fixture-access".parse()?);
        metadata.insert(
            "x-araphor-tenant",
            uuid::Uuid::from_bytes(replay.source.tenant_id)
                .to_string()
                .parse()?,
        );
        let access = auth.authenticate(&metadata, true).await?;
        let grant = access.package_grant(
            AnalysisSelectionV1::tenant(replay.source.tenant_id),
            PackageActionV1::Install,
        )?;
        let mut bundles = bundles()?;
        bundles.push(detector.clone());
        for bundle in &bundles {
            let installed = owner
                .execute(
                    grant.clone(),
                    PackageRequestV1::Install {
                        scope_id: "analysis".into(),
                        bundle: bundle.clone(),
                        parameters: (bundle.root.package_id == "example-burst")
                            .then(|| json!({"example-burst":{"detect":{"threshold":3}}})),
                    },
                    Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?),
                )
                .await?;
            assert!(installed.exports.iter().all(|export| export.active));
        }
        let execution = InstalledAnalysis::new(owner, "analysis")?;
        let actual = GraphAndFindingOwner::derive(replay, &execution)?;
        assert_eq!(actual.findings, expected.findings);
        assert_eq!(actual.graph, expected.graph);
        assert_eq!(actual.packages, expected.packages);
        let repeated = GraphAndFindingOwner::derive(replay, &execution)?;
        assert_eq!(actual, repeated);
        self.check(
            actual.last_cursor == 4,
            "native migrated graph did not cover four records",
        )?;
        assert!(actual
            .findings
            .iter()
            .any(|finding| finding.package_id == "example-burst"));
        let identities = bundles.iter().map(|bundle| {
        let PackageImplementationV1::Native { artifact, qualification: Some(qualification), .. } = &bundle.artifacts[0].implementations[0] else { return Err("native artifact absent".into()); };
        Ok(json!({"package_id":bundle.root.package_id,"revision":bundle.root.revision,
            "target":"native","platform":qualification.target,"artifact":Qualification::digest(artifact),
            "closure":qualification.closure_digest(artifact)?}))
    }).collect::<Result<Vec<_>>>()?;
        Ok(
            json!({"algorithms":["HF-PROC-001.detect","HF-DW-001.detect","HF-XNODE-001.detect"],
        "artifacts":identities,"same_input_findings_equal":true,"relationships_equal":true,
        "checkpoint_meaning_equal":true,"replay_equal":true,"python_unavailable":true,
        "physical_action_attempted":false,"performance_claim":false}),
        )
    }
}

#[cfg(test)]
mod tests;
