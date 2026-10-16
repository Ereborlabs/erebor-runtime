use std::{io::Write as _, path::Path, sync::Arc, time::SystemTime};

use araphor_analysis::GraphAndFindingOwner;
use araphor_analysis_sdk as sdk;
use araphor_component_build::ComponentBuilder;
use araphor_data::{
    EvidenceIntakeIdentityV1, FindingReasonV1, FindingStateV1, GraphPackageStateV1,
    GraphSnapshotV1, InstalledRefV1, PackageArtifactV1, PackageBundleV1, PackageImplementationV1,
    PackageRequestV1, PackageResponseV1,
};
use araphor_detector_example::BurstDetector;
use erebor_runtime_ipc::araphor as wire;
use mithril_control::{AuthenticatedEvidenceNodeV1, ClientAuth, ClientAuthConfig};
use mithril_node::{EffectObservationStore, EvidenceWalLimits, ObservationCanonicalizer};
use prost::Message as _;
use sdk::arrow_array::{cast::AsArray as _, types::UInt64Type};
use serde_json::json;
use zerocopy::IntoBytes as _;

use crate::control_fixture::MtlsFixture;

use super::super::graph_notification::{GraphInputs, GraphNotificationQualification};
use super::{Fixture, Result};

const COMPONENT: &[u8] = araphor_analysis_builtins::components::DETECTOR;

pub(super) fn bundle() -> PackageBundleV1 {
    let descriptor = BurstDetector::package();
    let artifact = PackageArtifactV1 {
        implementations: vec![PackageImplementationV1::Wasm {
            exports: descriptor
                .exports
                .iter()
                .map(|model| model.name.clone())
                .collect(),

            artifact: COMPONENT.to_vec(),
        }],
        descriptor,
        fixtures: Vec::new(),
    };
    PackageBundleV1 {
        schema_version: 1,
        root: artifact.reference(),
        artifacts: vec![artifact],
    }
}

pub(super) async fn run(
    root: &Path,
    tls: &MtlsFixture,
    auth: Arc<ClientAuth>,
    bundle: &PackageBundleV1,
    config: &ClientAuthConfig,
    qualification: &super::AnalysisPackageQualification,
) -> Result<serde_json::Value> {
    DetectorQualification {
        root,
        tls,
        auth,
        bundle,
        config,
        qualification,
    }
    .run()
    .await
}

struct DetectorQualification<'a> {
    root: &'a Path,
    tls: &'a MtlsFixture,
    auth: Arc<ClientAuth>,
    bundle: &'a PackageBundleV1,
    config: &'a ClientAuthConfig,
    qualification: &'a super::AnalysisPackageQualification,
}

struct SavedResult {
    source: EvidenceIntakeIdentityV1,
    snapshot: GraphSnapshotV1,
    result_id: String,
    references: Vec<InstalledRefV1>,
    now: u64,
}

impl DetectorQualification<'_> {
    async fn run(&self) -> Result<serde_json::Value> {
        let fixture = Fixture::open(self.root, self.auth.clone())
            .map_err(|error| format!("detector store open: {error}"))?;
        let (parameters, transport_bytes) = self
            .install(&fixture)
            .await
            .map_err(|error| format!("detector install: {error}"))?;
        let saved = self
            .process(&fixture, parameters)
            .map_err(|error| format!("detector process: {error}"))?;
        drop(fixture);
        let fixture = Fixture::open(self.root, self.auth.clone())
            .map_err(|error| format!("detector store reopen: {error}"))?;
        let graph = self
            .reopen(&fixture, &saved)
            .map_err(|error| format!("detector replay: {error}"))?;
        let migrated = if self.bundle.artifacts[0].implementations[0].target() == "native" {
            let data = fixture
                .control
                .analysis_store()
                .ok_or("native retained data absent")?;
            let replay =
                GraphNotificationQualification::replay(&data, &saved.source, &saved.snapshot)?;
            Some(
                self.qualification
                    .native_algorithms(
                        self.root,
                        self.auth.clone(),
                        self.bundle,
                        &replay,
                        &saved.snapshot,
                    )
                    .await?,
            )
        } else {
            None
        };
        self.revoke(&fixture, &graph, &saved)
            .map_err(|error| format!("detector trust removal: {error}"))?;
        Ok(json!({
            "package_id":"example-burst", "revision":"1", "bundle_digest":self.bundle.digest()?,
            "folder_admitted":true, "stored_threshold":3, "input_records":4,
            "package_transport":"native-grpc-tls", "transport_bytes":transport_bytes,
            "real_client_installed":true,
            "matching_evidence_records":3, "checkpoint":"4", "result_id":saved.result_id,
            "typed_reason":"example-burst.THRESHOLD", "task_groups_preserved":true,
            "restart_equal":true, "retry_result_equal":true, "host_rebuild":false,
            "trust_revocation_denied_historical_replay":true, "trust_revocation_denied_current_compute":true,
            "trust_revocation_preserved_retained_result":true,
            "physical_action_attempted":false,
            "execution_target":self.bundle.artifacts[0].implementations[0].target(),
            "artifact":saved.references.iter().find(|reference| reference.package_id == "example-burst").and_then(|reference| reference.artifact.as_ref()),
            "migrated_native_algorithms":migrated,
        }))
    }

    async fn install(&self, fixture: &Fixture) -> Result<(serde_json::Value, usize)> {
        let directory = self.root.join("detector-package");
        match &self.bundle.artifacts[0].implementations[0] {
            PackageImplementationV1::Wasm { .. } => ComponentBuilder::package_component(
                &BurstDetector::package(),
                COMPONENT,
                &directory,
            )?,
            PackageImplementationV1::Native {
                artifact,
                qualification: Some(qualification),
                ..
            } => {
                let metadata = json!({
                    "exports": qualification.exports,
                    "target": qualification.target,
                    "cpu_features": qualification.cpu_features,
                    "contract_version": qualification.contract_version,
                    "system_libraries": qualification.system_libraries,
                    "dependencies": qualification.dependencies.iter().map(|dependency| json!({
                        "name": dependency.name, "artifact": [], "digest": dependency.digest,
                    })).collect::<Vec<_>>(),
                });
                let dependencies = qualification
                    .dependencies
                    .iter()
                    .map(|dependency| (dependency.name.as_str(), dependency.artifact.as_slice()))
                    .collect::<Vec<_>>();
                ComponentBuilder::package_native(
                    &BurstDetector::package(),
                    artifact,
                    metadata,
                    &dependencies,
                    &directory,
                )?;
            }
            _ => return Err("detector implementation is not qualified".into()),
        }
        let local = PackageBundleV1::read(&directory)?;
        assert_eq!(local.digest()?, self.bundle.digest()?);
        let parameters = json!({"example-burst":{"detect":{"threshold":3}}});
        let operation = PackageRequestV1::Install {
            scope_id: "analysis".into(),
            bundle: local,
            parameters: Some(parameters.clone()),
        };
        let mut request = wire::PackageOperationRequest {
            definition: operation.encode()?,
            selection: None,
        };
        if request.encoded_len() <= 4 * 1024 * 1024 {
            // JSON whitespace preserves the large transport check and the executable identity.
            let mut decoder = minicbor::Decoder::new(&request.definition);
            assert_eq!(decoder.array()?, Some(3));
            assert_eq!(decoder.u32()?, 1);
            let mut metadata = decoder.bytes()?.to_vec();
            let archive = decoder.bytes()?;
            metadata.resize(
                metadata.len() + 4 * 1024 * 1024 + 1 - request.encoded_len(),
                b' ',
            );
            let mut encoder = minicbor::Encoder::new(Vec::new());
            encoder.array(3)?.u32(1)?.bytes(&metadata)?.bytes(archive)?;
            request.definition = encoder.into_writer();
        }
        let transport_bytes = request.encoded_len();
        assert!(transport_bytes > 4 * 1024 * 1024);
        let raw_size = match &self.bundle.artifacts[0].implementations[0] {
            PackageImplementationV1::Wasm { artifact, .. }
            | PackageImplementationV1::Native { artifact, .. } => artifact.len(),
            _ => return Err("detector implementation is not qualified".into()),
        };
        assert!(transport_bytes >= raw_size);
        let mut credential = tempfile::NamedTempFile::new_in(self.root)?;
        credential.write_all(b"fixture-access")?;
        let (client, server) = fixture
            .client(self.tls, self.config, credential.path())
            .await?;
        let result = client.package_operation(request).await;
        drop(client);
        server.shutdown().await?;
        let installed: PackageResponseV1 = serde_json::from_slice(&result?.result_json)?;
        assert!(installed.exports.iter().all(|export| export.active));
        Ok((parameters, transport_bytes))
    }

    fn process(&self, fixture: &Fixture, parameters: serde_json::Value) -> Result<SavedResult> {
        let source = self.accept(fixture)?;
        let data = fixture
            .control
            .analysis_store()
            .ok_or("detector data is absent")?;
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_nanos(),
        )?;
        let graph = GraphAndFindingOwner::new(
            data,
            Arc::new(GraphInputs::default()),
            fixture.control.installed_analysis()?,
        )?;
        let mut snapshot = None;
        for _ in 0..32 {
            graph.process(now)?;
            snapshot = graph.snapshot(&source)?;
            if snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.last_cursor == 4)
            {
                break;
            }
        }
        let snapshot = snapshot.ok_or("detector graph is absent")?;
        check(&snapshot)?;
        let finding = snapshot
            .findings
            .iter()
            .find(|finding| finding.package_id == "example-burst")
            .ok_or("detector finding is absent")?;
        let (result_id, _) = graph
            .current_finding([1; 16], &finding.finding_id)?
            .ok_or("detector result is absent")?;
        let references = graph
            .installed_refs([1; 16], &result_id)?
            .ok_or("installed detector references are absent")?;
        let reference = references
            .iter()
            .find(|reference| reference.package_id == "example-burst")
            .ok_or("detector reference is absent")?;
        assert_eq!(reference.parameters, Some(parameters));
        if self.bundle.artifacts[0].implementations[0].target() == "native" {
            assert_eq!(reference.target.as_deref(), Some("native"));
            let identity = reference
                .artifact
                .as_ref()
                .ok_or("native detector artifact identity absent")?;
            let PackageImplementationV1::Native {
                artifact,
                qualification: Some(qualification),
                ..
            } = &self.bundle.artifacts[0].implementations[0]
            else {
                return Err("native detector artifact absent".into());
            };
            assert_eq!(
                identity.digest,
                araphor_data::native::Qualification::digest(artifact)
            );
            assert_eq!(
                identity.closure_digest,
                Some(qualification.closure_digest(artifact)?)
            );
            assert_eq!(identity.platform.as_ref(), Some(&qualification.target));
        }
        assert!(!graph.refresh(&source, now + 1)?);
        assert_eq!(graph.snapshot(&source)?, Some(snapshot.clone()));
        Ok(SavedResult {
            source,
            snapshot,
            result_id,
            references,
            now,
        })
    }

    fn accept(&self, fixture: &Fixture) -> Result<EvidenceIntakeIdentityV1> {
        let authenticated = AuthenticatedEvidenceNodeV1 {
            tenant_id: [1; 16],
            node_id: "qualification-node".into(),
            node_boot_id: [7; 16],
            label_epoch: 1,
        };
        let wal = EffectObservationStore::durable(
            8,
            self.root.join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new([1; 16].into(), [3; 16].into(), 1, [7; 16].into())?,
        )?;
        for cursor in 1..=4 {
            let mut record = GraphNotificationQualification::native(cursor, false);
            if cursor == 4 {
                record.process_instance_id = [98; 16].into();
                record.task_cookie = 8;
            }
            wal.record_bytes(record.as_bytes());
        }
        let batch: mithril_control::EvidenceBatch = wal
            .next_evidence_batch()
            .ok_or("detector batch is absent")?
            .into();
        let source = EvidenceIntakeIdentityV1 {
            tenant_id: authenticated.tenant_id,
            node_id: authenticated.node_id.clone(),
            node_boot_id: authenticated.node_boot_id,
            label_epoch: authenticated.label_epoch,
            source_id: batch.source_id.as_slice().try_into()?,
            source_epoch: batch.source_epoch,
        };
        let receipt = fixture.intake.receive(&authenticated, batch)?;
        assert_eq!(receipt.contiguous_cursor, 4);
        Ok(source)
    }

    fn reopen(&self, fixture: &Fixture, saved: &SavedResult) -> Result<GraphAndFindingOwner> {
        let data = fixture
            .control
            .analysis_store()
            .ok_or("reopened detector data is absent")?;
        let graph = GraphAndFindingOwner::new(
            data,
            Arc::new(GraphInputs::default()),
            fixture.control.installed_analysis()?,
        )?;
        assert_eq!(
            graph.snapshot_result([1; 16], &saved.result_id)?,
            Some(saved.snapshot.clone())
        );
        assert_eq!(
            graph.installed_refs([1; 16], &saved.result_id)?,
            Some(saved.references.clone())
        );
        assert!(!graph.refresh(&saved.source, saved.now + 2)?);
        let retry = graph
            .snapshot(&saved.source)?
            .ok_or("detector retry snapshot is absent")?;
        check(&retry)?;
        assert_eq!(retry, saved.snapshot);
        assert_eq!(
            graph
                .current_finding([1; 16], saved.finding_id()?)?
                .map(|row| row.0),
            Some(saved.result_id.clone())
        );
        Ok(graph)
    }

    fn revoke(
        &self,
        fixture: &Fixture,
        graph: &GraphAndFindingOwner,
        saved: &SavedResult,
    ) -> Result<()> {
        let data = fixture
            .control
            .analysis_store()
            .ok_or("reopened detector data is absent")?;
        let execution = fixture.control.installed_analysis()?;
        let replay = GraphNotificationQualification::replay(&data, &saved.source, &saved.snapshot)?;
        let historical = execution.pin_at([1; 16], &saved.references)?;
        assert_eq!(
            GraphAndFindingOwner::derive(&replay, &historical)?.findings,
            saved.snapshot.findings
        );
        let digest = self.bundle.digest()?;
        let retained = self
            .config
            .package_trust
            .iter()
            .filter(|pin| pin.bundle_digest != digest)
            .cloned()
            .collect();
        self.auth.replace_package_trust(retained)?;
        assert!(execution.pin_at([1; 16], &saved.references).is_err());
        assert!(GraphAndFindingOwner::derive(&replay, &historical).is_err());
        assert!(graph.refresh(&saved.source, saved.now + 3).is_err());
        assert_eq!(
            graph.snapshot_result([1; 16], &saved.result_id)?,
            Some(saved.snapshot.clone())
        );
        assert_eq!(
            graph
                .current_finding([1; 16], saved.finding_id()?)?
                .map(|row| row.0),
            Some(saved.result_id.clone())
        );
        Ok(())
    }
}

impl SavedResult {
    fn finding_id(&self) -> Result<&str> {
        self.snapshot
            .findings
            .iter()
            .find(|finding| finding.package_id == "example-burst")
            .map(|finding| finding.finding_id.as_str())
            .ok_or_else(|| "detector finding is absent".into())
    }
}

fn check(snapshot: &GraphSnapshotV1) -> Result<()> {
    assert_eq!(snapshot.last_cursor, 4);
    let findings = snapshot
        .findings
        .iter()
        .filter(|finding| finding.package_id == "example-burst")
        .collect::<Vec<_>>();
    assert_eq!(findings.len(), 1);
    let finding = findings[0];
    assert_eq!(finding.state, FindingStateV1::CoverageInsufficient);
    assert_eq!(finding.evidence.len(), 3);
    assert_eq!(
        finding
            .evidence
            .iter()
            .map(|record| record.durable_cursor)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    let FindingReasonV1::Declared(reason) = &finding.reason else {
        return Err("detector reason is not typed".into());
    };
    assert_eq!(reason.code, "example-burst.THRESHOLD");
    let details = sdk::wire::Dataset::decode_ipc(
        "details",
        &reason.ipc,
        Some(&reason.schema),
        sdk::Limits::default(),
    )?;
    let batch = &details.batches[0];
    assert_eq!(batch.column(0).as_primitive::<UInt64Type>().value(0), 3);
    assert_eq!(batch.column(1).as_primitive::<UInt64Type>().value(0), 3);
    let checkpoint = snapshot
        .packages
        .iter()
        .find(|package| package.package_id == "example-burst")
        .ok_or("detector checkpoint is absent")?;
    assert_eq!(checkpoint.state, GraphPackageStateV1::Declared("4".into()));
    Ok(())
}
