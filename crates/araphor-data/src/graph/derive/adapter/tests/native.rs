use super::*;
use crate::package::native::Qualification;
use crate::package::tests::{Fixture, TestResult as NativeResult};
use crate::{PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRequestV1};
use std::{path::PathBuf, sync::Arc, time::Duration};

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_detectors_match_wasm() -> NativeResult {
    let directory = PathBuf::from(
        std::env::var_os("ARAPHOR_NATIVE_DIR").ok_or("ARAPHOR_NATIVE_DIR is required")?,
    );
    let input = input()?;
    let mut fixture = Fixture::new()?;
    fixture.grant.selection = crate::AnalysisSelectionV1::tenant(input.source.tenant_id);
    for (detector, filename) in [
        (algorithm::Detector::Process, "process"),
        (algorithm::Detector::Credentials, "credentials"),
        (algorithm::Detector::Kubernetes, "kubernetes"),
    ] {
        let package = detector.descriptor();
        let bytes = std::fs::read(
            directory.join(format!("{filename}.{}", std::env::consts::DLL_EXTENSION)),
        )?;
        let qualification = Qualification::inspect(
            &bytes,
            vec!["detect".into()],
            env!("ARAPHOR_NATIVE_TARGET").into(),
        )?;
        let artifact = PackageArtifactV1 {
            descriptor: package,
            implementations: vec![PackageImplementationV1::Native {
                export: "detect".into(),
                artifact: bytes,
                qualification: Some(qualification),
            }],
            fixtures: Vec::new(),
        };
        fixture
            .owner
            .execute(
                fixture.grant.clone(),
                PackageRequestV1::Install {
                    scope_id: "test".into(),
                    bundle: PackageBundleV1 {
                        schema_version: 1,
                        root: artifact.reference(),
                        artifacts: vec![artifact],
                    },
                    parameters: None,
                },
                Arc::new(crate::AnalysisReadControl::with_timeout(
                    Duration::from_secs(30),
                )?),
            )
            .await?;
    }
    let native = crate::InstalledAnalysis::new(fixture.owner.clone(), "test")?;
    let wasm = crate::InstalledAnalysis::testing(None, input.source.tenant_id)?;
    for detector in [
        algorithm::Detector::Process,
        algorithm::Detector::Credentials,
        algorithm::Detector::Kubernetes,
    ] {
        let mut selected = input.clone();
        match detector {
            algorithm::Detector::Process => {
                let mut wire = selected.records[0].decode()?;
                wire.decision =
                    erebor_interceptor_abi::EffectPhysicalResultV1::DeniedBeforeEffect as u32;
                wire.kernel_result = -13;
                wire.configured_errno = -13;
                selected.records[0].wire_record = Vec::<u8>::try_from(&wire)?;
            }
            algorithm::Detector::Kubernetes => {
                let (index, mut fact) = selected
                    .facts
                    .iter()
                    .enumerate()
                    .map(|(index, version)| {
                        GraphFactV1::try_from(version).map(|fact| (index, fact))
                    })
                    .collect::<crate::Result<Vec<_>>>()?
                    .into_iter()
                    .find(|(_, fact)| matches!(fact.value, GraphFactValueV1::Credential { .. }))
                    .ok_or("credential fixture fact missing")?;
                let GraphFactValueV1::Credential { proof_quality, .. } = fact.value else {
                    return Err("credential fixture fact missing".into());
                };
                fact.value = GraphFactValueV1::Kubernetes(KubernetesStageProofV1 {
                    cluster_id: "cluster".into(),
                    carried_request_id: Some("request".into()),
                    audit_id: Some("audit".into()),
                    object_uid: Some("object".into()),
                    resource_version: Some("version".into()),
                    owner_uid: Some("owner".into()),
                    pod_uid: Some("pod".into()),
                    node_id: Some("remote-node".into()),
                    full_container_id: Some("container".into()),
                    remote_admission_id: Some("admission".into()),
                    proof_quality,
                });
                selected.facts[index].body = serde_json::to_vec(&fact)?;
            }
            algorithm::Detector::Credentials => {}
        }
        let mut gapped = selected.clone();
        gapped.coverage[0].state = DiscoveryCoverageStateV1::Gapped;
        gapped.coverage[0].gap_reasons.push("FIXTURE_GAP".into());
        gapped.coverage_keys[0].state = DiscoveryCoverageStateV1::Gapped;
        gapped.coverage_keys[0]
            .gap_reasons
            .push("FIXTURE_GAP".into());
        for selected in [selected, gapped] {
            let selected = selected.normalized()?;
            let owner = GraphDerivation::new(&selected)?;
            let package = detector.descriptor();
            let mut evaluation = owner.evaluation_for(&package.exports[0])?;
            evaluation.context.seed = Some(9_007_199_254_740_999);
            let control = crate::AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
            let trusted = detector.evaluate(&evaluation)?;
            assert!(!trusted.reasons.is_empty());
            assert!(!trusted.evidence.is_empty());
            let expected = wasm.evaluate(
                selected.source.tenant_id,
                &package.id,
                &evaluation,
                &control,
            )?;
            let actual = native.evaluate(
                selected.source.tenant_id,
                &package.id,
                &evaluation,
                &control,
            )?;
            assert_eq!(actual.target, "native");
            assert!(actual.artifact.is_some());
            assert_eq!(expected.target, "wasm");
            assert_eq!(
                encoded(&package, &evaluation, &trusted)?,
                encoded(&package, &evaluation, &actual.output)?
            );
            assert_eq!(
                encoded(&package, &evaluation, &expected.output)?,
                encoded(&package, &evaluation, &actual.output)?
            );
            assert_eq!(actual.evaluation.context, evaluation.context);
            for (saved, supplied) in actual.evaluation.inputs.iter().zip(&evaluation.inputs) {
                assert_eq!(saved.revision, supplied.revision);
                assert_eq!(saved.coverage, supplied.coverage);
            }
            evaluation.checkpoint = actual.output.checkpoint.clone();
            evaluation.inputs.reverse();
            drop(actual);
            drop(expected);
            let replay = native.evaluate(
                selected.source.tenant_id,
                &package.id,
                &evaluation,
                &control,
            )?;
            let expected = wasm.evaluate(
                selected.source.tenant_id,
                &package.id,
                &evaluation,
                &control,
            )?;
            assert_eq!(
                encoded(&package, &evaluation, &trusted)?,
                encoded(&package, &evaluation, &replay.output)?
            );
            assert_eq!(
                encoded(&package, &evaluation, &expected.output)?,
                encoded(&package, &evaluation, &replay.output)?
            );
            drop(replay);
            drop(expected);
            let expected = GraphAndFindingOwner::derive(&selected, &wasm)?;
            let actual = GraphAndFindingOwner::derive(&selected, &native)?;
            assert_eq!(
                serde_json::to_value(actual)?,
                serde_json::to_value(expected)?
            );
        }
    }
    Ok(())
}

fn encoded(
    package: &sdk::Package,
    input: &sdk::Evaluation,
    output: &sdk::Output,
) -> NativeResult<serde_json::Value> {
    let output = sdk::wire::Output::encode(package, input, output)?;
    let datasets = |data: &[sdk::wire::Dataset]| {
        data.iter()
            .map(|data| serde_json::json!({"name":data.name,"ipc":data.arrow_ipc}))
            .collect::<Vec<_>>()
    };
    Ok(serde_json::json!({
        "datasets": datasets(&output.datasets), "evidence": output.evidence,
        "reasons": output.reasons.iter().map(|reason| serde_json::json!({"output":reason.output,"code":reason.code,"details":reason.details})).collect::<Vec<_>>(),
        "checkpoint": output.checkpoint.map(|checkpoint| serde_json::json!({"version":checkpoint.version,"datasets":datasets(&checkpoint.datasets)})),
    }))
}

mod large;

fn large_input() -> NativeResult<GraphReplayInputV1> {
    let mut input = input()?;
    let first = input.records[0].clone();
    input.records = (1..=185)
        .map(|cursor| {
            let mut record = first.clone();
            record.id.durable_cursor = cursor;
            record.original_kernel_sequence = Some(cursor);
            let mut wire = first.decode()?;
            wire.task_cookie = cursor;
            wire.observed_boottime_ns = cursor * 1_000;
            wire.ingested_utc_ns = cursor as i64;
            wire.decision =
                erebor_interceptor_abi::EffectPhysicalResultV1::DeniedBeforeEffect as u32;
            wire.kernel_result = -13;
            wire.configured_errno = -13;
            wire.decision_context
                .as_mut()
                .ok_or("decision context missing")?
                .original_kernel_sequence = cursor;
            record.wire_record = Vec::<u8>::try_from(&wire)?;
            Ok(record)
        })
        .collect::<NativeResult<Vec<_>>>()?;
    input.facts.clear();
    input.coverage[0].last_cursor = 185;
    input.coverage[0].expected_records = 185;
    Ok(input.normalized()?)
}
