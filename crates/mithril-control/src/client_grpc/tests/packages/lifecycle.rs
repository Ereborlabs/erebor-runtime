use araphor_data::{AnalysisSelectionV1, PackageReadinessV1};
use araphor_discovery_definition::{Definition, Program, Source};

use super::*;

#[tokio::test]
async fn instance_admission_is_inert() -> TestResult {
    let fixture = Fixture::new()?;
    let request = PackageRequestV1::AdmitInstance {
        instance_id: "public-counts".into(),
        definition_name: "public-count".into(),
        definition_revision: format!("sha256:{}", "1".repeat(64)),
    };
    let store = &fixture.service.data()?.store;
    let before = store.meta()?;
    assert_eq!(
        fixture
            .package(request.clone(), true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    assert_eq!(store.meta()?, before);
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    let PackageResponseV1::Definition(definition) = fixture
        .package(
            PackageRequestV1::AdmitDefinition {
                definition: Definition {
                    name: "public-count".into(),
                    description: "Count retained events.".into(),
                    labels: BTreeMap::new(),
                    program: Program::Sql {
                        source: Source::Inline {
                            inline: "SELECT COUNT(*) AS count FROM events".into(),
                        },
                    },
                },
            },
            true,
        )
        .await?
    else {
        return Err("admitted definition variant".into());
    };
    let before = store.meta()?;
    assert_eq!(
        fixture
            .package(request, true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::NotFound)
    );
    assert_eq!(store.meta()?, before);
    let request = PackageRequestV1::AdmitInstance {
        instance_id: "public-counts".into(),
        definition_name: definition.definition.name.clone(),
        definition_revision: definition.digest()?,
    };
    assert_eq!(
        fixture
            .package(request.clone(), false)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unauthenticated)
    );
    assert_eq!(store.meta()?, before);
    let PackageResponseV1::Instance(admitted) = fixture.package(request.clone(), true).await?
    else {
        return Err("admitted instance variant".into());
    };
    assert_eq!(admitted.id, "public-counts");
    assert_eq!(admitted.definition_revision, definition.digest()?);
    assert!(admitted.generation > 0);
    assert_eq!(admitted.generation, admitted.lifecycle);
    assert!(!admitted.running);
    assert!(!admitted.removed);
    assert_eq!(admitted.progress, 0);
    assert_eq!(admitted.status_progress, 0);
    assert!(matches!(admitted.readiness, PackageReadinessV1::Inactive));
    let control = AnalysisReadControl::default();
    let saved = store
        .managed_instance([1; 16], "public-counts", &control)?
        .ok_or("admitted instance")?;
    assert_eq!(saved.spec.definition, definition);
    assert!(saved.spec.manifest.calls.is_empty());
    let resume = store.managed_resume([1; 16], "public-counts", &control)?;
    assert_eq!(resume.completed, 0);
    assert!(resume.frontier.is_none());
    assert!(store.active_managed(&control)?.1.is_empty());
    assert!(store
        .managed_history(
            &AnalysisSelectionV1::tenant([1; 16]),
            "public-counts",
            &control,
        )?
        .is_empty());
    let before = store.meta()?;
    assert!(matches!(
        fixture.package(request, true).await?,
        PackageResponseV1::Instance(repeated)
            if repeated.generation == admitted.generation
                && repeated.lifecycle == admitted.lifecycle
                && repeated.progress == 0
                && !repeated.running
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(
        store.managed_instance([1; 16], "public-counts", &control)?,
        Some(saved)
    );
    Ok(())
}

#[tokio::test]
async fn instance_rpc_controls_lifecycle() -> TestResult {
    let fixture = Fixture::new()?;
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    let instance = fixture
        .retained_instance(
            "public-lifecycle",
            "SELECT CAST(7 AS BIGINT UNSIGNED) AS value",
        )
        .await?;
    let control = AnalysisReadControl::default();
    let store = &fixture.service.data()?.store;
    let saved = instance.admitted().clone();
    let run = PackageRequestV1::RunInstance {
        instance_id: saved.spec.id.clone(),
        expected_lifecycle: saved.lifecycle,
        evaluation_id: "public-step".into(),
        rebuild: false,
    };
    let before = store.meta()?;
    assert_eq!(
        fixture
            .package(run.clone(), false)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unauthenticated)
    );
    assert_eq!(store.meta()?, before);
    let PackageResponseV1::History(receipts) = fixture.package(run.clone(), true).await? else {
        return Err("public finite receipt".into());
    };
    assert_eq!(receipts.len(), 1);
    let attempt = store
        .managed_attempt([1; 16], &saved.spec.id, "public-step", &control)?
        .ok_or("public attempt")?;
    assert_eq!(attempt.instance().grant, saved.grant);
    let before = store.meta()?;
    assert!(
        matches!(fixture.package(run, true).await?, PackageResponseV1::History(repeated) if repeated == receipts)
    );
    assert_eq!(store.meta()?, before);
    let PackageResponseV1::Output(packet) = fixture
        .package(
            PackageRequestV1::ReadInstanceResult {
                instance_id: saved.spec.id.clone(),
                result_id: receipts[0].selected.result_id.clone(),
            },
            false,
        )
        .await?
    else {
        return Err("public selected output".into());
    };
    assert_eq!(
        packet
            .decode_any()?
            .batches
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        1
    );
    let PackageResponseV1::Definition(definition) = fixture
        .package(
            PackageRequestV1::AdmitDefinition {
                definition: Definition {
                    name: "public-update".into(),
                    description: String::new(),
                    labels: BTreeMap::new(),
                    program: Program::Sql {
                        source: Source::Inline {
                            inline: "SELECT CAST(9 AS BIGINT UNSIGNED) AS value".into(),
                        },
                    },
                },
            },
            true,
        )
        .await?
    else {
        return Err("public update definition".into());
    };
    let PackageResponseV1::Instance(updated) = fixture
        .package(
            PackageRequestV1::UpdateInstance {
                instance_id: saved.spec.id.clone(),
                expected_lifecycle: saved.lifecycle,
                definition_name: definition.definition.name.clone(),
                definition_revision: definition.digest()?,
                rebuild: true,
            },
            true,
        )
        .await?
    else {
        return Err("public update status".into());
    };
    assert_ne!(updated.generation, saved.generation);
    let PackageResponseV1::Instance(rolled) = fixture
        .package(
            PackageRequestV1::RollbackInstance {
                instance_id: saved.spec.id.clone(),
                expected_lifecycle: updated.lifecycle,
                generation: saved.generation,
                rebuild: true,
            },
            true,
        )
        .await?
    else {
        return Err("public rollback status".into());
    };
    let PackageResponseV1::Instance(started) = fixture
        .package(
            PackageRequestV1::StartInstance {
                instance_id: saved.spec.id.clone(),
                expected_lifecycle: rolled.lifecycle,
            },
            true,
        )
        .await?
    else {
        return Err("public start status".into());
    };
    assert!(started.running);
    let PackageResponseV1::Instance(stopped) = fixture
        .package(
            PackageRequestV1::StopInstance {
                instance_id: saved.spec.id.clone(),
                expected_lifecycle: started.lifecycle,
            },
            true,
        )
        .await?
    else {
        return Err("public stop status".into());
    };
    assert!(!stopped.running);
    let ordinary = store
        .managed_instance([1; 16], &saved.spec.id, &control)?
        .ok_or("ordinary lifecycle instance")?;
    assert_eq!(ordinary.grant, saved.grant);
    let PackageResponseV1::Instance(renewed) = fixture
        .package(
            PackageRequestV1::RenewInstance {
                instance_id: saved.spec.id.clone(),
                expected_lifecycle: stopped.lifecycle,
            },
            true,
        )
        .await?
    else {
        return Err("public renewed status".into());
    };
    assert!(!renewed.running);
    assert_eq!(renewed.generation, stopped.generation);
    assert_eq!(renewed.progress, stopped.progress);
    assert_eq!(
        store
            .managed_attempt([1; 16], &saved.spec.id, "public-step", &control)?
            .ok_or("retained public step")?
            .receipt(),
        Some(&receipts[0])
    );
    let before = store.meta()?;
    fixture.service.auth.replace_package_managers(Vec::new())?;
    assert_eq!(
        fixture
            .package(
                PackageRequestV1::StartInstance {
                    instance_id: saved.spec.id.clone(),
                    expected_lifecycle: renewed.lifecycle
                },
                true
            )
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    assert_eq!(store.meta()?, before);
    Ok(())
}
