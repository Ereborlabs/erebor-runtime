use std::collections::BTreeMap;

use araphor_analysis_sdk::{DataType, Field, Model, Package, Port, Schema};
use araphor_data::{
    AnalysisReadControl, PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRefV1,
    PackageRequestV1, PackageResponseV1, SqlModelV1,
};

use super::*;

mod instance;
mod qualification;

fn bundle() -> PackageBundleV1 {
    let mut descriptor = Package::new(
        "api.fixture",
        "1",
        vec![Model::new(
            "count",
            Vec::new(),
            vec![Port::new(
                "rows",
                Schema::new(vec![Field::new("count", DataType::UInt64, false)]),
            )],
        )],
    );
    descriptor.exports[0].input_mode = araphor_analysis_sdk::InputMode::Resolved;
    PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: descriptor.id.clone(),
            revision: descriptor.revision.clone(),
        },
        artifacts: vec![PackageArtifactV1 {
            descriptor,
            implementations: vec![PackageImplementationV1::Sql {
                export: "count".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([(
                        "rows".into(),
                        "SELECT 3::BIGINT UNSIGNED AS count".into(),
                    )]),
                    ..Default::default()
                },
            }],
            fixtures: Vec::new(),
        }],
    }
}

impl Fixture {
    async fn package(
        &self,
        operation: PackageRequestV1,
        mutation: bool,
    ) -> Result<PackageResponseV1, tonic::Status> {
        let request = proto::PackageOperationRequest {
            definition: operation
                .encode()
                .map_err(|_| Status::internal("test encoding"))?,
            selection: None,
        };
        let request = self
            .request(request, mutation)
            .map_err(|_| Status::internal("test request"))?;
        let reply = self.service.package_operation(request).await?.into_inner();
        PackageResponseV1::from_bytes(&reply.result).map_err(|_| Status::internal("test result"))
    }
}

#[tokio::test]
async fn definition_rpc_admission_is_not_execution() -> TestResult {
    use araphor_discovery_definition::{Definition, ImagePin, Program, Source};

    let fixture = Fixture::new()?;
    let definition = |name: &str, program| Definition {
        name: name.into(),
        description: "Count retained events.".into(),
        labels: BTreeMap::from([("team".into(), "security".into())]),
        program,
    };
    let sql = definition(
        "sql-counts",
        Program::Sql {
            source: Source::Inline {
                inline: "SELECT count(*) AS count FROM events".into(),
            },
        },
    );
    assert_eq!(
        fixture
            .package(
                PackageRequestV1::AdmitDefinition {
                    definition: sql.clone()
                },
                true
            )
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    let store = &fixture.service.data()?.store;
    let activations = store.package_activation_page(None)?;
    for definition in [
        sql,
        definition(
            "prql-counts",
            Program::Prql {
                source: Source::Inline {
                    inline: "from events\naggregate {count = count this}".into(),
                },
            },
        ),
    ] {
        let name = definition.name.clone();
        let PackageResponseV1::Definition(admitted) = fixture
            .package(
                PackageRequestV1::AdmitDefinition {
                    definition: definition.clone(),
                },
                true,
            )
            .await?
        else {
            return Err("definition absent".into());
        };
        assert_eq!(admitted.definition, definition);
        assert!(admitted.images.is_empty());
        let before = store.meta()?.commit_revision;
        assert!(matches!(
            fixture
                .package(PackageRequestV1::AdmitDefinition { definition }, true)
                .await?,
            PackageResponseV1::Definition(actual) if actual == admitted
        ));
        assert_eq!(store.meta()?.commit_revision, before);
        assert!(matches!(
            fixture
                .package(
                    PackageRequestV1::InspectDefinition {
                        name,
                        revision: Some(admitted.digest()?),
                    },
                    false
                )
                .await?,
            PackageResponseV1::Definition(actual) if actual == admitted
        ));
    }
    let invalid = definition(
        "invalid",
        Program::Sql {
            source: Source::Inline {
                inline: "DELETE FROM events".into(),
            },
        },
    );
    assert_eq!(
        fixture
            .package(
                PackageRequestV1::AdmitDefinition {
                    definition: invalid
                },
                true
            )
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::InvalidArgument)
    );
    assert!(store
        .definition([1; 16], "invalid", None, &AnalysisReadControl::default())?
        .is_none());
    let invalid = definition(
        "invalid-prql",
        Program::Prql {
            source: Source::Inline {
                inline: "from (".into(),
            },
        },
    );
    assert_eq!(
        fixture
            .package(
                PackageRequestV1::AdmitDefinition {
                    definition: invalid
                },
                true
            )
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::InvalidArgument)
    );
    assert!(store
        .definition(
            [1; 16],
            "invalid-prql",
            None,
            &AnalysisReadControl::default()
        )?
        .is_none());
    let uncaptured = definition(
        "uncaptured",
        Program::Sql {
            source: Source::File {
                file: "/server/must/not/read.sql".into(),
            },
        },
    );
    assert_eq!(
        fixture
            .package(
                PackageRequestV1::AdmitDefinition {
                    definition: uncaptured
                },
                true
            )
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::InvalidArgument)
    );
    let image = bundle();
    fixture
        .service
        .auth
        .replace_package_trust(vec![crate::PackageTrustPinV1 {
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            bundle_digest: image.digest()?,
        }])?;
    fixture
        .package(
            PackageRequestV1::InstallImage {
                bundle: image.clone(),
            },
            true,
        )
        .await?;
    let call = definition(
        "package-counts",
        Program::Sql {
            source: Source::Inline {
                inline: "SELECT * FROM \"api.fixture\".\"1\".count()".into(),
            },
        },
    );
    let PackageResponseV1::Definition(admitted) = fixture
        .package(
            PackageRequestV1::AdmitDefinition {
                definition: call.clone(),
            },
            true,
        )
        .await?
    else {
        return Err("call definition absent".into());
    };
    assert_eq!(admitted.definition, call);
    assert_eq!(admitted.images[0].image, image.root);
    assert_eq!(admitted.images[0].digest, image.digest()?);
    assert_eq!(store.package_activation_page(None)?, activations);
    let mut second = image.clone();
    second.root.package_id = "api.second".into();
    second.artifacts[0].descriptor.id = "api.second".into();
    let first_pin = ImagePin {
        image: image.root.clone(),
        digest: image.digest()?,
    };
    let second_pin = ImagePin {
        image: second.root.clone(),
        digest: second.digest()?,
    };
    let trust = |pins: &[ImagePin]| {
        pins.iter()
            .map(|pin| crate::PackageTrustPinV1 {
                tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
                bundle_digest: pin.digest.clone(),
            })
            .collect::<Vec<_>>()
    };
    fixture
        .service
        .auth
        .replace_package_trust(trust(&[first_pin.clone(), second_pin.clone()]))?;
    fixture
        .package(PackageRequestV1::InstallImage { bundle: second }, true)
        .await?;
    let multiple = "SELECT a.count AS first_count, b.count AS second_count FROM \"api.fixture\".\"1\".count() a CROSS JOIN \"api.second\".\"1\".count() b";
    let sql_call = definition(
        "multiple-sql",
        Program::Sql {
            source: Source::Inline {
                inline: multiple.into(),
            },
        },
    );
    fixture
        .service
        .auth
        .replace_package_trust(trust(std::slice::from_ref(&first_pin)))?;
    let before = store.meta()?;
    assert_eq!(
        fixture
            .package(
                PackageRequestV1::AdmitDefinition {
                    definition: sql_call.clone()
                },
                true
            )
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    assert_eq!(store.meta()?, before);
    assert!(store
        .definition(
            [1; 16],
            "multiple-sql",
            None,
            &AnalysisReadControl::default()
        )?
        .is_none());
    fixture
        .service
        .auth
        .replace_package_trust(trust(&[first_pin.clone(), second_pin.clone()]))?;
    for definition in [
        sql_call.clone(),
        definition(
            "multiple-prql",
            Program::Prql {
                source: Source::Inline {
                    inline: format!("from s\"{}\"", multiple.replace('"', "\\\"")),
                },
            },
        ),
    ] {
        let PackageResponseV1::Definition(admitted) = fixture
            .package(
                PackageRequestV1::AdmitDefinition {
                    definition: definition.clone(),
                },
                true,
            )
            .await?
        else {
            return Err("multiple call definition absent".into());
        };
        assert_eq!(admitted.definition, definition);
        assert_eq!(admitted.images, vec![first_pin.clone(), second_pin.clone()]);
    }
    let repeated = definition("repeated-image", Program::Sql { source: Source::Inline {
        inline: "SELECT a.count AS first_count, b.count AS second_count FROM \"api.fixture\".\"1\".count() a CROSS JOIN \"api.fixture\".\"1\".count() b".into(),
    } });
    let PackageResponseV1::Definition(repeated) = fixture
        .package(
            PackageRequestV1::AdmitDefinition {
                definition: repeated,
            },
            true,
        )
        .await?
    else {
        return Err("repeated image definition absent".into());
    };
    assert_eq!(repeated.images, vec![first_pin.clone()]);
    fixture
        .service
        .auth
        .replace_package_trust(trust(std::slice::from_ref(&first_pin)))?;
    let before = store.meta()?;
    assert_eq!(
        fixture
            .package(
                PackageRequestV1::AdmitDefinition {
                    definition: sql_call
                },
                true
            )
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    assert_eq!(store.meta()?, before);
    assert_eq!(store.package_activation_page(None)?, activations);
    fixture.service.auth.replace_package_managers(Vec::new())?;
    assert!(matches!(
        fixture
            .package(
                PackageRequestV1::InspectDefinition {
                    name: "package-counts".into(),
                    revision: None,
                },
                false
            )
            .await?,
        PackageResponseV1::Definition(actual) if actual == admitted
    ));
    Ok(())
}

#[tokio::test]
async fn package_rpc_authority_trust() -> TestResult {
    let fixture = Fixture::new()?;
    let bundle = bundle();
    let operation = PackageRequestV1::InstallImage {
        bundle: bundle.clone(),
    };
    assert_eq!(
        fixture
            .package(operation.clone(), true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    assert_eq!(
        fixture
            .package(operation.clone(), false)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unauthenticated)
    );
    assert_eq!(
        fixture
            .package(operation.clone(), true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    fixture
        .service
        .auth
        .replace_package_trust(vec![crate::PackageTrustPinV1 {
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            bundle_digest: bundle.digest()?,
        }])?;
    let PackageResponseV1::Image(installed) = fixture.package(operation, true).await? else {
        return Err("installed image variant".into());
    };
    assert_eq!(installed, bundle.metadata()?);
    let inspected = fixture
        .package(
            PackageRequestV1::InspectImage {
                package_id: "api.fixture".into(),
                revision: Some("1".into()),
            },
            false,
        )
        .await?;
    let PackageResponseV1::Image(inspected) = inspected else {
        return Err("inspected image variant".into());
    };
    assert_eq!(inspected, installed);
    fixture.service.auth.replace_package_managers(Vec::new())?;
    assert_eq!(
        fixture
            .package(PackageRequestV1::InstallImage { bundle }, true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    Ok(())
}

#[test]
fn package_response_encoding() -> TestResult {
    let response = PackageResponseV1::Image(bundle().metadata()?);
    let bytes = ClientGrpcOwner::package_response(&response)?;
    assert_eq!(
        serde_json::to_value(PackageResponseV1::from_bytes(&bytes)?)?,
        serde_json::to_value(&response)?
    );
    Ok(())
}

#[tokio::test]
async fn image_rpc_install_is_not_execution() -> TestResult {
    let fixture = Fixture::new()?;
    let bundle = bundle();
    let operation = PackageRequestV1::InstallImage {
        bundle: bundle.clone(),
    };
    assert_eq!(
        fixture
            .package(operation.clone(), true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    assert_eq!(
        fixture
            .package(operation.clone(), false)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unauthenticated)
    );
    assert_eq!(
        fixture
            .package(operation.clone(), true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    fixture
        .service
        .auth
        .replace_package_trust(vec![crate::PackageTrustPinV1 {
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            bundle_digest: bundle.digest()?,
        }])?;
    let data = &fixture.service.data()?.store;
    let activations = data.package_activation_page(None)?;
    let selected = fixture.request(
        proto::PackageOperationRequest {
            definition: operation.encode()?,
            selection: Some(proto::InputSelection {
                node_ids: vec!["node-a".into()],
                ..Default::default()
            }),
        },
        true,
    )?;
    assert_eq!(
        fixture
            .service
            .package_operation(selected)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::InvalidArgument)
    );
    assert!(data
        .package_image(
            [1; 16],
            &bundle.root.package_id,
            None,
            &AnalysisReadControl::default()
        )?
        .is_none());
    let PackageResponseV1::Image(installed) = fixture.package(operation.clone(), true).await?
    else {
        return Err("installed image variant".into());
    };
    assert_eq!(installed, bundle.metadata()?);
    assert_eq!(
        serde_json::to_value(PackageResponseV1::Image(installed.clone()))?,
        serde_json::json!({"image": bundle.metadata()?}),
    );
    assert_eq!(data.package_activation_page(None)?, activations);
    let revision = *data.subscribe_revision().borrow();
    fixture.package(operation, true).await?;
    assert_eq!(*data.subscribe_revision().borrow(), revision);
    fixture.service.auth.replace_package_managers(Vec::new())?;
    let inspected = fixture
        .package(
            PackageRequestV1::InspectImage {
                package_id: bundle.root.package_id.clone(),
                revision: Some(bundle.root.revision.clone()),
            },
            false,
        )
        .await?;
    let PackageResponseV1::Image(inspected) = inspected else {
        return Err("inspected image variant".into());
    };
    assert_eq!(inspected, installed);
    assert_eq!(data.package_activation_page(None)?, activations);
    Ok(())
}
