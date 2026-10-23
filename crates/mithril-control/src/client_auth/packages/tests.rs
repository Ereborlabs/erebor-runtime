use super::*;
use araphor_data::PackageBundleV1;
use araphor_discovery_definition::{Definition, ImagePin, Program, ResolvedDefinition, Source};

fn managers() -> Vec<InvestigateGrant> {
    vec![InvestigateGrant {
        subject: "alice".into(),
        tenant_id: Uuid::from_bytes([1; 16]).to_string(),
    }]
}

#[test]
fn package_permission_is_explicit() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = super::super::tests::owner()?;
    let session = super::super::tests::session(&owner)?;
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let inspect = access.package_grant(selection.clone(), PackageActionV1::Inspect)?;
    owner.check_package(&inspect, PackageActionV1::Inspect)?;
    assert!(access
        .package_grant(selection.clone(), PackageActionV1::Install)
        .is_err());
    owner.replace_package_managers(managers())?;
    let grant = access.package_grant(selection, PackageActionV1::Install)?;
    assert_ne!(
        grant.authorization_id.as_deref(),
        Some(session.token.as_str())
    );
    owner.check_package(&grant, PackageActionV1::Run)?;
    let mut changes = PackageAuthorization::changes(owner.as_ref());
    owner.replace_package_managers(Vec::new())?;
    assert!(changes.has_changed()?);
    changes.borrow_and_update();
    assert!(owner.check_package(&grant, PackageActionV1::Run).is_err());
    owner.replace_package_managers(managers())?;
    assert!(owner.check_package(&grant, PackageActionV1::Run).is_err());
    Ok(())
}

#[test]
fn package_logout_revokes_grant() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = super::super::tests::owner()?;
    owner.replace_package_managers(managers())?;
    let session = super::super::tests::session(&owner)?;
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    let grant = access.package_grant(AnalysisSelectionV1::tenant([1; 16]), PackageActionV1::Run)?;
    owner.check_package(&grant, PackageActionV1::Run)?;
    owner.logout(&session.token, &owner.origin, &session.csrf)?;
    assert!(owner.check_package(&grant, PackageActionV1::Run).is_err());
    Ok(())
}

#[test]
fn package_tenant_trust_pins() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = super::super::tests::owner()?;
    let pin = PackageTrustPinV1 {
        tenant_id: Uuid::from_bytes([1; 16]).to_string(),
        bundle_digest: format!("sha256:{}", "a".repeat(64)),
    };
    owner.replace_package_trust(vec![pin.clone()])?;
    let state = owner.state()?;
    assert!(state
        .package_trust
        .contains(&([1; 16], pin.bundle_digest.clone())));
    assert!(!state
        .package_trust
        .contains(&([2; 16], pin.bundle_digest.clone())));
    drop(state);
    assert!(owner
        .replace_package_trust(vec![pin.clone(), pin.clone()])
        .is_err());
    for digest in [
        "a".repeat(64),
        format!("sha256:{}", "A".repeat(64)),
        format!("SHA256:{}", "a".repeat(64)),
        format!("sha512:{}", "a".repeat(64)),
        format!("sha256:{}", "a".repeat(63)),
        format!("sha256:{}", "a".repeat(65)),
        format!("sha256:{}", "g".repeat(64)),
        format!("sha256:{}\n", "a".repeat(64)),
    ] {
        let mut invalid = pin.clone();
        invalid.bundle_digest = digest;
        assert!(owner.replace_package_trust(vec![invalid]).is_err());
        assert!(owner
            .state()?
            .package_trust
            .contains(&([1; 16], pin.bundle_digest.clone())));
    }
    Ok(())
}

fn bundle(query: &str) -> PackageBundleV1 {
    let mut descriptor = araphor_analysis_sdk::Package::new(
        "lock-fixture",
        "1",
        vec![araphor_analysis_sdk::Model::new(
            "count",
            Vec::new(),
            vec![araphor_analysis_sdk::Port::new(
                "rows",
                araphor_analysis_sdk::Schema::new(vec![araphor_analysis_sdk::Field::new(
                    "count",
                    araphor_analysis_sdk::DataType::UInt64,
                    false,
                )]),
            )],
        )],
    );
    descriptor.exports[0].input_mode = araphor_analysis_sdk::InputMode::Resolved;
    PackageBundleV1 {
        schema_version: 1,
        root: araphor_data::PackageRefV1 {
            package_id: "lock-fixture".into(),
            revision: "1".into(),
        },
        artifacts: vec![araphor_data::PackageArtifactV1 {
            descriptor,
            implementations: vec![araphor_data::PackageImplementationV1::Sql {
                export: "count".into(),
                program: araphor_data::SqlModelV1 {
                    outputs: std::collections::BTreeMap::from([("rows".into(), query.into())]),
                    ..Default::default()
                },
            }],
            fixtures: Vec::new(),
        }],
    }
}

#[test]
fn package_commit_holds_authority() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = super::super::tests::owner()?;
    owner.replace_package_managers(managers())?;
    let session = super::super::tests::session(&owner)?;
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    let grant = access.package_grant(AnalysisSelectionV1::tenant([1; 16]), PackageActionV1::Run)?;
    let bundle = bundle("SELECT 1::BIGINT UNSIGNED AS count");
    assert!(bundle.digest()?.starts_with("sha256:"));
    owner.replace_package_trust(vec![PackageTrustPinV1 {
        tenant_id: Uuid::from_bytes([1; 16]).to_string(),
        bundle_digest: bundle.digest()?,
    }])?;
    let admitted = araphor_data::PackageBundleRef::new(&bundle)?;
    let mut committed = false;
    owner.commit(&grant, PackageActionV1::Run, &admitted, &mut || {
        assert!(matches!(
            owner.state.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        committed = true;
        Ok(())
    })?;
    assert!(committed);
    let changed = self::bundle("SELECT 2::BIGINT UNSIGNED AS count");
    assert_ne!(bundle.digest()?, changed.digest()?);
    let changed_ref = araphor_data::PackageBundleRef::new(&changed)?;
    assert!(owner.admit(&grant, &changed_ref).is_err());
    committed = false;
    assert!(owner
        .commit(&grant, PackageActionV1::Run, &changed_ref, &mut || {
            committed = true;
            Ok(())
        })
        .is_err());
    assert!(!committed);
    owner.replace_package_trust(Vec::new())?;
    committed = false;
    assert!(owner
        .commit(&grant, PackageActionV1::Run, &admitted, &mut || {
            committed = true;
            Ok(())
        })
        .is_err());
    assert!(!committed);
    owner.commit(&grant, PackageActionV1::Remove, &admitted, &mut || {
        committed = true;
        Ok(())
    })?;
    assert!(committed);
    owner.replace_package_managers(Vec::new())?;
    assert!(owner
        .commit(&grant, PackageActionV1::Remove, &admitted, &mut || Ok(()))
        .is_err());
    Ok(())
}

fn definition() -> std::result::Result<ResolvedDefinition, Box<dyn std::error::Error>> {
    Ok(ResolvedDefinition::new(
        Definition {
            name: "auth-fixture".into(),
            description: String::new(),
            labels: Default::default(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: "SELECT 1".into(),
                },
            },
        },
        "SELECT 1".into(),
        Vec::new(),
    )?)
}

#[test]
fn definition_commit_holds_authority() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = super::super::tests::owner()?;
    let session = super::super::tests::session(&owner)?;
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    let definition = definition()?;
    assert!(definition.images.is_empty());
    let inspect = access.package_grant(
        AnalysisSelectionV1::tenant([1; 16]),
        PackageActionV1::Inspect,
    )?;
    let mut committed = false;
    assert!(owner
        .commit_definition(&inspect, &definition, || {
            committed = true;
            Ok(())
        })
        .is_err());
    assert!(!committed);
    owner.replace_package_managers(managers())?;
    let grant = access.package_grant(
        AnalysisSelectionV1::tenant([1; 16]),
        PackageActionV1::Install,
    )?;
    let result = owner.commit_definition(&grant, &definition, || {
        assert!(matches!(
            owner.state.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        committed = true;
        Ok(37_u64)
    })?;
    assert!(committed);
    assert_eq!(result, 37);
    Ok(())
}

#[test]
fn definition_commit_revocation() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let definition = definition()?;
    for revocation in ["manager", "grant", "session"] {
        let owner = super::super::tests::owner()?;
        owner.replace_package_managers(managers())?;
        let session = super::super::tests::session(&owner)?;
        let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
        let grant = access.package_grant(
            AnalysisSelectionV1::tenant([1; 16]),
            PackageActionV1::Install,
        )?;
        owner.check_package(&grant, PackageActionV1::Install)?;
        match revocation {
            "manager" => owner.replace_package_managers(Vec::new())?,
            "grant" => owner.replace_grants(Vec::new())?,
            _ => assert!(owner.revoke_session(&session.token)?),
        }
        let mut committed = false;
        assert!(matches!(
            owner.commit_definition(&grant, &definition, || {
                committed = true;
                Ok(())
            }),
            Err(araphor_data::Error::Package {
                code: araphor_data::PackageErrorCodeV1::Denied,
                ..
            })
        ));
        assert!(!committed, "{revocation}");
        match revocation {
            "manager" => owner.replace_package_managers(managers())?,
            "grant" => owner.replace_grants(managers())?,
            _ => continue,
        }
        assert!(owner
            .commit_definition(&grant, &definition, || {
                committed = true;
                Ok(())
            })
            .is_err());
        assert!(!committed, "{revocation}");
    }
    Ok(())
}

#[test]
fn definition_commit_expiry() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = super::super::tests::owner()?;
    owner.replace_package_managers(managers())?;
    let session = super::super::tests::session(&owner)?;
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    let grant = access.package_grant(
        AnalysisSelectionV1::tenant([1; 16]),
        PackageActionV1::Install,
    )?;
    owner.check_package(&grant, PackageActionV1::Install)?;
    let definition = definition()?;
    for expiry in [None, Some(0)] {
        let mut expired = grant.clone();
        expired.expires_utc_ns = expiry;
        let mut committed = false;
        assert!(matches!(
            owner.commit_definition(&expired, &definition, || {
                committed = true;
                Ok(())
            }),
            Err(araphor_data::Error::Package {
                code: araphor_data::PackageErrorCodeV1::Denied,
                ..
            })
        ));
        assert!(!committed);
    }
    Ok(())
}

#[test]
fn definition_commit_image_trust() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = super::super::tests::owner()?;
    owner.replace_package_managers(managers())?;
    let session = super::super::tests::session(&owner)?;
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    let grant = access.package_grant(
        AnalysisSelectionV1::tenant([1; 16]),
        PackageActionV1::Install,
    )?;
    let first = bundle("SELECT 1::BIGINT UNSIGNED AS count");
    let mut second = first.clone();
    second.root.revision = "2".into();
    second.artifacts[0].descriptor.revision = "2".into();
    let first_pin = ImagePin {
        image: first.root.clone(),
        digest: first.digest()?,
    };
    let second_pin = ImagePin {
        image: second.root.clone(),
        digest: second.digest()?,
    };
    assert_eq!(first_pin.image.package_id, second_pin.image.package_id);
    assert_ne!(first_pin.image.revision, second_pin.image.revision);
    assert_ne!(first_pin.digest, second_pin.digest);
    let trust = |tenant: [u8; 16], pin: &ImagePin| PackageTrustPinV1 {
        tenant_id: Uuid::from_bytes(tenant).to_string(),
        bundle_digest: pin.digest.clone(),
    };
    let mut definition = definition()?;
    let first_sql = format!(
        "SELECT * FROM \"{}\".\"{}\".count()",
        first_pin.image.package_id, first_pin.image.revision
    );
    let second_sql = format!(
        "SELECT * FROM \"{}\".\"{}\".count()",
        second_pin.image.package_id, second_pin.image.revision
    );
    definition.definition.program = Program::Sql {
        source: Source::Inline {
            inline: first_sql.clone(),
        },
    };
    definition.sql = first_sql.clone();
    definition.images = vec![first_pin.clone()];
    definition.validate()?;
    for pins in [Vec::new(), vec![trust([2; 16], &first_pin)]] {
        owner.replace_package_trust(pins)?;
        let mut committed = false;
        assert!(owner
            .commit_definition(&grant, &definition, || {
                committed = true;
                Ok(())
            })
            .is_err());
        assert!(!committed);
    }
    owner.replace_package_trust(vec![trust([1; 16], &first_pin)])?;
    let mut committed = false;
    owner.commit_definition(&grant, &definition, || {
        assert!(matches!(
            owner.state.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        committed = true;
        Ok(())
    })?;
    assert!(committed);
    let mut changed = definition.clone();
    changed.definition.program = Program::Sql {
        source: Source::Inline {
            inline: second_sql.clone(),
        },
    };
    changed.sql = second_sql.clone();
    changed.images = vec![second_pin.clone()];
    changed.validate()?;
    committed = false;
    assert!(owner
        .commit_definition(&grant, &changed, || {
            committed = true;
            Ok(())
        })
        .is_err());
    assert!(!committed);
    let both = format!("SELECT a.count AS first_count, b.count AS second_count FROM ({first_sql}) a CROSS JOIN ({second_sql}) b");
    definition.definition.program = Program::Sql {
        source: Source::Inline {
            inline: both.clone(),
        },
    };
    definition.sql = both;
    definition.images.push(second_pin.clone());
    definition.validate()?;
    assert!(owner
        .commit_definition(&grant, &definition, || {
            committed = true;
            Ok(())
        })
        .is_err());
    assert!(!committed);
    owner.replace_package_trust(vec![
        trust([1; 16], &first_pin),
        trust([1; 16], &second_pin),
    ])?;
    owner.commit_definition(&grant, &definition, || {
        committed = true;
        Ok(())
    })?;
    assert!(committed);
    owner.replace_package_trust(Vec::new())?;
    committed = false;
    assert!(owner
        .commit_definition(&grant, &definition, || {
            committed = true;
            Ok(())
        })
        .is_err());
    assert!(!committed);
    Ok(())
}

#[test]
fn definition_commit_requires_grant() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = super::super::tests::owner()?;
    owner.replace_package_managers(managers())?;
    let session = super::super::tests::session(&owner)?;
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    let grant = access.package_grant(AnalysisSelectionV1::tenant([1; 16]), PackageActionV1::Run)?;
    let mut committed = false;
    assert!(owner
        .commit_many(&[], &mut || {
            committed = true;
            Ok(())
        })
        .is_err());
    assert!(!committed);
    owner.commit_many(&[(&grant, PackageActionV1::Run, None)], &mut || {
        assert!(matches!(
            owner.state.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        committed = true;
        Ok(())
    })?;
    assert!(committed);
    owner.logout(&session.token, &owner.origin, &session.csrf)?;
    committed = false;
    assert!(owner
        .commit_many(&[(&grant, PackageActionV1::Run, None)], &mut || {
            committed = true;
            Ok(())
        })
        .is_err());
    assert!(!committed);
    Ok(())
}

#[test]
fn definition_commit_checks_images() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = super::super::tests::owner()?;
    owner.replace_package_managers(managers())?;
    let session = super::super::tests::session(&owner)?;
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    let grant = access.package_grant(AnalysisSelectionV1::tenant([1; 16]), PackageActionV1::Run)?;
    let first = bundle("SELECT 1::BIGINT UNSIGNED AS count");
    let second = bundle("SELECT 2::BIGINT UNSIGNED AS count");
    let first_ref = araphor_data::PackageBundleRef::new(&first)?;
    let second_ref = araphor_data::PackageBundleRef::new(&second)?;
    let pin = |bundle: &PackageBundleV1| -> std::result::Result<PackageTrustPinV1, Box<dyn std::error::Error>> {
        Ok(PackageTrustPinV1 {
            tenant_id: Uuid::from_bytes([1; 16]).to_string(),
            bundle_digest: bundle.digest()?,
        })
    };
    owner.replace_package_trust(vec![pin(&first)?])?;
    let grants = [
        (&grant, PackageActionV1::Run, None),
        (&grant, PackageActionV1::Update, Some(&first_ref)),
        (&grant, PackageActionV1::Rollback, Some(&second_ref)),
    ];
    let mut committed = false;
    assert!(owner
        .commit_many(&grants, &mut || {
            committed = true;
            Ok(())
        })
        .is_err());
    assert!(!committed);
    owner.replace_package_trust(vec![pin(&first)?, pin(&second)?])?;
    owner.commit_many(&grants, &mut || {
        assert!(matches!(
            owner.state.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        committed = true;
        Ok(())
    })?;
    assert!(committed);
    Ok(())
}
