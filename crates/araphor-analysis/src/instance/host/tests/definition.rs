use super::*;

#[tokio::test]
async fn prepared_definition_requires_install() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let authority = Authority::new(&fixture);
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
    let control = AnalysisReadControl::default();
    let session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, 0)?;
    let definition = araphor_discovery_definition::Definition {
        name: "host-definition".into(),
        description: String::new(),
        labels: Default::default(),
        program: araphor_discovery_definition::Program::Sql {
            source: araphor_discovery_definition::Source::Inline {
                inline: "SELECT 1 AS value".into(),
            },
        },
    };
    let prepared = session.prepare_definition(&definition).await?;
    let digest = prepared.resolved().digest()?;
    let before = fixture.query.store().meta()?;
    authority.install_denied.store(true, Ordering::SeqCst);
    let error = host
        .admit_prepared(
            session.clone(),
            fixture.grant.clone(),
            "host-definition-job".into(),
            prepared.clone(),
            ManagedDestination::Selected,
        )
        .await
        .err()
        .ok_or("definition admitted without Install")?;
    assert!(matches!(
        error,
        crate::Error::Query {
            source: araphor_query::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Denied,
                    field: "host fixture install",
                    ..
                }
            }
        }
    ));
    assert_eq!(authority.installs.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(fixture
        .query
        .store()
        .definition([1; 16], &definition.name, Some(&digest), &control)?
        .is_none());
    assert!(fixture
        .query
        .store()
        .managed_instance([1; 16], "host-definition-job", &control)?
        .is_none());
    authority.install_denied.store(false, Ordering::SeqCst);
    let admitted = host
        .admit_prepared(
            session.clone(),
            fixture.grant.clone(),
            "host-definition-job".into(),
            prepared.clone(),
            ManagedDestination::Selected,
        )
        .await?;
    assert_eq!(authority.installs.load(Ordering::SeqCst), 2);
    assert!(!admitted.admitted().running);
    assert_eq!(admitted.admitted().progress, 0);
    assert_eq!(
        fixture
            .query
            .store()
            .definition([1; 16], &definition.name, Some(&digest), &control)?
            .as_ref(),
        Some(prepared.resolved())
    );
    let committed = fixture.query.store().meta()?;
    assert_eq!(committed.commit_revision, before.commit_revision + 2);
    authority.install_denied.store(true, Ordering::SeqCst);
    let retained = host
        .admit_prepared(
            session,
            fixture.grant.clone(),
            "host-definition-job".into(),
            prepared,
            ManagedDestination::Selected,
        )
        .await?;
    assert_eq!(retained.admitted(), admitted.admitted());
    assert_eq!(authority.installs.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.query.store().meta()?, committed);
    Ok(())
}
