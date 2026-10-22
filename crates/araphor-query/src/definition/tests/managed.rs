use super::*;
use crate::definition::Invocation;
use araphor_data::{
    AnalysisSelectionV1, ManagedInstance, ManagedManifest, ManagedRead, ManagedSpec, PackageGrantV1,
};
use sdk::arrow_array::UInt64Array;

const NOW: u64 = 1_700_000_000_123_456_789;
const CAPACITY: usize = 256 * 1024;

impl Fixture {
    pub(super) fn managed(
        &self,
        definition: &PreparedDefinition,
        selection: AnalysisSelectionV1,
    ) -> TestResult<ManagedInstance> {
        self.engine
            .store()
            .admit_definition([1; 16], definition.resolved(), || Ok(()))?;
        Ok(self.engine.store().admit_managed(
            &ManagedSpec {
                tenant: [1; 16],
                id: "constant".into(),
                definition: definition.resolved().clone(),
                manifest: ManagedManifest {
                    format: 1,
                    planner: "datafusion-53/sql-call-1".into(),
                    definition: definition.resolved().digest()?,
                    calls: BTreeMap::new(),
                },
            },
            &PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection,
                expires_utc_ns: None,
                authorization_id: Some("constant-grant".into()),
            },
            || Ok(()),
        )?)
    }
}

#[tokio::test]
async fn constant_capture_keeps_state() -> TestResult {
    let fixture = Fixture::limits(Limits {
        input_bytes: CAPACITY,
        input_capacity: Some(CAPACITY),
        ..Limits::default()
    })?;
    let selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    let session =
        fixture
            .engine
            .session(selection.clone(), &AnalysisReadControl::default(), NOW)?;
    let definition = session
        .prepare_definition(&Fixture::sql("SELECT CAST(7 AS BIGINT UNSIGNED) AS value"))
        .await?;
    let retained = session.memory().input_reserved();
    assert!(retained > 0);
    let available = CAPACITY.checked_sub(retained).ok_or("admitted metadata")?;
    assert!(definition.sources().is_empty());
    let instance = fixture.managed(&definition, selection)?;
    let captured = session
        .capture_managed(
            &definition,
            Invocation::default(),
            ManagedRead {
                instance: instance.clone(),
                rebuild: true,
                completed: None,
            },
        )
        .await?;
    let state = captured
        .snapshot()
        .managed()
        .ok_or("managed state absent")?;
    assert_eq!(state.instance(), &instance);
    assert!(state.rebuild());
    assert!(state.datasets().next().is_none());
    assert!(captured.snapshot().results().next().is_none());
    assert!(session.memory().reserve_input(available).is_err());
    let result = captured.execute().await?;
    assert_eq!(
        result
            .snapshot
            .managed()
            .ok_or("delivered state absent")?
            .instance(),
        &instance
    );
    assert!(result.calls.is_empty());
    let values = result
        .batches
        .iter()
        .flat_map(|batch| {
            batch
                .column(0)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .unwrap()
                .values()
                .iter()
                .copied()
        })
        .collect::<Vec<_>>();
    assert_eq!(values, [7]);
    drop(result);
    assert_eq!(session.memory().input_reserved(), retained);
    let released = session.memory().reserve_input(available)?;
    assert!(session.memory().reserve_input(1).is_err());
    drop(released);
    let captured = session
        .capture_managed(
            &definition,
            Invocation::default(),
            ManagedRead {
                instance,
                rebuild: false,
                completed: None,
            },
        )
        .await?;
    captured.cancel_and_join().await?;
    assert_eq!(session.memory().input_reserved(), retained);
    let released = session.memory().reserve_input(available)?;
    drop(released);
    drop(definition);
    drop(session.memory().reserve_input(CAPACITY)?);
    Ok(())
}

#[tokio::test]
async fn managed_capture_rejects_state() -> TestResult {
    let fixture = Fixture::new()?;
    let selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    let session =
        fixture
            .engine
            .session(selection.clone(), &AnalysisReadControl::default(), NOW)?;
    let definition = session
        .prepare_definition(&Fixture::sql("SELECT 1 AS value"))
        .await?;
    let instance = fixture.managed(&definition, selection)?;
    for checkpoints in [false, true] {
        let mut invocation = Invocation::default();
        if checkpoints {
            invocation.checkpoints.insert(
                0,
                sdk::Checkpoint {
                    version: 1,
                    datasets: Vec::new(),
                },
            );
        } else {
            invocation.inputs.insert(0, Vec::new());
        }
        let error = session
            .capture_managed(
                &definition,
                invocation,
                ManagedRead {
                    instance: instance.clone(),
                    rebuild: false,
                    completed: None,
                },
            )
            .await
            .err()
            .ok_or("mixed state was accepted")?;
        assert_eq!(crate::Failure::from(&error), crate::Failure::InvalidQuery);
    }
    let output = session
        .execute_definition(&definition, Invocation::default())
        .await?;
    assert!(output.snapshot.managed().is_none());
    Ok(())
}

#[tokio::test]
async fn managed_capture_keeps_binding() -> TestResult {
    let fixture = Fixture::new()?;
    let selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    let session =
        fixture
            .engine
            .session(selection.clone(), &AnalysisReadControl::default(), NOW)?;
    let definition = session
        .prepare_definition(&Fixture::sql("SELECT 1 AS value"))
        .await?;
    let instance = fixture.managed(&definition, selection)?;
    for changed_scope in [false, true] {
        let mut changed = instance.clone();
        if changed_scope {
            changed.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
        } else {
            changed.spec.definition.sql.push(' ');
        }
        let error = session
            .capture_managed(
                &definition,
                Invocation::default(),
                ManagedRead {
                    instance: changed,
                    rebuild: false,
                    completed: None,
                },
            )
            .await
            .err()
            .ok_or("unbound state was accepted")?;
        assert_eq!(crate::Failure::from(&error), crate::Failure::Denied);
    }
    Ok(())
}
