use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use duckdb::params;

use super::*;
use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1, AnalysisExtractLimits,
    AnalysisInputTables, AnalysisReadControl, AnalysisReadModeV1, AnalysisReferenceOriginV1,
    AnalysisReferenceV1, AnalysisSelectionV1, AnalysisTableRead, AnalysisWitnessV1,
    ClockDependency, ContextSensitivityV1, InstalledContext, PackageErrorCodeV1 as Code,
    PackageGrantV1, PackageReadinessV1, PackageRefV1, ResultContext, ValidatedEvidenceBatchV1,
};

struct Fixture {
    _directory: tempfile::TempDir,
    store: Arc<AnalysisStore>,
    selection: AnalysisSelectionV1,
    reference: sdk::OutputRef,
    installed: InstalledContext,
    result: PackageResultV1,
    schema: sdk::Schema,
}

impl Fixture {
    fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("store"))?);
        let identity = crate::analysis::tests::identity();
        let selection = AnalysisSelectionV1::tenant(identity.tenant_id);
        Self::append(&store, 1)?;
        let context = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: identity.tenant_id,
                owner_id: "input".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: b"{}".to_vec(),
        };
        let context_revision = store.commit_context(&context)?;
        let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
        let mut revision = package("first", "v1")?;
        let mut artifact = revision.decode_artifact()?;
        artifact.descriptor.exports[0].outputs[0].schema = schema.clone();
        revision.descriptor = serde_json::to_vec(&artifact.descriptor)?;
        revision.artifact = crate::StoredArtifact::encode(&artifact)?;
        store.install_package(&[revision], || Ok(()))?;
        let installed = InstalledContext {
            grant: PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection: selection.clone(),
                expires_utc_ns: None,
                authorization_id: None,
            },
            root: PackageRefV1 {
                package_id: "first".into(),
                revision: "v1".into(),
            },
            parameters: None,
            readiness: PackageReadinessV1::Ready,
            status_checkpoint: 0,
            prepared: true,
            clock: ClockDependency::None,
        };
        let mut active = activation("first", "v1");
        active.metadata = serde_json::to_vec(&installed)?;
        let active = store.activate_package(&active, None, None, || Ok(()))?;
        let mut input = commit(active, "first-1");
        input.metadata = serde_json::to_vec(&ResultContext::new(
            "first-1",
            1,
            &artifact.descriptor.exports[0],
            &[],
        ))?;
        input.datasets = Self::packet(&schema, 7)?;
        input.witnesses = vec![AnalysisWitnessV1 {
            identity: identity.into(),
            cursor: 1,
            expires_utc_ns: 100,
        }];
        input.context_refs = vec![AnalysisContextRefV1 {
            key: context.key,
            commit_revision: context_revision,
        }];
        store.commit_package(&input, || Ok(()))?;
        let result = store
            .package_result(selection.tenant_id, "first-1")?
            .ok_or("result")?;
        Ok(Self {
            _directory: directory,
            store,
            selection,
            reference: sdk::OutputRef {
                package: "first".into(),
                revision: "v1".into(),
                export: "model".into(),
                output: "rows".into(),
            },
            installed,
            result,
            schema,
        })
    }

    fn append(store: &AnalysisStore, cursor: u64) -> crate::Result<()> {
        let record = crate::EvidenceRecord {
            observed_boottime_ns: cursor,
            ..Default::default()
        };
        let framed = Vec::<u8>::try_from(&record)?;
        store.accept_validated_batch(
            crate::analysis::tests::identity(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: cursor,
                frame_ends: vec![framed.len()],
                framed_records: framed.into(),
            },
        )?;
        Ok(())
    }

    fn packet(schema: &sdk::Schema, value: u64) -> crate::Result<Vec<u8>> {
        let batch = sdk::RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(sdk::arrow_array::UInt64Array::from(vec![value]))],
        )
        .map_err(sdk::Error::from)
        .context(crate::AnalysisContractSnafu)?;
        let dataset = sdk::wire::Dataset::encode(
            &sdk::Dataset {
                name: "rows".into(),
                batches: vec![batch],
            },
            schema,
            sdk::Limits::default(),
        )
        .context(crate::AnalysisContractSnafu)?;
        serde_json::to_vec(&sdk::wire::Output {
            datasets: vec![dataset],
            ..Default::default()
        })
        .context(crate::PackageEncodingSnafu)
    }

    fn read(
        &self,
        selection: &AnalysisSelectionV1,
        authorized: &AnalysisSelectionV1,
        references: &[sdk::OutputRef],
        mode: AnalysisReadModeV1,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> crate::Result<crate::AnalysisPositionPageV1> {
        let relations = BTreeSet::from(["events".to_owned()]);
        let columns = BTreeMap::from([(
            "events".to_owned(),
            BTreeSet::from([AnalysisStore::table_schemas()["events"]
                .index_of("source_cursor")
                .map_err(sdk::Error::from)
                .context(crate::AnalysisContractSnafu)?]),
        )]);
        let outputs = references
            .iter()
            .map(|reference| (reference.clone(), Arc::new(self.schema.clone())))
            .collect::<Vec<_>>();
        self.store.read_tables(
            selection,
            AnalysisTableRead {
                relations: &relations,
                columns: &columns,
                event_ranges: None,
                inputs: Some(AnalysisInputTables {
                    authorized,
                    scope: "scope",
                    outputs: &outputs,
                    limits: sdk::Limits::default(),
                }),
                mode,
                now: 1,
            },
            limits,
            control,
        )
    }

    fn metadata(
        &self,
        authorized: &AnalysisSelectionV1,
        reference: &sdk::OutputRef,
    ) -> crate::Result<crate::AnalysisPositionPageV1> {
        let page = self.read(
            &self.selection,
            authorized,
            std::slice::from_ref(reference),
            AnalysisReadModeV1::Metadata,
            Default::default(),
            &AnalysisReadControl::default(),
        )?;
        assert!(page.packages.is_empty());
        assert!(page.tables.values().all(Vec::is_empty));
        Ok(page)
    }
}

#[test]
fn package_output_snapshot() -> TestResult {
    let fixture = Fixture::new()?;
    let before = fixture.store.meta()?;
    let mut replacement = fixture.result.commit.clone();
    replacement.activation = fixture
        .store
        .package_activation(&replacement.activation.key)?
        .ok_or("active")?;
    replacement.expected_checkpoint_revision = replacement.activation.checkpoint_revision;
    replacement.result_id = "first-2".into();
    replacement.datasets = Fixture::packet(&fixture.schema, 8)?;
    replacement.witnesses[0].cursor = 2;
    let control = AnalysisReadControl::default();
    let writer = Arc::clone(&fixture.store);
    control.on_read_step(move || {
        Fixture::append(&writer, 2)?;
        writer.commit_package(&replacement, || Ok(()))?;
        Ok(())
    })?;
    let page = fixture.read(
        &fixture.selection,
        &fixture.selection,
        std::slice::from_ref(&fixture.reference),
        AnalysisReadModeV1::Complete,
        Default::default(),
        &control,
    )?;
    let mut cursors = Vec::new();
    for batch in &page.tables["events"] {
        let values = batch
            .column_by_name("source_cursor")
            .ok_or("source cursor absent")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("source cursor is not UInt64")?;
        cursors.extend_from_slice(values.values());
    }
    let (schema, batches, coverage) = page.packages.get(&0).ok_or("package table")?;
    assert_eq!(schema.as_ref(), &fixture.schema);
    assert_eq!(coverage.state, sdk::CoverageState::Complete);
    let mut captured = Vec::new();
    for batch in batches {
        let values = batch
            .column(0)
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("package value is not UInt64")?;
        captured.extend_from_slice(values.values());
    }
    assert_eq!(page.extraction.meta, before);
    assert_eq!(cursors, [1]);
    assert_eq!(captured, [7]);
    assert_eq!(
        page.extraction
            .references
            .iter()
            .filter_map(AnalysisReferenceV1::result)
            .cloned()
            .collect::<Vec<_>>(),
        vec![PackageResultRefV1 {
            result_id: fixture.result.commit.result_id.clone(),
            commit_revision: fixture.result.commit_revision,
        }]
    );
    assert_eq!(
        page.extraction
            .references
            .iter()
            .filter_map(AnalysisReferenceV1::context)
            .cloned()
            .collect::<Vec<_>>(),
        fixture.result.commit.context_refs
    );
    let mut witnesses = fixture.result.commit.witnesses.clone();
    let mut raw = witnesses[0].clone();
    raw.expires_utc_ns = 0;
    witnesses.insert(0, raw);
    assert_eq!(page.extraction.witnesses, witnesses);
    let next = fixture.metadata(&fixture.selection, &fixture.reference)?;
    assert!(next.extraction.meta.commit_revision > before.commit_revision);
    assert_eq!(
        next.extraction
            .references
            .iter()
            .find_map(AnalysisReferenceV1::result)
            .ok_or("result")?
            .result_id,
        "first-2"
    );
    Ok(())
}

#[test]
fn package_output_current() -> TestResult {
    let fixture = Fixture::new()?;
    assert_eq!(
        fixture
            .metadata(&fixture.selection, &fixture.reference)?
            .extraction
            .references
            .iter()
            .find_map(AnalysisReferenceV1::result)
            .ok_or("result")?
            .result_id,
        "first-1"
    );
    for (change, restore) in [
        ("UPDATE package_activations SET active = false", "UPDATE package_activations SET active = true"),
        ("UPDATE package_activations SET revision = 'wrong'", "UPDATE package_activations SET revision = 'v1'"),
        ("UPDATE package_results SET stale = true", "UPDATE package_results SET stale = false"),
        ("DELETE FROM package_heads", "INSERT INTO package_heads SELECT tenant_id, scope_id, package_id, export_name, window_id, result_id FROM package_results"),
        ("UPDATE package_activations SET result_id = 'missing'", "UPDATE package_activations SET result_id = 'first-1'"),
        ("UPDATE package_results SET scope_id = 'wrong'", "UPDATE package_results SET scope_id = 'scope'"),
    ] {
        fixture.store.writer()?.get_mut()?.execute(change, [])?;
        assert!(matches!(fixture.metadata(&fixture.selection, &fixture.reference),
            Err(crate::Error::Package { code: Code::Incomplete, .. })), "{change}");
        fixture.store.writer()?.get_mut()?.execute(restore, [])?;
        assert!(fixture.metadata(&fixture.selection, &fixture.reference).is_ok());
    }
    let mut wrong = fixture.reference.clone();
    wrong.revision = "v2".into();
    assert!(matches!(
        fixture.metadata(&fixture.selection, &wrong),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    Ok(())
}

#[test]
fn package_output_historical_scope() -> TestResult {
    let fixture = Fixture::new()?;
    let mut narrowed = AnalysisSelectionV1::new(
        fixture.selection.tenant_id,
        vec![crate::analysis::tests::identity()],
    );
    narrowed.received_until = std::ops::Bound::Included(100);
    let active = fixture
        .store
        .package_activation(&fixture.result.commit.activation.key)?
        .ok_or("active")?;
    let mut renewed = fixture.installed.clone();
    renewed.grant.selection = narrowed.clone();
    renewed.grant.revision += 1;
    fixture.store.renew_package(
        &active,
        &serde_json::to_vec(&renewed)?,
        "renewed",
        || Ok(()),
    )?;
    assert!(matches!(
        fixture.metadata(&narrowed, &fixture.reference),
        Err(crate::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    assert!(fixture
        .metadata(&fixture.selection, &fixture.reference)
        .is_ok());
    let foreign = AnalysisSelectionV1::tenant([9; 16]);
    assert!(matches!(
        fixture.metadata(&foreign, &fixture.reference),
        Err(crate::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    let page = fixture.read(
        &narrowed,
        &fixture.selection,
        std::slice::from_ref(&fixture.reference),
        AnalysisReadModeV1::Metadata,
        Default::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(
        page.extraction
            .references
            .iter()
            .find_map(AnalysisReferenceV1::result)
            .ok_or("result")?
            .result_id,
        "first-1"
    );
    Ok(())
}

#[test]
fn package_output_preflights_payload() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.store.writer()?.get_mut()?.execute(
        "UPDATE package_results SET datasets = ?",
        params![vec![b'x'; 32 * 1024]],
    )?;
    assert!(fixture
        .metadata(&fixture.selection, &fixture.reference)
        .is_ok());
    let result = fixture.read(
        &fixture.selection,
        &fixture.selection,
        std::slice::from_ref(&fixture.reference),
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits {
            input_bytes: 16 * 1024,
            ..Default::default()
        },
        &AnalysisReadControl::default(),
    );
    assert!(matches!(
        result,
        Err(crate::Error::AnalysisInputTooLarge {
            resource: "selected input bytes",
            ..
        })
    ));
    assert!(matches!(
        fixture.read(
            &fixture.selection,
            &fixture.selection,
            std::slice::from_ref(&fixture.reference),
            AnalysisReadModeV1::Complete,
            Default::default(),
            &AnalysisReadControl::default()
        ),
        Err(crate::Error::PackageEncoding { .. })
    ));
    Ok(())
}

#[test]
fn package_output_revocation() -> TestResult {
    use std::sync::atomic::{AtomicBool, Ordering};

    let fixture = Fixture::new()?;
    let control = Arc::new(AnalysisReadControl::default());
    let observed = Arc::new(AtomicBool::new(false));
    let revoked = Arc::clone(&control);
    let entered = Arc::clone(&observed);
    control.on_read_step(move || {
        entered.store(true, Ordering::Release);
        revoked.cancel()
    })?;
    let result = fixture.read(
        &fixture.selection,
        &fixture.selection,
        std::slice::from_ref(&fixture.reference),
        AnalysisReadModeV1::Complete,
        Default::default(),
        &control,
    );
    assert!(matches!(
        result,
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert!(observed.load(Ordering::Acquire));
    assert!(fixture
        .metadata(&fixture.selection, &fixture.reference)
        .is_ok());
    Ok(())
}

#[test]
fn reference_origins_merge() -> TestResult {
    let fixture = Fixture::new()?;
    let context = &fixture.result.commit.context_refs[0];
    let scope = crate::ProcessorScopeV1 {
        processor_id: "native-proof".into(),
        method_version: 1,
        identity: crate::analysis::tests::identity(),
    };
    fixture
        .store
        .register_processor(&scope, crate::ProcessorClassV1::Optional, 1)?;
    let mut witness = fixture.result.commit.witnesses[0].clone();
    witness.expires_utc_ns = 50;
    let native = fixture
        .store
        .commit_result(&crate::AnalysisResultCommitV1 {
            scope,
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 0,
            context_revision: context.commit_revision,
            result_id: "native-proof".into(),
            body: b"native".to_vec(),
            created_utc_ns: 1,
            witnesses: vec![witness.clone()],
            context_refs: vec![context.clone()],
        })?;
    let mut selection = fixture.selection.clone();
    selection.results = vec!["first-1".into(), "native-proof".into()];
    let requests = vec![fixture.reference.clone(), fixture.reference.clone()];
    let page = fixture.read(
        &selection,
        &fixture.selection,
        &requests,
        AnalysisReadModeV1::Metadata,
        Default::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(page.extraction.references.len(), 3);
    let context_entry = page
        .extraction
        .references
        .iter()
        .find(|entry| entry.context().is_some())
        .ok_or("context")?;
    assert_eq!(context_entry.context(), Some(context));
    assert_eq!(
        context_entry.origins(),
        &[
            AnalysisReferenceOriginV1::Context,
            AnalysisReferenceOriginV1::ExplicitResult,
            AnalysisReferenceOriginV1::Package(0),
            AnalysisReferenceOriginV1::Package(1),
        ]
    );
    let first = page
        .extraction
        .references
        .iter()
        .find(|entry| {
            entry
                .result()
                .is_some_and(|reference| reference.result_id == "first-1")
        })
        .ok_or("first")?;
    assert_eq!(
        first.origins(),
        &[
            AnalysisReferenceOriginV1::ExplicitResult,
            AnalysisReferenceOriginV1::Package(0),
            AnalysisReferenceOriginV1::Package(1),
        ]
    );
    let native_entry = page
        .extraction
        .references
        .iter()
        .find(|entry| {
            entry
                .result()
                .is_some_and(|reference| reference.result_id == "native-proof")
        })
        .ok_or("native")?;
    assert_eq!(
        native_entry.result().ok_or("native")?.commit_revision,
        native.commit_revision
    );
    assert_eq!(
        native_entry.origins(),
        &[AnalysisReferenceOriginV1::ExplicitResult]
    );
    assert_eq!(page.extraction.witnesses, vec![witness]);
    Ok(())
}
