use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::{
    analysis::{
        native::{ManagedCommit, ManagedReturn},
        PackageResultRefV1, PreparedProfile, ProfileCommit,
    },
    AnalysisExtractLimits, AnalysisReadControl, AnalysisReadModeV1, AnalysisResultCommitV1,
    AnalysisResultReceiptV1, AnalysisSelectionV1, AnalysisTableRead, DiscoveryProfileV1,
    ManagedCall, ManagedDestination, ManagedFrontier, ManagedManifest, ManagedRead, ManagedRequest,
    ManagedSpec, PackageArtifactV1, PackageBundle, PackageBundleV1, PackageGrantV1,
    PackageImplementationV1, SqlModelV1,
};
use araphor_discovery_definition::{Definition, ImagePin, Program, ResolvedDefinition, Source};

use super::Fixture;

pub(super) struct ProfileWriter<'a> {
    fixture: &'a Fixture,
    model: sdk::Model,
}

impl<'a> ProfileWriter<'a> {
    pub(super) fn new(fixture: &'a Fixture) -> araphor_data::Result<Self> {
        let store = &fixture.store;
        let tenant = fixture.source.tenant_id;
        let schema = sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]);
        let model = sdk::Model::new(
            "count",
            Vec::new(),
            vec![sdk::Port::new("rows", schema.clone())],
        );
        let artifact = PackageArtifactV1 {
            descriptor: sdk::Package::new("profile-fixture", "1", vec![model.clone()]),
            implementations: vec![PackageImplementationV1::Sql {
                export: "count".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([(
                        "rows".into(),
                        "SELECT 1::BIGINT UNSIGNED AS count".into(),
                    )]),
                    ..Default::default()
                },
            }],
            fixtures: Vec::new(),
        };
        let image = PackageBundle::try_from(PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        })?;
        store.install_package_image(tenant, &image, || Ok(()))?;
        let pin = ImagePin {
            image: image.bundle().root.clone(),
            digest: image.digest().into(),
        };
        let sql = "SELECT * FROM \"profile-fixture\".\"1\".count()".to_owned();
        let definition = ResolvedDefinition::new(
            Definition {
                name: "profile".into(),
                description: String::new(),
                labels: BTreeMap::new(),
                program: Program::Sql {
                    source: Source::Inline {
                        inline: sql.clone(),
                    },
                },
            },
            sql,
            vec![pin.clone()],
        )?;
        let revision = store.admit_definition(tenant, &definition, || Ok(()))?;
        let instance = store.admit_managed(
            &ManagedSpec {
                tenant,
                id: "profile".into(),
                definition,
                manifest: ManagedManifest {
                    format: 1,
                    planner: "datafusion-55/sql-call-1".into(),
                    definition: revision,
                    calls: BTreeMap::from([(
                        10,
                        ManagedCall {
                            image: pin.clone(),
                            package: pin.image,
                            export: "count".into(),
                            arguments: Vec::new(),
                            target: "sql".into(),
                            artifact: None,
                            dependencies: Default::default(),
                        },
                    )]),
                    selected_schema: schema,
                },
                destination: ManagedDestination::DiscoveryProfile {
                    source: fixture.source.clone(),
                    call: 10,
                    output: "rows".into(),
                },
            },
            &PackageGrantV1 {
                principal: "profile-fixture".into(),
                revision: 1,
                selection: AnalysisSelectionV1::tenant(tenant),
                expires_utc_ns: None,
                authorization_id: Some("profile-fixture".into()),
            },
            || Ok(()),
        )?;
        store.set_managed_running(tenant, "profile", instance.lifecycle, true, || Ok(()))?;
        Ok(Self { fixture, model })
    }

    pub(super) fn publish(
        &self,
        profile: DiscoveryProfileV1,
        previous: Option<PackageResultRefV1>,
    ) -> Result<AnalysisResultReceiptV1, Box<dyn std::error::Error>> {
        let store = &self.fixture.store;
        let control = AnalysisReadControl::default();
        let resume = store.managed_resume(profile.scope.identity.tenant_id, "profile", &control)?;
        let requests = BTreeMap::from([(
            "discovery_state".into(),
            Some(
                (0..araphor_data::AnalysisStore::table_schemas()["discovery_state"]
                    .fields()
                    .len())
                    .collect(),
            ),
        )]);
        let selection = resume
            .instance
            .spec
            .destination
            .selection(&resume.instance.grant.selection)?
            .project(&requests)?;
        let now = profile.updated_utc_ns;
        let page = store.read_managed_tables_filtered(
            &selection,
            &ManagedRead {
                instance: resume.instance,
                expected: None,
                rebuild: false,
                follow: false,
                completed: Some(resume.completed),
                execution: None,
                source: None,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now,
            },
            AnalysisExtractLimits::default(),
            &control,
            None,
        )?;
        let cursor = crate::follow::Cursor::new(
            &page.page.extraction.meta,
            crate::follow::Operation::Replace,
            [0; 32],
            page.page.scanned_through,
            now,
        )
        .encode()?;
        let attempt = store.register_managed_attempt(
            &page.state,
            &ManagedRequest {
                id: profile.profile_id.clone(),
                time_utc_ns: now,
                seed: Some(7),
                rebuild: false,
                witness_expiry: u64::MAX,
                frontier: Some(ManagedFrontier {
                    cursor,
                    next_change: None,
                    pending: false,
                }),
            },
            || Ok(()),
        )?;
        let evaluation = sdk::Evaluation {
            export: "count".into(),
            inputs: Vec::new(),
            parameters: None,
            checkpoint: None,
            previous_outputs: Vec::new(),
            context: sdk::EvaluationContext {
                id: attempt.request().id.clone(),
                time_utc_ns: now as i64,
                seed: attempt.request().seed,
            },
        };
        let output = sdk::Output {
            datasets: vec![sdk::Dataset {
                name: "rows".into(),
                batches: vec![sdk::RecordBatch::try_new(
                    Arc::new(self.model.outputs[0].schema.clone()),
                    vec![Arc::new(sdk::arrow_array::UInt64Array::from(vec![1]))],
                )?],
            }],
            checkpoint: None,
            evidence: Vec::new(),
            reasons: Vec::new(),
        };
        let returns = [ManagedReturn {
            call: 10,
            evaluation: &evaluation,
            output: &output,
            changes: None,
            graph: None,
            retained: None,
        }];
        let budget = self
            .fixture
            .engine
            .memory()
            .managed_budget(&control, self.fixture.engine.limits().input_bytes);
        let input = ManagedCommit {
            control: &control,
            budget: budget.as_ref(),
            attempt: &attempt,
            completed: true,
            now_utc_ns: now,
            returns: &returns,
            selected: &output.datasets[0],
            selected_schema: &attempt.instance().spec.manifest.selected_schema,
        };
        let packet = ProfileCommit {
            request: AnalysisResultCommitV1 {
                scope: profile.scope.clone(),
                expected_cursor: 0,
                consumed_cursor: 0,
                coverage_revision: 0,
                context_revision: 0,
                result_id: profile.profile_id.clone(),
                body: Vec::new(),
                created_utc_ns: now,
                witnesses: Vec::new(),
                context_refs: Vec::new(),
            },
            profile: PreparedProfile::new(profile)?,
            previous: previous.clone(),
            head: previous,
            notice: None,
        };
        let (_, receipt) = store.commit_managed_profile(
            store.prepare_managed(&input)?,
            Some(packet),
            || Ok(()),
        )?;
        Ok(receipt.ok_or("profile receipt")?)
    }
}
