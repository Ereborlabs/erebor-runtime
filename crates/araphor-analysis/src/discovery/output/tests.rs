use super::*;

use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_builtins::discovery as builtin;
use araphor_analysis_sdk as sdk;
use araphor_data::*;
use araphor_discovery_definition::{Definition, Program, Source};
use araphor_package::{PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRefV1};
use araphor_query::definition::Invocation;
use araphor_query::execution::{Engine, Limits};
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::logical_expr::LogicalPlan;
use serde::Serialize;

mod baseline;
mod corpus;
mod forged;
mod native;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy)]
enum Target {
    Wasm,
    Native,
}

struct Fixture {
    query: Arc<Engine>,
    bundle: PackageBundleV1,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        Self::target(Target::Wasm, Limits::default())
    }

    fn target(target: Target, limits: Limits) -> TestResult<Self> {
        let descriptor = builtin::Discovery::package();
        let exports = descriptor
            .exports
            .iter()
            .map(|model| model.name.clone())
            .collect::<Vec<_>>();
        let implementation = match target {
            Target::Wasm => PackageImplementationV1::Wasm {
                exports,
                artifact: araphor_analysis_builtins::components::DISCOVERY.to_vec(),
            },
            Target::Native => {
                let directory = std::env::var_os("ARAPHOR_NATIVE_DIR")
                    .ok_or("ARAPHOR_NATIVE_DIR is required")?;
                let artifact = std::fs::read(
                    std::path::PathBuf::from(directory)
                        .join(format!("discovery.{}", std::env::consts::DLL_EXTENSION)),
                )?;
                let qualification = araphor_package::Qualification::inspect(
                    &artifact,
                    exports,
                    std::env::var("ARAPHOR_NATIVE_TARGET")?,
                )?;
                PackageImplementationV1::Native {
                    export: "atoms".into(),
                    artifact,
                    qualification: Some(qualification),
                }
            }
        };
        assert_eq!(
            implementation.target(),
            match target {
                Target::Wasm => "wasm",
                Target::Native => "native",
            }
        );
        let identity = implementation.identity()?.ok_or("artifact identity")?;
        assert!(!identity.digest.is_empty());
        assert_eq!(
            identity.closure_digest.is_some(),
            matches!(target, Target::Native)
        );
        assert_eq!(
            identity.platform.is_some(),
            matches!(target, Target::Native)
        );
        let bundle = PackageBundleV1 {
            schema_version: 1,
            root: PackageRefV1 {
                package_id: descriptor.id.clone(),
                revision: descriptor.revision.clone(),
            },
            artifacts: vec![PackageArtifactV1 {
                implementations: vec![implementation],
                descriptor,
                fixtures: Vec::new(),
            }],
        };
        Self::installed(bundle, limits)
    }

    fn installed(bundle: PackageBundleV1, limits: Limits) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        store.install_package_image(
            Self::input()?.tenant_id,
            &araphor_package::PackageBundle::try_from(bundle.clone())?,
            || Ok(()),
        )?;
        Ok(Self {
            query: Engine::new(store, limits)?,
            bundle,
            _directory: directory,
        })
    }

    fn passthrough(call: &PackageCall) -> TestResult<Self> {
        let ports = call
            .descriptor()
            .exports
            .iter()
            .find(|model| model.name == call.export())
            .ok_or("export")?
            .outputs
            .clone();
        let outputs = ports
            .iter()
            .map(|port| {
                let projection = port
                    .schema
                    .fields()
                    .iter()
                    .map(|field| format!("\"{}\"", field.name()))
                    .collect::<Vec<_>>()
                    .join(", ");
                (
                    port.name.clone(),
                    format!("SELECT {projection} FROM \"{}\"", port.name),
                )
            })
            .collect();
        let descriptor = sdk::Package::new(
            "typed-result",
            "1",
            vec![sdk::Model::new(call.export(), ports.clone(), ports)],
        );
        Self::installed(
            PackageBundleV1 {
                schema_version: 1,
                root: PackageRefV1 {
                    package_id: descriptor.id.clone(),
                    revision: descriptor.revision.clone(),
                },
                artifacts: vec![PackageArtifactV1 {
                    descriptor,
                    implementations: vec![PackageImplementationV1::Sql {
                        export: call.export().into(),
                        program: araphor_package::SqlModelV1 {
                            outputs,
                            ..Default::default()
                        },
                    }],
                    fixtures: Vec::new(),
                }],
            },
            Limits::default(),
        )
    }

    fn input() -> araphor_data::Result<DiscoveryInputManifestV1> {
        DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
        )
    }

    fn data<T: Serialize>(export: &str, name: &str, rows: &[T]) -> TestResult<sdk::Dataset> {
        let descriptor = builtin::Discovery::package();
        let model = descriptor
            .exports
            .iter()
            .find(|model| model.name == export)
            .ok_or("export")?;
        let port = &model
            .inputs
            .iter()
            .find(|input| input.port.name == name)
            .ok_or("input")?
            .port;
        Ok(Rows::encode(port, rows)?)
    }

    async fn call(
        &self,
        export: &str,
        inputs: Vec<sdk::Dataset>,
    ) -> TestResult<(PackageCall, Arc<CallResult>)> {
        let descriptor = &self.bundle.artifacts[0].descriptor;
        let model = descriptor
            .exports
            .iter()
            .find(|model| model.name == export)
            .ok_or("export")?;
        let control = AnalysisReadControl::default();
        let mut session = self.query.session(
            AnalysisSelectionV1::tenant(Self::input()?.tenant_id),
            &control,
            0,
        )?;
        for (index, data) in inputs.iter().enumerate() {
            let port = &model
                .inputs
                .iter()
                .find(|input| input.port.name == data.name)
                .ok_or("input")?
                .port;
            session.register(
                &format!("__result_input_{index}"),
                Arc::new(port.schema.clone()),
                &data.batches,
            )?;
        }
        let output = model.outputs.first().ok_or("output selector")?;
        let selector =
            datafusion::sql::sqlparser::ast::Value::SingleQuotedString(output.name.clone())
                .to_string();
        let args = std::iter::once(selector)
            .chain(inputs.iter().enumerate().map(|(index, data)| {
                format!("{} => (SELECT * FROM __result_input_{index})", data.name)
            }))
            .collect::<Vec<_>>()
            .join(", ");
        let definition = Definition {
            name: "discovery-result".into(),
            description: String::new(),
            labels: BTreeMap::new(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: format!(
                        "SELECT * FROM \"{}\".\"{}\".\"{export}\"({args})",
                        self.bundle.root.package_id, self.bundle.root.revision
                    ),
                },
            },
        };
        let prepared = session.prepare_definition(&definition).await?;
        let mut calls = Vec::new();
        prepared.plan.apply_with_subqueries(|plan| {
            if let LogicalPlan::Extension(extension) = plan {
                if let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() {
                    calls.push(call.clone());
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        assert_eq!(calls.len(), 1);
        let call = calls.remove(0);
        let mut output = session
            .execute_definition(&prepared, Invocation::default())
            .await?;
        let result = output.calls.remove(&call.id()).ok_or("call return")?;
        assert!(output.calls.is_empty());
        assert!(result.belongs_to(&call));
        assert_eq!(call.descriptor(), descriptor);
        assert_eq!(call.package(), &self.bundle.root);
        assert_eq!(call.image().image, self.bundle.root);
        assert_eq!(call.image().digest, self.bundle.digest()?);
        let implementation = self
            .bundle
            .artifact(call.package())?
            .implementation(export)?;
        assert!(matches!(implementation.target(), "sql" | "wasm" | "native"));
        assert_eq!(
            implementation.identity()?.is_some(),
            implementation.target() != "sql"
        );
        let evaluation = result.evaluation();
        assert_eq!(evaluation.export, export);
        assert!(!evaluation.context.id.is_empty());
        assert_eq!(evaluation.context.time_utc_ns, 0);
        assert_eq!(evaluation.context.seed, None);
        assert!(evaluation.parameters.is_none());
        assert!(evaluation.checkpoint.is_none());
        assert_eq!(evaluation.inputs.len(), inputs.len());
        for expected in &inputs {
            let actual = evaluation.input(&expected.name)?;
            let schema = Arc::new(
                model
                    .inputs
                    .iter()
                    .find(|input| input.port.name == expected.name)
                    .ok_or("input")?
                    .port
                    .schema
                    .clone(),
            );
            let expected = datafusion::arrow::compute::concat_batches(&schema, &expected.batches)?;
            // Query sets the native batch size to 200 rows.
            let expected = if expected.num_rows() == 0 {
                vec![expected]
            } else {
                (0..expected.num_rows())
                    .step_by(200)
                    .map(|offset| expected.slice(offset, (expected.num_rows() - offset).min(200)))
                    .collect::<Vec<_>>()
            };
            assert_eq!(actual.data.batches, expected);
            assert!(!actual.revision.owner.is_empty());
            assert!(!actual.revision.id.is_empty());
        }
        let returned = result.output();
        descriptor
            .check_evaluation(evaluation)?
            .validate_output(returned)?;
        assert_eq!(returned.datasets.len(), model.outputs.len());
        assert_eq!(
            returned
                .datasets
                .iter()
                .map(|data| &data.name)
                .collect::<std::collections::BTreeSet<_>>(),
            model
                .outputs
                .iter()
                .map(|port| &port.name)
                .collect::<std::collections::BTreeSet<_>>()
        );
        assert!(returned.evidence.is_empty());
        assert!(returned.reasons.is_empty());
        assert!(returned.checkpoint.is_none());
        if implementation.target() != "sql" {
            let expected = builtin::Discovery::evaluate(evaluation)?;
            assert_eq!(
                serde_json::to_value(sdk::wire::Output::encode(
                    descriptor, evaluation, &expected
                )?)?,
                serde_json::to_value(sdk::wire::Output::encode(descriptor, evaluation, returned)?)?
            );
        }
        Ok((call, result))
    }

    async fn recorded(
        &self,
        input: &DiscoveryInputManifestV1,
    ) -> TestResult<DiscoveryRecordedResultV1> {
        let (call, result) = self.atoms(input).await?;
        Ok(DiscoveryOwner::recorded_result(input, &call, &result)?)
    }

    async fn atoms(
        &self,
        input: &DiscoveryInputManifestV1,
    ) -> TestResult<(PackageCall, Arc<CallResult>)> {
        let records = input
            .records
            .iter()
            .map(Self::record)
            .collect::<TestResult<Vec<_>>>()?;
        let contexts = input
            .contexts
            .iter()
            .map(|context| {
                let record = input
                    .records
                    .iter()
                    .find(|record| record.id == context.record_id);
                Ok(builtin::Context {
                    record_id: context.record_id.clone(),
                    atom_key: record
                        .map(|record| Self::key(input, record, context))
                        .transpose()?,
                })
            })
            .collect::<TestResult<Vec<_>>>()?;
        self.call(
            "atoms",
            vec![
                builtin::Record::encode(&records)?,
                Self::data("atoms", "contexts", &contexts)?,
                Self::data("atoms", "exclusions", &input.exclusions)?,
                Self::data("atoms", "coverage", &input.coverage)?,
                Self::data("atoms", "lifecycle", &input.lifecycle)?,
                Self::data(
                    "atoms",
                    "observed",
                    &[input.proof_kind == DiscoveryProofKindV1::ObservedRuntime],
                )?,
            ],
        )
        .await
    }

    fn record(record: &DiscoveryRecordV1) -> TestResult<builtin::Record<'_>> {
        let wire = record.decode()?;
        Ok(builtin::Record {
            id: record.id.clone(),
            bytes: std::borrow::Cow::Borrowed(&record.wire_record),
            temporal: wire.temporal_coverage,
            effect: (&wire).into(),
            generation: wire.profile_generation_ref_id,
            original_sequence: record.original_kernel_sequence,
            source: wire
                .decision_context
                .as_ref()
                .map(|source| builtin::Lifetime {
                    process: source.process_instance_id.clone(),
                    entry: source.entry_instance_id.clone(),
                    binding: source.binding_id.clone(),
                    role: source.role_id,
                    state: source.state_id,
                    rule: source.entry_rule_id,
                    sequence: source.original_kernel_sequence,
                }),
        })
    }

    fn key(
        input: &DiscoveryInputManifestV1,
        record: &DiscoveryRecordV1,
        context: &DiscoveryContextBindingV1,
    ) -> TestResult<BehaviorAtomKeyV1> {
        let wire = record.decode()?;
        Ok(BehaviorAtomKeyV1 {
            stream: record.id.stream.clone(),
            cpu_id: record.id.cpu_id,
            subject_revision: context.subject_revision.clone(),
            image_digest: context.image_digest.clone(),
            configuration_digest: context.configuration_digest.clone(),
            process_instance_id: context.process_instance_id,
            entry_instance_id: context.entry_instance_id,
            binding_id: context.binding_id,
            role_id: context.role_id,
            state_id: context.state_id,
            entry_rule_id: context.entry_rule_id,
            catalog_revision: context.catalog_revision,
            static_key: context.static_key.clone(),
            policy_revision: context.policy_revision.clone(),
            generation: wire.profile_generation_ref_id.unwrap_or_default(),
            coverage_interval_id: wire.coverage_interval_id.as_ref().try_into()?,
            temporal_coverage: wire.temporal_coverage,
            effect: (&wire).into(),
            physical_result: DiscoveryPhysicalResultV1::Unknown,
            proof_kind: input.proof_kind,
        })
    }

    fn sides<T: Clone>(values: [&[T]; 2]) -> Vec<builtin::Side<T>> {
        values
            .into_iter()
            .enumerate()
            .flat_map(|(side, values)| {
                values.iter().cloned().map(move |value| builtin::Side {
                    side: side as u8,
                    value,
                })
            })
            .collect()
    }

    async fn merged(
        &self,
        left: &BehaviorSnapshotV1,
        right: &BehaviorSnapshotV1,
    ) -> TestResult<BehaviorSnapshotV1> {
        let metadata = [left, right].map(|snapshot| builtin::Snapshot {
            tenant_id: snapshot.tenant_id,
            source_revision: snapshot.source_revision.clone(),
            proof_kind: snapshot.proof_kind,
            counts: builtin::Counts {
                duplicates: 0,
                accepted: snapshot.accepted_records,
                included: snapshot.included_records,
                unresolved: snapshot.unresolved_records,
                excluded: snapshot.excluded_records,
            },
        });
        let (call, result) = self
            .call(
                "merge",
                vec![
                    Self::data("merge", "snapshots", &metadata)?,
                    Self::data("merge", "atoms", &Self::sides([&left.atoms, &right.atoms]))?,
                    Self::data(
                        "merge",
                        "coverage",
                        &Self::sides([&left.coverage, &right.coverage]),
                    )?,
                    Self::data(
                        "merge",
                        "unresolved",
                        &Self::sides([&left.unresolved, &right.unresolved]),
                    )?,
                    Self::data(
                        "merge",
                        "excluded",
                        &Self::sides([&left.excluded, &right.excluded]),
                    )?,
                    Self::data(
                        "merge",
                        "lifecycle",
                        &Self::sides([&left.lifecycle, &right.lifecycle]),
                    )?,
                ],
            )
            .await?;
        Ok(DiscoveryOwner::merge_result(left, right, &call, &result)?)
    }

    async fn groups(
        &self,
        snapshot: &BehaviorSnapshotV1,
    ) -> TestResult<Vec<BehaviorDisplayGroupV1>> {
        let (call, result) = self
            .call(
                "groups",
                vec![
                    Self::data("groups", "atoms", &snapshot.atoms)?,
                    Self::data("groups", "coverage", &snapshot.coverage)?,
                ],
            )
            .await?;
        Ok(DiscoveryOwner::group_result(snapshot, &call, &result)?)
    }

    async fn comparison(
        &self,
        current: &BehaviorSnapshotV1,
        baseline: &DiscoveryReviewedBaselineV1,
    ) -> TestResult<DiscoveryComparisonV1> {
        let groups = self.groups(current).await?;
        let prior = self.groups(&baseline.snapshot).await?;
        let resources = [current, &baseline.snapshot].map(|snapshot| {
            snapshot
                .atoms
                .iter()
                .map(|atom| atom.key.clone())
                .collect::<Vec<_>>()
        });
        let states = [current, &baseline.snapshot].map(|snapshot| builtin::MatchState {
            coverage: snapshot.coverage.clone(),
            lifecycle: snapshot.lifecycle.clone(),
        });
        let (call, result) = self
            .call(
                "compare",
                vec![
                    Self::data("compare", "groups", &Self::sides([&groups, &prior]))?,
                    Self::data(
                        "compare",
                        "resources",
                        &Self::sides([&resources[0], &resources[1]]),
                    )?,
                    Self::data("compare", "forbidden", &baseline.forbidden)?,
                    Self::data("compare", "states", &states)?,
                ],
            )
            .await?;
        Ok(DiscoveryOwner::comparison_result(
            current, baseline, &groups, &prior, &call, &result,
        )?)
    }
}
