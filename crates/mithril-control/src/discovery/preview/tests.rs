use std::{borrow::Cow, collections::BTreeMap, sync::Arc};

use araphor_analysis_builtins::{discovery as builtin, Rows};
use araphor_data::{
    AnalysisReadControl, AnalysisSelectionV1, AnalysisStore, BehaviorAtomKeyV1,
    DiscoveryPhysicalResultV1, DiscoveryProofKindV1, PackageArtifactV1, PackageBundleV1,
    PackageImplementationV1,
};
use araphor_discovery_definition::{Definition, Program, Source};
use araphor_query::definition::Invocation;
use araphor_query::execution::{Engine, Limits};
use erebor_interceptor_abi::KernelEffectFamilyV1;

use super::*;
use crate::{SimulatedDispositionV1, SimulatedPhysicalResultV1};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn input() -> TestResult<DiscoveryInputManifestV1> {
    Ok(DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )?)
}

struct Fixture {
    query: Arc<Engine>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let descriptor = builtin::Discovery::package();
        let exports = descriptor
            .exports
            .iter()
            .map(|model| model.name.clone())
            .collect();
        let bundle = PackageBundleV1 {
            schema_version: 1,
            root: araphor_data::PackageRefV1 {
                package_id: descriptor.id.clone(),
                revision: descriptor.revision.clone(),
            },
            artifacts: vec![PackageArtifactV1 {
                descriptor,
                implementations: vec![PackageImplementationV1::Wasm {
                    exports,
                    artifact: araphor_analysis_builtins::components::DISCOVERY.to_vec(),
                }],
                fixtures: Vec::new(),
            }],
        };
        store.install_package_image(
            input()?.tenant_id,
            &araphor_data::PackageBundle::try_from(bundle)?,
            || Ok(()),
        )?;
        Ok(Self {
            query: Engine::new(store, Limits::default())?,
            _directory: directory,
        })
    }

    async fn call(
        &self,
        input: &DiscoveryInputManifestV1,
    ) -> TestResult<(PackageCall, Arc<CallResult>)> {
        let records = input
            .records
            .iter()
            .map(|record| {
                let wire = record.decode()?;
                Ok(builtin::Record {
                    id: record.id.clone(),
                    bytes: Cow::Borrowed(&record.wire_record),
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
            })
            .collect::<TestResult<Vec<_>>>()?;
        let contexts = input
            .contexts
            .iter()
            .map(|context| {
                let record = input
                    .records
                    .iter()
                    .find(|record| record.id == context.record_id)
                    .ok_or("recorded context source is absent")?;
                let wire = record.decode()?;
                Ok(builtin::Context {
                    record_id: context.record_id.clone(),
                    atom_key: Some(BehaviorAtomKeyV1 {
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
                    }),
                })
            })
            .collect::<TestResult<Vec<_>>>()?;
        let descriptor = builtin::Discovery::package();
        let model = descriptor
            .exports
            .iter()
            .find(|model| model.name == "atoms")
            .ok_or("recorded export is absent")?;
        let port = |name: &str| {
            model
                .inputs
                .iter()
                .find(|input| input.port.name == name)
                .map(|input| &input.port)
                .ok_or("recorded input port is absent")
        };
        let inputs = [
            builtin::Record::encode(&records)?,
            Rows::encode(port("contexts")?, &contexts)?,
            Rows::encode(port("exclusions")?, &input.exclusions)?,
            Rows::encode(port("coverage")?, &input.coverage)?,
            Rows::encode(port("lifecycle")?, &input.lifecycle)?,
            Rows::encode(
                port("observed")?,
                &[input.proof_kind == DiscoveryProofKindV1::ObservedRuntime],
            )?,
        ];
        let mut session = self.query.session(
            AnalysisSelectionV1::tenant(input.tenant_id),
            &AnalysisReadControl::default(),
            0,
        )?;
        let mut arguments = Vec::new();
        for data in inputs {
            let name = format!("preview_{}", data.name);
            session.register(
                &name,
                Arc::new(port(&data.name)?.schema.clone()),
                &data.batches,
            )?;
            arguments.push(format!("{} => (SELECT * FROM {name})", data.name));
        }
        let definition = Definition {
            name: "recorded-preview".into(),
            description: String::new(),
            labels: BTreeMap::new(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: format!(
                        "SELECT * FROM discovery.\"1\".atoms('atoms', {})",
                        arguments.join(", ")
                    ),
                },
            },
        };
        let prepared = session.prepare_definition(&definition).await?;
        let mut call = None;
        PackageCall::any(&prepared.plan, &mut |found| {
            assert!(call.replace(found.clone()).is_none());
            Ok(false)
        })?;
        let call = call.ok_or("recorded call is absent")?;
        let mut output = session
            .execute_definition(&prepared, Invocation::default())
            .await?;
        let result = output
            .calls
            .remove(&call.id())
            .ok_or("recorded result is absent")?;
        assert!(output.calls.is_empty());
        assert!(result.belongs_to(&call));
        Ok((call, result))
    }
}

#[tokio::test]
async fn discovery_preview_native_compiler() -> TestResult<()> {
    let policy = PolicyDocumentV1::parse(
        std::path::Path::new("policy-v1.yaml"),
        include_bytes!("../../../tests/fixtures/policy-v1.yaml"),
    )?;
    let fixture = Fixture::new()?;
    let input = input()?;
    let (call, result) = fixture.call(&input).await?;
    let preview = DiscoveryStaticPreviewV1::recorded(&input, &policy, &call, &result)?;
    assert_eq!(preview.simulations.len(), 1);
    assert_eq!(preview.snapshot.unresolved_records, 1);
    assert_eq!(
        preview.simulations[0].disposition,
        SimulatedDispositionV1::WouldDeny
    );
    assert_eq!(
        preview.simulations[0].physical_result,
        SimulatedPhysicalResultV1::NotAttempted
    );
    Ok(())
}

#[tokio::test]
async fn discovery_preview_family_rejection() -> TestResult<()> {
    let policy = PolicyDocumentV1::parse(
        std::path::Path::new("policy-v1.yaml"),
        include_bytes!("../../../tests/fixtures/policy-v1.yaml"),
    )?;
    let mut input = input()?;
    let operation = crate::CompiledOperationV1::try_from("CONNECT")?;
    for context in &mut input.contexts {
        context.static_key.effect_family = KernelEffectFamilyV1::Network as u16;
        context.static_key.operation_id = "CONNECT".into();
        context.static_key.operation = operation.kernel_id as u16;
    }
    for record in &mut input.records {
        let mut wire = record.decode()?;
        wire.effect_family = KernelEffectFamilyV1::Network as u32;
        wire.operation = operation.kernel_id as u32;
        record.wire_record = Vec::<u8>::try_from(&wire)?;
    }
    let fixture = Fixture::new()?;
    let (call, result) = fixture.call(&input).await?;
    assert!(matches!(
        DiscoveryStaticPreviewV1::recorded(&input, &policy, &call, &result),
        Err(crate::Error::Discovery {
            code: "STATIC_FAMILY_UNSUPPORTED",
            ..
        })
    ));
    Ok(())
}

#[tokio::test]
async fn discovery_preview_native_lowering() -> TestResult<()> {
    let mut spec = crate::WorkloadProtectionPolicySpec::parse(
        std::path::Path::new("kubernetes-entry-roles-v1.yaml"),
        include_bytes!("../../../tests/fixtures/kubernetes-entry-roles-v1.yaml"),
    )?;
    spec.roles[0].files[0].recursive = false;
    let mut resource = crate::policy_custom_resource("worker", "tenant-a", spec)?;
    resource.metadata.uid = Some("30000000-0000-4000-8000-000000000001".into());
    resource.metadata.generation = Some(1);
    let policy = crate::lower_kubernetes_policy(
        &resource,
        "10000000-0000-4000-8000-000000000001",
        "10000000-0000-4000-8000-000000000002",
        "10000000-0000-4000-8000-000000000003",
    )?;
    let compiled = PolicyCompiler.compile(&policy)?;
    let key = compiled
        .compiled_cells
        .iter()
        .find(|cell| {
            cell.key.effect_family == EffectFamilyV1::File
                && cell.key.operation_id == "OPEN_READ"
                && cell.key.entry_kind == crate::EntryKindV1::ContainerStart
        })
        .ok_or("lowered exact file key is absent")?;
    assert!(key.key.object_selector.starts_with("PATH:"));
    let mut input = input()?;
    for context in &mut input.contexts {
        context.static_key = araphor_data::DiscoveryPolicyKeyV1::try_from(&key.key)?;
    }
    let fixture = Fixture::new()?;
    let (call, result) = fixture.call(&input).await?;
    let preview = DiscoveryStaticPreviewV1::recorded(&input, &policy, &call, &result)?;
    assert_eq!(preview.source_policy_digest, compiled.source_policy_digest);
    assert_eq!(preview.simulations.len(), 1);
    assert_eq!(
        preview.simulations[0].disposition,
        SimulatedDispositionV1::Deny
    );
    assert_eq!(
        preview.simulations[0].physical_result,
        SimulatedPhysicalResultV1::NotAttempted
    );
    Ok(())
}

#[tokio::test]
async fn preview_binds_execution() -> TestResult {
    let fixture = Fixture::new()?;
    let input = input()?;
    let policy = PolicyDocumentV1::parse(
        std::path::Path::new("policy-v1.yaml"),
        include_bytes!("../../../tests/fixtures/policy-v1.yaml"),
    )?;
    let (call, result) = fixture.call(&input).await?;
    let (other, _) = fixture.call(&input).await?;
    assert!(DiscoveryStaticPreviewV1::recorded(&input, &policy, &other, &result).is_err());
    for change in 0..3 {
        let mut changed = input.clone();
        match change {
            0 => changed.tenant_id = [99; 16],
            1 => changed.records[0].id.stream.source_id = [99; 16],
            _ => changed.records[0].wire_record.push(0),
        }
        assert!(DiscoveryStaticPreviewV1::recorded(&changed, &policy, &call, &result).is_err());
    }
    let preview = DiscoveryStaticPreviewV1::recorded(&input, &policy, &call, &result)?;
    assert_eq!(preview.snapshot.accepted_records, 3);
    assert!(preview
        .simulations
        .iter()
        .all(|result| { result.physical_result == SimulatedPhysicalResultV1::NotAttempted }));
    Ok(())
}

#[tokio::test]
async fn preview_denies_dynamic_exception() -> TestResult {
    let fixture = Fixture::new()?;
    let input = input()?;
    let (call, result) = fixture.call(&input).await?;
    let mut policy = PolicyDocumentV1::parse(
        std::path::Path::new("policy-v1.yaml"),
        include_bytes!("../../../tests/fixtures/policy-v1.yaml"),
    )?;
    policy.rollout.desired_profile_mode = crate::ProfileModeV1::Protect;
    policy
        .file_exception_grants
        .push(crate::FileExceptionGrantTemplateV1 {
            grant_id: "recorded-open".into(),
            denied_file_rule_ids: vec![policy.rules[0].rule_id.clone()],
            maximum_duration_ns: 1,
            maximum_uses: 1,
        });
    assert!(PolicyCompiler
        .compile(&policy)?
        .compiled_cells
        .iter()
        .any(|cell| cell.consuming_exception_id.is_some()));
    assert!(matches!(
        DiscoveryStaticPreviewV1::recorded(&input, &policy, &call, &result),
        Err(crate::Error::Discovery {
            code: "DYNAMIC_EXCEPTION_UNSUPPORTED",
            ..
        })
    ));
    Ok(())
}
