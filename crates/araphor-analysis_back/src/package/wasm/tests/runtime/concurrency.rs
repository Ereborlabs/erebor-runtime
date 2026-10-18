use std::sync::{mpsc, Arc};
use std::time::Duration;

use araphor_analysis_builtins::{discovery as builtin, Rows};
use araphor_analysis_sdk as sdk;

use crate::package::wasm::execution::GuestEntry;
use crate::{AnalysisReadControl, InstalledAnalysis, PackageErrorCodeV1 as Code};

use super::TestResult;

fn input(tenant: u8, counts: [u64; 2]) -> sdk::Result<sdk::Evaluation> {
    let limits = sdk::Limits {
        max_batches: 4,
        max_rows: 16,
        max_bytes: 1024 * 1024,
        max_checkpoint_bytes: 1024 * 1024,
    };
    let atoms: Vec<_> = counts
        .into_iter()
        .enumerate()
        .map(|(index, count)| {
            let key = atom_key(tenant, index);
            builtin::BehaviorAtomV1 {
                evidence_sample: vec![builtin::DiscoveryRecordIdV1 {
                    stream: key.stream.clone(),
                    cpu_id: u32::from(tenant),
                    durable_cursor: index as u64 + 1,
                }],
                key,
                count,
                first_cursor: index as u64 + 1,
                last_cursor: index as u64 + 1,
            }
        })
        .collect();
    let datasets = vec![
        Rows::encode(
            &builtin::Discovery::port::<builtin::BehaviorAtomV1>("atoms"),
            &atoms,
            limits,
        )?,
        Rows::encode::<builtin::DiscoveryCoverageV1>(
            &builtin::Discovery::port::<builtin::DiscoveryCoverageV1>("coverage"),
            &[],
            limits,
        )?,
    ];
    Ok(sdk::Evaluation {
        export: "groups".into(),
        inputs: datasets
            .into_iter()
            .map(|data| sdk::Input {
                data,
                revision: sdk::Revision {
                    owner: "concurrency-fixture".into(),
                    id: format!("tenant-{tenant}"),
                    window: None,
                },
                coverage: sdk::Coverage {
                    state: sdk::CoverageState::Complete,
                    limits: Vec::new(),
                },
            })
            .collect(),
        checkpoint: None,
        parameters: None,
        context: sdk::EvaluationContext {
            id: format!("tenant-{tenant}"),
            time_utc_ns: 123,
            seed: None,
            limits,
        },
    })
}

fn assert_group(result: &crate::InstalledEvaluation, tenant: u8, count: u64) -> TestResult {
    assert_eq!(result.evaluation.context.id, format!("tenant-{tenant}"));
    assert_eq!(result.output.datasets.len(), 1);
    let groups: Vec<builtin::BehaviorDisplayGroupV1> = Rows::decode(
        &builtin::Discovery::port::<builtin::BehaviorDisplayGroupV1>("groups"),
        &result.output.datasets[0],
        result.evaluation.context.limits,
    )?;
    assert_eq!(groups.len(), 1);
    assert_eq!(
        groups[0].key,
        builtin::BehaviorDisplayKeyV1::from(&atom_key(tenant, 0))
    );
    assert_eq!(groups[0].count, count);
    assert_eq!(
        groups[0].members,
        [atom_key(tenant, 0), atom_key(tenant, 1)]
    );
    assert_eq!(
        groups[0].evidence_sample,
        [1, 2].map(|cursor| builtin::DiscoveryRecordIdV1 {
            stream: atom_key(tenant, 0).stream,
            cpu_id: u32::from(tenant),
            durable_cursor: cursor,
        })
    );
    assert!(groups[0].coverage.is_empty());
    assert!(result.output.checkpoint.is_none());
    assert!(result.output.evidence.is_empty());
    assert!(result.output.reasons.is_empty());
    Ok(())
}

#[test]
fn installed_guests_overlap() -> TestResult {
    let execution = InstalledAnalysis::testing_tenants(None, &[[1; 16], [2; 16]])?;
    let owner = execution.testing_owner();
    let first = execution.snapshot([1; 16])?;
    let second = execution.snapshot([2; 16])?;
    assert!(Arc::ptr_eq(&owner, &first.testing_owner()));
    assert!(Arc::ptr_eq(&owner, &second.testing_owner()));
    let first_input = input(1, [2, 3])?;
    let second_input = input(2, [7, 11])?;
    let first_control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let second_control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    std::thread::scope(|scope| -> TestResult {
        let (entered, first_ready) = mpsc::channel();
        let (first_release, release) = mpsc::channel();
        *owner
            .wasm
            .entered
            .lock()
            .map_err(|_| Code::Incomplete.error("component test gate"))? = Some(GuestEntry {
            entered,
            release: Some(release),
        });
        let first =
            scope.spawn(|| first.evaluate([1; 16], "discovery", &first_input, &first_control));
        first_ready.recv_timeout(Duration::from_secs(5))?;

        let (entered, second_ready) = mpsc::channel();
        let (second_release, release) = mpsc::channel();
        *owner
            .wasm
            .entered
            .lock()
            .map_err(|_| Code::Incomplete.error("component test gate"))? = Some(GuestEntry {
            entered,
            release: Some(release),
        });
        let second =
            scope.spawn(|| second.evaluate([2; 16], "discovery", &second_input, &second_control));
        second_ready.recv_timeout(Duration::from_secs(5))?;

        first_release.send(())?;
        second_release.send(())?;
        let first = first
            .join()
            .map_err(|_| Code::Incomplete.error("component concurrency worker"))??;
        let second = second
            .join()
            .map_err(|_| Code::Incomplete.error("component concurrency worker"))??;
        assert_group(&first, 1, 5)?;
        assert_group(&second, 2, 18)?;
        Ok(())
    })
}

fn atom_key(tenant: u8, index: usize) -> builtin::BehaviorAtomKeyV1 {
    use builtin::*;
    BehaviorAtomKeyV1 {
        stream: EvidenceIntakeIdentityV1 {
            tenant_id: [tenant; 16],
            node_id: format!("node-{tenant}"),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        },
        cpu_id: u32::from(tenant),
        subject_revision: format!("tenant-{tenant}"),
        image_digest: "image".into(),
        configuration_digest: "config".into(),
        process_instance_id: [1; 16],
        entry_instance_id: [2; 16],
        binding_id: [3; 16],
        role_id: 1,
        state_id: 1,
        entry_rule_id: 1,
        catalog_revision: 1,
        static_key: DiscoveryPolicyKeyV1 {
            workload_selector_id: "workload".into(),
            protected_scope_id: "scope".into(),
            execution_set_id: "execution".into(),
            entry_kind: "entry".into(),
            role_id: "role".into(),
            process_state_id: "state".into(),
            effect_family: 1,
            operation_id: "operation".into(),
            operation: 1,
            operation_argument: 0,
            argument_wildcard: false,
            object_selector: "object".into(),
            binding_lifecycle: "lifecycle".into(),
        },
        policy_revision: DiscoveryPolicyRevisionV1 {
            profile_id: "profile".into(),
            profile_version: 1,
            source_revision_id: "source".into(),
            signed_profile_digest: "digest".into(),
        },
        generation: index as u64 + 1,
        coverage_interval_id: [4; 16],
        temporal_coverage: 1,
        effect: DiscoveryEffectKeyV1 {
            task_cookie: 7,
            target_task_cookie: None,
            process_lineage_id: Vec::new(),
            authority_domain_id: Vec::new(),
            execution_set_id: Vec::new(),
            exact_object_id: vec![7; 16],
            destination_id: 0,
            policy_rule_id: 1,
            reason: 0,
            decision: 1,
            effect_family: 1,
            operation: 1,
            operation_argument: Some(0),
            configured_errno: -13,
            kernel_result: -13,
            exact_file_object: None,
        },
        physical_result: DiscoveryPhysicalResultV1::Unknown,
        proof_kind: DiscoveryProofKindV1::RecordedInput,
    }
}
