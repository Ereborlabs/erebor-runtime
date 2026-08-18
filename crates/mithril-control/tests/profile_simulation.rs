use std::collections::BTreeSet;
use std::path::Path;

use mithril_control::{
    BindingLifecycleV1, CompiledDecisionCellV1, CompiledOperationV1, CompiledPhysicalResultV1,
    EffectFamilyV1, EntryKindV1, HardSafetyConditionV1, NonPreventionReasonV1, PolicyCompiler,
    PolicyDocumentV1, PolicySimulator, SimulatedDispositionV1, SimulatedPhysicalResultV1,
    StaticDecisionKeyV1,
};
use serde::Deserialize;

const POLICY: &str = include_str!("fixtures/policy-v1.yaml");
const MATRIX: &str = include_str!("fixtures/profile-simulation.json");
const FIXTURE_REGISTRY: &str = include_str!("../../../spec/qualification/v1/fixtures.yaml");

const REQUIRED_ENFORCEMENT_FIXTURES: [&str; 38] = [
    "ADMIN-EXEC-APPROVAL-001",
    "DEVICE-DERIVED-001",
    "FILE-CONTENT-RACE-002",
    "FILE-FD-PASS-001",
    "FILE-IDENTITY-001",
    "FILE-MMAP-001",
    "FILE-MMAP-SHARED-011",
    "FILE-NAMESPACE-001",
    "FILE-SA-TOKEN-OPEN-001",
    "FILE-VMA-SNAPSHOT-001",
    "HF-LOCAL-001",
    "IPC-ASYNC-UNSUPPORTED-010",
    "IPC-PEER-RACE-004",
    "IPC-PROCESS-CHANNEL-009",
    "IPC-RELATIONSHIP-ALLOW-003",
    "IPC-RELATIONSHIP-UNMATCHED-005",
    "LSM-DENY-SATURATION-001",
    "MEM-EXEC-001",
    "MEM-KERNEL-MAP-002",
    "MOUNT-ATTR-001",
    "MOUNT-CAS-002",
    "MOUNT-PROPAGATION-003",
    "MOUNT-SNAPSHOT-004",
    "SELF-PROTECT-001",
    "STATE-PERSISTENT-FILE-LIFETIME-007",
    "FILE-DELEGATED-EGRESS-001",
    "HF-004-RESULT-001",
    "HF-011-READ-RESULT-001",
    "HF-NET-001",
    "IPC-LOCAL-INET-008",
    "NET-ACCEPT-PASS-001",
    "NET-DNS-EXFIL-001",
    "NET-NS-PASS-001",
    "NET-RECV-001",
    "NET-REWRITE-001",
    "NET-SHARED-RESPONSE-002",
    "NET-SOCKCTL-001",
    "NET-SOCKET-LIFE-001",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Matrix {
    schema_version: u32,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    case_id: String,
    fixture_id: String,
    actor: String,
    object: String,
    effect_family: EffectFamilyV1,
    operation_id: String,
    expected: Expected,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Expected {
    Allow,
    WouldDeny,
    HardDenyUnsupported,
    HardDenyAmbiguousTopology,
    HardDenyPriorLsm,
    UnresolvedNoCoveredEffect,
    UnresolvedOutsideAuthority,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRegistry {
    schema_version: u32,
    architecture_revision_sha256: String,
    fixture_ids: Vec<String>,
}

#[test]
fn observation_simulates_every_required_future_fixture_and_incident_branch(
) -> Result<(), Box<dyn std::error::Error>> {
    let matrix: Matrix = serde_json::from_str(MATRIX)?;
    let registry: FixtureRegistry = serde_json::from_str(FIXTURE_REGISTRY)?;
    assert_eq!(matrix.schema_version, 1);
    assert_eq!(registry.schema_version, 1);
    assert_eq!(registry.architecture_revision_sha256.len(), 64);

    let case_ids = matrix
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(case_ids.len(), matrix.cases.len(), "duplicate case IDs");

    let registered = registry
        .fixture_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let matrix_registered = matrix
        .cases
        .iter()
        .map(|case| case.fixture_id.as_str())
        .filter(|fixture| registered.contains(fixture))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        matrix_registered,
        REQUIRED_ENFORCEMENT_FIXTURES.into_iter().collect(),
        "matrix must cover exactly the registered future fixtures and incident branches"
    );
    let incident_ids = matrix
        .cases
        .iter()
        .map(|case| case.fixture_id.clone())
        .filter(|fixture| fixture.starts_with("HF-0") && fixture.len() == 6)
        .collect::<BTreeSet<_>>();
    let expected_incident_ids = (2..=12)
        .map(|number| format!("HF-{number:03}"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        incident_ids, expected_incident_ids,
        "matrix must cover HF-002 through HF-012"
    );

    let document = PolicyDocumentV1::parse(Path::new("policy-v1.yaml"), POLICY.as_bytes())?;
    let base = PolicyCompiler.compile(&document)?;
    let cell_template = base.compiled_cells[0].clone();

    for case in matrix.cases {
        assert!(!case.actor.is_empty() && !case.object.is_empty());
        if !matches!(
            case.expected,
            Expected::UnresolvedNoCoveredEffect | Expected::UnresolvedOutsideAuthority
        ) {
            assert!(
                CompiledOperationV1::try_from(case.operation_id.as_str()).is_ok(),
                "{} has no closed kernel operation",
                case.case_id
            );
        }
        verify_case(&base, &cell_template, case);
    }
    Ok(())
}

fn verify_case(
    base: &mithril_control::StaticExpandedProfileV1,
    cell_template: &CompiledDecisionCellV1,
    case: Case,
) {
    let key = StaticDecisionKeyV1 {
        workload_selector_id: "worker".to_owned(),
        protected_scope_id: "33333333-3333-4333-8333-333333333333".to_owned(),
        execution_set_id: "44444444-4444-4444-8444-444444444444".to_owned(),
        entry_kind: EntryKindV1::ContainerStart,
        role_id: case.actor.clone(),
        process_state_id: "base".to_owned(),
        effect_family: case.effect_family,
        operation_id: case.operation_id,
        object_selector: format!("CASE:{}:{}", case.fixture_id, case.object),
        binding_lifecycle: BindingLifecycleV1::Active,
    };
    let mut profile = base.clone();
    profile.compiled_cells.clear();

    let simulation = match case.expected {
        Expected::Allow | Expected::WouldDeny => {
            let mut cell = cell_template.clone();
            cell.key = key.clone();
            cell.physical_result = if matches!(case.expected, Expected::Allow) {
                cell.errno = None;
                CompiledPhysicalResultV1::AllowEffect
            } else {
                CompiledPhysicalResultV1::SimulatablePolicyDeny
            };
            cell.source_rule_ids = vec![case.case_id.clone()];
            profile.compiled_cells.push(cell);
            PolicySimulator::new(&profile).simulate(key.clone(), None)
        }
        Expected::HardDenyUnsupported => PolicySimulator::new(&profile).simulate(
            key.clone(),
            Some(HardSafetyConditionV1::UnsupportedPhysicalBoundary),
        ),
        Expected::HardDenyAmbiguousTopology => PolicySimulator::new(&profile)
            .simulate(key.clone(), Some(HardSafetyConditionV1::AmbiguousTopology)),
        Expected::HardDenyPriorLsm => PolicySimulator::new(&profile)
            .simulate(key.clone(), Some(HardSafetyConditionV1::PriorLsmDenial)),
        Expected::UnresolvedNoCoveredEffect => PolicySimulator::non_prevention(
            key.clone(),
            NonPreventionReasonV1::NoCoveredPhysicalEffect,
        ),
        Expected::UnresolvedOutsideAuthority => {
            PolicySimulator::non_prevention(key.clone(), NonPreventionReasonV1::OutsideAuthority)
        }
    };

    assert_eq!(simulation.actor_and_object, key, "{}", case.case_id);
    match case.expected {
        Expected::Allow => {
            assert_eq!(simulation.disposition, SimulatedDispositionV1::Allow);
            assert_eq!(simulation.evaluation_stage, "LOCAL_PRE_EFFECT");
        }
        Expected::WouldDeny => {
            assert_eq!(simulation.disposition, SimulatedDispositionV1::WouldDeny);
            assert_eq!(simulation.evaluation_stage, "LOCAL_PRE_EFFECT");
        }
        Expected::HardDenyUnsupported
        | Expected::HardDenyAmbiguousTopology
        | Expected::HardDenyPriorLsm => {
            assert_eq!(simulation.disposition, SimulatedDispositionV1::HardDeny);
            assert_eq!(simulation.evaluation_stage, "LOCAL_PRE_EFFECT");
        }
        Expected::UnresolvedNoCoveredEffect | Expected::UnresolvedOutsideAuthority => {
            assert_eq!(simulation.disposition, SimulatedDispositionV1::Unresolved);
            assert_eq!(simulation.evaluation_stage, "NO_LOCAL_DECISION_POINT");
            assert_eq!(
                simulation.physical_result,
                SimulatedPhysicalResultV1::Unknown
            );
        }
    }
}
