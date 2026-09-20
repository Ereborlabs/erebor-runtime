use std::collections::BTreeSet;

use serde::Deserialize;

use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    version: u32,
    proof_kind: DiscoveryProofKindV1,
    operator_protocol: Vec<String>,
    cases: Vec<Case>,
    capabilities: Vec<Capability>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    partition: String,
    groups: Vec<Group>,
    expected: Expected,
    question: String,
    acceptable_dispositions: Vec<DiscoverySecurityDispositionV1>,
    required_facts: Vec<String>,
    next_check: String,
    untrusted_text: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    count: u64,
    label: String,
    variation: Variation,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Variation {
    Routine,
    Denied,
    State,
    Release,
    Entry,
    MissingContext,
    Gapped,
    ReplicaGapped,
    Unknown,
    MissingObject,
    Outbound,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    accepted: u64,
    atoms: usize,
    unresolved: u64,
    prevented: u64,
    coverage: CoverageStateV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capability {
    id: String,
    owner: DiscoveryReferenceOwnerV1,
    available: String,
    unsupported: String,
}

impl Case {
    fn input(&self) -> TestResult<DiscoveryInputManifestV1> {
        let mut input = super::input()?;
        let seed_record = input.records[0].clone();
        let seed_context = input.contexts[0].clone();
        input.source_revision = format!("synthetic-pilot-v1/{}", self.id);
        input.records.clear();
        input.contexts.clear();
        for (group_index, group) in self.groups.iter().enumerate() {
            assert!(!group.label.is_empty());
            assert!((1..=10_000).contains(&group.count));
            for _ in 0..group.count {
                let mut record = seed_record.clone();
                let cursor = input.records.len() as u64 + 1;
                record.id.durable_cursor = cursor;
                record.original_kernel_sequence = Some(cursor + 100);
                record.observation.source_sequence = cursor;
                record.observation.observed_boottime_ns = cursor + 1000;
                record.observation.ingested_utc_ns = i64::try_from(cursor + 2000)?;
                record.observation.effect.decision = 0;
                record.observation.effect.kernel_result = 0;
                record.observation.effect.configured_errno = 0;
                let mut context = seed_context.clone();
                context.record_id = record.id.clone();
                match group.variation {
                    Variation::Routine => {}
                    Variation::Denied => {
                        record.observation.effect.decision = 1;
                        record.observation.effect.kernel_result = -13;
                        record.observation.effect.configured_errno = -13;
                    }
                    Variation::State => context.state_id += group_index as u32 + 1,
                    Variation::Release => {
                        context.image_digest = format!("sha256:{}", "c".repeat(64));
                        context.configuration_digest = "d".repeat(64);
                        context.subject_revision = "workload-uid-a/revision-2".into();
                    }
                    Variation::Entry => {
                        context.entry_instance_id.low += 1;
                        context.entry_rule_id += 1;
                    }
                    Variation::MissingContext => {}
                    Variation::Gapped => {
                        record.observation.temporal_coverage = crate::TemporalCoverageV1::Gapped;
                    }
                    Variation::ReplicaGapped => {
                        record.id.stream.node_id = "node-b".into();
                        context.record_id = record.id.clone();
                        context.subject_revision = "workload-uid-b/revision-1".into();
                        context.process_instance_id.low += 1;
                        context.entry_instance_id.low += 1;
                        context.binding_id.low += 1;
                        record.observation.temporal_coverage = crate::TemporalCoverageV1::Gapped;
                    }
                    Variation::Unknown => {
                        record.observation.temporal_coverage = crate::TemporalCoverageV1::Unknown;
                    }
                    Variation::MissingObject => record.observation.effect.exact_object_id = None,
                    Variation::Outbound => {
                        record.observation.effect.effect_family = 3;
                        record.observation.effect.operation = 12;
                        record.observation.effect.exact_object_id = None;
                        record.observation.effect.destination_id = Some(31);
                        context.static_key.effect_family = crate::EffectFamilyV1::Network;
                        context.static_key.operation_id = "CONNECT".into();
                        context.static_key.object_selector = "DESTINATION:fixture-api".into();
                    }
                }
                if !matches!(group.variation, Variation::MissingContext) {
                    input.contexts.push(context);
                }
                input.records.push(record);
            }
        }
        let seed_coverage = input.coverage[0].clone();
        input.coverage.clear();
        for record in &input.records {
            if let Some(range) = input
                .coverage
                .iter_mut()
                .find(|range| range.stream == record.id.stream)
            {
                range.last_cursor = record.id.durable_cursor;
                range.expected_records += 1;
            } else {
                let mut range = seed_coverage.clone();
                range.stream = record.id.stream.clone();
                range.first_cursor = record.id.durable_cursor;
                range.last_cursor = record.id.durable_cursor;
                range.expected_records = 1;
                input.coverage.push(range);
            }
        }
        Ok(input)
    }
}

#[test]
fn discovery_pilot_preserves_exact_counts_risk_and_replay() -> TestResult<()> {
    let corpus: Corpus = serde_json::from_slice(include_bytes!(
        "../../../../mithril-e2e/fixtures/discovery/pilot.json"
    ))?;
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.proof_kind, DiscoveryProofKindV1::Synthetic);
    assert_eq!(corpus.operator_protocol.len(), 6);
    assert_eq!(corpus.cases.len(), 21);
    let mut ids = BTreeSet::new();
    for case in corpus.cases {
        assert!(ids.insert(case.id.clone()));
        assert!(["TRAIN", "TUNE", "HELD_OUT_VALID", "FORBIDDEN"].contains(&case.partition.as_str()));
        assert!(!case.question.is_empty() && !case.next_check.is_empty());
        assert!(!case.acceptable_dispositions.is_empty() && !case.required_facts.is_empty());
        assert!(case.untrusted_text.iter().all(|text| text.len() <= 1024));
        let mut input = case.input()?;
        let expected = &case.expected;
        let result = DiscoveryOwner.derive_recorded(&input)?.snapshot;
        assert_eq!(result.accepted_records, expected.accepted, "{}", case.id);
        assert_eq!(result.atoms.len(), expected.atoms, "{}", case.id);
        assert_eq!(
            result.unresolved_records, expected.unresolved,
            "{}",
            case.id
        );
        assert!(
            result
                .coverage
                .iter()
                .any(|range| range.state == expected.coverage),
            "{}",
            case.id
        );
        if case.id == "unequal-coverage" {
            assert_eq!(result.coverage.len(), 2);
            assert_ne!(result.atoms[0].key.stream, result.atoms[1].key.stream);
            assert_ne!(result.coverage[0].state, result.coverage[1].state);
        }
        assert_eq!(
            result.included_records + result.unresolved_records + result.excluded_records,
            result.accepted_records
        );
        let prevented: u64 = result
            .atoms
            .iter()
            .filter(|atom| atom.physical_result == DiscoveryPhysicalResultV1::Prevented)
            .map(|atom| atom.count)
            .sum();
        assert_eq!(prevented, expected.prevented, "{}", case.id);
        assert!(result
            .atoms
            .iter()
            .all(|atom| atom.evidence_sample.len() <= 8));
        input.records.reverse();
        input.contexts.reverse();
        input.records.extend(input.records.clone());
        let replay = DiscoveryOwner.derive_recorded(&input)?;
        assert_eq!(replay.duplicate_deliveries, expected.accepted);
        assert_eq!(replay.snapshot, result, "{}", case.id);
    }
    let expected = [
        "HF-LOCAL-001",
        "HF-NET-001",
        "HF-SEM-001",
        "HF-XNODE-001",
        "HF-RESP-001",
        "HF-RESP-002",
        "HF-PROV-001",
    ];
    assert_eq!(
        corpus
            .capabilities
            .iter()
            .map(|capability| capability.id.as_str())
            .collect::<Vec<_>>(),
        expected
    );
    for capability in corpus.capabilities {
        assert!(!capability.available.is_empty() && !capability.unsupported.is_empty());
        let (mut packet, _) = super::investigation()?;
        packet.owner_facts = vec![DiscoveryOwnerFactV1::Unsupported {
            owner: capability.owner,
            reason: capability.unsupported,
        }];
        packet.validate()?;
    }
    Ok(())
}

#[test]
fn discovery_defender_contract_keeps_owner_obligations_after_client_restart() -> TestResult<()> {
    let (mut packet, mut report) = super::investigation()?;
    let finding = DiscoveryReferenceV1 {
        owner: DiscoveryReferenceOwnerV1::Finding,
        id: "synthetic-critical-finding".into(),
        digest: DiscoveryDigestV1::of(&"critical-priority-floor")?,
        ..packet.scope.subject.clone()
    };
    packet.scope.finding = Some(finding.clone());
    packet.owner_facts = vec![
        DiscoveryOwnerFactV1::Available {
            reference: finding,
            recorded_utc_ns: 2500,
            valid_from_utc_ns: 2500,
            valid_until_utc_ns: None,
        },
        DiscoveryOwnerFactV1::Available {
            reference: DiscoveryReferenceV1 {
                owner: DiscoveryReferenceOwnerV1::Notification,
                id: "synthetic-notification-attempt".into(),
                digest: DiscoveryDigestV1::of(&"delivery-failed;human-ack-absent")?,
                ..packet.scope.subject.clone()
            },
            recorded_utc_ns: 2600,
            valid_from_utc_ns: 2600,
            valid_until_utc_ns: None,
        },
        DiscoveryOwnerFactV1::Unsupported {
            owner: DiscoveryReferenceOwnerV1::Approval,
            reason: "No response approval owner is available in this fixture.".into(),
        },
        DiscoveryOwnerFactV1::Unsupported {
            owner: DiscoveryReferenceOwnerV1::Response,
            reason: "No response actuator or readback is available in this fixture.".into(),
        },
    ];
    packet.missing_facts.extend([
        "HUMAN_ACKNOWLEDGEMENT".into(),
        "ACTION_READBACK".into(),
        "REPLACEMENT_WATCH".into(),
    ]);
    report.scope = packet.scope.clone();
    report.classification.scope = packet.scope.clone();
    report.classification.context_digest = DiscoveryDigestV1::of(&packet)?;
    report.detections[0].scope = packet.scope.clone();
    report.classification.detection_digests = vec![DiscoveryDigestV1::of(&report.detections[0])?];
    report.query_receipts[0].scope = packet.scope.clone();
    report.suggestions[0].scope = packet.scope.clone();
    report.suggestions[0].payload = DiscoverySuggestionPayloadV1::ResponsePlan {
        plan: None,
        unsupported_reason: Some("No response owner is available.".into()),
    };
    let frozen_facts = packet.owner_facts.clone();
    for refused in [false, true] {
        report.classification.abstained = refused;
        report.classification.suggested_disposition = if refused {
            DiscoverySecurityDispositionV1::Unknown
        } else {
            DiscoverySecurityDispositionV1::Expected
        };
        report.classification.suggested_priority = DiscoverySuggestedPriorityV1::Low;
        report.validate_against(&packet)?;
        let resumed_packet = ContextPacket::from_json(&serde_json::to_vec(&packet)?)?;
        let resumed_report =
            AssessmentReport::from_json(&serde_json::to_vec(&report)?, &resumed_packet)?;
        assert_eq!(resumed_report, report);
        assert_eq!(resumed_packet.owner_facts, frozen_facts);
        assert_eq!(
            resumed_report.suggestions[0].state,
            DiscoverySuggestionStateV1::Draft
        );
        assert!(resumed_packet
            .missing_facts
            .contains(&"ACTION_READBACK".into()));
    }
    let report_digest = DiscoveryDigestV1::of(&report)?;
    let mut late = packet.clone();
    late.scope.parents.push(DiscoveryReferenceV1 {
        owner: DiscoveryReferenceOwnerV1::Discovery,
        id: "prior-assessment".into(),
        digest: report_digest,
        ..packet.scope.subject.clone()
    });
    late.scope.subject.revision += 1;
    late.scope.lifetime.low += 1;
    assert!(report.validate_against(&late).is_err());
    assert_eq!(packet.owner_facts, frozen_facts);
    Ok(())
}

#[test]
fn discovery_late_evidence_and_coverage_create_new_content() -> TestResult<()> {
    let mut input = super::input()?;
    let sealed = DiscoveryOwner.derive_recorded(&input)?.snapshot;
    let mut late = input.records[0].clone();
    late.id.durable_cursor = 4;
    late.original_kernel_sequence = Some(104);
    late.observation.source_sequence = 4;
    let mut context = input.contexts[0].clone();
    context.record_id = late.id.clone();
    input.records.push(late);
    input.contexts.push(context);
    input.coverage[0].last_cursor = 4;
    input.coverage[0].expected_records = 4;
    input.coverage[0].coverage_revision += 1;
    input.coverage[0].state = CoverageStateV1::Gapped;
    input.coverage[0]
        .gap_reasons
        .push("LATE_COVERAGE_CORRECTION".into());
    let revised = DiscoveryOwner.derive_recorded(&input)?.snapshot;
    assert_ne!(revised.content_digest, sealed.content_digest);
    assert_ne!(revised.input_digest, sealed.input_digest);
    assert_eq!(revised.accepted_records, sealed.accepted_records + 1);
    assert_eq!(sealed.coverage[0].state, CoverageStateV1::Healthy);
    assert_eq!(revised.coverage[0].state, CoverageStateV1::Gapped);
    Ok(())
}
