use super::*;
use crate::{CoverageStateV1, PolicyDocumentV1, SimulatedDispositionV1, SimulatedPhysicalResultV1};

type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

mod corpus;

fn input() -> TestResult<DiscoveryInputManifestV1> {
    DiscoveryInputManifestV1::from_json(include_bytes!(
        "../../../mithril-e2e/fixtures/discovery/manifest.json"
    ))
    .map_err(Into::into)
}

#[test]
fn exact_counts_preserve_denial_and_missing_context() -> TestResult<()> {
    let result = DiscoveryOwner::default().derive_recorded(&input()?)?;
    assert_eq!(result.duplicate_deliveries, 1);
    assert_eq!(result.snapshot.accepted_records, 3);
    assert_eq!(result.snapshot.included_records, 2);
    assert_eq!(result.snapshot.unresolved_records, 1);
    assert_eq!(result.snapshot.atoms.len(), 1);
    assert_eq!(result.snapshot.atoms[0].count, 2);
    assert_eq!(
        result.snapshot.atoms[0].physical_result,
        DiscoveryPhysicalResultV1::Prevented
    );
    assert_eq!(result.snapshot.atoms[0].key.static_key.role_id, "converter");
    Ok(())
}

#[test]
fn replay_and_duplicate_delivery_do_not_change_content() -> TestResult<()> {
    let original = input()?;
    let expected = DiscoveryOwner::default()
        .derive_recorded(&original)?
        .snapshot;
    let mut permuted = original.clone();
    permuted.records.reverse();
    permuted.contexts.reverse();
    assert_eq!(
        DiscoveryOwner::default()
            .derive_recorded(&permuted)?
            .snapshot,
        expected
    );
    permuted.records.extend(original.records);
    assert_eq!(
        DiscoveryOwner::default()
            .derive_recorded(&permuted)?
            .snapshot,
        expected
    );
    Ok(())
}

#[test]
fn conflicting_duplicates_and_foreign_context_fail() -> TestResult<()> {
    let mut conflicting = input()?;
    conflicting.records[3].observation.effect.kernel_result = 0;
    assert!(DiscoveryOwner::default()
        .derive_recorded(&conflicting)
        .is_err());
    let mut foreign = input()?;
    foreign.contexts[0].record_id.stream.node_id = "another-node".into();
    assert!(DiscoveryOwner::default().derive_recorded(&foreign).is_err());
    let mut foreign = input()?;
    foreign.records[0].observation.tenant_id.high = 99;
    assert!(DiscoveryOwner::default().derive_recorded(&foreign).is_err());
    Ok(())
}

#[test]
fn changed_result_actor_image_and_object_remain_distinct() -> TestResult<()> {
    for change in 0..4 {
        let mut changed = input()?;
        match change {
            0 => changed.records[1].observation.effect.kernel_result = -1,
            1 => changed.records[1].observation.effect.task_cookie += 1,
            2 => changed.contexts[1].image_digest = format!("sha256:{}", "c".repeat(64)),
            _ => {
                changed.records[1].observation.effect.exact_object_id =
                    Some(crate::EvidenceIdV1::new(29, 30))
            }
        }
        assert_eq!(
            DiscoveryOwner::default()
                .derive_recorded(&changed)?
                .snapshot
                .atoms
                .len(),
            2
        );
    }
    Ok(())
}

#[test]
fn missing_records_never_produce_complete_coverage() -> TestResult<()> {
    let mut partial = input()?;
    partial
        .records
        .retain(|record| record.id.durable_cursor != 3);
    let result = DiscoveryOwner::default().derive_recorded(&partial)?;
    assert_eq!(result.snapshot.coverage[0].state, CoverageStateV1::Gapped);
    assert!(result.snapshot.coverage[0]
        .gap_reasons
        .contains(&"INPUT_RANGE_INCOMPLETE".into()));
    Ok(())
}

#[test]
fn positions_and_proof_kinds_are_not_interchangeable() -> TestResult<()> {
    let mut changed = input()?;
    let expected = DiscoveryOwner::default()
        .derive_recorded(&changed)?
        .snapshot
        .input_digest;
    changed.records[1].original_kernel_sequence = Some(999);
    assert_ne!(
        DiscoveryOwner::default()
            .derive_recorded(&changed)?
            .snapshot
            .input_digest,
        expected
    );
    changed = input()?;
    changed.proof_kind = DiscoveryProofKindV1::RecordedInput;
    assert_ne!(
        DiscoveryOwner::default()
            .derive_recorded(&changed)?
            .snapshot
            .input_digest,
        expected
    );
    Ok(())
}

#[test]
fn unknown_schema_and_fields_are_rejected() -> TestResult<()> {
    let mut changed = input()?;
    changed.schema_version = 2;
    assert!(changed.validate().is_err());
    let mut json = serde_json::to_value(input()?)?;
    json["authority"] = serde_json::json!("allow");
    assert!(DiscoveryInputManifestV1::from_json(&serde_json::to_vec(&json)?).is_err());
    let mut json = serde_json::to_value(input()?)?;
    json["contexts"][0]["static_key"]["authority"] = serde_json::json!("allow");
    assert!(DiscoveryInputManifestV1::from_json(&serde_json::to_vec(&json)?).is_err());
    Ok(())
}

#[test]
fn static_preview_calls_the_native_compiler_and_simulator() -> TestResult<()> {
    let policy = PolicyDocumentV1::parse(
        std::path::Path::new("policy-v1.yaml"),
        include_bytes!("../../tests/fixtures/policy-v1.yaml"),
    )?;
    let simulation = DiscoveryOwner::default().simulate_recorded(&input()?, &policy)?;
    assert_eq!(simulation.simulations.len(), 1);
    assert_eq!(simulation.unresolved_records, 1);
    assert_eq!(
        simulation.simulations[0].disposition,
        SimulatedDispositionV1::WouldDeny
    );
    assert_eq!(
        simulation.simulations[0].physical_result,
        SimulatedPhysicalResultV1::NotAttempted
    );
    Ok(())
}

#[test]
fn exact_file_candidate_uses_native_kubernetes_lowering() -> TestResult<()> {
    let mut spec = crate::WorkloadProtectionPolicySpec::parse(
        std::path::Path::new("kubernetes-entry-roles-v1.yaml"),
        include_bytes!("../../tests/fixtures/kubernetes-entry-roles-v1.yaml"),
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
    let compiled = crate::PolicyCompiler.compile(&policy)?;
    let key = compiled
        .compiled_cells
        .iter()
        .find(|cell| {
            cell.key.effect_family == crate::EffectFamilyV1::File
                && cell.key.operation_id == "OPEN_READ"
                && cell.key.entry_kind == crate::EntryKindV1::ContainerStart
        })
        .ok_or("lowered exact file key is absent")?
        .key
        .clone();
    assert!(key.object_selector.starts_with("PATH:"));
    let mut input = input()?;
    for context in &mut input.contexts {
        context.static_key = key.clone();
    }
    let preview = DiscoveryOwner::default().simulate_recorded(&input, &policy)?;
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

#[test]
fn supplied_context_cannot_change_an_observed_operation() -> TestResult<()> {
    let mut changed = input()?;
    changed.contexts[0].static_key.operation_id = "OPEN_WRITE".into();
    assert!(DiscoveryOwner::default().derive_recorded(&changed).is_err());
    Ok(())
}

#[test]
fn interleaved_cpu_cursors_do_not_create_a_false_gap() -> TestResult<()> {
    let mut input = input()?;
    input.coverage[0].expected_records = 2;
    let mut other_cpu = input.coverage[0].clone();
    other_cpu.cpu_id = 1;
    other_cpu.first_cursor = 2;
    other_cpu.last_cursor = 2;
    other_cpu.expected_records = 1;
    input.coverage.push(other_cpu);
    input.records[1].id.cpu_id = 1;
    input.records[1].observation.cpu_id = 1;
    input.contexts[1].record_id.cpu_id = 1;
    let result = DiscoveryOwner::default().derive_recorded(&input)?;
    assert!(result
        .snapshot
        .coverage
        .iter()
        .all(|coverage| coverage.state == CoverageStateV1::Healthy));
    Ok(())
}

#[test]
fn query_contract_is_one_request_and_resume_binds_scope_and_epoch() -> TestResult<()> {
    let query: DiscoveryQueryRequestV1 =
        serde_json::from_str(r#"{"sql":"SELECT id FROM events"}"#)?;
    query.validate_shape()?;
    assert!(!query.follow);
    let mut invalid = query.clone();
    invalid.cursor = Some("position".into());
    assert!(invalid.validate_shape().is_err());
    let current = DiscoveryFollowPositionV1 {
        query_digest: DiscoveryDigestV1::of(&query.sql)?,
        scope_digest: DiscoveryDigestV1::of(&"tenant-and-subject")?,
        disclosure_revision: 1,
        view_version: 1,
        projection_epoch: 1,
        last_scanned_revision: 10,
        expires_utc_ns: 100,
    };
    let mut saved = current.clone();
    saved.last_scanned_revision = 4;
    saved.validate_resume(&current, 50)?;
    saved.projection_epoch = 2;
    assert!(saved.validate_resume(&current, 50).is_err());
    saved = current.clone();
    saved.disclosure_revision = 2;
    assert!(saved.validate_resume(&current, 50).is_err());
    assert!(current.validate_resume(&current, 100).is_err());
    Ok(())
}

fn investigation() -> TestResult<(ContextPacket, AssessmentReport)> {
    let input = input()?;
    let input_digest = DiscoveryOwner::default()
        .derive_recorded(&input)?
        .snapshot
        .input_digest;
    let subject = DiscoveryReferenceV1 {
        tenant_id: input.tenant_id,
        owner: DiscoveryReferenceOwnerV1::Inventory,
        id: "workload-uid-a".into(),
        revision: 1,
        digest: input_digest.clone(),
    };
    let scope = DiscoveryInvestigationScopeV1 {
        tenant_id: input.tenant_id,
        subject: subject.clone(),
        lifetime: crate::EvidenceIdV1::new(21, 22),
        input_digest,
        finding: None,
        parents: vec![],
    };
    let packet = ContextPacket {
        schema_version: 1,
        scope: scope.clone(),
        proof_kind: DiscoveryProofKindV1::Synthetic,
        question: "Was the credential read prevented, and what remains unknown?".into(),
        cutoff_utc_ns: 3000,
        disclosure: DisclosurePolicyV1 {
            principal: "fixture-investigator".into(),
            revision: 1,
            purpose: "credential-access-investigation".into(),
            destination: DiscoveryDisclosureDestinationV1::LocalOnly,
            allowed_fields: vec!["operation".into(), "kernel_result".into()],
        },
        records: vec![input.records[0].id.clone()],
        owner_facts: vec![DiscoveryOwnerFactV1::Unsupported {
            owner: DiscoveryReferenceOwnerV1::Response,
            reason: "The response runtime is not qualified for this fixture.".into(),
        }],
        missing_facts: vec!["PROVIDER_AUDIT".into(), "ENTRY_PURPOSE".into()],
        complete_coverage: false,
    };
    let method = DiscoveryMethodV1 {
        id: "fixture-credential-read".into(),
        version: "1".into(),
        parameters_digest: DiscoveryDigestV1::of(&"exact-denial")?,
        client_supplied: true,
    };
    let detection = DetectionAssessment {
        scope: scope.clone(),
        method: method.clone(),
        result: DiscoveryDetectionResultV1::Matched,
        supporting: packet.records.clone(),
        refuting: vec![],
        unsupported_predicates: vec!["PROVIDER_USE".into()],
    };
    let classification = ClassificationAssessment {
        scope: scope.clone(),
        context_digest: DiscoveryDigestV1::of(&packet)?,
        detection_digests: vec![DiscoveryDigestV1::of(&detection)?],
        method,
        taxonomy_version: "1".into(),
        activity: "credential-read-attempt".into(),
        suggested_disposition: DiscoverySecurityDispositionV1::Suspicious,
        suggested_priority: DiscoverySuggestedPriorityV1::High,
        claims: vec![DiscoveryClaimV1 {
            id: "denied-read".into(),
            text: "The source records a prevented read. Provider use is unknown.".into(),
            supporting: packet.records.clone(),
            refuting: vec![],
            missing_facts: vec!["PROVIDER_AUDIT".into()],
        }],
        competing_hypotheses: vec!["UNDECLARED_MAINTENANCE".into(), "INTRUSION_ATTEMPT".into()],
        missing_facts: packet.missing_facts.clone(),
        abstained: false,
    };
    let report = AssessmentReport {
        schema_version: 1,
        scope: scope.clone(),
        classification,
        detections: vec![detection],
        suggestions: vec![Suggestion {
            scope: scope.clone(),
            target: subject,
            rationale_claim_ids: vec!["denied-read".into()],
            payload: DiscoverySuggestionPayloadV1::AskOwner {
                question: "Was this entry an approved maintenance operation?".into(),
            },
            preconditions: vec!["EXACT_WORKLOAD_LIFETIME".into()],
            risks: vec!["MISSING_PURPOSE".into()],
            expected_effect: "Resolve the entry purpose without a policy change.".into(),
            tests: vec![],
            required_permission: "discovery.draft".into(),
            state: DiscoverySuggestionStateV1::Draft,
        }],
        query_receipts: vec![QueryReceipt {
            scope,
            principal: packet.disclosure.principal.clone(),
            disclosure_revision: 1,
            query_digest: DiscoveryDigestV1::of(&"credential-read")?,
            view_version: 1,
            read_revision: 1,
            result_digest: DiscoveryDigestV1::of(&packet.records)?,
            returned_rows: 1,
            returned_bytes: 256,
            complete_result: true,
            records: packet.records.clone(),
        }],
        completed_checks: vec!["DENIED_READ".into()],
        missing_checks: vec!["PROVIDER_USE".into()],
    };
    Ok((packet, report))
}

#[test]
fn investigation_contract_round_trip_preserves_drafts_and_missing_facts() -> TestResult<()> {
    let (packet, report) = investigation()?;
    let packet = ContextPacket::from_json(&serde_json::to_vec(&packet)?)?;
    let copy = AssessmentReport::from_json(&serde_json::to_vec(&report)?, &packet)?;
    assert_eq!(copy, report);
    assert_eq!(copy.suggestions[0].state, DiscoverySuggestionStateV1::Draft);
    assert!(matches!(
        packet.owner_facts[0],
        DiscoveryOwnerFactV1::Unsupported { .. }
    ));
    Ok(())
}

#[test]
fn report_rejects_foreign_stale_fabricated_and_authority_fields() -> TestResult<()> {
    let (packet, report) = investigation()?;
    for change in 0..6 {
        let mut changed = report.clone();
        match change {
            0 => changed.scope.tenant_id.high += 1,
            1 => changed.classification.context_digest.0[0] ^= 1,
            2 => changed.classification.claims[0].supporting[0].durable_cursor = 999,
            3 => changed.suggestions[0].target.revision += 1,
            4 => changed.query_receipts[0].disclosure_revision += 1,
            _ => changed.suggestions[0].rationale_claim_ids[0] = "invented-claim".into(),
        }
        assert!(
            changed.validate_against(&packet).is_err(),
            "mutation {change}"
        );
    }
    let mut json = serde_json::to_value(&report)?;
    json["classification"]["authority"] = serde_json::json!("HUMAN_CONFIRMED");
    assert!(AssessmentReport::from_json(&serde_json::to_vec(&json)?, &packet).is_err());
    Ok(())
}

#[test]
fn empty_query_results_do_not_prove_absence_and_refusal_is_not_benign() -> TestResult<()> {
    let (packet, mut report) = investigation()?;
    report.detections[0].result = DiscoveryDetectionResultV1::NotMatched;
    report.classification.detection_digests = vec![DiscoveryDigestV1::of(&report.detections[0])?];
    assert!(report.validate_against(&packet).is_err());
    let (packet, mut report) = investigation()?;
    report.classification.abstained = true;
    report.classification.suggested_disposition = DiscoverySecurityDispositionV1::Expected;
    assert!(report.validate_against(&packet).is_err());
    report.classification.suggested_disposition = DiscoverySecurityDispositionV1::Unknown;
    report.validate_against(&packet)?;
    Ok(())
}

#[test]
fn coverage_and_zero_kernel_result_do_not_merge_with_proven_denial() -> TestResult<()> {
    let mut input = input()?;
    input.records[1].observation.temporal_coverage = crate::TemporalCoverageV1::Gapped;
    input.records[1].observation.effect.kernel_result = 0;
    let result = DiscoveryOwner::default().derive_recorded(&input)?;
    assert_eq!(result.snapshot.coverage[0].state, CoverageStateV1::Gapped);
    assert_eq!(result.snapshot.atoms.len(), 2);
    assert!(result
        .snapshot
        .atoms
        .iter()
        .any(|atom| atom.physical_result == DiscoveryPhysicalResultV1::Unknown));
    input.records[1].observation.temporal_coverage = crate::TemporalCoverageV1::Unknown;
    assert_eq!(
        DiscoveryOwner::default()
            .derive_recorded(&input)?
            .snapshot
            .coverage[0]
            .state,
        CoverageStateV1::Unknown
    );
    Ok(())
}

#[test]
fn investigation_rejects_unknown_owner_records_and_invalid_methods() -> TestResult<()> {
    let (packet, report) = investigation()?;
    let mut unknown = packet.scope.subject.clone();
    unknown.id = "invented".into();
    for payload in [
        DiscoverySuggestionPayloadV1::RunReviewedTest {
            fixture: unknown.clone(),
        },
        DiscoverySuggestionPayloadV1::PolicyChange {
            proposal: unknown.clone(),
        },
        DiscoverySuggestionPayloadV1::ResponsePlan {
            plan: Some(unknown.clone()),
            unsupported_reason: None,
        },
    ] {
        let mut changed = report.clone();
        changed.suggestions[0].payload = payload;
        assert!(changed.validate_against(&packet).is_err());
    }
    let mut changed = report.clone();
    changed.suggestions[0].tests.push(unknown);
    assert!(changed.validate_against(&packet).is_err());
    for change in 0..4 {
        let mut changed = report.clone();
        match change {
            0 => changed.classification.method.id.clear(),
            1 => changed.classification.method.version.clear(),
            2 => changed.classification.method.parameters_digest.0 = [0; 32],
            _ => changed.classification.claims[0].refuting = packet.records.clone(),
        }
        assert!(changed.validate_against(&packet).is_err());
    }
    Ok(())
}

#[test]
fn investigation_binds_evidence_cutoff_coverage_and_disclosure() -> TestResult<()> {
    let (mut packet, _) = investigation()?;
    let input = input()?;
    packet.cutoff_utc_ns = u64::try_from(input.records[0].observation.ingested_utc_ns)?;
    packet.validate_evidence(&input)?;
    packet.validate_disclosure(&packet.disclosure)?;
    for change in 0..4 {
        let mut current = packet.disclosure.clone();
        match change {
            0 => current.principal = "other-principal".into(),
            1 => current.purpose = "other-purpose".into(),
            2 => current.destination = DiscoveryDisclosureDestinationV1::HostedRedacted,
            _ => current.allowed_fields.clear(),
        }
        assert!(packet.validate_disclosure(&current).is_err());
    }
    packet.cutoff_utc_ns -= 1;
    assert!(packet.validate_evidence(&input).is_err());
    packet.cutoff_utc_ns += 1;
    packet.records[0].durable_cursor = 999;
    assert!(packet.validate_evidence(&input).is_err());
    let (mut packet, _) = investigation()?;
    let mut input = input;
    input.coverage[0].state = CoverageStateV1::Gapped;
    packet.scope.input_digest = DiscoveryOwner::default()
        .derive_recorded(&input)?
        .snapshot
        .input_digest;
    packet.complete_coverage = true;
    assert!(packet.validate_evidence(&input).is_err());
    Ok(())
}

#[test]
fn valid_citation_does_not_establish_provider_use() -> TestResult<()> {
    let (packet, mut report) = investigation()?;
    report.classification.claims[0].text = "The provider accepted the stolen credential.".into();
    report.validate_against(&packet)?;
    assert!(packet.missing_facts.contains(&"PROVIDER_AUDIT".into()));
    assert_eq!(
        DiscoveryOwner::default()
            .derive_recorded(&input()?)?
            .snapshot
            .atoms[0]
            .physical_result,
        DiscoveryPhysicalResultV1::Prevented
    );
    Ok(())
}

#[test]
fn packet_rejects_future_and_expired_owner_facts() -> TestResult<()> {
    let (mut packet, _) = investigation()?;
    for (recorded, start, end, valid) in [
        (2000, 2000, None, true),
        (3000, 3000, Some(3001), true),
        (3001, 2000, None, false),
        (2000, 3001, None, false),
        (2000, 2000, Some(3000), false),
        (2000, 2000, Some(2999), false),
        (0, 2000, None, false),
        (2000, 0, None, false),
    ] {
        packet.owner_facts = vec![DiscoveryOwnerFactV1::Available {
            reference: packet.scope.subject.clone(),
            recorded_utc_ns: recorded,
            valid_from_utc_ns: start,
            valid_until_utc_ns: end,
        }];
        assert_eq!(packet.validate().is_ok(), valid);
    }
    Ok(())
}
