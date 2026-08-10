use std::path::Path;

use ed25519_dalek::SigningKey;
use mithril_control::{
    AntiRollbackStore, CompiledPhysicalResultV1, HardSafetyConditionV1, PolicyCompiler,
    PolicyDispositionV1, PolicyDocumentV1, PolicySimulator, ProfileCandidateArtifactV1,
    ProfileSealRequestV1, RegistryDigestsV1, RollbackAuthorizationArtifactV1,
    RollbackAuthorizationPayloadV1, SimulatedDispositionV1,
};

const VALID_POLICY: &str = include_str!("fixtures/policy-v1.yaml");

fn parse(source: &str) -> mithril_control::Result<PolicyDocumentV1> {
    PolicyDocumentV1::parse(Path::new("policy-v1.yaml"), source.as_bytes())
}

#[test]
fn checked_policy_is_closed_and_compiles_deterministically() -> mithril_control::Result<()> {
    let document = parse(VALID_POLICY)?;
    let first = PolicyCompiler.compile(&document)?;
    let second = PolicyCompiler.compile(&document)?;
    assert_eq!(first, second);
    assert_eq!(first.compiled_cells.len(), 1);
    Ok(())
}

#[test]
fn restricted_yaml_rejects_ambiguous_or_open_input() {
    let cases = [
        VALID_POLICY.replacen(
            "kind: ProtectionPolicy",
            "kind: ProtectionPolicy\nkind: ProtectionPolicy",
            1,
        ),
        VALID_POLICY.replacen(
            "kind: ProtectionPolicy",
            "kind: ProtectionPolicy\nunknown: true",
            1,
        ),
        VALID_POLICY.replacen("kind: ProtectionPolicy", "kind: &kind ProtectionPolicy", 1),
        VALID_POLICY.replacen(
            "kind: ProtectionPolicy",
            "kind: !custom ProtectionPolicy",
            1,
        ),
        format!("{VALID_POLICY}\n---\n{VALID_POLICY}"),
        VALID_POLICY.replacen(
            "desired_profile_mode: OBSERVE",
            "desired_profile_mode: UNKNOWN",
            1,
        ),
    ];
    for source in cases {
        assert!(parse(&source).is_err());
    }
}

#[test]
fn comments_do_not_change_canonical_policy() -> mithril_control::Result<()> {
    let plain = PolicyCompiler.compile(&parse(VALID_POLICY)?)?;
    let commented = PolicyCompiler.compile(&parse(&format!("# ignored\n{VALID_POLICY}"))?)?;
    assert_eq!(plain.canonical_policy, commented.canonical_policy);
    assert_eq!(plain.source_policy_digest, commented.source_policy_digest);
    Ok(())
}

#[test]
fn compiler_rejects_unknown_or_ambiguous_kernel_dimensions() -> mithril_control::Result<()> {
    let mut unknown_role = parse(VALID_POLICY)?;
    let mithril_control::RuleMatchV1::LocalPreEffect(effect) =
        &mut unknown_role.rules[0].rule_match
    else {
        unreachable!("fixture has a local effect rule")
    };
    effect.subject.role_ids = vec!["unknown-role".to_owned()];
    assert!(PolicyCompiler.compile(&unknown_role).is_err());

    let mut duplicate_object = parse(VALID_POLICY)?;
    let mithril_control::RuleMatchV1::LocalPreEffect(effect) =
        &mut duplicate_object.rules[0].rule_match
    else {
        unreachable!("fixture has a local effect rule")
    };
    effect.object = mithril_control::LocalObjectSelectorV1::ExactObjectKeys {
        exact_object_key_ids: vec![7, 7],
    };
    assert!(PolicyCompiler.compile(&duplicate_object).is_err());
    Ok(())
}

#[test]
fn unequal_exact_overlap_requires_one_explicit_override() -> mithril_control::Result<()> {
    let mut document = parse(VALID_POLICY)?;
    let mut allow = document.rules[0].clone();
    allow.rule_id = "allow-projected-token-open".to_owned();
    allow.requested_disposition = PolicyDispositionV1::Allow;
    allow.errno = None;
    document.rules.push(allow);
    assert!(PolicyCompiler.compile(&document).is_err());

    document.rules[1]
        .overrides_rule_ids
        .push("deny-projected-token-open".to_owned());
    let compiled = PolicyCompiler.compile(&document)?;
    assert_eq!(compiled.compiled_cells.len(), 1);
    assert_eq!(
        compiled.compiled_cells[0].physical_result,
        CompiledPhysicalResultV1::AllowEffect
    );
    Ok(())
}

#[test]
fn signature_binds_source_and_recomputed_compiler_output() -> mithril_control::Result<()> {
    let document = parse(VALID_POLICY)?;
    let compiled = PolicyCompiler.compile(&document)?;
    let key = SigningKey::from_bytes(&[7; 32]);
    let artifact =
        ProfileCandidateArtifactV1::sign(&document, compiled, seal_request(1, 1, None), &key)?;
    artifact.verify(&key.verifying_key())?;
    artifact.verify_at(&key.verifying_key(), 1_800_000_000_000_000_000)?;
    assert!(artifact
        .verify_at(&key.verifying_key(), 2_000_000_000_000_000_000)
        .is_err());

    let mut changed_cells = artifact.clone();
    changed_cells.compiled_profile.compiled_cells[0].physical_result =
        CompiledPhysicalResultV1::AllowEffect;
    assert!(changed_cells.verify(&key.verifying_key()).is_err());

    let mut changed_source = artifact;
    changed_source.policy_document.metadata.profile_version = 2;
    assert!(changed_source.verify(&key.verifying_key()).is_err());
    Ok(())
}

#[test]
fn observe_never_converts_hard_safety_failures_to_allow() -> mithril_control::Result<()> {
    let compiled = PolicyCompiler.compile(&parse(VALID_POLICY)?)?;
    let key = compiled.compiled_cells[0].key.clone();
    let simulator = PolicySimulator::new(&compiled);
    assert_eq!(
        simulator.simulate(key.clone(), None).disposition,
        SimulatedDispositionV1::WouldDeny
    );
    for condition in [
        HardSafetyConditionV1::PriorLsmDenial,
        HardSafetyConditionV1::MissingTaskIdentity,
        HardSafetyConditionV1::CorruptGeneration,
        HardSafetyConditionV1::EmergencyRestriction,
        HardSafetyConditionV1::AmbiguousTopology,
        HardSafetyConditionV1::UnsupportedPhysicalBoundary,
    ] {
        assert_eq!(
            simulator.simulate(key.clone(), Some(condition)).disposition,
            SimulatedDispositionV1::HardDeny
        );
    }
    Ok(())
}

#[test]
fn rollback_is_exact_signed_and_one_use() -> Result<(), Box<dyn std::error::Error>> {
    let key = SigningKey::from_bytes(&[9; 32]);
    let mut version_two = parse(VALID_POLICY)?;
    version_two.metadata.profile_version = 2;
    let current = signed(&version_two, seal_request(1, 2, None), &key)?;
    let target_document = parse(VALID_POLICY)?;
    let authorization_id = "88888888-8888-4888-8888-888888888888";
    let target = signed(
        &target_document,
        seal_request(1, 1, Some(authorization_id)),
        &key,
    )?;
    let platform = "ab".repeat(32);
    let rollback = RollbackAuthorizationArtifactV1::sign(
        "test-key".to_owned(),
        RollbackAuthorizationPayloadV1 {
            authorization_id: authorization_id.to_owned(),
            trust_domain_id: target.header.trust_domain_id.clone(),
            issuer_id: target.header.issuer_id.clone(),
            approver_principal_id: "99999999-9999-4999-8999-999999999999".to_owned(),
            sequence_epoch: 1,
            issuer_sequence: 3,
            profile_id: target.header.profile_id.clone(),
            current_digest: current.header.policy_document_digest.clone(),
            current_version: 2,
            exact_older_target_digest: target.header.policy_document_digest.clone(),
            exact_older_target_version: 1,
            closed_reason_code: 1,
            human_reason_artifact_digest: None,
            exact_platform_scope_digest: platform.clone(),
            issued_at_utc_ns: 10,
            expires_at_utc_ns: 30,
        },
        &key,
    )?;
    let directory = tempfile::tempdir()?;
    let mut store = AntiRollbackStore::load(directory.path().join("rollback.json"))?;
    store.accept(&current, None, &platform, 20)?;
    assert!(store.accept(&target, None, &platform, 20).is_err());
    assert!(store
        .accept(
            &target,
            Some((&rollback, &key.verifying_key())),
            "wrong-platform",
            20,
        )
        .is_err());
    store.accept(
        &target,
        Some((&rollback, &key.verifying_key())),
        &platform,
        20,
    )?;

    let mut version_three = parse(VALID_POLICY)?;
    version_three.metadata.profile_version = 3;
    let next = signed(&version_three, seal_request(1, 4, None), &key)?;
    store.accept(&next, None, &platform, 20)?;
    assert!(store
        .accept(
            &target,
            Some((&rollback, &key.verifying_key())),
            &platform,
            20,
        )
        .is_err());
    Ok(())
}

fn signed(
    document: &PolicyDocumentV1,
    request: ProfileSealRequestV1,
    key: &SigningKey,
) -> mithril_control::Result<ProfileCandidateArtifactV1> {
    ProfileCandidateArtifactV1::sign(document, PolicyCompiler.compile(document)?, request, key)
}

fn seal_request(
    sequence_epoch: u64,
    issuer_sequence: u64,
    rollback_authorization_id: Option<&str>,
) -> ProfileSealRequestV1 {
    let digest = "00".repeat(32);
    ProfileSealRequestV1 {
        signing_key_id: "test-key".to_owned(),
        issuer_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
        sequence_epoch,
        issuer_sequence,
        rollback_authorization_id: rollback_authorization_id.map(str::to_owned),
        registry_digests: RegistryDigestsV1 {
            provider_numeric_registry_bundle_digest: digest.clone(),
            required_capability_schema_digest: digest.clone(),
            source_selector_registry_digest: digest.clone(),
            object_classifier_registry_digest: digest.clone(),
            reason_code_registry_digest: digest.clone(),
            correlation_package_registry_digest: digest.clone(),
            provider_vocabulary_registry_digest: digest,
        },
    }
}
