use super::*;
use crate::{DiscoveryDigestV1, DiscoveryPolicyKeyV1, EvidenceIntakeIdentityV1};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) struct CatalogFixture {
    pub(crate) identity: EvidenceIntakeIdentityV1,
    pub(crate) catalog: EvidenceDecisionCatalogV1,
    pub(crate) record: EvidenceRecord,
}

impl CatalogFixture {
    pub(crate) fn new() -> TestResult<Self> {
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        let exact = EvidenceExactFileObject {
            profile_generation_ref_id: 11,
            mount_id_unique: 12,
            inode: 13,
            inode_generation: 14,
            mount_namespace_inode: 15,
            filesystem_device: 16,
        };
        let mut catalog = EvidenceDecisionCatalogV1 {
            node_boot_id: identity.node_boot_id.into(),
            profile_id: uuid::Uuid::from_bytes([19; 16]).to_string(),
            profile_version: 20,
            policy_document_digest: "ab".repeat(32),
            profile_generation_ref_id: 11,
            binding_id: [21; 16].into(),
            role_id: 22,
            state_id: 23,
            entry_rule_id: 24,
            exact_file_object: exact,
            exact_object_key_id: 17,
            composite_atom_id: 18,
            static_key: StaticDecisionKeyV1 {
                workload_selector_id: "workload".into(),
                protected_scope_id: uuid::Uuid::from_bytes([6; 16]).to_string(),
                execution_set_id: uuid::Uuid::from_bytes([7; 16]).to_string(),
                entry_kind: EntryKindV1::ContainerStart,
                role_id: "application".into(),
                process_state_id: "running".into(),
                effect_family: EffectFamilyV1::File,
                operation_id: "OPEN_READ".into(),
                object_selector: "PATH:/test".into(),
                binding_lifecycle: BindingLifecycleV1::Active,
            },
            digest: DiscoveryDigestV1([0; 32]),
        };
        catalog.digest = catalog.content_digest()?;
        let object = EvidenceFileObjectV1::from(&catalog.exact_file_object)
            .observation_id(catalog.exact_object_key_id);
        let record = EvidenceRecord {
            observed_boottime_ns: 1_000,
            ingested_utc_ns: 1,
            coverage_interval_id: vec![25; 16].into(),
            profile_generation_ref_id: Some(11),
            task_cookie: 9,
            process_lineage_id: vec![5; 16].into(),
            authority_domain_id: vec![6; 16].into(),
            execution_set_id: vec![7; 16].into(),
            exact_object_id: object.to_be_bytes().to_vec().into(),
            policy_rule_id: 18,
            reason: 1,
            decision: 1,
            effect_family: 2,
            operation: 2,
            temporal_coverage: EvidenceTemporalCoverage::Complete as i32,
            decision_context: Some(EvidenceDecisionContext {
                schema_version: 1,
                original_kernel_sequence: 200,
                process_instance_id: vec![26; 16],
                entry_instance_id: vec![27; 16],
                binding_id: catalog.binding_id.to_be_bytes().to_vec(),
                profile_generation_ref_id: catalog.profile_generation_ref_id,
                role_id: catalog.role_id,
                state_id: catalog.state_id,
                entry_rule_id: catalog.entry_rule_id,
                exact_file_object: Some(catalog.exact_file_object),
                exact_object_key_id: catalog.exact_object_key_id,
                composite_atom_id: catalog.composite_atom_id,
                catalog_json: catalog.clone().seal()?,
                catalog_state: "AVAILABLE".into(),
            }),
            ..Default::default()
        };
        Ok(Self {
            identity,
            catalog,
            record,
        })
    }

    fn check(&self) -> EvidenceModelResult<ObservationEnvelopeV1> {
        ObservationEnvelopeV1::from_wire_record(
            self.identity.tenant_id.into(),
            self.identity.node_boot_id.into(),
            self.identity.source_id.into(),
            self.identity.source_epoch,
            1,
            0,
            &self.record,
        )
    }

    fn reseal(&mut self) -> TestResult {
        self.record
            .decision_context
            .as_mut()
            .ok_or("context")?
            .catalog_json = self.catalog.clone().seal()?;
        Ok(())
    }
}

#[test]
fn catalog_wire_keys() -> TestResult {
    let fixture = CatalogFixture::new()?;
    fixture.check()?;
    let context = fixture.record.decision_context.as_ref().ok_or("context")?;
    assert_eq!(
        EvidenceDecisionCatalogV1::from_context(context)?,
        Some(fixture.catalog.clone())
    );
    let wire: serde_json::Value = serde_json::from_slice(&context.catalog_json)?;
    let key = wire["static_key"].as_object().ok_or("wire key")?;
    assert_eq!(key.len(), 10);
    assert_eq!(key["entry_kind"], "CONTAINER_START");
    assert_eq!(key["effect_family"], "FILE");
    assert_eq!(key["binding_lifecycle"], "ACTIVE");
    assert!(!key.contains_key("operation"));
    let normalized = DiscoveryPolicyKeyV1::try_from(&fixture.catalog.static_key)?;
    assert_eq!(
        (
            normalized.effect_family,
            normalized.operation,
            normalized.operation_argument
        ),
        (2, 2, 0)
    );
    assert!(!normalized.argument_wildcard);
    assert_eq!(
        StaticDecisionKeyV1::try_from(&normalized)?,
        fixture.catalog.static_key
    );
    Ok(())
}

#[test]
fn catalog_digest_coordinates() -> TestResult {
    for change in 0..17 {
        let mut fixture = CatalogFixture::new()?;
        match change {
            0 => fixture.catalog.digest.0[0] ^= 1,
            1 => fixture.catalog.profile_id = "invalid".into(),
            2 => fixture.catalog.profile_version = 0,
            3 => fixture.catalog.policy_document_digest = "AB".repeat(32),
            4 => fixture.catalog.profile_generation_ref_id += 1,
            5 => fixture.catalog.binding_id = [0; 16].into(),
            6 => fixture.catalog.role_id += 1,
            7 => fixture.catalog.state_id += 1,
            8 => fixture.catalog.entry_rule_id += 1,
            9 => fixture.catalog.exact_file_object.inode += 1,
            10 => fixture.catalog.exact_object_key_id += 1,
            11 => fixture.catalog.composite_atom_id += 1,
            12 => fixture.catalog.node_boot_id = [99; 16].into(),
            13 => fixture.catalog.static_key.operation_id = "WRITE".into(),
            14..=16 => {}
            _ => unreachable!(),
        }
        if change == 0 {
            fixture
                .record
                .decision_context
                .as_mut()
                .ok_or("context")?
                .catalog_json = serde_json::to_vec(&fixture.catalog)?;
        } else {
            fixture.reseal()?;
        }
        if change >= 14 {
            let context = fixture.record.decision_context.as_mut().ok_or("context")?;
            let mut value: serde_json::Value = serde_json::from_slice(&context.catalog_json)?;
            match change {
                14 => value["unknown"] = true.into(),
                15 => value["static_key"]["unknown"] = true.into(),
                16 => value["static_key"]["entry_kind"] = "UNKNOWN_ENTRY".into(),
                _ => unreachable!(),
            }
            context.catalog_json = serde_json::to_vec(&value)?;
        }
        assert!(
            fixture.check().is_err(),
            "accepted catalog mutation {change}"
        );
    }
    Ok(())
}

#[test]
fn catalog_validates_wire() -> TestResult {
    for change in 0..11 {
        let mut fixture = CatalogFixture::new()?;
        match change {
            0 => fixture.record.observed_boottime_ns = 0,
            1 => fixture.record.reason = u32::MAX,
            2 => fixture.record.effect_family = 0,
            3 => fixture.record.operation_argument = Some(0),
            4 => fixture.record.exact_object_id = vec![99; 16].into(),
            5 => fixture.identity.source_id = [0; 16],
            6 => fixture.record.temporal_coverage = i32::MAX,
            7 => {
                fixture
                    .record
                    .decision_context
                    .as_mut()
                    .ok_or("context")?
                    .schema_version = 2
            }
            8 => {
                fixture
                    .record
                    .decision_context
                    .as_mut()
                    .ok_or("context")?
                    .original_kernel_sequence = 0
            }
            9 => {
                fixture
                    .record
                    .decision_context
                    .as_mut()
                    .ok_or("context")?
                    .binding_id = vec![21; 15]
            }
            10 => fixture.record.policy_rule_id += 1,
            _ => unreachable!(),
        }
        assert!(
            fixture.check().is_err(),
            "accepted observation mutation {change}"
        );
    }
    Ok(())
}

#[test]
fn catalog_absence_states() -> TestResult {
    let mut context = EvidenceDecisionContext::default();
    for state in [
        "",
        "MISSING_CATALOG",
        "NO_EXACT_MATCH",
        "AMBIGUOUS",
        "CATALOG_LIMIT",
        "CONTEXT_LIMIT",
    ] {
        context.catalog_state = state.into();
        assert!(EvidenceDecisionCatalogV1::from_context(&context)?.is_none());
    }
    for state in ["AVAILABLE", "UNSUPPORTED"] {
        context.catalog_state = state.into();
        assert!(EvidenceDecisionCatalogV1::from_context(&context).is_err());
    }
    Ok(())
}
