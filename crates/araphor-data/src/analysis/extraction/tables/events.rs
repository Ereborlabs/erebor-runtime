use super::*;
use crate::{AnalysisRecordV1, EvidenceIntakeIdentityV1, EvidenceRecord};

impl Capture<'_> {
    table_row! {
        #[allow(clippy::too_many_arguments)]
        pub(in crate::analysis::extraction) fn event(
            &mut self,
            identity: &EvidenceIntakeIdentityV1,
            cpu_id: u32,
            received_utc_ns: u64,
            record: &AnalysisRecordV1,
            decoded: Option<&EvidenceRecord>,
            checked_catalog: bool,
            budget: &mut ReadBudget<'_>,
        );
        schema event_fields;
        row(self, "events", budget);
        setup {
            if !self.read.requests.contains_key("events") {
                return Ok(true);
            }
            if self.read.event_ranges.is_some_and(|ranges| {
                !ranges
                    .iter()
                    .any(|(first, last)| (*first..=*last).contains(&received_utc_ns))
            }) {
                return Ok(true);
            }
            budget.grow(&mut self.witnesses)?;
            budget.charge(identity.node_id.len())?;
            self.witnesses.push(AnalysisWitnessV1 {
                identity: identity.clone().into(),
                cursor: record.cursor,
                expires_utc_ns: 0,
            });
            self.received_min = Some(
                self.received_min
                    .map_or(received_utc_ns, |value| value.min(received_utc_ns)),
            );
            if self.read.projected("events").is_none() {
                return Ok(true);
            }
            let context = decoded.and_then(|value| value.decision_context.as_ref());
            let exact = context.and_then(|value| value.exact_file_object.as_ref());
            let catalog = if checked_catalog {
                if context.is_some_and(|context| !context.catalog_json.is_empty()) {
                    let wire = decoded.ok_or_else(|| invalid("the checked event is not decoded"))?;
                    crate::ObservationEnvelopeV1::from_wire_catalog(
                        identity.tenant_id.into(),
                        identity.node_boot_id.into(),
                        identity.source_id.into(),
                        identity.source_epoch,
                        record.cursor,
                        cpu_id,
                        wire,
                    ).map(|(_, catalog)| catalog)
                } else {
                    context.map(crate::EvidenceDecisionCatalogV1::from_context)
                        .transpose().map(Option::flatten)
                }.map_err(|source| crate::Error::DiscoveryContext {
                    source: Box::new(source),
                    location: snafu::location!(),
                })?
            } else {
                None
            };
            let key = catalog.as_ref()
                .map(|catalog| crate::DiscoveryPolicyKeyV1::try_from(&catalog.static_key))
                .transpose()?;
        }
        fields {
            tenant_id => Binary(false): Some(&identity.tenant_id),
            node_id => Utf8(false): Some(&identity.node_id),
            node_boot_id => Binary(false): Some(&identity.node_boot_id),
            label_epoch => UInt64(false): Some(identity.label_epoch),
            source_id => Binary(false): Some(&identity.source_id),
            source_epoch => UInt64(false): Some(identity.source_epoch),
            cpu_id => UInt32(false): Some(cpu_id),
            source_cursor => UInt64(false): Some(record.cursor),
            commit_revision => UInt64(false): Some(record.position.commit_revision),
            ordinal => UInt32(false): Some(record.position.ordinal),
            received_utc_ns => UInt64(false): Some(received_utc_ns),
            received_at => TimestampMicrosecond(false): Some(i64::try_from(received_utc_ns/1000).map_err(|_|overflow())?),
            observed_boottime_ns => UInt64(false): decoded.map(|value| value.observed_boottime_ns),
            ingested_utc_ns => Int64(false): decoded.map(|value| value.ingested_utc_ns),
            coverage_interval_id => Binary(false): decoded.map(|value| value.coverage_interval_id.as_ref()),
            profile_generation_ref_id => UInt64(true): decoded.and_then(|value| value.profile_generation_ref_id),
            task_cookie => UInt64(false): decoded.map(|value| value.task_cookie),
            process_lineage_id => Binary(false): decoded.map(|value| value.process_lineage_id.as_ref()),
            authority_domain_id => Binary(false): decoded.map(|value| value.authority_domain_id.as_ref()),
            execution_set_id => Binary(false): decoded.map(|value| value.execution_set_id.as_ref()),
            exact_object_id => Binary(false): decoded.map(|value| value.exact_object_id.as_ref()),
            destination_id => UInt64(false): decoded.map(|value| value.destination_id),
            policy_rule_id => UInt64(false): decoded.map(|value| value.policy_rule_id),
            reason => UInt32(false): decoded.map(|value| value.reason),
            decision => UInt32(false): decoded.map(|value| value.decision),
            effect_family => UInt32(false): decoded.map(|value| value.effect_family),
            operation => UInt32(false): decoded.map(|value| value.operation),
            configured_errno => Int32(false): decoded.map(|value| value.configured_errno),
            kernel_result => Int32(false): decoded.map(|value| value.kernel_result),
            temporal_coverage => Int32(false): decoded.map(|value| value.temporal_coverage),
            target_task_cookie => UInt64(true): decoded.and_then(|value| value.target_task_cookie),
            operation_argument => UInt32(true): decoded.and_then(|value| value.operation_argument),
            context_schema_version => UInt32(true): context.map(|value|value.schema_version),
            kernel_sequence => UInt64(true): context.map(|value|value.original_kernel_sequence),
            process_instance_id => Binary(true): context.map(|value|value.process_instance_id.as_slice()),
            entry_instance_id => Binary(true): context.map(|value|value.entry_instance_id.as_slice()),
            binding_id => Binary(true): context.map(|value|value.binding_id.as_slice()),
            context_profile_generation_ref_id => UInt64(true): context.map(|value|value.profile_generation_ref_id),
            role_id => UInt32(true): context.map(|value|value.role_id),
            state_id => UInt32(true): context.map(|value|value.state_id),
            entry_rule_id => UInt32(true): context.map(|value|value.entry_rule_id),
            exact_object_key_id => UInt64(true): context.map(|value|value.exact_object_key_id),
            composite_atom_id => UInt64(true): context.map(|value|value.composite_atom_id),
            catalog_json => Binary(true): context.map(|value|value.catalog_json.as_slice()),
            catalog_state => Utf8(true): context.map(|value|value.catalog_state.as_str()),
            exact_profile_generation_ref_id => UInt64(true): exact.map(|value|value.profile_generation_ref_id),
            mount_id_unique => UInt64(true): exact.map(|value|value.mount_id_unique),
            inode => UInt64(true): exact.map(|value|value.inode),
            inode_generation => UInt64(true): exact.map(|value|value.inode_generation),
            mount_namespace_inode => UInt32(true): exact.map(|value|value.mount_namespace_inode),
            filesystem_device => UInt32(true): exact.map(|value|value.filesystem_device),
            framed_record => Binary(false): Some(record.framed_record.as_slice()),
            catalog_profile_id => Utf8(true): catalog.as_ref().map(|value| value.profile_id.as_str()),
            catalog_profile_version => UInt64(true): catalog.as_ref().map(|value| value.profile_version),
            catalog_policy_document_digest => Utf8(true): catalog.as_ref().map(|value| value.policy_document_digest.as_str()),
            catalog_key_workload_selector_id => Utf8(true): key.as_ref().map(|value| value.workload_selector_id.as_str()),
            catalog_key_protected_scope_id => Utf8(true): key.as_ref().map(|value| value.protected_scope_id.as_str()),
            catalog_key_execution_set_id => Utf8(true): key.as_ref().map(|value| value.execution_set_id.as_str()),
            catalog_key_entry_kind => Utf8(true): key.as_ref().map(|value| value.entry_kind.as_str()),
            catalog_key_role_id => Utf8(true): key.as_ref().map(|value| value.role_id.as_str()),
            catalog_key_process_state_id => Utf8(true): key.as_ref().map(|value| value.process_state_id.as_str()),
            catalog_key_effect_family => UInt32(true): key.as_ref().map(|value| u32::from(value.effect_family)),
            catalog_key_operation_id => Utf8(true): key.as_ref().map(|value| value.operation_id.as_str()),
            catalog_key_operation => UInt32(true): key.as_ref().map(|value| u32::from(value.operation)),
            catalog_key_operation_argument => UInt32(true): key.as_ref().map(|value| value.operation_argument),
            catalog_key_argument_wildcard => Boolean(true): key.as_ref().map(|value| value.argument_wildcard),
            catalog_key_object_selector => Utf8(true): key.as_ref().map(|value| value.object_selector.as_str()),
            catalog_key_binding_lifecycle => Utf8(true): key.as_ref().map(|value| value.binding_lifecycle.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::catalog_tests::CatalogFixture;
    use crate::{AnalysisExtractLimits, AnalysisReadModeV1, ValidatedEvidenceBatchV1};
    use sdk::arrow_array::{Array, BooleanArray, StringArray, UInt32Array, UInt64Array};

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn capture(fixture: &CatalogFixture, fields: &[&str]) -> TestResult<AnalysisPositionPageV1> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("data"))?;
        let frame = Vec::<u8>::try_from(&fixture.record)?;
        store.accept_validated_batch(
            fixture.identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                frame_ends: vec![frame.len()],
                framed_records: frame.into(),
            },
        )?;
        let schema = &AnalysisStore::table_schemas()["events"];
        let columns = fields
            .iter()
            .map(|field| schema.index_of(field))
            .collect::<std::result::Result<_, _>>()?;
        let requests = BTreeMap::from([("events".into(), Some(columns))]);
        let selection =
            AnalysisSelectionV1::new(fixture.identity.tenant_id, vec![fixture.identity.clone()]);
        Ok(store.read_tables(
            &selection,
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                inputs: None,
                mode: AnalysisReadModeV1::Complete,
                now: 2,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?)
    }

    #[test]
    fn checked_catalog_arrow_capture() -> TestResult {
        let fixture = CatalogFixture::new()?;
        let fields = [
            "catalog_profile_id",
            "catalog_profile_version",
            "catalog_policy_document_digest",
            "catalog_key_workload_selector_id",
            "catalog_key_protected_scope_id",
            "catalog_key_execution_set_id",
            "catalog_key_entry_kind",
            "catalog_key_role_id",
            "catalog_key_process_state_id",
            "catalog_key_effect_family",
            "catalog_key_operation_id",
            "catalog_key_operation",
            "catalog_key_operation_argument",
            "catalog_key_argument_wildcard",
            "catalog_key_object_selector",
            "catalog_key_binding_lifecycle",
            "framed_record",
            "source_cursor",
        ];
        let page = capture(&fixture, &fields)?;
        assert_eq!(page.extraction.witnesses.len(), 1);
        let batch = &page.tables["events"][0];
        assert_eq!(batch.num_rows(), 1);
        let key = &fixture.catalog.static_key;
        for (field, expected) in [
            ("catalog_profile_id", fixture.catalog.profile_id.as_str()),
            (
                "catalog_policy_document_digest",
                fixture.catalog.policy_document_digest.as_str(),
            ),
            (
                "catalog_key_workload_selector_id",
                key.workload_selector_id.as_str(),
            ),
            (
                "catalog_key_protected_scope_id",
                key.protected_scope_id.as_str(),
            ),
            (
                "catalog_key_execution_set_id",
                key.execution_set_id.as_str(),
            ),
            ("catalog_key_entry_kind", "CONTAINER_START"),
            ("catalog_key_role_id", key.role_id.as_str()),
            (
                "catalog_key_process_state_id",
                key.process_state_id.as_str(),
            ),
            ("catalog_key_operation_id", "OPEN_READ"),
            ("catalog_key_object_selector", key.object_selector.as_str()),
            ("catalog_key_binding_lifecycle", "ACTIVE"),
        ] {
            let array = batch
                .column_by_name(field)
                .ok_or("field")?
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or("Utf8")?;
            assert_eq!(array.null_count(), 0);
            assert_eq!(array.value(0), expected, "{field}");
        }
        for (field, expected) in [
            ("catalog_key_effect_family", 2),
            ("catalog_key_operation", 2),
            ("catalog_key_operation_argument", 0),
        ] {
            let array = batch
                .column_by_name(field)
                .ok_or("field")?
                .as_any()
                .downcast_ref::<UInt32Array>()
                .ok_or("UInt32")?;
            assert_eq!(array.value(0), expected, "{field}");
        }
        let version = batch
            .column_by_name("catalog_profile_version")
            .ok_or("version")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("UInt64")?;
        assert_eq!(version.value(0), fixture.catalog.profile_version);
        let wildcard = batch
            .column_by_name("catalog_key_argument_wildcard")
            .ok_or("wildcard")?
            .as_any()
            .downcast_ref::<BooleanArray>()
            .ok_or("Boolean")?;
        assert!(!wildcard.value(0));
        let frame = batch
            .column_by_name("framed_record")
            .ok_or("frame")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::BinaryArray>()
            .ok_or("Binary")?;
        assert_eq!(frame.value(0), Vec::<u8>::try_from(&fixture.record)?);
        Ok(())
    }

    #[test]
    fn checked_catalog_preserves_raw() -> TestResult {
        let mut fixture = CatalogFixture::new()?;
        fixture
            .record
            .decision_context
            .as_mut()
            .ok_or("context")?
            .catalog_json = b"invalid JSON".to_vec();
        assert!(capture(&fixture, &["catalog_profile_id"]).is_err());
        assert!(capture(&fixture, &["catalog_key_operation"]).is_err());
        let raw = capture(&fixture, &["framed_record", "catalog_json"])?;
        assert_eq!(raw.tables["events"][0].num_rows(), 1);
        fixture = CatalogFixture::new()?;
        fixture.record.exact_object_id = vec![99; 16].into();
        assert!(capture(&fixture, &["catalog_key_role_id"]).is_err());
        Ok(())
    }

    #[test]
    fn checked_catalog_absence() -> TestResult {
        let mut fixture = CatalogFixture::new()?;
        fixture.record.effect_family = 0;
        let context = fixture.record.decision_context.as_mut().ok_or("context")?;
        context.catalog_json.clear();
        context.catalog_state = "MISSING_CATALOG".into();
        let page = capture(&fixture, &["catalog_profile_id", "catalog_key_operation"])?;
        let batch = &page.tables["events"][0];
        assert_eq!(batch.num_rows(), 1);
        assert!(batch
            .columns()
            .iter()
            .all(|column| column.null_count() == 1));
        fixture
            .record
            .decision_context
            .as_mut()
            .ok_or("context")?
            .catalog_state = "AVAILABLE".into();
        assert!(capture(&fixture, &["catalog_profile_id"]).is_err());
        Ok(())
    }
}
