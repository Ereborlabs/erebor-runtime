use super::input::relation;

const PROFILE_ONLY: &str = "This field is present only on a profile row.";
const ATOM_ONLY: &str = "This field is present only on an atom row.";
const DOCUMENT_ONLY: &str = "This owner fact is not an imported discovery document.";

relation! {
    pub(super) BEHAVIORS, behavior(sink; profile: &crate::DiscoveryProfileV1, commit_revision: u64, atom: Option<&crate::BehaviorAtomV1>, discovery_enabled: bool) {
        name: "behaviors",
        join_keys: "tenant_id,profile_id,profile_revision,atom_key. atom_key contains the full source lifetime, static key, result, and proof class. Names and time are not join keys.",
        owner: "araphor-data.DiscoveryOwner",
        readiness: "conditional",
        description: "Current working and retained sealed profiles. Profile rows carry counts once; atom rows carry record_count. Source records are not physical-action counts. Coverage and unresolved records are explicit. No retained profile does not prove healthy coverage or current discovery enablement.",
        setup {
            let source = &profile.scope.identity;
            let snapshot = &profile.snapshot;
            let key = atom.map(|atom| &atom.key);
            let proof = match snapshot.proof_kind {
                crate::DiscoveryProofKindV1::ObservedRuntime => "OBSERVED_RUNTIME",
                crate::DiscoveryProofKindV1::RecordedInput => "RECORDED_INPUT",
                crate::DiscoveryProofKindV1::Synthetic => "SYNTHETIC",
                crate::DiscoveryProofKindV1::ConfigurationScan => "CONFIGURATION_SCAN",
            };
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(source.tenant_id.as_slice());
            node_id: Utf8("exact Node ID", "") => Some(source.node_id.as_str());
            node_boot_id: Binary("16-byte ID", "") => Some(source.node_boot_id.as_slice());
            label_epoch: UInt64("label epoch", "") => Some(source.label_epoch);
            source_id: Binary("16-byte ID", "") => Some(source.source_id.as_slice());
            source_epoch: UInt64("receipt source epoch", "") => Some(source.source_epoch);
            cpu_id: UInt32("CPU ID", ATOM_ONLY) => key.map(|key| key.cpu_id);
            profile_id: Utf8("exact retained profile ID", "") => Some(profile.profile_id.as_str());
            interval_id: Utf8("stable profile interval ID", "") => Some(profile.interval_id.as_str());
            profile_revision: UInt64("profile revision", "") => Some(profile.revision);
            facts_revision: UInt64("captured policy-fact revision", "") => Some(profile.facts_revision);
            coverage_revision: UInt64("captured coverage notice; qualified range revisions remain in coverage", "") =>
                Some(profile.coverage_revision);
            method_version: UInt64("discovery method version", "") => Some(profile.scope.method_version);
            commit_revision: UInt64("captured store revision", "") => Some(commit_revision);
            profile_state: Utf8("working or sealed", "") => Some(if profile.sealed { "sealed" } else { "working" });
            created_utc_ns: UInt64("UTC nanoseconds", "") => Some(profile.created_utc_ns);
            updated_utc_ns: UInt64("UTC nanoseconds", "") => Some(profile.updated_utc_ns);
            input_bytes: UInt64("accepted framed input bytes", "") => Some(profile.input_bytes);
            incomplete: Boolean("explicit incomplete profile", "") => Some(profile.incomplete);
            kind: Utf8("profile or atom", "") => Some(if atom.is_some() { "atom" } else { "profile" });
            source_revision: Utf8("exact input source revision", "") => Some(snapshot.source_revision.as_str());
            proof_kind: Utf8("unchanged proof class", "") => Some(proof);
            accepted_records: UInt64("unique accepted source records", PROFILE_ONLY) =>
                atom.is_none().then_some(snapshot.accepted_records);
            included_records: UInt64("resolved source records", PROFILE_ONLY) =>
                atom.is_none().then_some(snapshot.included_records);
            unresolved_records: UInt64("unresolved source records", PROFILE_ONLY) =>
                atom.is_none().then_some(snapshot.unresolved_records);
            excluded_records: UInt64("explicitly excluded source records", PROFILE_ONLY) =>
                atom.is_none().then_some(snapshot.excluded_records);
            atom_key: Binary("JSON full atom key; not a digest", ATOM_ONLY) =>
                key.map(|key| Self::json(sink, key)).transpose()?;
            subject_revision: Utf8("exact workload subject revision", ATOM_ONLY) =>
                key.map(|key| key.subject_revision.as_str());
            image_digest: Utf8("retained image security identity", ATOM_ONLY) =>
                key.map(|key| key.image_digest.as_str());
            configuration_digest: Utf8("retained configuration security identity", ATOM_ONLY) =>
                key.map(|key| key.configuration_digest.as_str());
            process_instance_id: Binary("16-byte ID", ATOM_ONLY) =>
                key.map(|key| key.process_instance_id.as_slice());
            entry_instance_id: Binary("16-byte ID", ATOM_ONLY) => key.map(|key| key.entry_instance_id.as_slice());
            binding_id: Binary("16-byte ID", ATOM_ONLY) => key.map(|key| key.binding_id.as_slice());
            role_id: UInt32("declared role ID", ATOM_ONLY) => key.map(|key| key.role_id);
            state_id: UInt32("declared process state ID", ATOM_ONLY) => key.map(|key| key.state_id);
            entry_rule_id: UInt32("declared entry rule ID", ATOM_ONLY) => key.map(|key| key.entry_rule_id);
            catalog_revision: UInt64("exact decision catalog revision", ATOM_ONLY) =>
                key.map(|key| key.catalog_revision);
            generation: UInt64("local profile generation", ATOM_ONLY) => key.map(|key| key.generation);
            coverage_interval_id: Binary("16-byte ID", ATOM_ONLY) =>
                key.map(|key| key.coverage_interval_id.as_slice());
            temporal_coverage: Int32("unchanged source coverage code", ATOM_ONLY) =>
                key.map(|key| key.temporal_coverage);
            operation_id: Utf8("exact static operation ID", ATOM_ONLY) =>
                key.map(|key| key.static_key.operation_id.as_str());
            static_key: Binary("JSON full static policy key", ATOM_ONLY) =>
                key.map(|key| Self::json(sink, &key.static_key)).transpose()?;
            policy_revision: Binary("JSON exact retained policy provenance", ATOM_ONLY) =>
                key.map(|key| Self::json(sink, &key.policy_revision)).transpose()?;
            effect: Binary("JSON unchanged source effect fields", ATOM_ONLY) =>
                key.map(|key| Self::json(sink, &key.effect)).transpose()?;
            source_reason: UInt32("unchanged source reason code", ATOM_ONLY) => key.map(|key| key.effect.reason);
            source_decision: UInt32("unchanged source decision code", ATOM_ONLY) =>
                key.map(|key| key.effect.decision);
            kernel_result: Int32("unchanged kernel return code", ATOM_ONLY) =>
                key.map(|key| key.effect.kernel_result);
            physical_result: Utf8("prevented or unknown", ATOM_ONLY) =>
                key.map(|key| match key.physical_result { crate::DiscoveryPhysicalResultV1::Prevented => "prevented", crate::DiscoveryPhysicalResultV1::Unknown => "unknown" });
            record_count: UInt64("atom source-record count; zero on profile rows", "") =>
                Some(atom.map_or(0, |atom| atom.count));
            first_cursor: UInt64("first source cursor", ATOM_ONLY) => atom.map(|atom| atom.first_cursor);
            last_cursor: UInt64("last source cursor", ATOM_ONLY) => atom.map(|atom| atom.last_cursor);
            evidence_sample: Binary("JSON exact source record references", ATOM_ONLY) =>
                atom.map(|atom| Self::json(sink, &atom.evidence_sample)).transpose()?;
            coverage: Binary("JSON explicit captured source ranges", "") =>
                Some(if let Some(key) = key {
                    let mut ranges = Vec::new();
                    for range in &snapshot.coverage {
                        if range.stream == key.stream && range.cpu_id == key.cpu_id && range.coverage_interval_id == key.coverage_interval_id {
                            sink.grow(&mut ranges)?;
                            ranges.push(range);
                        }
                    }
                    Self::json(sink, &ranges)?
                } else { Self::json(sink, &snapshot.coverage)? });
            lifecycle: Binary("JSON complete lifecycle matrix", PROFILE_ONLY) =>
                if atom.is_none() { Some(Self::json(sink, &snapshot.lifecycle)?) } else { None };
            gaps: Binary("JSON reported processor gaps", PROFILE_ONLY) =>
                if atom.is_none() { Some(Self::json(sink, &profile.gaps)?) } else { None };
            context_refs: Binary("JSON exact owner context references", PROFILE_ONLY) =>
                if atom.is_none() { Some(Self::json(sink, &profile.context_refs)?) } else { None };
            effect_family: UInt32("unchanged source effect family", ATOM_ONLY) =>
                key.map(|key| key.effect.effect_family);
            operation: UInt32("unchanged source operation", ATOM_ONLY) => key.map(|key| key.effect.operation);
            operation_argument: UInt32("unchanged source argument", "No source argument is present, or this is a profile row.") =>
                key.and_then(|key| key.effect.operation_argument);
            configured_errno: Int32("configured pre-effect errno", ATOM_ONLY) =>
                key.map(|key| key.effect.configured_errno);
            exact_object_id: Binary("exact source object ID", ATOM_ONLY) =>
                key.map(|key| key.effect.exact_object_id.as_slice());
            task_cookie: UInt64("exact source task cookie", ATOM_ONLY) => key.map(|key| key.effect.task_cookie);
            target_task_cookie: UInt64("exact target task cookie", "No target task cookie is present, or this is a profile row.") =>
                key.and_then(|key| key.effect.target_task_cookie);
            unresolved: Binary("JSON unresolved source record references and reasons", PROFILE_ONLY) =>
                if atom.is_none() { Some(Self::json(sink, &snapshot.unresolved)?) } else { None };
            excluded: Binary("JSON excluded source record references and reasons", PROFILE_ONLY) =>
                if atom.is_none() { Some(Self::json(sink, &snapshot.excluded)?) } else { None };
            discovery_enabled: Boolean("captured runtime discovery owner presence", "") => Some(discovery_enabled);
        }
    }
}

relation! {
    pub(super) CONTEXT, discovery_context(sink; context: &crate::AnalysisContextVersionV1) {
        name: "context",
        join_keys: "tenant_id,owner_id,entity_key,lifetime_key,owner_revision. A document also binds the exact subject and method revisions.",
        owner: "araphor-data.AnalysisStore",
        readiness: "available",
        description: "Exact authorized owner facts and imported document revisions. Source health, policy provenance, and inventory remain owner facts. Sensitivity and validity are unchanged. Document text grants no authority. Missing selected versions remain explicit in result metadata.",
        setup {
            let revision = if context.key.owner_id == "discovery-context-v1" {
                Some(crate::DiscoveryContextRevisionV1::try_from(context)?)
            } else { None };
            let document = revision.as_ref().map(|revision| &revision.document);
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(context.key.tenant_id.as_slice());
            owner_id: Utf8("exact owner ID", "") => Some(context.key.owner_id.as_str());
            entity_key: Binary("exact entity key", "") => Some(context.key.entity_key.as_slice());
            lifetime_key: Binary("exact lifetime key", "") => Some(context.key.lifetime_key.as_slice());
            owner_revision: UInt64("exact owner revision", "") => Some(context.key.owner_revision);
            valid_from_utc_ns: UInt64("inclusive UTC nanoseconds", "The owner did not provide a start time.") =>
                context.valid_from_utc_ns;
            valid_until_utc_ns: UInt64("exclusive UTC nanoseconds", "The owner did not provide an end time.") =>
                context.valid_until_utc_ns;
            sensitivity: Utf8("public, tenant, or host_restricted", "") => Some(<&str>::from(context.sensitivity));
            body: Binary("unchanged owner body bytes", "") => Some(context.body.as_slice());
            kind: Utf8("imported document kind", DOCUMENT_ONLY) =>
                document.map(|document| match document.kind {
                    crate::DiscoveryContextKindV1::Runbook => "RUNBOOK",
                    crate::DiscoveryContextKindV1::WorkloadOwnership => "WORKLOAD_OWNERSHIP",
                    crate::DiscoveryContextKindV1::DeploymentChange => "DEPLOYMENT_CHANGE",
                    crate::DiscoveryContextKindV1::ReviewedAssessment => "REVIEWED_ASSESSMENT",
                    crate::DiscoveryContextKindV1::ThreatReference => "THREAT_REFERENCE",
                });
            subject_owner_id: Utf8("exact subject owner ID", DOCUMENT_ONLY) =>
                document.map(|document| document.subject.owner_id.as_str());
            subject_entity_key: Binary("exact subject entity key", DOCUMENT_ONLY) =>
                document.map(|document| document.subject.entity_key.as_slice());
            subject_lifetime_key: Binary("exact subject lifetime key", DOCUMENT_ONLY) =>
                document.map(|document| document.subject.lifetime_key.as_slice());
            subject_revision: UInt64("exact subject owner revision", DOCUMENT_ONLY) =>
                document.map(|document| document.subject.owner_revision);
            method_id: Utf8("exact method ID", DOCUMENT_ONLY) =>
                document.map(|document| document.method.id.as_str());
            method_revision: UInt64("exact method revision", DOCUMENT_ONLY) =>
                document.map(|document| document.method.revision);
            origin: Utf8("unchanged document source", DOCUMENT_ONLY) =>
                document.map(|document| document.origin.as_str());
            trust: Utf8("reviewed or unreviewed", DOCUMENT_ONLY) =>
                document.map(|document| match document.trust() { crate::DiscoveryContextTrustV1::Reviewed => "reviewed", crate::DiscoveryContextTrustV1::Unreviewed => "unreviewed" });
            imported_utc_ns: UInt64("recorded import UTC nanoseconds", DOCUMENT_ONLY) =>
                revision.as_ref().map(|revision| revision.imported_utc_ns);
            approver: Utf8("explicit document reviewer", "This owner fact is not an imported document, or the document has no review.") =>
                document.and_then(|document| document.approver.as_deref());
            text: Utf8("unchanged document text; not execution instructions", DOCUMENT_ONLY) =>
                document.map(|document| document.text.as_str());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::input::{tests::mapped, InputSchema};
    use crate::{
        AnalysisContextKeyV1, AnalysisInputV1, ContextSensitivityV1, DiscoveryContextDocumentV1,
        DiscoveryContextKindV1, DiscoveryInputManifestV1, DiscoveryMethodV1, DiscoveryOwner,
        ProcessorScopeV1, DISCOVERY_SCHEMA_VERSION,
    };
    use crate::{AnalysisContextVersionV1, DiscoveryContextRevisionV1, DiscoveryProfileV1};
    use duckdb::types::Value;

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

    fn profile() -> TestResult<DiscoveryProfileV1> {
        let input = DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
        )?;
        let execution = crate::InstalledAnalysis::testing(None, input.tenant_id)?;
        let profile = DiscoveryProfileV1 {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            scope: ProcessorScopeV1 {
                processor_id: "discovery".into(),
                method_version: u64::from(DISCOVERY_SCHEMA_VERSION),
                identity: input.coverage[0].stream.clone(),
            },
            profile_id: "retained-profile".into(),
            interval_id: "retained-profile".into(),
            revision: 1,
            facts_revision: 1,
            coverage_revision: 2,
            created_utc_ns: 1000,
            updated_utc_ns: 3000,
            sealed: true,
            input_bytes: input
                .records
                .iter()
                .map(|record| record.wire_record.len() as u64)
                .sum(),
            incomplete: true,
            gaps: Vec::new(),
            snapshot: DiscoveryOwner::derive_recorded(&input, &execution)?.snapshot,
            context_refs: Vec::new(),
        };
        profile.validate()?;
        Ok(profile)
    }

    fn field<'a>(schema: &InputSchema, row: &'a [Value], name: &str) -> TestResult<&'a Value> {
        let index = schema
            .fields()
            .iter()
            .position(|field| field.name().as_str() == name)
            .ok_or("query field absent")?;
        row.get(index).ok_or_else(|| "query value absent".into())
    }

    #[test]
    fn discovery_query_atom_projection() -> TestResult {
        let mut profile = profile()?;
        let summary = mapped(AnalysisInputV1::Behavior {
            profile: &profile,
            commit_revision: 9,
            atom: None,
            discovery_enabled: true,
        })?;
        let atom = mapped(AnalysisInputV1::Behavior {
            profile: &profile,
            commit_revision: 9,
            atom: Some(&profile.snapshot.atoms[0]),
            discovery_enabled: true,
        })?;
        assert_eq!(summary.len(), BEHAVIORS.fields().len());
        assert_eq!(atom.len(), BEHAVIORS.fields().len());
        assert_eq!(
            field(&BEHAVIORS, &summary, "coverage_revision")?,
            &Value::UBigInt(2)
        );
        assert_eq!(
            field(&BEHAVIORS, &atom, "coverage_revision")?,
            &Value::UBigInt(2)
        );
        assert_eq!(
            field(&BEHAVIORS, &summary, "accepted_records")?,
            &Value::UBigInt(3)
        );
        assert_eq!(
            field(&BEHAVIORS, &summary, "unresolved_records")?,
            &Value::UBigInt(1)
        );
        assert_eq!(
            field(&BEHAVIORS, &summary, "record_count")?,
            &Value::UBigInt(0)
        );
        assert_eq!(field(&BEHAVIORS, &atom, "accepted_records")?, &Value::Null);
        assert_eq!(
            field(&BEHAVIORS, &atom, "record_count")?,
            &Value::UBigInt(2)
        );
        assert_eq!(field(&BEHAVIORS, &atom, "kernel_result")?, &Value::Int(-13));
        assert_eq!(
            field(&BEHAVIORS, &atom, "source_reason")?,
            &Value::UInt(profile.snapshot.atoms[0].key.effect.reason)
        );
        assert_eq!(
            field(&BEHAVIORS, &atom, "source_decision")?,
            &Value::UInt(profile.snapshot.atoms[0].key.effect.decision)
        );
        assert_eq!(
            field(&BEHAVIORS, &atom, "physical_result")?,
            &Value::Text("prevented".into())
        );
        let Value::Blob(key) = field(&BEHAVIORS, &atom, "atom_key")? else {
            return Err("full atom key absent".into());
        };
        assert_eq!(
            serde_json::from_slice::<crate::BehaviorAtomKeyV1>(key)?,
            profile.snapshot.atoms[0].key
        );
        assert_eq!(field(&BEHAVIORS, &atom, "lifecycle")?, &Value::Null);
        assert!(!atom.is_empty());
        profile.snapshot.atoms[0].key.static_key.argument_wildcard = true;
        profile.snapshot.atoms[0].key.static_key.operation_argument = 7;
        profile.snapshot.atoms[0].key.effect.operation_argument = Some(42);
        profile.validate()?;
        let atom = mapped(AnalysisInputV1::Behavior {
            profile: &profile,
            commit_revision: 9,
            atom: Some(&profile.snapshot.atoms[0]),
            discovery_enabled: true,
        })?;
        assert_eq!(
            field(&BEHAVIORS, &atom, "operation_argument")?,
            &Value::UInt(42)
        );
        let Value::Blob(key) = field(&BEHAVIORS, &atom, "static_key")? else {
            return Err("full static key absent".into());
        };
        let key: crate::DiscoveryPolicyKeyV1 = serde_json::from_slice(key)?;
        assert!(key.argument_wildcard);
        assert_eq!(key.operation_argument, 7);
        Ok(())
    }

    #[test]
    fn discovery_query_format_rejection() -> TestResult {
        let mut profile = profile()?;
        let mut input = DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
        )?;
        input.records.clear();
        input.contexts.clear();
        input.coverage.clear();
        input.exclusions.clear();
        input.lifecycle.clear();
        profile.snapshot = DiscoveryOwner::derive_recorded(
            &input,
            &crate::InstalledAnalysis::testing(None, input.tenant_id)?,
        )?
        .snapshot;
        profile.input_bytes = 0;
        assert!(profile.snapshot.atoms.is_empty());
        for sealed in [false, true] {
            profile.sealed = sealed;
            let bytes = serde_json::to_vec(&profile)?;
            assert_eq!(DiscoveryProfileV1::try_from(bytes.as_slice())?, profile);
            for change in 0..3 {
                let mut old = serde_json::to_value(&profile)?;
                match change {
                    0 => old["schema_version"] = serde_json::json!(DISCOVERY_SCHEMA_VERSION - 1),
                    1 => {
                        old["scope"]["method_version"] =
                            serde_json::json!(DISCOVERY_SCHEMA_VERSION - 1)
                    }
                    _ => {
                        old["snapshot"]["schema_version"] =
                            serde_json::json!(DISCOVERY_SCHEMA_VERSION - 1)
                    }
                }
                assert!(matches!(
                    DiscoveryProfileV1::try_from(serde_json::to_vec(&old)?.as_slice()),
                    Err(crate::Error::DiscoveryInvalid {
                        field: "profile bounds" | "snapshot schema",
                        ..
                    })
                ));
            }
        }
        input.schema_version = DISCOVERY_SCHEMA_VERSION - 1;
        assert!(matches!(
            DiscoveryInputManifestV1::try_from(serde_json::to_vec(&input)?.as_slice()),
            Err(crate::Error::DiscoveryInvalid {
                field: "schema version",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn discovery_query_context_projection() -> TestResult {
        let profile = profile()?;
        let subject = AnalysisContextKeyV1 {
            tenant_id: profile.scope.identity.tenant_id,
            owner_id: "inventory".into(),
            entity_key: b"workload".to_vec(),
            lifetime_key: b"exact-lifetime".to_vec(),
            owner_revision: 3,
        };
        let fact = AnalysisContextVersionV1 {
            key: subject.clone(),
            valid_from_utc_ns: Some(1000),
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::HostRestricted,
            body: b"unchanged qualified owner fact".to_vec(),
        };
        let row = mapped(AnalysisInputV1::DiscoveryContext(&fact))?;
        assert_eq!(row.len(), CONTEXT.fields().len());
        assert_eq!(
            field(&CONTEXT, &row, "body")?,
            &Value::Blob(fact.body.clone())
        );
        assert_eq!(
            field(&CONTEXT, &row, "sensitivity")?,
            &Value::Text("host_restricted".into())
        );
        assert_eq!(field(&CONTEXT, &row, "trust")?, &Value::Null);
        let document = DiscoveryContextRevisionV1 {
            imported_utc_ns: 2500,
            document: DiscoveryContextDocumentV1 {
                schema_version: DISCOVERY_SCHEMA_VERSION,
                tenant_id: subject.tenant_id,
                id: "runbook".into(),
                revision: 1,
                kind: DiscoveryContextKindV1::Runbook,
                subject: subject.clone(),
                method: DiscoveryMethodV1 {
                    id: "credential-read".into(),
                    revision: 2,
                },
                origin: "operator".into(),
                valid_from_utc_ns: 1000,
                valid_until_utc_ns: None,
                sensitivity: ContextSensitivityV1::Tenant,
                approver: None,
                text: "Supplied instructions remain text.".into(),
            },
        };
        let stored = AnalysisContextVersionV1::try_from(&document)?;
        let row = mapped(AnalysisInputV1::DiscoveryContext(&stored))?;
        assert_eq!(row.len(), CONTEXT.fields().len());
        assert_eq!(
            field(&CONTEXT, &row, "subject_revision")?,
            &Value::UBigInt(3)
        );
        assert_eq!(
            field(&CONTEXT, &row, "method_revision")?,
            &Value::UBigInt(2)
        );
        assert_eq!(
            field(&CONTEXT, &row, "trust")?,
            &Value::Text("unreviewed".into())
        );
        assert_eq!(
            field(&CONTEXT, &row, "text")?,
            &Value::Text(document.document.text)
        );
        Ok(())
    }
}
