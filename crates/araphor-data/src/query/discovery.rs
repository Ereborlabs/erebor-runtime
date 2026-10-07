use duckdb::core::LogicalTypeId::*;
use duckdb::types::Value;
use snafu::IntoError as _;

use super::input::{InputField, InputRow, InputSchema};
use crate::{
    AnalysisContextVersionV1, BehaviorAtomV1, DiscoveryContextRevisionV1,
    DiscoveryPhysicalResultV1, DiscoveryProfileV1, DiscoveryProofKindV1, Result,
};

const PROFILE_ONLY: &str = "This field is present only on a profile row.";
const ATOM_ONLY: &str = "This field is present only on an atom row.";
const DOCUMENT_ONLY: &str = "This owner fact is not an imported discovery document.";

pub(super) const BEHAVIORS: InputSchema = InputSchema {
    name: "behaviors",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("node_id", Varchar, "exact Node ID", ""),
        InputField("node_boot_id", Blob, "16-byte ID", ""),
        InputField("label_epoch", UBigint, "label epoch", ""),
        InputField("source_id", Blob, "16-byte ID", ""),
        InputField("source_epoch", UBigint, "receipt source epoch", ""),
        InputField("cpu_id", UInteger, "CPU ID", ATOM_ONLY),
        InputField("profile_id", Varchar, "exact retained profile ID", ""),
        InputField("interval_id", Varchar, "stable profile interval ID", ""),
        InputField("profile_revision", UBigint, "profile revision", ""),
        InputField("facts_revision", UBigint, "captured policy-fact revision", ""),
        InputField("coverage_revision", UBigint, "captured coverage notice; qualified range revisions remain in coverage", ""),
        InputField("method_version", UBigint, "discovery method version", ""),
        InputField("commit_revision", UBigint, "captured store revision", ""),
        InputField("profile_state", Varchar, "working or sealed", ""),
        InputField("created_utc_ns", UBigint, "UTC nanoseconds", ""),
        InputField("updated_utc_ns", UBigint, "UTC nanoseconds", ""),
        InputField("input_bytes", UBigint, "accepted framed input bytes", ""),
        InputField("incomplete", Boolean, "explicit incomplete profile", ""),
        InputField("kind", Varchar, "profile or atom", ""),
        InputField("source_revision", Varchar, "exact input source revision", ""),
        InputField("proof_kind", Varchar, "unchanged proof class", ""),
        InputField("accepted_records", UBigint, "unique accepted source records", PROFILE_ONLY),
        InputField("included_records", UBigint, "resolved source records", PROFILE_ONLY),
        InputField("unresolved_records", UBigint, "unresolved source records", PROFILE_ONLY),
        InputField("excluded_records", UBigint, "explicitly excluded source records", PROFILE_ONLY),
        InputField("atom_key", Blob, "JSON full atom key; not a digest", ATOM_ONLY),
        InputField("subject_revision", Varchar, "exact workload subject revision", ATOM_ONLY),
        InputField("image_digest", Varchar, "retained image security identity", ATOM_ONLY),
        InputField("configuration_digest", Varchar, "retained configuration security identity", ATOM_ONLY),
        InputField("process_instance_id", Blob, "16-byte ID", ATOM_ONLY),
        InputField("entry_instance_id", Blob, "16-byte ID", ATOM_ONLY),
        InputField("binding_id", Blob, "16-byte ID", ATOM_ONLY),
        InputField("role_id", UInteger, "declared role ID", ATOM_ONLY),
        InputField("state_id", UInteger, "declared process state ID", ATOM_ONLY),
        InputField("entry_rule_id", UInteger, "declared entry rule ID", ATOM_ONLY),
        InputField("catalog_revision", UBigint, "exact decision catalog revision", ATOM_ONLY),
        InputField("generation", UBigint, "local profile generation", ATOM_ONLY),
        InputField("coverage_interval_id", Blob, "16-byte ID", ATOM_ONLY),
        InputField("temporal_coverage", Integer, "unchanged source coverage code", ATOM_ONLY),
        InputField("operation_id", Varchar, "exact static operation ID", ATOM_ONLY),
        InputField("static_key", Blob, "JSON full static policy key", ATOM_ONLY),
        InputField("policy_revision", Blob, "JSON exact retained policy provenance", ATOM_ONLY),
        InputField("effect", Blob, "JSON unchanged source effect fields", ATOM_ONLY),
        InputField("source_reason", UInteger, "unchanged source reason code", ATOM_ONLY),
        InputField("source_decision", UInteger, "unchanged source decision code", ATOM_ONLY),
        InputField("kernel_result", Integer, "unchanged kernel return code", ATOM_ONLY),
        InputField("physical_result", Varchar, "prevented or unknown", ATOM_ONLY),
        InputField("record_count", UBigint, "atom source-record count; zero on profile rows", ""),
        InputField("first_cursor", UBigint, "first source cursor", ATOM_ONLY),
        InputField("last_cursor", UBigint, "last source cursor", ATOM_ONLY),
        InputField("evidence_sample", Blob, "JSON exact source record references", ATOM_ONLY),
        InputField("coverage", Blob, "JSON explicit captured source ranges", ""),
        InputField("lifecycle", Blob, "JSON complete lifecycle matrix", PROFILE_ONLY),
        InputField("gaps", Blob, "JSON reported processor gaps", PROFILE_ONLY),
        InputField("context_refs", Blob, "JSON exact owner context references", PROFILE_ONLY),
        InputField("effect_family", UInteger, "unchanged source effect family", ATOM_ONLY),
        InputField("operation", UInteger, "unchanged source operation", ATOM_ONLY),
        InputField("operation_argument", UInteger, "unchanged source argument", "No source argument is present, or this is a profile row."),
        InputField("configured_errno", Integer, "configured pre-effect errno", ATOM_ONLY),
        InputField("exact_object_id", Blob, "exact source object ID", ATOM_ONLY),
        InputField("task_cookie", UBigint, "exact source task cookie", ATOM_ONLY),
        InputField("target_task_cookie", UBigint, "exact target task cookie", "No target task cookie is present, or this is a profile row."),
        InputField("unresolved", Blob, "JSON unresolved source record references and reasons", PROFILE_ONLY),
        InputField("excluded", Blob, "JSON excluded source record references and reasons", PROFILE_ONLY),
        InputField("discovery_enabled", Boolean, "captured runtime discovery owner presence", ""),
    ],
    join_keys: "tenant_id,profile_id,profile_revision,atom_key. atom_key contains the full source lifetime, static key, result, and proof class. Names and time are not join keys.",
    owner: "araphor-data.DiscoveryOwner",
    readiness: "conditional",
    description: "Current working and retained sealed profiles. Profile rows carry counts once; atom rows carry record_count. Source records are not physical-action counts. Coverage and unresolved records are explicit. No retained profile does not prove healthy coverage or current discovery enablement.",
};

pub(super) const CONTEXT: InputSchema = InputSchema {
    name: "context",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("owner_id", Varchar, "exact owner ID", ""),
        InputField("entity_key", Blob, "exact entity key", ""),
        InputField("lifetime_key", Blob, "exact lifetime key", ""),
        InputField("owner_revision", UBigint, "exact owner revision", ""),
        InputField("valid_from_utc_ns", UBigint, "inclusive UTC nanoseconds", "The owner did not provide a start time."),
        InputField("valid_until_utc_ns", UBigint, "exclusive UTC nanoseconds", "The owner did not provide an end time."),
        InputField("sensitivity", Varchar, "public, tenant, or host_restricted", ""),
        InputField("body", Blob, "unchanged owner body bytes", ""),
        InputField("kind", Varchar, "imported document kind", DOCUMENT_ONLY),
        InputField("subject_owner_id", Varchar, "exact subject owner ID", DOCUMENT_ONLY),
        InputField("subject_entity_key", Blob, "exact subject entity key", DOCUMENT_ONLY),
        InputField("subject_lifetime_key", Blob, "exact subject lifetime key", DOCUMENT_ONLY),
        InputField("subject_revision", UBigint, "exact subject owner revision", DOCUMENT_ONLY),
        InputField("method_id", Varchar, "exact method ID", DOCUMENT_ONLY),
        InputField("method_revision", UBigint, "exact method revision", DOCUMENT_ONLY),
        InputField("origin", Varchar, "unchanged document source", DOCUMENT_ONLY),
        InputField("trust", Varchar, "reviewed or unreviewed", DOCUMENT_ONLY),
        InputField("imported_utc_ns", UBigint, "recorded import UTC nanoseconds", DOCUMENT_ONLY),
        InputField("approver", Varchar, "explicit document reviewer", "This owner fact is not an imported document, or the document has no review."),
        InputField("text", Varchar, "unchanged document text; not execution instructions", DOCUMENT_ONLY),
    ],
    join_keys: "tenant_id,owner_id,entity_key,lifetime_key,owner_revision. A document also binds the exact subject and method revisions.",
    owner: "araphor-data.AnalysisStore",
    readiness: "available",
    description: "Exact authorized owner facts and imported document revisions. Source health, policy provenance, and inventory remain owner facts. Sensitivity and validity are unchanged. Document text grants no authority. Missing selected versions remain explicit in result metadata.",
};

pub(super) fn behavior_row(
    profile: &DiscoveryProfileV1,
    commit_revision: u64,
    atom: Option<&BehaviorAtomV1>,
    discovery_enabled: bool,
) -> Result<InputRow> {
    let source = &profile.scope.identity;
    let snapshot = &profile.snapshot;
    let proof = match snapshot.proof_kind {
        DiscoveryProofKindV1::ObservedRuntime => "OBSERVED_RUNTIME",
        DiscoveryProofKindV1::RecordedInput => "RECORDED_INPUT",
        DiscoveryProofKindV1::Synthetic => "SYNTHETIC",
        DiscoveryProofKindV1::ConfigurationScan => "CONFIGURATION_SCAN",
    };
    let mut row = InputRow(vec![
        Value::Blob(source.tenant_id.to_vec()),
        Value::Text(source.node_id.clone()),
        Value::Blob(source.node_boot_id.to_vec()),
        Value::UBigInt(source.label_epoch),
        Value::Blob(source.source_id.to_vec()),
        Value::UBigInt(source.source_epoch),
        atom.map_or(Value::Null, |atom| Value::UInt(atom.key.cpu_id)),
        Value::Text(profile.profile_id.clone()),
        Value::Text(profile.interval_id.clone()),
        Value::UBigInt(profile.revision),
        Value::UBigInt(profile.facts_revision),
        Value::UBigInt(profile.coverage_revision),
        Value::UBigInt(profile.scope.method_version),
        Value::UBigInt(commit_revision),
        Value::Text(if profile.sealed { "sealed" } else { "working" }.into()),
        Value::UBigInt(profile.created_utc_ns),
        Value::UBigInt(profile.updated_utc_ns),
        Value::UBigInt(profile.input_bytes),
        Value::Boolean(profile.incomplete),
        Value::Text(if atom.is_some() { "atom" } else { "profile" }.into()),
        Value::Text(snapshot.source_revision.clone()),
        Value::Text(proof.into()),
    ]);
    if let Some(atom) = atom {
        row.0.resize(row.0.len() + 4, Value::Null);
        let key = &atom.key;
        row.0.extend([
            json_blob(key)?,
            Value::Text(key.subject_revision.clone()),
            Value::Text(key.image_digest.clone()),
            Value::Text(key.configuration_digest.clone()),
            Value::Blob(key.process_instance_id.to_vec()),
            Value::Blob(key.entry_instance_id.to_vec()),
            Value::Blob(key.binding_id.to_vec()),
            Value::UInt(key.role_id),
            Value::UInt(key.state_id),
            Value::UInt(key.entry_rule_id),
            Value::UBigInt(key.catalog_revision),
            Value::UBigInt(key.generation),
            Value::Blob(key.coverage_interval_id.to_vec()),
            Value::Int(key.temporal_coverage),
            Value::Text(key.static_key.operation_id.clone()),
            json_blob(&key.static_key)?,
            json_blob(&key.policy_revision)?,
            json_blob(&key.effect)?,
            Value::UInt(key.effect.reason),
            Value::UInt(key.effect.decision),
            Value::Int(key.effect.kernel_result),
            Value::Text(
                match key.physical_result {
                    DiscoveryPhysicalResultV1::Prevented => "prevented",
                    DiscoveryPhysicalResultV1::Unknown => "unknown",
                }
                .into(),
            ),
            Value::UBigInt(atom.count),
            Value::UBigInt(atom.first_cursor),
            Value::UBigInt(atom.last_cursor),
            json_blob(&atom.evidence_sample)?,
        ]);
        let coverage: Vec<_> = snapshot
            .coverage
            .iter()
            .filter(|range| {
                range.stream == key.stream
                    && range.cpu_id == key.cpu_id
                    && range.coverage_interval_id == key.coverage_interval_id
            })
            .collect();
        row.0.push(json_blob(&coverage)?);
        row.0.resize(row.0.len() + 3, Value::Null);
        row.0.extend([
            Value::UInt(key.effect.effect_family),
            Value::UInt(key.effect.operation),
            key.effect
                .operation_argument
                .map_or(Value::Null, Value::UInt),
            Value::Int(key.effect.configured_errno),
            Value::Blob(key.effect.exact_object_id.clone()),
            Value::UBigInt(key.effect.task_cookie),
            key.effect
                .target_task_cookie
                .map_or(Value::Null, Value::UBigInt),
            Value::Null,
            Value::Null,
        ]);
    } else {
        row.0.extend([
            Value::UBigInt(snapshot.accepted_records),
            Value::UBigInt(snapshot.included_records),
            Value::UBigInt(snapshot.unresolved_records),
            Value::UBigInt(snapshot.excluded_records),
        ]);
        row.0.resize(row.0.len() + 22, Value::Null);
        row.0.push(Value::UBigInt(0));
        row.0.resize(row.0.len() + 3, Value::Null);
        row.0.extend([
            json_blob(&snapshot.coverage)?,
            json_blob(&snapshot.lifecycle)?,
            json_blob(&profile.gaps)?,
            json_blob(&profile.context_refs)?,
        ]);
        row.0.resize(row.0.len() + 7, Value::Null);
        row.0.extend([
            json_blob(&snapshot.unresolved)?,
            json_blob(&snapshot.excluded)?,
        ]);
    }
    row.0.push(Value::Boolean(discovery_enabled));
    Ok(row)
}

pub(super) fn context_row(context: &AnalysisContextVersionV1) -> Result<InputRow> {
    let mut row = InputRow::from(context);
    if context.key.owner_id == "discovery-context-v1" {
        let revision = DiscoveryContextRevisionV1::try_from(context)?;
        let document = &revision.document;
        row.0.extend([
            Value::Text(
                match document.kind {
                    crate::DiscoveryContextKindV1::Runbook => "RUNBOOK",
                    crate::DiscoveryContextKindV1::WorkloadOwnership => "WORKLOAD_OWNERSHIP",
                    crate::DiscoveryContextKindV1::DeploymentChange => "DEPLOYMENT_CHANGE",
                    crate::DiscoveryContextKindV1::ReviewedAssessment => "REVIEWED_ASSESSMENT",
                    crate::DiscoveryContextKindV1::ThreatReference => "THREAT_REFERENCE",
                }
                .into(),
            ),
            Value::Text(document.subject.owner_id.clone()),
            Value::Blob(document.subject.entity_key.clone()),
            Value::Blob(document.subject.lifetime_key.clone()),
            Value::UBigInt(document.subject.owner_revision),
            Value::Text(document.method.id.clone()),
            Value::UBigInt(document.method.revision),
            Value::Text(document.origin.clone()),
            Value::Text(
                match document.trust() {
                    crate::DiscoveryContextTrustV1::Reviewed => "reviewed",
                    crate::DiscoveryContextTrustV1::Unreviewed => "unreviewed",
                }
                .into(),
            ),
            Value::UBigInt(revision.imported_utc_ns),
            document.approver.clone().map_or(Value::Null, Value::Text),
            Value::Text(document.text.clone()),
        ]);
    } else {
        row.0.resize(CONTEXT.columns.len(), Value::Null);
    }
    Ok(row)
}

fn json_blob(value: &impl serde::Serialize) -> Result<Value> {
    serde_json::to_vec(value)
        .map(Value::Blob)
        .map_err(|source| crate::QueryEncodingSnafu.into_error(source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnalysisContextKeyV1, AnalysisInputV1, ContextSensitivityV1, DiscoveryContextDocumentV1,
        DiscoveryContextKindV1, DiscoveryInputManifestV1, DiscoveryMethodV1, DiscoveryOwner,
        ProcessorScopeV1, DISCOVERY_SCHEMA_VERSION,
    };

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

    fn profile() -> TestResult<DiscoveryProfileV1> {
        let input = DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
        )?;
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
            snapshot: DiscoveryOwner::derive_recorded(&input)?.snapshot,
            context_refs: Vec::new(),
        };
        profile.validate()?;
        Ok(profile)
    }

    fn field<'a>(schema: &InputSchema, row: &'a InputRow, name: &str) -> TestResult<&'a Value> {
        let index = schema
            .columns
            .iter()
            .position(|field| field.0 == name)
            .ok_or("query field absent")?;
        row.0.get(index).ok_or_else(|| "query value absent".into())
    }

    #[test]
    fn discovery_query_atom_projection() -> TestResult {
        let mut profile = profile()?;
        let summary = InputRow::try_from(AnalysisInputV1::Behavior {
            profile: &profile,
            commit_revision: 9,
            atom: None,
            discovery_enabled: true,
        })?;
        let atom = InputRow::try_from(AnalysisInputV1::Behavior {
            profile: &profile,
            commit_revision: 9,
            atom: Some(&profile.snapshot.atoms[0]),
            discovery_enabled: true,
        })?;
        assert_eq!(summary.0.len(), BEHAVIORS.columns.len());
        assert_eq!(atom.0.len(), BEHAVIORS.columns.len());
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
        assert!(atom.allocation_bytes()? > 0);
        profile.snapshot.atoms[0].key.static_key.argument_wildcard = true;
        profile.snapshot.atoms[0].key.static_key.operation_argument = 7;
        profile.snapshot.atoms[0].key.effect.operation_argument = Some(42);
        profile.validate()?;
        let atom = behavior_row(&profile, 9, Some(&profile.snapshot.atoms[0]), true)?;
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
        profile.snapshot = DiscoveryOwner::derive_recorded(&input)?.snapshot;
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
        let row = InputRow::try_from(AnalysisInputV1::DiscoveryContext(&fact))?;
        assert_eq!(row.0.len(), CONTEXT.columns.len());
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
        let row = InputRow::try_from(AnalysisInputV1::DiscoveryContext(&stored))?;
        assert_eq!(row.0.len(), CONTEXT.columns.len());
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
