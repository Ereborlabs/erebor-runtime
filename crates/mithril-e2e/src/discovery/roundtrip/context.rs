use std::error::Error;

use araphor_data::{
    AnalysisContextKeyV1, ContextSensitivityV1, DiscoveryContextAccessV1,
    DiscoveryContextBindingV1, DiscoveryContextEvidenceV1, DiscoveryContextRequestV1,
    DiscoveryContextViewV1, DiscoveryMethodV1, DiscoveryOwner, DiscoveryProofKindV1,
    DiscoveryRecordV1,
};

pub(super) fn check(
    record: &DiscoveryRecordV1,
    binding: &DiscoveryContextBindingV1,
) -> Result<(), Box<dyn Error>> {
    let subject = AnalysisContextKeyV1 {
        tenant_id: record.id.stream.tenant_id,
        owner_id: "discovery".into(),
        entity_key: record.id.stream.exact_key(),
        lifetime_key: binding.process_instance_id.to_vec(),
        owner_revision: binding.catalog_revision,
    };
    let mut request = DiscoveryContextRequestV1 {
        access: DiscoveryContextAccessV1 {
            tenant_id: record.id.stream.tenant_id,
            subject: subject.clone(),
            principal: "qualified-operator".into(),
            grant_revision: 3,
            purpose: "inspect retained process context".into(),
            sensitivities: vec![ContextSensitivityV1::Tenant],
            can_import: false,
            can_review: false,
        },
        method: DiscoveryMethodV1 {
            id: "qualified-context".into(),
            revision: 2,
        },
        from_utc_ns: 1000,
        cutoff_utc_ns: 3000,
        question: "Which retained records are in this context window?".into(),
        records: vec![DiscoveryContextEvidenceV1 {
            record_id: record.id.clone(),
            subject,
            received_utc_ns: Some(2000),
            proof_kind: DiscoveryProofKindV1::ObservedRuntime,
        }],
        owner_facts: Vec::new(),
        missing_facts: Vec::new(),
    };
    let input = DiscoveryOwner::context_input(&request, &[])?;
    let selected = DiscoveryContextViewV1::try_from(&input)?;
    if selected.records != request.records
        || selected.access != request.access
        || selected.method != request.method
        || selected.cutoff_utc_ns != 3000
        || input.data.name != "context"
        || input.data.batches.len() != 1
        || input.data.batches[0].num_rows() != 1
        || !input
            .coverage
            .limits
            .iter()
            .any(|reason| reason == "SOURCE_HEALTH_UNAVAILABLE")
    {
        return Err(
            "the SDK context input changed the selected identities or missing facts".into(),
        );
    }
    request.cutoff_utc_ns = 1999;
    let cutoff = DiscoveryOwner::context_input(&request, &[])?;
    let selected = DiscoveryContextViewV1::try_from(&cutoff)?;
    if !selected.records.is_empty()
        || selected.omissions.get("EVIDENCE_OUTSIDE_WINDOW_OR_UNDATED") != Some(&1)
        || cutoff.revision.id == input.revision.id
        || !cutoff
            .coverage
            .limits
            .iter()
            .any(|reason| reason == "NO_QUALIFIED_SUBJECT_EVIDENCE")
    {
        return Err("the SDK context input lost its cutoff or omissions".into());
    }
    Ok(())
}
