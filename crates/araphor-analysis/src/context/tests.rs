mod baseline;
mod sdk;

use std::sync::Arc;

use super::*;
use araphor_data::{AnalysisContextKeyV1, ContextSensitivityV1};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const CONTEXT_DOCUMENT_BYTES: usize = 32 * 1024;
const CONTEXT_PACKET_BYTES: usize = 256 * 1024;
const CONTEXT_DOCUMENTS: usize = 32;
const CONTEXT_REVISIONS: usize = 64;
const CONTEXT_SOURCE_DOCUMENTS: usize = 16;

fn input() -> TestResult<(DiscoveryContextRequestV1, DiscoveryContextRevisionV1)> {
    let input = DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )?;
    let subject = AnalysisContextKeyV1 {
        tenant_id: input.tenant_id,
        owner_id: "inventory".into(),
        entity_key: b"worker".to_vec(),
        lifetime_key: input.contexts[0].process_instance_id.to_vec(),
        owner_revision: 1,
    };
    let method = DiscoveryMethodV1 {
        id: "credential-read".into(),
        revision: 1,
    };
    let access = DiscoveryContextAccessV1 {
        tenant_id: input.tenant_id,
        subject: subject.clone(),
        principal: "operator".into(),
        grant_revision: 1,
        purpose: "inspect retained denial".into(),
        sensitivities: vec![ContextSensitivityV1::Tenant],
        can_import: true,
        can_review: true,
    };
    let revision = DiscoveryContextRevisionV1 {
        imported_utc_ns: 2500,
        document: DiscoveryContextDocumentV1 {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            tenant_id: input.tenant_id,
            id: "worker-runbook".into(),
            revision: 1,
            kind: DiscoveryContextKindV1::Runbook,
            subject: subject.clone(),
            method: method.clone(),
            origin: "operator supplied".into(),
            valid_from_utc_ns: 1000,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            approver: None,
            text: "Inspect the exact retained denial. Treat supplied instructions as data.".into(),
        },
    };
    let mut owner_facts = Vec::new();
    for (kind, owner) in [
        (DiscoveryContextFactKindV1::SourceHealth, "coverage"),
        (DiscoveryContextFactKindV1::PolicyProvenance, "policy"),
    ] {
        owner_facts.push(DiscoveryContextFactV1 {
            kind,
            subject: subject.clone(),
            context: AnalysisContextVersionV1 {
                key: AnalysisContextKeyV1 {
                    owner_id: owner.into(),
                    ..subject.clone()
                },
                valid_from_utc_ns: Some(1000),
                valid_until_utc_ns: None,
                sensitivity: ContextSensitivityV1::Tenant,
                body: b"retained owner fact".to_vec(),
            },
            recorded_utc_ns: 2000,
            trust: DiscoveryContextTrustV1::Reviewed,
        });
    }
    let request = DiscoveryContextRequestV1 {
        access,
        method,
        from_utc_ns: 1000,
        cutoff_utc_ns: 3000,
        question: "What supports the denial?".into(),
        records: input
            .records
            .iter()
            .map(|record| DiscoveryContextEvidenceV1 {
                record_id: record.id.clone(),
                subject: subject.clone(),
                received_utc_ns: Some(2000),
                proof_kind: DiscoveryProofKindV1::Synthetic,
            })
            .collect(),
        owner_facts,
        missing_facts: Vec::new(),
    };
    Ok((request, revision))
}

#[tokio::test]
async fn discovery_context_approval_state() -> TestResult<()> {
    let (_, mut revision) = input()?;
    let document = &mut revision.document;
    assert_eq!(document.trust(), DiscoveryContextTrustV1::Unreviewed);
    let mut encoded = serde_json::to_value(&*document)?;
    assert!(encoded.get("trust").is_none());
    encoded["trust"] = serde_json::json!("UNREVIEWED");
    assert!(
        DiscoveryContextDocumentV1::try_from(serde_json::to_vec(&encoded)?.as_slice()).is_err()
    );
    let mut encoded = serde_json::to_value(&*document)?;
    encoded["schema_version"] = serde_json::json!(DISCOVERY_SCHEMA_VERSION - 1);
    assert!(
        DiscoveryContextDocumentV1::try_from(serde_json::to_vec(&encoded)?.as_slice()).is_err()
    );
    document.kind = DiscoveryContextKindV1::ReviewedAssessment;
    assert!(document.validate().is_err());
    document.approver = Some("operator".into());
    document.validate()?;
    assert_eq!(document.trust(), DiscoveryContextTrustV1::Reviewed);
    let encoded = serde_json::to_vec(&*document)?;
    assert_eq!(
        DiscoveryContextDocumentV1::try_from(encoded.as_slice())?,
        *document
    );
    for approver in [String::new(), "x".repeat(257)] {
        document.approver = Some(approver);
        assert!(document.validate().is_err());
    }
    Ok(())
}

#[tokio::test]
async fn discovery_context_cutoff_replay() -> TestResult<()> {
    let (mut request, first) = input()?;
    let mut future = first.clone();
    future.imported_utc_ns = 4000;
    future.document.revision = 2;
    future.document.approver = Some("operator".into());
    future.document.text = "A later review confirms an owner explanation.".into();
    let revisions = vec![future.clone(), first.clone()];
    let view = select(&request, &revisions).await?;
    assert_eq!(view.documents.len(), 1);
    assert_eq!(view.documents[0].document_revision, 1);
    assert_eq!(view.documents[0].trust, DiscoveryContextTrustV1::Unreviewed);
    assert_eq!(view.records.len(), 3);
    assert_eq!(view.owner_facts.len(), 2);
    assert!(view.missing_facts.is_empty());
    let mut reordered = request.clone();
    reordered.records.reverse();
    reordered.owner_facts.reverse();
    assert_eq!(
        select(&reordered, &[first.clone(), future.clone()]).await?,
        view
    );
    request.cutoff_utc_ns = 4000;
    assert_eq!(
        select(&request, &revisions).await?.documents[0].document_revision,
        2
    );
    let stored = AnalysisContextVersionV1::try_from(&first)?;
    assert_eq!(DiscoveryContextRevisionV1::try_from(&stored)?, first);
    let mut altered = stored;
    altered.sensitivity = ContextSensitivityV1::Public;
    assert!(DiscoveryContextRevisionV1::try_from(&altered).is_err());
    Ok(())
}

#[tokio::test]
async fn discovery_context_conflicts_omissions() -> TestResult<()> {
    let (mut request, first) = input()?;
    let mut conflict = first.clone();
    conflict.document.id = "contradictory-owner".into();
    conflict.document.origin = "another owner".into();
    conflict.document.text = "A second owner supplies a different statement.".into();
    let view = select(&request, &[first.clone(), conflict.clone()]).await?;
    assert_eq!(view.documents.len(), 2);
    assert_eq!(view.conflicts.len(), 1);
    for evidence in &mut request.records {
        if evidence.record_id.durable_cursor == 1 {
            evidence.received_utc_ns = None;
        }
    }
    request.owner_facts[0].recorded_utc_ns = 4000;
    let view = select(&request, std::slice::from_ref(&first)).await?;
    assert!(view
        .missing_facts
        .iter()
        .any(|fact| fact == "SOURCE_HEALTH_UNAVAILABLE"));
    assert_eq!(
        view.omissions.get("EVIDENCE_OUTSIDE_WINDOW_OR_UNDATED"),
        Some(&1)
    );
    request.access.sensitivities.clear();
    let view = select(&request, std::slice::from_ref(&first)).await?;
    assert!(view.documents.is_empty());
    assert_eq!(view.omissions.get("DOCUMENT_ACCESS_DENIED"), Some(&1));
    conflict.document.tenant_id = [9; 16];
    conflict.document.subject.tenant_id = [9; 16];
    assert!(select(&request, &[conflict]).await.is_err());
    request
        .access
        .sensitivities
        .push(ContextSensitivityV1::Tenant);
    let mut mismatched = first;
    mismatched.document.subject.owner_revision += 1;
    let view = select(&request, &[mismatched]).await?;
    assert!(view.documents.is_empty());
    assert_eq!(view.omissions.get("DOCUMENT_SUBJECT_MISMATCH"), Some(&1));
    Ok(())
}

#[tokio::test]
async fn discovery_context_source_quota() -> TestResult<()> {
    let (request, first) = input()?;
    let mut revisions: Vec<_> = (0..=CONTEXT_SOURCE_DOCUMENTS)
        .map(|ordinal| {
            let mut revision = first.clone();
            revision.document.id = format!("document-{ordinal:03}");
            revision
        })
        .collect();
    let view = select_quota(&request, &revisions).await?;
    assert_eq!(
        view.available_documents,
        CONTEXT_SOURCE_DOCUMENTS as u64 + 1
    );
    assert_eq!(view.documents.len(), CONTEXT_SOURCE_DOCUMENTS);
    assert_eq!(view.omissions.get("DOCUMENT_SOURCE_LIMIT"), Some(&1));
    let mut separate = first.clone();
    separate.document.id = "separate-source".into();
    separate.document.origin = "second source".into();
    revisions.push(separate);
    assert_eq!(
        select_quota(&request, &revisions).await?.documents.len(),
        CONTEXT_SOURCE_DOCUMENTS + 1
    );
    revisions[CONTEXT_SOURCE_DOCUMENTS].document.text =
        "An omitted source document contradicts the retained text.".into();
    let view = select_quota(&request, &revisions).await?;
    assert_eq!(view.conflicts.len(), 1);
    assert!(view.conflicts[0]
        .document_ids
        .contains(&revisions[CONTEXT_SOURCE_DOCUMENTS].document.id));
    let revisions: Vec<_> = (0..CONTEXT_DOCUMENTS)
        .map(|ordinal| {
            let mut revision = first.clone();
            revision.document.id = format!("bounded-{ordinal:04}");
            revision
        })
        .collect();
    select_quota(&request, &revisions).await?;
    let mut over = revisions;
    let mut extra = first;
    extra.document.id = "over-limit".into();
    over.push(extra);
    assert!(select_quota(&request, &over).await.is_err());
    Ok(())
}

#[tokio::test]
async fn discovery_context_byte_quota() -> TestResult<()> {
    let (request, mut revision) = input()?;
    let size = serde_json::to_vec(&revision)?.len();
    revision
        .document
        .text
        .extend(std::iter::repeat_n('x', CONTEXT_DOCUMENT_BYTES - size));
    assert_eq!(serde_json::to_vec(&revision)?.len(), CONTEXT_DOCUMENT_BYTES);
    revision.validate()?;
    AnalysisContextVersionV1::try_from(&revision)?;
    let (_directory, owner) = context(ContextLimits {
        document_bytes: Some(CONTEXT_DOCUMENT_BYTES),
        ..Default::default()
    })?;
    owner.document_bytes(&revision)?;
    revision.document.text.push('x');
    revision.validate()?;
    assert!(owner.document_bytes(&revision).is_err());
    assert!(owner.import_context(&request.access, &revision).is_err());
    assert!(owner
        .select_captured(
            &request,
            &[revision.clone()],
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    revision.document.text = "Bounded supplied text.".into();
    let mut duplicate = revision.clone();
    duplicate.document.text = "Conflicting retained bytes.".into();
    assert!(select(&request, &[revision, duplicate]).await.is_err());
    Ok(())
}

#[tokio::test]
async fn discovery_context_subject_revision() -> TestResult<()> {
    let (mut request, first) = input()?;
    for (index, fact) in request.owner_facts.iter_mut().enumerate() {
        fact.context.key.lifetime_key = vec![20 + index as u8];
    }
    let view = select(&request, std::slice::from_ref(&first)).await?;
    assert_eq!(view.owner_facts.len(), 2);
    assert!(view.omissions.is_empty());
    request.owner_facts[0].subject.owner_revision += 1;
    let view = select(&request, std::slice::from_ref(&first)).await?;
    assert_eq!(view.owner_facts.len(), 1);
    assert_eq!(view.omissions.get("FACT_SUBJECT_MISMATCH"), Some(&1));
    assert!(view
        .missing_facts
        .iter()
        .any(|fact| fact == "SOURCE_HEALTH_UNAVAILABLE"));
    let mut backwards = first.clone();
    backwards.document.revision += 1;
    backwards.imported_utc_ns -= 1;
    assert!(select(&request, &[first, backwards]).await.is_err());
    Ok(())
}

#[tokio::test]
async fn discovery_context_packet_quota() -> TestResult<()> {
    let (mut request, first) = input()?;
    let mut facts = Vec::new();
    for ordinal in 0..16 {
        let mut fact = request.owner_facts[0].clone();
        fact.context.key.entity_key = vec![ordinal];
        fact.context.body = vec![b'x'; CONTEXT_DOCUMENT_BYTES];
        facts.push(fact);
    }
    request.owner_facts = facts;
    let view = select_packet(&request, &[first]).await?;
    assert!(serde_json::to_vec(&view)?.len() <= CONTEXT_PACKET_BYTES);
    assert!(view.omissions.contains_key("PACKET_OWNER_FACT_BYTES"));
    assert!(view.omissions.contains_key("PACKET_EVIDENCE_BYTES"));
    assert!(view
        .missing_facts
        .iter()
        .any(|fact| fact == "NO_QUALIFIED_SUBJECT_EVIDENCE"));
    Ok(())
}

#[tokio::test]
async fn discovery_context_history_identity() -> TestResult<()> {
    let (_, first) = input()?;
    first.validate_history(None)?;
    let mut next = first.clone();
    next.document.revision += 1;
    next.imported_utc_ns += 1;
    next.validate_history(Some(&first))?;
    for change in 0..5 {
        let mut invalid = next.clone();
        match change {
            0 => invalid.document.subject.owner_revision += 1,
            1 => invalid.document.method.revision += 1,
            2 => invalid.document.kind = DiscoveryContextKindV1::ThreatReference,
            3 => invalid.document.origin = "changed origin".into(),
            _ => invalid.imported_utc_ns = first.imported_utc_ns - 1,
        }
        assert!(invalid.validate_history(Some(&first)).is_err());
    }
    next.document.revision += 1;
    assert!(next.validate_history(Some(&first)).is_err());
    Ok(())
}

#[tokio::test]
async fn discovery_context_default_limits_are_disabled() -> TestResult<()> {
    let (request, first) = input()?;
    let (_directory, owner) = context(ContextLimits::default())?;
    assert!(serde_json::to_value(owner.limits)?
        .as_object()
        .ok_or("context limits object")?
        .values()
        .all(serde_json::Value::is_null));
    let mut revisions: Vec<_> = (0..17)
        .map(|ordinal| {
            let mut revision = first.clone();
            revision.document.id = format!("unlimited-{ordinal:03}");
            revision
        })
        .collect();
    revisions[0].document.text = "x".repeat(33 * 1024);
    revisions[0].validate()?;
    owner.import_context(&request.access, &revisions[0])?;
    let view = owner
        .select_captured(&request, &revisions, &AnalysisReadControl::default())
        .await?;
    assert_eq!(view.available_documents, 17);
    assert_eq!(view.documents.len(), 17);
    assert!(!view.omissions.contains_key("DOCUMENT_SOURCE_LIMIT"));
    assert!(!view.omissions.contains_key("PACKET_DOCUMENT_BYTES"));
    Ok(())
}

#[tokio::test]
async fn discovery_context_configured_limits() -> TestResult<()> {
    let (request, first) = input()?;
    let mut conflict = first.clone();
    conflict.document.id = "second-document".into();
    conflict.document.text = "A different retained statement.".into();
    let (_directory, owner) = context(ContextLimits {
        evidence: Some(1),
        owner_facts: Some(1),
        handles: Some(3),
        conflict_handles: Some(1),
        revisions: Some(2),
        ..Default::default()
    })?;
    let revisions = [first, conflict];
    let view = owner
        .select_captured(&request, &revisions, &AnalysisReadControl::default())
        .await?;
    assert_eq!(view.records.len(), 1);
    assert_eq!(view.owner_facts.len(), 1);
    assert_eq!(view.documents.len(), 1);
    assert_eq!(view.conflicts[0].document_ids.len(), 1);
    for (reason, expected) in [
        ("EVIDENCE_HANDLE_LIMIT", 2),
        ("OWNER_FACT_LIMIT", 1),
        ("DOCUMENT_HANDLE_LIMIT", 1),
        ("CONFLICT_HANDLE_LIMIT", 1),
    ] {
        assert_eq!(view.omissions.get(reason), Some(&expected));
    }
    let mut overflow = revisions.to_vec();
    overflow.push(revisions[0].clone());
    assert!(owner
        .select_captured(&request, &overflow, &AnalysisReadControl::default())
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn discovery_context_native_order() -> TestResult<()> {
    let (mut request, _) = input()?;
    request.records.truncate(2);
    for (row, cursor) in request.records.iter_mut().zip([10, 2]) {
        row.record_id.durable_cursor = cursor;
    }
    let mut second = request.owner_facts[0].clone();
    second.context.key.owner_revision = 10;
    request.owner_facts[0].context.key.owner_revision = 2;
    request.owner_facts = vec![second, request.owner_facts[0].clone()];
    let view = select(&request, &[]).await?;
    assert_eq!(
        view.records
            .iter()
            .map(|row| row.record_id.durable_cursor)
            .collect::<Vec<_>>(),
        [2, 10]
    );
    assert_eq!(
        view.owner_facts
            .iter()
            .map(|row| row.context.key.owner_revision)
            .collect::<Vec<_>>(),
        [2, 10]
    );
    assert!(view.documents.is_empty());
    request.records.clear();
    request.owner_facts.clear();
    let empty = select(&request, &[]).await?;
    assert!(empty.records.is_empty() && empty.owner_facts.is_empty() && empty.documents.is_empty());
    Ok(())
}

#[tokio::test]
async fn discovery_context_native_capture() -> TestResult<()> {
    let (mut request, first) = input()?;
    let (_directory, owner) = context(ContextLimits::default())?;
    owner.import_context(&request.access, &first)?;
    let mut future = first.clone();
    future.document.revision = 2;
    future.imported_utc_ns = 4000;
    future.document.approver = Some(request.access.principal.clone());
    owner.import_context(&request.access, &future)?;
    let mut other = first.clone();
    other.document.tenant_id = [9; 16];
    other.document.subject.tenant_id = [9; 16];
    let mut other_access = request.access.clone();
    other_access.tenant_id = [9; 16];
    other_access.subject.tenant_id = [9; 16];
    owner.import_context(&other_access, &other)?;
    let control = AnalysisReadControl::default();
    let initial = owner.select_context(&request, &control).await?;
    assert_eq!(initial.documents.len(), 1);
    assert_eq!(initial.documents[0].document_revision, 1);
    assert_eq!(initial.omissions.get("DOCUMENT_AFTER_CUTOFF"), Some(&1));
    assert_eq!(initial.available_documents, 1);
    request.cutoff_utc_ns = 4000;
    let packet = owner.context_input(&request, &control).await?;
    let later = Context::decode_context(&packet)?;
    assert_eq!(later.documents.len(), 1);
    assert_eq!(later.documents[0].document_revision, 2);
    assert_eq!(later.documents[0].trust, DiscoveryContextTrustV1::Reviewed);
    assert_eq!(later.documents[0].key.tenant_id, request.access.tenant_id);
    control.cancel()?;
    assert!(owner.select_context(&request, &control).await.is_err());
    Ok(())
}

#[tokio::test]
async fn discovery_context_import_history() -> TestResult<()> {
    let (request, first) = input()?;
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let owner = Context::new(Engine::new(
        store.clone(),
        araphor_query::execution::Limits::default(),
    )?);
    let reference = owner.import_context(&request.access, &first)?;
    assert_eq!(owner.import_context(&request.access, &first)?, reference);
    let mut conflicting = first.clone();
    conflicting.document.text = "Changed immutable document bytes.".into();
    assert!(owner.import_context(&request.access, &conflicting).is_err());
    let before = store.meta()?;
    let mut denied = request.access.clone();
    denied.can_import = false;
    assert!(owner.import_context(&denied, &first).is_err());
    let mut reviewed = first.clone();
    reviewed.document.revision = 2;
    reviewed.imported_utc_ns += 1;
    reviewed.document.approver = Some(request.access.principal.clone());
    denied = request.access.clone();
    denied.can_review = false;
    assert!(owner.import_context(&denied, &reviewed).is_err());
    let mut wrong = reviewed.clone();
    wrong.document.approver = Some("another reviewer".into());
    assert!(owner.import_context(&request.access, &wrong).is_err());
    assert_eq!(store.meta()?, before);
    let later = owner.import_context(&request.access, &reviewed)?;
    assert!(later.commit_revision > reference.commit_revision);
    assert_eq!(owner.import_context(&request.access, &first)?, reference);
    assert_eq!(
        store.context_version(&reference.key)?,
        Some(AnalysisContextVersionV1::try_from(&first)?)
    );
    assert_eq!(
        store.context_version(&later.key)?,
        Some(AnalysisContextVersionV1::try_from(&reviewed)?)
    );
    let before = store.meta()?;
    let mut backwards = reviewed;
    backwards.document.revision = 3;
    backwards.imported_utc_ns = first.imported_utc_ns;
    assert!(owner.import_context(&request.access, &backwards).is_err());
    assert_eq!(store.meta()?, before);
    Ok(())
}

fn context(limits: ContextLimits) -> TestResult<(tempfile::TempDir, Context)> {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let query_limits = araphor_query::execution::Limits {
        input_bytes: 128 * 1024 * 1024,
        output_bytes: 128 * 1024 * 1024,
        ..Default::default()
    };
    let mut context = Context::new(Engine::new(store, query_limits)?);
    context.set_limits(limits);
    Ok((directory, context))
}

async fn select(
    request: &DiscoveryContextRequestV1,
    revisions: &[DiscoveryContextRevisionV1],
) -> TestResult<DiscoveryContextViewV1> {
    let (_directory, context) = context(ContextLimits::default())?;
    Ok(context
        .select_captured(request, revisions, &AnalysisReadControl::default())
        .await?)
}

async fn select_quota(
    request: &DiscoveryContextRequestV1,
    revisions: &[DiscoveryContextRevisionV1],
) -> TestResult<DiscoveryContextViewV1> {
    let (_directory, context) = context(ContextLimits {
        source_documents: Some(CONTEXT_SOURCE_DOCUMENTS),
        documents: Some(CONTEXT_DOCUMENTS),
        revisions: Some(CONTEXT_REVISIONS),
        ..Default::default()
    })?;
    Ok(context
        .select_captured(request, revisions, &AnalysisReadControl::default())
        .await?)
}

async fn select_packet(
    request: &DiscoveryContextRequestV1,
    revisions: &[DiscoveryContextRevisionV1],
) -> TestResult<DiscoveryContextViewV1> {
    let (_directory, context) = context(ContextLimits {
        packet_bytes: Some(CONTEXT_PACKET_BYTES),
        ..Default::default()
    })?;
    Ok(context
        .select_captured(request, revisions, &AnalysisReadControl::default())
        .await?)
}

async fn context_input(
    request: &DiscoveryContextRequestV1,
    revisions: &[DiscoveryContextRevisionV1],
) -> TestResult<araphor_analysis_sdk::Input> {
    Ok(Context::input(&select(request, revisions).await?)?)
}
