use std::sync::Mutex;

use araphor_data::*;

use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn control_notification_revocation_survives_restart_and_requires_new_revision() -> TestResult {
    let dir = tempfile::tempdir()?;
    let grant = NotificationGrantV1 {
        tenant_id: [1; 16],
        principal_id: [2; 16],
        principal: NotificationPrincipalV1::Human,
        authorization_revision: 1,
        routes: vec!["route".into()],
        operations: vec![NotificationOperationV1::Read],
        max_sensitivity: ContextSensitivityV1::Tenant,
        expires_utc_ns: 1000,
    };
    {
        let owner = ConfiguredNotificationAuthority::new(
            crate::ControlStore::open(dir.path())?,
            std::slice::from_ref(&grant),
        )?;
        owner.check(&grant, 100)?;
        owner.revoke(grant.tenant_id, grant.principal_id, 1)?;
        assert!(owner.check(&grant, 100).is_err());
    }
    let owner = ConfiguredNotificationAuthority::new(
        crate::ControlStore::open(dir.path())?,
        std::slice::from_ref(&grant),
    )?;
    assert!(owner.check(&grant, 101).is_err());
    assert!(owner.replace(grant.clone()).is_err());
    let mut next = grant.clone();
    next.authorization_revision = 2;
    owner.replace(next.clone())?;
    assert!(owner.check(&grant, 102).is_err());
    owner.check(&next, 102)?;
    Ok(())
}

#[test]
fn control_notification_stage_isolation() -> TestResult {
    let dir = tempfile::tempdir()?;
    let data = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = finding_graph(data.clone())?;
    let sink = Arc::new(Sink::default());
    let owner = ControlNotificationOwner::new(
        crate::ControlStore::open(dir.path().join("control"))?,
        data.clone(),
        NotificationControlConfigV1 {
            grants: vec![grant([1; 16]), grant([2; 16])],
            routes: [[1; 16], [2; 16]]
                .into_iter()
                .flat_map(|tenant| [policy(tenant, "primary"), policy(tenant, "escalation")])
                .collect(),
        },
        10,
    )?
    .with_sink(sink.clone());
    let other = grant([2; 16]);
    let concern = owner.router().submit_concern(
        &other,
        "primary",
        UnconfirmedNotificationConcernV1 {
            concern_id: [7; 16],
            model_label: "review".into(),
            summary: "Review this concern".into(),
            context: Vec::new(),
            sensitivity: ContextSensitivityV1::Tenant,
            suggested_priority: NotificationPriorityV1::Info,
        },
        100,
    )?;
    fill_context_quota(&data)?;
    for now in [150, 151] {
        assert!(matches!(
            owner.process(&graph, now),
            Err(crate::Error::DataStore { source, .. })
                if matches!(*source, araphor_data::Error::StorageCapacity {
                    resource: "tenant retained revisions", ..
                })
        ));
    }
    let calls = sink.calls.lock().map_err(|_| "sink lock")?;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].key, concern.key);
    let current = owner.router().obligations(&other, 151)?.remove(0);
    assert_eq!(current.deadline_utc_ns, concern.deadline_utc_ns);
    assert!(matches!(
        current.attempts[0].result,
        Some(NotificationSinkResultV1::Accepted { .. })
    ));
    Ok(())
}

fn grant(tenant: [u8; 16]) -> NotificationGrantV1 {
    NotificationGrantV1 {
        tenant_id: tenant,
        principal_id: [9; 16],
        principal: NotificationPrincipalV1::Agent,
        authorization_revision: 1,
        routes: vec!["escalation".into(), "primary".into()],
        operations: vec![
            NotificationOperationV1::Configure,
            NotificationOperationV1::Read,
            NotificationOperationV1::SubmitConcern,
        ],
        max_sensitivity: ContextSensitivityV1::HostRestricted,
        expires_utc_ns: 1000,
    }
}

fn policy(tenant: [u8; 16], route: &str) -> NotificationPolicyV1 {
    NotificationPolicyV1 {
        tenant_id: tenant,
        route_id: route.into(),
        revision: 1,
        package_ids: vec![if route == "primary" {
            "HF-PROC-001".into()
        } else {
            "HF-XNODE-001".into()
        }],
        minimum_priority: NotificationPriorityV1::High,
        acknowledgement_ns: 100,
        retry_limit: 4,
        retry_delay_ns: 1,
        escalation_route_id: "escalation".into(),
        max_sensitivity: ContextSensitivityV1::HostRestricted,
        allow_concerns: true,
    }
}

fn finding_graph(
    data: Arc<AnalysisStore>,
) -> std::result::Result<GraphAndFindingOwner, Box<dyn std::error::Error>> {
    let source = EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    };
    let wire = Vec::<u8>::try_from(&EvidenceRecord {
        effect_family: 1,
        operation: 1,
        coverage_interval_id: vec![4; 16].into(),
        ..Default::default()
    })?;
    let length = wire.len();
    data.accept_validated_batch(
        source,
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            framed_records: wire.into(),
            frame_ends: vec![length],
        },
    )?;
    let graph = GraphAndFindingOwner::new(data, Arc::new(Context))?;
    assert_eq!(graph.process(20)?, 1);
    assert_eq!(graph.current_findings([1; 16])?.len(), 1);
    Ok(graph)
}

fn fill_context_quota(data: &AnalysisStore) -> TestResult {
    for number in 0..1024u32 {
        match data.commit_context(&AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "quota-input".into(),
                entity_key: number.to_be_bytes().to_vec(),
                lifetime_key: b"input".to_vec(),
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: vec![1],
        }) {
            Ok(_) => {}
            Err(araphor_data::Error::StorageCapacity {
                resource: "tenant retained revisions",
                ..
            }) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    Err("context quota was not reached".into())
}

struct Context;

impl GraphContextProvider for Context {
    fn facts(
        &self,
        _record: &DiscoveryRecordV1,
    ) -> araphor_data::Result<Vec<AnalysisContextVersionV1>> {
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct Sink {
    calls: Mutex<Vec<NotificationDeliveryV1>>,
}

impl NotificationSink for Sink {
    fn deliver(&self, request: &NotificationDeliveryV1) -> NotificationSinkResultV1 {
        let Ok(mut calls) = self.calls.lock() else {
            return NotificationSinkResultV1::Failed {
                reason: NotificationFailureV1::SinkUnavailable,
            };
        };
        calls.push(request.clone());
        NotificationSinkResultV1::Accepted {
            receipt: "accepted".into(),
        }
    }
}
