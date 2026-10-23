use super::*;
use crate::notification::tests::{grant, policy};
use araphor_data::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn notification_restores_without_graph() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut config = super::graph::configuration(directory.path(), true, false)?;
    let tenant = uuid::Uuid::parse_str(&config.allowed_nodes[0].tenant_id)?.into_bytes();
    let mut approval = grant(tenant);
    approval.expires_utc_ns = u64::MAX;
    let routes = ["escalation", "primary"]
        .into_iter()
        .map(|name| {
            let mut route = policy(tenant, name);
            route.acknowledgement_ns = 1_000_000_000_000;
            route.retry_delay_ns = 1_000_000_000_000;
            route
        })
        .collect();
    config.notifications = crate::NotificationControlConfigV1 {
        grants: vec![approval.clone()],
        routes,
        ..Default::default()
    };
    let parts = config.clone().into_parts()?;
    assert!(parts.client.is_none());
    assert!(parts.discovery.is_none());
    let data = parts.control.analysis_store().ok_or("notification data")?;
    let owner = parts
        .control
        .notification_owner()
        .ok_or("notification owner")?;
    let now = araphor_query::follow::Clock::now_ns(&araphor_query::follow::SystemClock::default())?;
    let concern = owner.router().submit_concern(
        &approval,
        "primary",
        UnconfirmedNotificationConcernV1 {
            concern_id: [23; 16],
            model_label: "review".into(),
            summary: "Review this concern".into(),
            context: Vec::new(),
            sensitivity: ContextSensitivityV1::Tenant,
            suggested_priority: NotificationPriorityV1::Info,
        },
        now,
    )?;
    let saved = data
        .managed_instance(tenant, "notifications", &AnalysisReadControl::default())?
        .ok_or("running notification job")?;
    assert!(saved.running);
    assert!(saved.spec.definition.images.is_empty());
    assert!(saved.spec.manifest.calls.is_empty());
    assert_eq!(saved.grant.selection, AnalysisSelectionV1::tenant(tenant));
    drop(owner);
    drop(data);
    drop(parts);

    config.graph_enabled = false;
    let other_tenant = uuid::Uuid::from_bytes([240; 16]);
    assert_ne!(tenant, other_tenant.into_bytes());
    config.allowed_nodes[0].tenant_id = other_tenant.to_string();
    let parts = config.clone().into_parts()?;
    assert!(parts.graph.is_none());
    assert!(parts.discovery.is_none());
    assert!(parts.client.is_none());
    let data = parts.control.analysis_store().ok_or("restored data")?;
    assert!(!data.graph_enabled());
    let packages = parts.control.analysis_packages(None)?;
    let host = parts.instances.as_ref().ok_or("restored Host")?;
    assert!(Arc::ptr_eq(host, &packages.instances));
    let owner = parts
        .control
        .notification_owner()
        .ok_or("restored Router")?;
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let mut revisions = data.subscribe_revision();
    let serving = tokio::spawn(Arc::clone(host).serve(stopped, u64::MAX));
    let observed = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let state = owner
                .router()
                .obligations(&approval, now)?
                .into_iter()
                .find(|state| state.key == concern.key)
                .ok_or("retained concern")?;
            if state.attempts.len() == 2
                && state.attempts.iter().all(|attempt| {
                    matches!(
                        attempt.result,
                        Some(NotificationSinkResultV1::Failed {
                            reason: NotificationFailureV1::SinkUnavailable
                        })
                    )
                })
            {
                break Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            revisions.changed().await?;
        }
    })
    .await?;
    stop.send(true)?;
    tokio::time::timeout(std::time::Duration::from_secs(30), serving).await???;
    let state = observed?;
    assert!(state
        .attempts
        .iter()
        .all(|attempt| attempt.result.is_some()));
    assert_eq!(
        data.managed_instance(tenant, "notifications", &AnalysisReadControl::default())?
            .ok_or("retained running intent")?,
        saved
    );
    let resume = data.managed_resume(tenant, "notifications", &AnalysisReadControl::default())?;
    assert_eq!(resume.completed, 0);
    assert_eq!(resume.instance.progress, 0);
    assert!(resume.frontier.is_none());
    assert!(data
        .managed_history(
            &AnalysisSelectionV1::tenant(tenant),
            "notifications",
            &AnalysisReadControl::default()
        )?
        .is_empty());
    drop(owner);
    drop(packages);
    drop(data);
    drop(parts);
    let parts = config.into_parts()?;
    let reopened = parts
        .control
        .notification_owner()
        .ok_or("reopened Router")?
        .router()
        .obligations(&approval, now)?;
    assert_eq!(
        reopened
            .into_iter()
            .find(|entry| entry.key == concern.key)
            .ok_or("reopened concern")?,
        state
    );
    Ok(())
}

#[test]
fn notification_disabled_stays_empty() -> TestResult {
    let directory = tempfile::tempdir()?;
    let config = super::graph::configuration(directory.path(), false, false)?;
    let tenant = uuid::Uuid::parse_str(&config.allowed_nodes[0].tenant_id)?.into_bytes();
    let parts = config.into_parts()?;
    let data = parts.control.analysis_store().ok_or("disabled data")?;
    assert!(parts.instances.is_none());
    assert!(data
        .active_managed(&AnalysisReadControl::default())?
        .1
        .is_empty());
    assert!(data
        .definition(
            tenant,
            "mithril-control-notifications",
            None,
            &AnalysisReadControl::default()
        )?
        .is_none());
    for bundle in araphor_analysis::GraphProgram::images()
        .into_iter()
        .chain(std::iter::once(
            araphor_analysis::Package::discovery_bundle()?,
        ))
    {
        assert!(data
            .package_image(
                tenant,
                &bundle.root.package_id,
                Some(&bundle.root.revision),
                &AnalysisReadControl::default()
            )?
            .is_none());
    }
    assert!(!data.graph_enabled());
    assert!(!data.discovery_enabled());
    Ok(())
}

#[test]
fn notification_bootstrap_pages_tenants() -> TestResult {
    let directory = tempfile::tempdir()?;
    let parts = super::graph::configuration(directory.path(), false, false)?.into_parts()?;
    let data = parts.control.analysis_store().ok_or("bootstrap data")?;
    let mut tenants = Vec::new();
    for number in 0..257u128 {
        let tenant = uuid::Uuid::from_u128(10_000 + number).into_bytes();
        tenants.push(tenant);
        data.accept_validated_batch(
            EvidenceIntakeIdentityV1 {
                tenant_id: tenant,
                node_id: "retained-only-node".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                frame_ends: vec![5],
                framed_records: b"frame".as_slice().into(),
            },
        )?;
    }
    let owner = parts
        .control
        .notification_owner()
        .ok_or("bootstrap Router")?;
    let mut context_grant = grant([41; 16]);
    context_grant.expires_utc_ns = u64::MAX;
    owner.authority().replace(context_grant.clone())?;
    owner
        .router()
        .configure(&context_grant, policy([41; 16], "primary"), 100)?;
    let packages = parts.control.configured_packages(None, true)?;
    packages.notifications(&crate::NotificationControlConfigV1 {
        grants: vec![grant([42; 16])],
        routes: Vec::new(),
        ..Default::default()
    })?;
    for tenant in tenants.into_iter().chain([[41; 16], [42; 16]]) {
        let job = data
            .managed_instance(tenant, "notifications", &AnalysisReadControl::default())?
            .ok_or("bootstrap tenant job")?;
        assert!(job.running);
        assert_eq!(job.grant.selection, AnalysisSelectionV1::tenant(tenant));
        assert!(job.spec.definition.images.is_empty());
        assert!(job.spec.manifest.calls.is_empty());
    }
    let current = data
        .managed_instance([41; 16], "notifications", &AnalysisReadControl::default())?
        .ok_or("job to stop")?;
    data.stop_managed(&current, || Ok(()))?;
    let stopped = data
        .managed_instance([41; 16], "notifications", &AnalysisReadControl::default())?
        .ok_or("stopped job")?;
    packages.notifications(&crate::NotificationControlConfigV1::default())?;
    assert_eq!(
        data.managed_instance([41; 16], "notifications", &AnalysisReadControl::default())?
            .ok_or("retained stopped job")?,
        stopped
    );
    assert!(!data.graph_enabled());
    Ok(())
}
