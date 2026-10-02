use std::sync::{Arc, Barrier};

use erebor_interceptor_abi::EffectObservationV1;
use mithril_control::ControlStore;
use mithril_node::{
    CoverageGapReasonV1, EvidenceWalLimits, NodeControlConnector, NodeControlMessage, TrustCache,
};
use tokio::time::{timeout, Duration};
use zerocopy::IntoBytes as _;

use super::{
    OutagePolicyFixture as PolicyFixture, TcpBlackholeOwner, OUTAGE_NAMESPACE_UID as NS,
    OUTAGE_NOW as NOW,
};
use crate::{control_fixture::MtlsFixture, platform::TestResult};

#[tokio::test]
async fn partition_replaces_policy() -> TestResult<()> {
    let tls = MtlsFixture::new(false)?;
    let store = ControlStore::open(tls.path().join("control-store"))?;
    let fixture = PolicyFixture::new(store.clone());
    let first = fixture.resource(1)?;
    let facts = fixture.inventory(&first)?;
    let control = tls
        .control_with_store(store, 1)?
        .with_policy_desired_state(fixture.owner.clone());
    assert!(control.replace_kubernetes_workload_inventory(facts.clone())?);
    let prepared = fixture.owner.reconcile(&first, NS, &facts, NOW)?;
    let first = prepared.bundles.first().ok_or("missing first bundle")?;
    let first_id = &first.candidate.candidate_content_id;
    let server = tls.start(control.clone()).await?;
    let proxy = TcpBlackholeOwner::start(server.address()).await?;
    let connector =
        NodeControlConnector::new(tls.node_config(proxy.address()), "node-a".into(), [7; 16]);
    let mut trust = TrustCache::load(&tls.path().join("trust"))?;
    let registration = PolicyFixture::registration([7; 16], false);
    let mut old = connector.connect(registration, false, &mut trust).await?;
    old.report_readiness(true, true).await?;
    control.bind_kubernetes_node_session("worker-a", "dddddddd-dddd-4ddd-8ddd-dddddddddddd")?;
    let offered = old.policy_inventory(None, Vec::new()).await?;
    assert_eq!(&offered.candidate_content_id, first_id);
    let ack = old
        .acknowledge_policy(PolicyFixture::active_acknowledgement(first, 1, NOW + 1))
        .await?;
    assert_eq!(ack.rollout_state, "ACTIVE");

    proxy.block()?;
    let second = fixture.resource(2)?;
    let prepared = fixture.owner.reconcile(&second, NS, &facts, NOW + 2)?;
    let second = prepared.bundles.first().ok_or("missing replacement")?;
    let second_id = &second.candidate.candidate_content_id;
    assert_ne!(second_id, first_id);
    let closed = timeout(Duration::from_secs(30), old.next_message()).await?;
    assert!(closed.is_err(), "blackholed session returned a message");
    drop(old);
    proxy.unblock()?;

    let wal = tls.wal(EvidenceWalLimits::default())?;
    wal.record_bytes(
        EffectObservationV1 {
            observed_boottime_ns: 1,
            source_sequence: 1,
            task_cookie: 7,
            reason: 9,
            physical_result: 1,
            effect_family: 1,
            operation: 1,
            ..Default::default()
        }
        .as_bytes(),
    );
    wal.mark_coverage_gapped(CoverageGapReasonV1::ControlDelay)?;
    let retained = wal.next_evidence_batch().ok_or("missing evidence")?;
    let mut connection = connector
        .connect(PolicyFixture::registration([7; 16], true), true, &mut trust)
        .await?;
    connection.report_readiness(true, true).await?;
    connection.send_evidence_batch(retained.clone()).await?;
    let NodeControlMessage::EvidenceAck(ack) = connection.next_message().await? else {
        return Err("Control did not acknowledge retained partition evidence".into());
    };
    assert_eq!(ack.contiguous_cursor, retained.last_cursor);
    wal.acknowledge_evidence(ack)?;
    assert!(wal.next_evidence_batch().is_none());
    let coverage = wal.coverage_snapshot().ok_or("missing coverage")?;
    let intervals = coverage.current_intervals();
    assert_eq!(intervals.len(), 1);
    let expected = connection
        .send_coverage_report(&coverage, &intervals[0])
        .await?;
    let NodeControlMessage::CoverageAck(actual) = connection.next_message().await? else {
        return Err("Control did not acknowledge partition coverage".into());
    };
    assert_eq!(actual, expected);
    let replacement = connection
        .policy_inventory(Some(first_id), vec![first.bundle_digest.clone()])
        .await?;
    assert!(replacement.candidate_available);
    assert_eq!(&replacement.candidate_content_id, second_id);

    drop(connection);
    proxy.stop().await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn priority_release_wakes_coverage() -> TestResult<()> {
    let tls = MtlsFixture::new(false)?;
    let store = ControlStore::open(tls.path().join("control-store"))?;
    let server = tls.start(tls.control_with_store(store.clone(), 1)?).await?;
    let proxy = TcpBlackholeOwner::start(server.address()).await?;
    let connector =
        NodeControlConnector::new(tls.node_config(proxy.address()), "node-a".into(), [7; 16]);
    let mut trust = TrustCache::load(tls.path())?;
    let mut old = connector
        .connect(super::registration(), false, &mut trust)
        .await?;

    proxy.block()?;
    let closed = timeout(Duration::from_secs(30), old.next_message()).await?;
    assert!(closed.is_err(), "blackholed session returned a message");
    drop(old);
    proxy.unblock()?;
    let mut connection = connector
        .connect(super::registration(), false, &mut trust)
        .await?;
    let wal = tls.wal(EvidenceWalLimits::default())?;
    wal.record_bytes(
        EffectObservationV1 {
            observed_boottime_ns: 1,
            source_sequence: 1,
            task_cookie: 7,
            reason: 9,
            physical_result: 1,
            effect_family: 1,
            operation: 1,
            ..Default::default()
        }
        .as_bytes(),
    );
    wal.mark_coverage_gapped(CoverageGapReasonV1::ControlDelay)?;
    connection
        .send_evidence_batch(
            wal.next_evidence_batch()
                .ok_or("missing partition evidence")?,
        )
        .await?;
    let NodeControlMessage::EvidenceAck(ack) = connection.next_message().await? else {
        return Err("Control did not acknowledge retained partition evidence".into());
    };
    wal.acknowledge_evidence(ack)?;
    let coverage = wal
        .coverage_snapshot()
        .ok_or("missing partition coverage")?;
    let mut intervals = coverage.current_intervals();
    let interval = intervals.pop().ok_or("missing current interval")?;
    assert!(intervals.is_empty());

    let priority_entered = Arc::new(Barrier::new(2));
    let priority_release = Arc::new(Barrier::new(2));
    let evidence_entered = Arc::new(Barrier::new(2));
    let evidence_release = Arc::new(Barrier::new(2));
    assert!(
        store.pause_next_evidence_wait_for_test(evidence_entered.clone(), evidence_release.clone())
    );
    let priority_task = tokio::task::spawn_blocking({
        let store = store.clone();
        let entered = priority_entered.clone();
        let release = priority_release.clone();
        move || store.hold_priority_for_test(&entered, &release)
    });
    tokio::task::spawn_blocking(move || priority_entered.wait()).await?;
    let mut pending = tokio::spawn(async move {
        let result = connection.send_coverage_report(&coverage, &interval).await;
        (connection, result)
    });
    tokio::task::spawn_blocking(move || evidence_entered.wait()).await?;
    tokio::task::spawn_blocking(move || priority_release.wait()).await?;
    tokio::task::spawn_blocking(move || evidence_release.wait()).await?;
    let completed = timeout(Duration::from_millis(500), &mut pending).await;
    let needed_rescue = completed.is_err();
    let (mut connection, result) = match completed {
        Ok(result) => result?,
        Err(_) => {
            tokio::task::spawn_blocking(move || store.commit_index()).await?;
            pending.await?
        }
    };
    priority_task.await??;
    assert!(
        !needed_rescue,
        "coverage slept after the final priority operation"
    );
    let expected = result?;
    let NodeControlMessage::CoverageAck(actual) = connection.next_message().await? else {
        return Err("Control did not acknowledge partition coverage".into());
    };
    assert_eq!(actual, expected);
    drop(connection);
    proxy.stop().await?;
    server.shutdown().await?;
    Ok(())
}
