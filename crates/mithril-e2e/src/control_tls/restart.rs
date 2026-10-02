use mithril_control::{ControlStore, PolicyBundleV1};
use mithril_node::{EvidenceWalLimits, NodeControlMessage as Message, TrustCache};

use super::OutagePolicyFixture as Policy;
use super::{batch_source_id, OUTAGE_NAMESPACE_UID as NS, OUTAGE_NOW as NOW};
use crate::{control_fixture::MtlsFixture, platform::TestResult};

#[tokio::test]
async fn restart_converges_with_replay() -> TestResult<()> {
    let tls = MtlsFixture::new(false)?;
    let store = ControlStore::open(tls.path().join("control-evidence"))?;
    let mut trust = TrustCache::load(&tls.path().join("trust"))?;
    let (mut prior, mut cached) = (String::new(), Vec::new());

    for step in [1, 2] {
        let policy = Policy::new(store.clone());
        let facts = policy.inventory(&policy.resource(1)?)?;
        let resource = policy.resource(step)?;
        let now = NOW + 3 * (step - 1);
        let prepared = policy.owner.reconcile(&resource, NS, &facts, now)?;
        let bundle = prepared.bundles.first().ok_or("missing desired bundle")?;
        let id = &bundle.candidate.candidate_content_id;
        let digest = &bundle.bundle_digest;
        let control = tls
            .control_with_store(store.clone(), 1)?
            .with_policy_desired_state(policy.owner.clone());
        assert!(control.replace_kubernetes_workload_inventory(facts.clone())?);
        let server = tls.start(control.clone()).await?;
        let client = tls.connector(&server, "node-a", [7; 16]);
        let reg = Policy::registration([7; 16], step == 2);
        let (server, mut node) = server.connect(client, reg, step == 2, &mut trust).await?;
        node.report_readiness(true, true).await?;
        control.bind_kubernetes_node_session("worker-a", "dddddddd-dddd-4ddd-8ddd-dddddddddddd")?;
        let wal = tls.wal(EvidenceWalLimits::default())?;
        let retained = wal.next_evidence_batch();
        let expected = if let Some(batch) = &retained {
            let coverage = wal.coverage_snapshot().ok_or("missing retained coverage")?;
            let intervals = coverage.current_intervals();
            assert_eq!(intervals.len(), 1);
            node.send_evidence_batch(batch.clone()).await?;
            Some(node.send_coverage_report(&coverage, &intervals[0]).await?)
        } else {
            None
        };
        let candidate = (!prior.is_empty()).then_some(prior.as_str());
        let offer = node.policy_inventory(candidate, cached).await?;
        assert!(offer.desired_inventory_complete && offer.candidate_available);
        assert_eq!(&offer.candidate_content_id, id);
        assert_eq!(&offer.bundle_digest, digest);
        assert_ne!(id, &prior);
        let mut bytes = Vec::with_capacity(usize::try_from(offer.bundle_bytes)?);
        for index in 0..offer.chunk_count {
            let chunk = node
                .fetch_policy_chunk(id.clone(), digest.clone(), index)
                .await?;
            assert_eq!(chunk.chunk_index, index);
            assert_eq!(chunk.chunk_count, offer.chunk_count);
            bytes.extend_from_slice(&chunk.payload);
        }
        let delivered: PolicyBundleV1 = serde_json::from_slice(&bytes)?;
        assert_eq!(&delivered, bundle);
        let ack = Policy::active_acknowledgement(&delivered, step as u64, now + 1);
        let accepted = node.acknowledge_policy(ack).await?;
        assert_eq!(accepted.rollout_state, "ACTIVE");
        let reconciled = policy.owner.reconcile(&resource, NS, &facts, now + 2)?;
        let state = reconciled.status.rollout;
        let counts = (state.desired, state.active, state.updating, state.failed);
        assert_eq!(counts, (1, 1, 0, 0));

        if let Some(batch) = retained {
            assert_eq!(step, 2);
            let messages = (node.next_message().await?, node.next_message().await?);
            let (evidence, coverage) = match messages {
                (Message::EvidenceAck(e), Message::CoverageAck(c))
                | (Message::CoverageAck(c), Message::EvidenceAck(e)) => (e, c),
                _ => return Err("Control returned unexpected acknowledgements".into()),
            };
            assert_eq!(evidence.contiguous_cursor, batch.last_cursor);
            assert_eq!(Some(coverage), expected);
            assert!(wal.acknowledge_evidence(evidence)?);
            assert!(wal.next_evidence_batch().is_none());
            let identity = tls.identity(batch_source_id(&batch)?);
            let accepted = store.accepted_evidence_records(&identity)?;
            assert_eq!(accepted, batch.decode_records()?);
        } else {
            assert_eq!(step, 1, "Control restart lost the retained WAL batch");
        }
        assert_eq!(control.registered_nonce_count(), 1);
        drop(node);
        server.shutdown().await?;
        prior = id.clone();
        cached = vec![digest.clone()];
        drop(wal);
        if step == 1 {
            assert_eq!(tls.effect_batch(1)?.record_count(), 1);
        }
    }
    Ok(())
}
