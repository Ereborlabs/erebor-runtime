use erebor_interceptor_abi::EffectObservationV1;
use mithril_control::{
    ControlStore, CoverageCounters, CoverageInterval, CoverageReport, EvidenceIntakeOwner,
};
use mithril_node::{CoverageStateV1, EvidenceWalLimits, NodeControlMessage, TrustCache};
use tokio::time::{timeout, Duration};
use zerocopy::IntoBytes as _;

use super::registration;
use crate::control_fixture::MtlsFixture;
use crate::platform::TestResult;

#[tokio::test]
async fn coverage_upload_keeps_truth() -> TestResult<()> {
    let fixture = MtlsFixture::new(false)?;
    let path = fixture.path().join("control-evidence");
    let store = ControlStore::open(&path)?;
    let intake = EvidenceIntakeOwner::from_store(store.clone());
    let control = fixture.control_with_store(store, 1)?;
    let server = fixture.start(control).await?;
    let wal = fixture.wal(EvidenceWalLimits::default())?;
    let mut event = EffectObservationV1 {
        reason: 9,
        physical_result: 1,
        effect_family: 1,
        operation: 1,
        ..EffectObservationV1::default()
    };
    for (cpu, sequence, cookie) in [(0, 2, 7), (1, 3, 8)] {
        event.observed_boottime_ns = sequence;
        event.source_sequence = sequence;
        event.source_cpu_id = cpu;
        event.task_cookie = cookie;
        wal.record_bytes(event.as_bytes());
    }

    let connector = fixture.connector(&server, "node-a", [7; 16]);
    let mut trust = TrustCache::load(fixture.path())?;
    let mut connection = connector.connect(registration(), false, &mut trust).await?;
    let snapshot = wal.coverage_snapshot().ok_or("missing coverage snapshot")?;
    let current = snapshot.current_intervals();
    assert_eq!(current.len(), 2);
    assert_ne!(current[0].source_id, current[1].source_id);
    assert_eq!(snapshot.source_epoch, 1);
    assert!(!snapshot.supports_negative_claim());

    for interval in current {
        let cpu = interval.cpu_id;
        assert_eq!(interval.state, CoverageStateV1::Unknown);
        let expected = timeout(
            Duration::from_secs(2),
            connection.send_coverage_report(&snapshot, &interval),
        )
        .await
        .map_err(|error| format!("coverage upload for CPU {cpu} at {path:?}: {error}"))??;
        let message = timeout(Duration::from_secs(2), connection.next_message())
            .await
            .map_err(|error| {
                format!("coverage acknowledgement for CPU {cpu} at {path:?}: {error}")
            })??;
        let NodeControlMessage::CoverageAck(actual) = message else {
            return Err("Control returned no coverage acknowledgement".into());
        };
        assert_eq!(actual, expected);
        let identity = fixture.identity(interval.source_id.to_be_bytes());
        let persisted = intake
            .latest_coverage_report(&identity)?
            .ok_or("missing persisted coverage")?;
        assert_eq!(persisted.intervals.len(), 1);
        assert!(persisted.intervals[0].current);
        assert_ne!(persisted.intervals[0].state, "HEALTHY");
        let report = CoverageReport {
            source_id: interval.source_id.to_be_bytes().to_vec(),
            cpu_id: cpu,
            source_epoch: snapshot.source_epoch,
            revision: snapshot.revision,
            intervals: vec![CoverageInterval {
                current: true,
                interval_id: interval.interval_id.to_be_bytes().to_vec(),
                source_epoch: interval.source_epoch,
                revision: interval.revision,
                state: "UNKNOWN".to_owned(),
                first_sequence: u64::from(cpu) + 2,
                last_sequence: Some(u64::from(cpu) + 2),
                opening_counters: Some(CoverageCounters {
                    next_sequence: u64::from(cpu) + 1,
                    ..CoverageCounters::default()
                }),
                closing_counters: None,
                gap_reasons: Vec::new(),
            }],
        };
        assert_eq!(persisted, report);
    }

    drop(connection);
    server.shutdown().await?;
    Ok(())
}
