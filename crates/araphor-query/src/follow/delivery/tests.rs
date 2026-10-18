use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, AnalysisStore};
use futures_util::StreamExt as _;

use super::*;
use crate::execution::{Engine, Limits};
use crate::follow::Clock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Item {
    Metadata,
    Row,
    Checkpoint,
    Health,
    Error,
    Complete,
}

struct Authority {
    valid: AtomicBool,
    changes: watch::Sender<u64>,
}

impl Authority {
    fn revoke(&self) {
        self.valid.store(false, Ordering::SeqCst);
        self.changes.send_replace(1);
    }
}

struct TestClock {
    changes: watch::Sender<u64>,
    reads: AtomicUsize,
}

impl Clock for TestClock {
    fn now_ns(&self) -> Result<u64> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(*self.changes.borrow())
    }
    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

struct Encoder {
    authority: Arc<Authority>,
    fail: bool,
}

impl Encoder {
    fn encode(item: Item, memory: &mut MemoryReservation) -> std::result::Result<Item, Failure> {
        memory
            .try_resize(8)
            .map_err(|source| Failure::native(&source))?;
        Ok(item)
    }
}

impl Consumer for Encoder {
    type Item = Item;
    type Error = Failure;

    fn authorize(&self) -> std::result::Result<(), Failure> {
        if self.authority.valid.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(Failure::Denied)
        }
    }
    fn changes(&self) -> watch::Receiver<u64> {
        self.authority.changes.subscribe()
    }
    fn expires(&self) -> Instant {
        Instant::now() + Duration::from_secs(60)
    }
    fn expired(&self) -> Failure {
        Failure::Denied
    }
    fn code(&self, failure: Failure) -> Failure {
        failure
    }
    fn rows(&self, _: &Update) -> usize {
        1
    }
    fn encode(
        &mut self,
        action: Action<'_>,
        _: &Update,
        memory: &mut MemoryReservation,
    ) -> std::result::Result<Item, Failure> {
        let item = match action {
            Action::Metadata => Item::Metadata,
            Action::Row(_) => Item::Row,
            Action::Checkpoint => Item::Checkpoint,
            Action::Health(_) => Item::Health,
            Action::Error { .. } => Item::Error,
            Action::Complete { .. } => Item::Complete,
        };
        let item = Self::encode(item, memory)?;
        if self.fail && item == Item::Metadata {
            Err(Failure::EvaluationFailed)
        } else {
            Ok(item)
        }
    }
    fn complete_after_checkpoint(&self, _: &Update) -> bool {
        false
    }
    fn deadline_completes(&self) -> bool {
        false
    }
}

struct Fixture {
    engine: Arc<Engine>,
    authority: Arc<Authority>,
    clock: Arc<TestClock>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(AnalysisStore::open(directory.path().join("data")).unwrap());
        let engine = Engine::new(
            store,
            Limits {
                input_capacity: Some(128 * 1024 * 1024),
                output_capacity: Some(16 * 1024 * 1024),
                extract_timeout: Some(Duration::from_secs(5)),
                evaluate_timeout: Some(Duration::from_secs(5)),
                global_streams: Some(16),
                tenant_streams: Some(4),
                ..Default::default()
            },
        )
        .unwrap();
        Self {
            engine,
            authority: Arc::new(Authority {
                valid: AtomicBool::new(true),
                changes: watch::channel(0).0,
            }),
            clock: Arc::new(TestClock {
                changes: watch::channel(1_000_000_000).0,
                reads: AtomicUsize::new(0),
            }),
            _directory: directory,
        }
    }

    async fn delivery(&self, timeout: Duration, follow: bool, fail: bool) -> Delivery<Encoder> {
        let inner = self
            .engine
            .subscribe(
                "SELECT 1 AS value",
                Vec::new(),
                AnalysisSelectionV1::tenant([1; 16]),
                Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap()),
                b"delivery authority",
                None,
                self.clock.clone(),
                follow,
            )
            .await
            .unwrap();
        Delivery::new(
            inner,
            Encoder {
                authority: Arc::clone(&self.authority),
                fail,
            },
            None,
            timeout,
            None,
        )
        .unwrap()
    }
}

async fn next(delivery: &mut Delivery<Encoder>) -> std::result::Result<Item, Failure> {
    tokio::time::timeout(Duration::from_secs(8), delivery.next())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn phases_and_conversion_lifetime() {
    let fixture = Fixture::new();
    let mut delivery = fixture
        .delivery(Duration::from_secs(10), false, false)
        .await;
    let capacity = fixture
        .engine
        .limits()
        .output_capacity
        .expect("configured output capacity");
    assert_eq!(next(&mut delivery).await, Ok(Item::Metadata));
    assert!(delivery.holds_output());
    assert_eq!(delivery.frame_bytes(), 8);
    assert!(fixture.engine.memory().reserve_output(capacity).is_err());
    assert_eq!(next(&mut delivery).await, Ok(Item::Row));
    assert_eq!(next(&mut delivery).await, Ok(Item::Checkpoint));
    assert!(!delivery.holds_output());
    assert_eq!(next(&mut delivery).await, Ok(Item::Complete));
    assert!(fixture.engine.memory().reserve_output(capacity).is_err());
    assert!(delivery.next().await.is_none());
    assert!(fixture.engine.memory().reserve_output(capacity).is_ok());
}

#[tokio::test]
async fn failed_conversion_releases_immediately() {
    let fixture = Fixture::new();
    let mut delivery = fixture.delivery(Duration::from_secs(10), true, true).await;
    assert_eq!(next(&mut delivery).await, Err(Failure::EvaluationFailed));
    assert_eq!(delivery.frame_bytes(), 0);
    assert!(fixture
        .engine
        .memory()
        .reserve_output(
            fixture
                .engine
                .limits()
                .output_capacity
                .expect("configured output capacity")
        )
        .is_ok());
    assert!(delivery.next().await.is_none());
}

#[tokio::test]
async fn idle_demand_releases_producer() {
    let fixture = Fixture::new();
    let mut delivery = fixture
        .delivery(Duration::from_millis(10), true, false)
        .await;
    assert_eq!(fixture.clock.reads.load(Ordering::SeqCst), 0);
    assert_eq!(Arc::strong_count(&fixture.clock), 2);
    let held: Vec<_> = (0..3)
        .map(|_| fixture.engine.reserve_stream([1; 16]).unwrap())
        .collect();
    assert!(fixture.engine.reserve_stream([1; 16]).is_err());
    assert_eq!(next(&mut delivery).await, Ok(Item::Metadata));
    let reads = fixture.clock.reads.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(next(&mut delivery).await, Err(Failure::OutputTimeout));
    assert_eq!(fixture.clock.reads.load(Ordering::SeqCst), reads);
    assert_eq!(Arc::strong_count(&fixture.clock), 1);
    assert!(fixture.engine.reserve_stream([1; 16]).is_ok());
    assert_eq!(delivery.frame_bytes(), 0);
    assert!(delivery.next().await.is_none());
    drop(held);
}

#[tokio::test]
async fn native_wait_is_not_output_idle() {
    let fixture = Fixture::new();
    let mut delivery = fixture
        .delivery(Duration::from_millis(10), true, false)
        .await;
    for item in [Item::Metadata, Item::Row, Item::Checkpoint] {
        assert_eq!(next(&mut delivery).await, Ok(item));
    }
    let pending = delivery.next();
    futures_util::pin_mut!(pending);
    assert!(futures_util::poll!(&mut pending).is_pending());
    tokio::time::sleep(Duration::from_millis(30)).await;
    fixture.clock.changes.send_replace(2_000_000_000);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(8), pending)
            .await
            .unwrap()
            .unwrap(),
        Ok(Item::Health)
    );
}

#[tokio::test]
async fn authority_interrupts_native_wait() {
    let fixture = Fixture::new();
    let mut delivery = fixture.delivery(Duration::from_secs(10), true, false).await;
    for item in [Item::Metadata, Item::Row, Item::Checkpoint] {
        assert_eq!(next(&mut delivery).await, Ok(item));
    }
    let pending = delivery.next();
    futures_util::pin_mut!(pending);
    assert!(futures_util::poll!(&mut pending).is_pending());
    fixture.authority.revoke();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .unwrap()
            .unwrap(),
        Err(Failure::Denied)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn authority_interrupts_read_check() {
    let fixture = Fixture::new();
    let mut delivery = fixture.delivery(Duration::from_secs(10), true, false).await;
    assert_eq!(next(&mut delivery).await, Ok(Item::Metadata));
    let parked = Arc::new(tokio::sync::Notify::new());
    let checking = Arc::clone(&parked);
    delivery.checking = Some(Box::pin(async move {
        checking.notify_one();
        futures_util::future::pending().await
    }));
    let pending = tokio::spawn(async move {
        let result = delivery.next().await;
        (result, delivery)
    });
    tokio::time::timeout(Duration::from_secs(1), parked.notified())
        .await
        .unwrap();
    fixture.authority.revoke();
    let (result, mut delivery) = tokio::time::timeout(Duration::from_secs(1), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, Some(Err(Failure::Denied)));
    assert_eq!(Arc::strong_count(&fixture.clock), 1);
    assert_eq!(delivery.frame_bytes(), 0);
    assert!(fixture
        .engine
        .memory()
        .reserve_output(
            fixture
                .engine
                .limits()
                .output_capacity
                .expect("configured output capacity")
        )
        .is_ok());
    assert!(delivery.next().await.is_none());
}
