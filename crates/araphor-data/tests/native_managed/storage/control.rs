use super::super::attempts::field as mut_field;
use super::calls::call_context;
use super::StorageFixture as Fixture;
use super::*;
use araphor_data::{
    AnalysisExtractLimits, AnalysisReadModeV1, AnalysisStore, AnalysisTableRead,
    AnalysisTableRequests, EvidenceIntakeIdentityV1, ManagedExit, ManagedMember, ManagedResume,
    ManagedStatus,
};
use serde::{Deserialize, Serialize};
use serde_value::Value;

#[path = "control/history.rs"]
mod history;
#[path = "control/lifecycle.rs"]
mod lifecycle;
#[path = "control/recovery.rs"]
mod recovery;
#[path = "control/removal.rs"]
mod removal;
#[path = "control/renewal.rs"]
mod renewal;
#[path = "control/status.rs"]
mod status;
#[path = "control/version.rs"]
mod version;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const DESCRIPTION: &str = "Retain independent call state.";

fn fixture(store: &NativeStore) -> TestResult<Fixture> {
    Fixture::new(store, "counter", DESCRIPTION.into())
}

fn identity() -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    }
}

fn request(id: &str) -> ManagedRequest {
    ManagedRequest {
        id: id.into(),
        time_utc_ns: 10,
        seed: Some(7),
        rebuild: false,
        witness_expiry: u64::MAX,
        frontier: None,
    }
}

fn single(store: &NativeStore, prefix: &[u8]) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let view = store.view()?;
    let mut entries = records(&view, prefix)?.into_iter();
    let entry = entries.next().ok_or("native record")?;
    assert!(entries.next().is_none(), "native prefix is not unique");
    Ok(entry)
}

fn framed(value: &impl Serialize) -> TestResult<Vec<u8>> {
    Ok([vec![0], rmp_serde::to_vec_named(value)?].concat())
}

fn attempt_record(store: &NativeStore, id: &str) -> TestResult<(Vec<u8>, Vec<u8>)> {
    super::terminal::attempt_record(store.view()?.as_ref(), id)
}

#[derive(Deserialize)]
struct Captured {
    grant: PackageGrantV1,
    lifecycle: u64,
    running: bool,
    prior: BTreeMap<u64, Option<PackageResultRefV1>>,
}

fn capture_record(store: &NativeStore, id: &str) -> TestResult<Captured> {
    #[derive(Deserialize)]
    struct Attempt {
        capture: Captured,
    }
    let (_, bytes) = attempt_record(store, id)?;
    let saved: Attempt = rmp_serde::from_slice(&bytes[1..])?;
    Ok(saved.capture)
}

#[derive(Deserialize, Serialize)]
struct Version {
    spec: ManagedSpec,
    scope: AnalysisSelectionV1,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FailureOrigin {
    Admission,
    Attempt,
}

#[derive(Deserialize, Serialize)]
struct Failure {
    origin: FailureOrigin,
    code: Code,
    progress: u64,
    revision: u64,
}
