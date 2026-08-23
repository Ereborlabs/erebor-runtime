use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    mem::{offset_of, size_of},
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Mutex, MutexGuard, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_interceptor_abi::{EffectObservationV1, Id128V1, NetworkAddressFamilyV1};
use erebor_runtime_core::{OutputPlan, SessionSpec};
use erebor_runtime_session::{SessionOutputError, SessionOutputStores, StreamKind};
use serde::{Deserialize, Serialize};
use zerocopy::FromBytes as _;

const EVIDENCE_SCHEMA: &str = "erebor.runtime.effect-observation";
const COVERAGE_SCHEMA: &str = "erebor.runtime.effect-coverage";
const EVIDENCE_SCHEMA_VERSION: u32 = 1;
const EVIDENCE_SOURCE: &str = "runtime-interceptor";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct EvidenceRouteSnapshot {
    pub(crate) processed: u64,
    pub(crate) persisted: u64,
    pub(crate) parse_failures: u64,
    pub(crate) write_failures: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct EvidenceOwnerSnapshot {
    pub(crate) processed: u64,
    pub(crate) persisted: u64,
    pub(crate) parse_failures: u64,
    pub(crate) write_failures: u64,
    pub(crate) unattributed_parse_failures: u64,
    pub(crate) unknown_bindings: u64,
    pub(crate) successful_polls: u64,
    pub(crate) poll_failures: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct KernelEvidenceSnapshot {
    pub(crate) attempted: u64,
    pub(crate) suppressed: u64,
    pub(crate) requested: u64,
    pub(crate) emitted: u64,
    pub(crate) lost: u64,
    pub(crate) classifier_miss_count: u64,
    pub(crate) unresolved: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EvidenceCoverageInput {
    pub(crate) recovery: bool,
    pub(crate) complete: bool,
    pub(crate) route: EvidenceRouteSnapshot,
    pub(crate) owner_start: EvidenceOwnerSnapshot,
    pub(crate) owner_end: EvidenceOwnerSnapshot,
    pub(crate) kernel_start: KernelEvidenceSnapshot,
    pub(crate) kernel_end: KernelEvidenceSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceRecordOutcome {
    Persisted,
    ParseFailed,
    UnknownBinding,
    WriteFailed,
}

#[derive(Debug)]
pub(crate) enum EvidenceRouteError {
    ZeroBinding,
    DuplicateBinding { binding_id: String },
    OpenOutput { source: SessionOutputError },
}

#[derive(Debug)]
pub(crate) enum EvidenceCoverageError {
    UnknownBinding { binding_id: String },
    Clock,
    Encode { source: serde_json::Error },
    Write { source: SessionOutputError },
}

impl fmt::Display for EvidenceRouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBinding => {
                formatter.write_str("an evidence route requires a nonzero binding")
            }
            Self::DuplicateBinding { binding_id } => {
                write!(
                    formatter,
                    "evidence binding `{binding_id}` is already registered"
                )
            }
            Self::OpenOutput { source } => {
                write!(formatter, "cannot open evidence output: {source}")
            }
        }
    }
}

impl Error for EvidenceRouteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OpenOutput { source } => Some(source),
            Self::ZeroBinding | Self::DuplicateBinding { .. } => None,
        }
    }
}

impl fmt::Display for EvidenceCoverageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownBinding { binding_id } => {
                write!(
                    formatter,
                    "evidence binding `{binding_id}` is not registered"
                )
            }
            Self::Clock => formatter.write_str("the system clock cannot timestamp coverage"),
            Self::Encode { source } => {
                write!(formatter, "cannot encode evidence coverage: {source}")
            }
            Self::Write { source } => {
                write!(formatter, "cannot persist evidence coverage: {source}")
            }
        }
    }
}

impl Error for EvidenceCoverageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encode { source } => Some(source),
            Self::Write { source } => Some(source),
            Self::UnknownBinding { .. } | Self::Clock => None,
        }
    }
}

#[derive(Default)]
pub(crate) struct RuntimeEvidenceRouter {
    state: Mutex<EvidenceState>,
}

#[derive(Default)]
struct EvidenceState {
    routes: BTreeMap<Id128V1, EvidenceRoute>,
    owner: EvidenceOwnerSnapshot,
}

struct EvidenceRoute {
    outputs: SessionOutputStores,
    counters: EvidenceRouteSnapshot,
}

impl RuntimeEvidenceRouter {
    pub(crate) fn register(
        &self,
        binding_id: Id128V1,
        spec: &SessionSpec,
    ) -> Result<(), EvidenceRouteError> {
        self.register_output(binding_id, spec.output())
    }

    pub(crate) fn register_output(
        &self,
        binding_id: Id128V1,
        output: &OutputPlan,
    ) -> Result<(), EvidenceRouteError> {
        if binding_id.is_zero() {
            return Err(EvidenceRouteError::ZeroBinding);
        }
        let mut state = self.lock_state();
        if state.routes.contains_key(&binding_id) {
            return Err(EvidenceRouteError::DuplicateBinding {
                binding_id: id_hex(binding_id),
            });
        }
        let outputs = SessionOutputStores::open(output)
            .map_err(|source| EvidenceRouteError::OpenOutput { source })?;
        debug_assert!(outputs.stream(StreamKind::Evidence).required());
        state.routes.insert(
            binding_id,
            EvidenceRoute {
                outputs,
                counters: EvidenceRouteSnapshot::default(),
            },
        );
        Ok(())
    }

    pub(crate) fn unregister(&self, binding_id: Id128V1) -> Option<EvidenceRouteSnapshot> {
        self.lock_state()
            .routes
            .remove(&binding_id)
            .map(|route| route.counters)
    }

    pub(crate) fn route_snapshot(&self, binding_id: Id128V1) -> Option<EvidenceRouteSnapshot> {
        self.lock_state()
            .routes
            .get(&binding_id)
            .map(|route| route.counters)
    }

    pub(crate) fn owner_snapshot(&self) -> EvidenceOwnerSnapshot {
        self.lock_state().owner
    }

    pub(crate) fn record_poll_failure(&self) {
        let mut state = self.lock_state();
        increment(&mut state.owner.poll_failures);
    }

    pub(crate) fn record_poll_success(&self) {
        let mut state = self.lock_state();
        increment(&mut state.owner.successful_polls);
    }

    pub(crate) fn append_final_coverage(
        &self,
        binding_id: Id128V1,
        input: EvidenceCoverageInput,
    ) -> Result<(), EvidenceCoverageError> {
        let mut state = self.lock_state();
        let EvidenceState { routes, owner } = &mut *state;
        let Some(route) = routes.get_mut(&binding_id) else {
            increment(&mut owner.unknown_bindings);
            return Err(EvidenceCoverageError::UnknownBinding {
                binding_id: id_hex(binding_id),
            });
        };
        let timestamp_unix_ms = unix_time_ms().ok_or_else(|| {
            increment(&mut route.counters.write_failures);
            increment(&mut owner.write_failures);
            EvidenceCoverageError::Clock
        })?;
        let encoded = serde_json::to_vec(&EvidenceCoverageRecordV1 {
            schema: COVERAGE_SCHEMA,
            schema_version: EVIDENCE_SCHEMA_VERSION,
            binding_id: id_hex(binding_id),
            recovery: input.recovery,
            complete: input.complete,
            route: input.route,
            owner_start: input.owner_start,
            owner_end: input.owner_end,
            kernel_start: input.kernel_start,
            kernel_end: input.kernel_end,
        })
        .map_err(|source| {
            increment(&mut route.counters.write_failures);
            increment(&mut owner.write_failures);
            EvidenceCoverageError::Encode { source }
        })?;
        route
            .outputs
            .stream(StreamKind::Evidence)
            .append(timestamp_unix_ms, EVIDENCE_SOURCE, encoded)
            .map(|_record| ())
            .map_err(|source| {
                increment(&mut route.counters.write_failures);
                increment(&mut owner.write_failures);
                EvidenceCoverageError::Write { source }
            })
    }

    pub(crate) fn record_bytes(&self, bytes: &[u8]) -> EvidenceRecordOutcome {
        let event = match EffectObservationV1::read_from_bytes(bytes) {
            Ok(event) => event,
            Err(_error) => {
                self.record_parse_failure(bytes);
                return EvidenceRecordOutcome::ParseFailed;
            }
        };
        let mut state = self.lock_state();
        let EvidenceState { routes, owner } = &mut *state;
        let Some(route) = routes.get_mut(&event.binding_id) else {
            increment(&mut owner.unknown_bindings);
            return EvidenceRecordOutcome::UnknownBinding;
        };

        increment(&mut route.counters.processed);
        increment(&mut owner.processed);
        let timestamp_unix_ms = match unix_time_ms() {
            Some(timestamp) => timestamp,
            None => {
                increment(&mut route.counters.write_failures);
                increment(&mut owner.write_failures);
                return EvidenceRecordOutcome::WriteFailed;
            }
        };
        let encoded = match serde_json::to_vec(&EvidenceRecordV1::from_event(event, bytes)) {
            Ok(encoded) => encoded,
            Err(_error) => {
                increment(&mut route.counters.write_failures);
                increment(&mut owner.write_failures);
                return EvidenceRecordOutcome::WriteFailed;
            }
        };
        if route
            .outputs
            .stream(StreamKind::Evidence)
            .append(timestamp_unix_ms, EVIDENCE_SOURCE, encoded)
            .is_err()
        {
            increment(&mut route.counters.write_failures);
            increment(&mut owner.write_failures);
            return EvidenceRecordOutcome::WriteFailed;
        }
        increment(&mut route.counters.persisted);
        increment(&mut owner.persisted);
        EvidenceRecordOutcome::Persisted
    }

    fn record_parse_failure(&self, bytes: &[u8]) {
        let mut state = self.lock_state();
        increment(&mut state.owner.parse_failures);
        let Some(binding_id) = binding_id_from_prefix(bytes) else {
            increment(&mut state.owner.unattributed_parse_failures);
            return;
        };
        let Some(route) = state.routes.get_mut(&binding_id) else {
            increment(&mut state.owner.unattributed_parse_failures);
            return;
        };
        // The stable prefix assigns decoder health only. It never creates an evidence record.
        increment(&mut route.counters.parse_failures);
    }

    fn lock_state(&self) -> MutexGuard<'_, EvidenceState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn binding_id_from_prefix(bytes: &[u8]) -> Option<Id128V1> {
    let start = offset_of!(EffectObservationV1, binding_id);
    let end = start.checked_add(size_of::<Id128V1>())?;
    let binding_id = Id128V1::read_from_bytes(bytes.get(start..end)?).ok()?;
    (!binding_id.is_zero()).then_some(binding_id)
}

fn increment(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

fn unix_time_ms() -> Option<u64> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(duration.as_millis()).ok()
}

fn id_hex(id: Id128V1) -> String {
    hex::encode(id.to_be_bytes())
}

#[derive(Serialize)]
struct EvidenceCoverageRecordV1 {
    schema: &'static str,
    schema_version: u32,
    binding_id: String,
    recovery: bool,
    complete: bool,
    route: EvidenceRouteSnapshot,
    owner_start: EvidenceOwnerSnapshot,
    owner_end: EvidenceOwnerSnapshot,
    kernel_start: KernelEvidenceSnapshot,
    kernel_end: KernelEvidenceSnapshot,
}

#[derive(Serialize)]
struct EvidenceRecordV1 {
    schema: &'static str,
    schema_version: u32,
    observed_boottime_ns: u64,
    source_cpu_id: u32,
    source_sequence: u64,
    binding_id: String,
    execution_set_id: String,
    profile_generation_ref_id: u64,
    process_instance_id: String,
    task_cookie: u64,
    active_role_id: u32,
    process_state_vector_id: u32,
    entry_kind: u16,
    effect_family: u16,
    operation: u16,
    exact_object_key_id: u64,
    reason: u8,
    physical_result: u8,
    configured_errno: i16,
    kernel_result: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_peer: Option<NetworkPeerV1>,
    raw_abi_hex: String,
}

impl EvidenceRecordV1 {
    fn from_event(event: EffectObservationV1, bytes: &[u8]) -> Self {
        Self {
            schema: EVIDENCE_SCHEMA,
            schema_version: EVIDENCE_SCHEMA_VERSION,
            observed_boottime_ns: event.observed_boottime_ns,
            source_cpu_id: event.source_cpu_id,
            source_sequence: event.source_sequence,
            binding_id: id_hex(event.binding_id),
            execution_set_id: id_hex(event.execution_set_id),
            profile_generation_ref_id: event.profile_generation_ref_id,
            process_instance_id: id_hex(event.process_instance_id),
            task_cookie: event.task_cookie,
            active_role_id: event.active_role_id,
            process_state_vector_id: event.process_state_vector_id,
            entry_kind: event.entry_kind,
            effect_family: event.effect_family,
            operation: event.operation,
            exact_object_key_id: event.exact_object_key_id,
            reason: event.reason,
            physical_result: event.physical_result,
            configured_errno: event.configured_errno,
            kernel_result: event.kernel_result,
            network_peer: NetworkPeerV1::from_event(&event),
            raw_abi_hex: hex::encode(bytes),
        }
    }
}

#[derive(Serialize)]
struct NetworkPeerV1 {
    address_family: u8,
    protocol: u8,
    address: String,
    port: u16,
}

impl NetworkPeerV1 {
    fn from_event(event: &EffectObservationV1) -> Option<Self> {
        let populated = event.network_address_family != 0
            || event.network_protocol != 0
            || event.network_peer_port != 0
            || event.network_peer_address.iter().any(|byte| *byte != 0);
        populated.then(|| Self {
            address_family: event.network_address_family,
            protocol: event.network_protocol,
            address: network_address(event),
            port: event.network_peer_port,
        })
    }
}

fn network_address(event: &EffectObservationV1) -> String {
    match event.network_address_family {
        family if family == NetworkAddressFamilyV1::Ipv4 as u8 => Ipv4Addr::new(
            event.network_peer_address[0],
            event.network_peer_address[1],
            event.network_peer_address[2],
            event.network_peer_address[3],
        )
        .to_string(),
        family if family == NetworkAddressFamilyV1::Ipv6 as u8 => {
            Ipv6Addr::from(event.network_peer_address).to_string()
        }
        _ => hex::encode(event.network_peer_address),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use erebor_interceptor_abi::{
        EffectObservationV1, Id128V1, NetworkAddressFamilyV1, NetworkProtocolV1,
    };
    use erebor_runtime_core::{OutputPlan, OutputStreamRequirements};
    use erebor_runtime_session::{SessionOutputStores, StreamKind};
    use serde_json::Value;
    use tempfile::TempDir;
    use zerocopy::IntoBytes as _;

    use super::{
        EvidenceCoverageInput, EvidenceOwnerSnapshot, EvidenceRecordOutcome, EvidenceRouteSnapshot,
        KernelEvidenceSnapshot, RuntimeEvidenceRouter,
    };

    fn output_plan(
        root: PathBuf,
        maximum_bytes: u64,
    ) -> Result<OutputPlan, Box<dyn std::error::Error>> {
        Ok(OutputPlan::new(
            root,
            maximum_bytes,
            maximum_bytes,
            16,
            OutputStreamRequirements::optional(),
        )?)
    }

    fn event(binding_id: Id128V1) -> EffectObservationV1 {
        EffectObservationV1 {
            observed_boottime_ns: 41,
            source_sequence: 42,
            source_cpu_id: 7,
            task_cookie: 43,
            profile_generation_ref_id: 44,
            process_instance_id: Id128V1::new(5, 6),
            binding_id,
            execution_set_id: Id128V1::new(7, 8),
            active_role_id: 45,
            process_state_vector_id: 46,
            entry_kind: 47,
            effect_family: 48,
            operation: 49,
            exact_object_key_id: 50,
            reason: 9,
            physical_result: 1,
            configured_errno: 13,
            kernel_result: -13,
            network_peer_address: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            network_peer_port: 443,
            network_address_family: NetworkAddressFamilyV1::Ipv6 as u8,
            network_protocol: NetworkProtocolV1::Tcp as u8,
            ..EffectObservationV1::default()
        }
    }

    #[test]
    fn routes_exact_abi_record_to_required_evidence_stream(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let output = output_plan(temporary.path().join("output"), 100_000)?;
        let binding_id = Id128V1::new(1, 2);
        let router = RuntimeEvidenceRouter::default();
        router.register_output(binding_id, &output)?;
        let observation = event(binding_id);
        let bytes = observation.as_bytes();

        assert_eq!(router.record_bytes(bytes), EvidenceRecordOutcome::Persisted);
        assert_eq!(
            router.unregister(binding_id),
            Some(EvidenceRouteSnapshot {
                processed: 1,
                persisted: 1,
                parse_failures: 0,
                write_failures: 0,
            })
        );

        let outputs = SessionOutputStores::open(&output)?;
        assert!(outputs.stream(StreamKind::Evidence).required());
        let cursor = outputs.stream(StreamKind::Evidence).read_after(0, 2)?;
        let [record] = cursor.records() else {
            return Err("expected one evidence record".into());
        };
        let value: Value = serde_json::from_slice(record.data())?;
        assert_eq!(value["schema"], "erebor.runtime.effect-observation");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["source_cpu_id"], 7);
        assert_eq!(value["source_sequence"], 42);
        assert_eq!(value["binding_id"], "00000000000000010000000000000002");
        assert_eq!(value["effect_family"], 48);
        assert_eq!(value["operation"], 49);
        assert_eq!(value["network_peer"]["address"], "2001:db8::1");
        assert_eq!(value["network_peer"]["port"], 443);
        assert_eq!(value["raw_abi_hex"], hex::encode(bytes));
        Ok(())
    }

    #[test]
    fn counts_route_parse_failures_without_writing_evidence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let output = output_plan(temporary.path().join("output"), 100_000)?;
        let binding_id = Id128V1::new(3, 4);
        let router = RuntimeEvidenceRouter::default();
        router.register_output(binding_id, &output)?;
        let mut bytes = event(binding_id).as_bytes().to_vec();
        bytes.push(0);

        assert_eq!(
            router.record_bytes(&bytes),
            EvidenceRecordOutcome::ParseFailed
        );
        assert_eq!(
            router.route_snapshot(binding_id),
            Some(EvidenceRouteSnapshot {
                parse_failures: 1,
                ..EvidenceRouteSnapshot::default()
            })
        );
        assert_eq!(
            router.owner_snapshot(),
            EvidenceOwnerSnapshot {
                parse_failures: 1,
                ..EvidenceOwnerSnapshot::default()
            }
        );
        Ok(())
    }

    #[test]
    fn counts_unknown_bindings_unattributed_parses_and_poll_failures(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let router = RuntimeEvidenceRouter::default();
        let unknown = event(Id128V1::new(9, 10));

        assert_eq!(
            router.record_bytes(unknown.as_bytes()),
            EvidenceRecordOutcome::UnknownBinding
        );
        assert_eq!(
            router.record_bytes(&[0; 8]),
            EvidenceRecordOutcome::ParseFailed
        );
        router.record_poll_failure();

        assert_eq!(
            router.owner_snapshot(),
            EvidenceOwnerSnapshot {
                parse_failures: 1,
                unattributed_parse_failures: 1,
                unknown_bindings: 1,
                poll_failures: 1,
                ..EvidenceOwnerSnapshot::default()
            }
        );
        Ok(())
    }

    #[test]
    fn counts_required_stream_write_failure() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let output = output_plan(temporary.path().join("output"), 5)?;
        let binding_id = Id128V1::new(11, 12);
        let router = RuntimeEvidenceRouter::default();
        router.register_output(binding_id, &output)?;

        assert_eq!(
            router.record_bytes(event(binding_id).as_bytes()),
            EvidenceRecordOutcome::WriteFailed
        );
        assert_eq!(
            router.route_snapshot(binding_id),
            Some(EvidenceRouteSnapshot {
                processed: 1,
                persisted: 0,
                parse_failures: 0,
                write_failures: 1,
            })
        );
        assert_eq!(
            router.owner_snapshot(),
            EvidenceOwnerSnapshot {
                processed: 1,
                write_failures: 1,
                ..EvidenceOwnerSnapshot::default()
            }
        );
        Ok(())
    }

    #[test]
    fn final_coverage_keeps_its_snapshot_when_another_route_advances(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let output = output_plan(temporary.path().join("output"), 100_000)?;
        let other_output = output_plan(temporary.path().join("other-output"), 100_000)?;
        let binding_id = Id128V1::new(13, 14);
        let other_binding_id = Id128V1::new(15, 16);
        let router = RuntimeEvidenceRouter::default();
        router.register_output(binding_id, &output)?;
        router.register_output(other_binding_id, &other_output)?;
        router.append_final_coverage(
            binding_id,
            EvidenceCoverageInput {
                recovery: true,
                complete: false,
                route: EvidenceRouteSnapshot::default(),
                owner_start: EvidenceOwnerSnapshot::default(),
                owner_end: EvidenceOwnerSnapshot {
                    poll_failures: 1,
                    ..EvidenceOwnerSnapshot::default()
                },
                kernel_start: KernelEvidenceSnapshot::default(),
                kernel_end: KernelEvidenceSnapshot {
                    lost: 2,
                    ..KernelEvidenceSnapshot::default()
                },
            },
        )?;
        assert_eq!(
            router.record_bytes(event(other_binding_id).as_bytes()),
            EvidenceRecordOutcome::Persisted
        );
        router.unregister(binding_id);
        router.unregister(other_binding_id);

        let outputs = SessionOutputStores::open(&output)?;
        let cursor = outputs.stream(StreamKind::Evidence).read_after(0, 2)?;
        let [record] = cursor.records() else {
            return Err("expected one final coverage record".into());
        };
        let value: Value = serde_json::from_slice(record.data())?;
        assert_eq!(value["schema"], "erebor.runtime.effect-coverage");
        assert_eq!(value["recovery"], true);
        assert_eq!(value["complete"], false);
        assert_eq!(value["owner_end"]["poll_failures"], 1);
        assert_eq!(value["owner_end"]["processed"], 0);
        assert_eq!(value["kernel_end"]["lost"], 2);
        assert_eq!(router.owner_snapshot().processed, 1);
        Ok(())
    }
}
