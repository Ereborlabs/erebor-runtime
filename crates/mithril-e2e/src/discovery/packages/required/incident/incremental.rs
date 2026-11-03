use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use araphor_data::{EvidenceIntakeIdentityV1, ManagedGraphOperation, StorePositionV1};
use erebor_interceptor_abi::EffectObservationV1;
use erebor_runtime_ipc::araphor::{self as wire, query_frame::Payload};
use erebor_telemetry::tracing::{
    field::{Field, Visit},
    instrument::WithSubscriber as _,
    Event, Subscriber,
};
use erebor_telemetry::tracing_subscriber::{layer::Context, prelude::*, Layer, Registry};
use mithril_control::EvidenceIdV1;
use mithril_node::{ControlConnection, EffectObservationStore, TrustCache};
use zerocopy::IntoBytes as _;

use super::super::super::*;
use super::super::input::{configuration, now, upload_on, wal};
use super::{input, Incident};
use crate::control_fixture::OutagePolicyFixture;
use crate::discovery::roundtrip::signed_catalog;

#[derive(Default)]
struct Sample(BTreeMap<String, String>);

impl Visit for Sample {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().into(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
}

impl Sample {
    fn text(&self, name: &str) -> Result<&str> {
        self.0
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("missing work field {name}").into())
    }

    fn number(&self, name: &str) -> Result<u64> {
        Ok(self.text(name)?.parse()?)
    }
}

#[derive(Clone, Default)]
struct Work {
    samples: Arc<Mutex<Vec<Sample>>>,
    changed: Arc<tokio::sync::Notify>,
}

impl<S: Subscriber> Layer<S> for Work {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        if event.metadata().fields().field("stage").is_none()
            || event.metadata().fields().field("cut_revision").is_none()
        {
            return;
        }
        let mut sample = Sample::default();
        event.record(&mut sample);
        self.samples
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(sample);
        self.changed.notify_waiters();
    }
}

impl Work {
    fn start(&self) -> usize {
        self.samples
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }

    async fn completed(
        &self,
        source: &Source,
        start: usize,
        result: &str,
        publication: u64,
    ) -> Result<(usize, u64, u64)> {
        let instance = ManagedGraphOperation::Evaluate.instance_id(&source.identity);
        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                {
                    let samples = self
                        .samples
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    if let Some((index, committed)) =
                        samples.iter().enumerate().skip(start).find(|(_, sample)| {
                            sample.0.get("instance_id") == Some(&instance)
                                && sample.0.get("stage").map(String::as_str) == Some("graph_commit")
                                && sample.0.get("graph_result_id").map(String::as_str)
                                    == Some(result)
                                && sample
                                    .0
                                    .get("graph_revision")
                                    .and_then(|value| value.parse::<u64>().ok())
                                    == Some(publication)
                                && sample
                                    .0
                                    .get("coverage_revision")
                                    .and_then(|value| value.parse::<u64>().ok())
                                    .is_some_and(|revision| revision >= source.report_revision)
                        })
                    {
                        let cut = committed.number("cut_revision")?;
                        let receipt = committed.number("publication_revision")?;
                        let mut read = false;
                        for (index, sample) in samples.iter().enumerate().skip(index + 1) {
                            if sample.0.get("instance_id") != Some(&instance)
                                || sample.number("cut_revision")? != cut
                            {
                                continue;
                            }
                            match sample.text("stage")? {
                                "source_done" => read = true,
                                "subscription_done"
                                    if read
                                        && sample.number("publication_revision")? == receipt =>
                                {
                                    return Ok((index + 1, cut, receipt))
                                }
                                _ => {}
                            }
                        }
                    }
                }
                changed.await;
            }
        })
        .await
        .map_err(|_| {
            format!(
                "execution completion: source {}, cursor {}, Graph {publication}, report {}",
                source.seed, source.cursor, source.report_revision
            )
        })?
    }

    async fn read(
        &self,
        source: &Source,
        start: usize,
        result: &str,
        publication: u64,
        journal: u64,
    ) -> Result<()> {
        let (end, cut, receipt) = self.completed(source, start, result, publication).await?;
        assert!(
            journal <= cut && cut < receipt && publication <= receipt,
            "journal {journal}, context {cut}, Graph {publication}, receipt {receipt}"
        );
        let instance = ManagedGraphOperation::Evaluate.instance_id(&source.identity);
        let samples = self
            .samples
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut totals = BTreeMap::<String, u64>::new();
        let mut executed = std::collections::BTreeSet::new();
        let mut committed = std::collections::BTreeSet::new();
        let mut present = std::collections::BTreeSet::new();
        for sample in samples[start..end]
            .iter()
            .filter(|sample| sample.0.get("instance_id") == Some(&instance))
        {
            let step = sample.number("cut_revision")?;
            let stage = sample.text("stage")?;
            match stage {
                "source" if sample.text("source_name")? == "events" => {
                    let rows = sample.number("rows")?;
                    if rows > 0 && source.cursor > 1 {
                        assert_eq!(
                            sample.text("bounds_known")?,
                            "true",
                            "unmeasured event read: {:?}",
                            sample.0
                        );
                        assert_eq!(
                            (
                                sample.number("first_cursor")?,
                                sample.number("last_cursor")?
                            ),
                            (source.cursor, source.cursor),
                            "old disjoint event read: {:?}",
                            sample.0
                        );
                    }
                    *totals.entry("source".into()).or_default() += rows;
                    *totals.entry("source_reads".into()).or_default() += 1;
                }
                "capture"
                    if sample.text("operation")? == "journal_read"
                        && sample.text("source_name")? == "events" =>
                {
                    assert_eq!(
                        (
                            sample.number("first_cursor")?,
                            sample.number("last_cursor")?
                        ),
                        (source.cursor, source.cursor),
                        "old journal frame decoded: {:?}",
                        sample.0
                    );
                    assert_eq!(
                        sample.number("frame_rows")?,
                        1,
                        "single arrival read a frame with old records"
                    );
                    assert_eq!(
                        sample.number("body_bytes")?,
                        source.upload_bytes,
                        "journal read included another upload"
                    );
                    assert!(
                        sample.number("bytes")? > source.upload_bytes,
                        "journal frame bytes omit its envelope"
                    );
                    *totals.entry("journal_rows".into()).or_default() += sample.number("rows")?;
                    *totals.entry("journal_bytes".into()).or_default() += sample.number("bytes")?;
                    *totals.entry("journal_reads".into()).or_default() += 1;
                }
                "capture" if sample.text("operation")? == "complete" => {
                    *totals.entry("capture".into()).or_default() += sample.number("read_count")?;
                }
                "graph_input" | "context" => {
                    *totals.entry(stage.into()).or_default() += sample.number("rows")?;
                }
                "package" => {
                    let call = sample.number("call_id")?;
                    let units = (
                        sample.number("affected_rows")?,
                        sample.number("before_rows")?,
                        sample.number("after_rows")?,
                    );
                    assert!(
                        units == (0, 0, 0) || units == (1, u64::from(present.contains(&call)), 1),
                        "package used unrelated units: {:?}",
                        sample.0
                    );
                    assert!(executed.insert((step, call)), "package repeated in one cut");
                    *totals.entry("package".into()).or_default() += sample.number("rows")?;
                    *totals.entry("outputs".into()).or_default() += sample.number("output_rows")?;
                }
                "call_commit" => {
                    let units = sample.number("unit_rows")?;
                    assert_eq!(
                        sample.number("removal_rows")?,
                        0,
                        "disjoint append removed a unit"
                    );
                    let roots = (
                        sample.number("first_root_cursor")?,
                        sample.number("last_root_cursor")?,
                    );
                    if units == 0 {
                        assert_eq!(roots, (0, 0), "empty call changed an old root");
                        assert_eq!(
                            sample.number("record_rows")?,
                            0,
                            "empty call stored records"
                        );
                    } else {
                        let call = sample.number("call_id")?;
                        assert_eq!(
                            (units, sample.number("record_rows")?),
                            (1, 1),
                            "changed stored units: {:?}",
                            sample.0
                        );
                        assert_eq!(
                            roots,
                            (source.cursor, source.cursor),
                            "old stored unit changed: {:?}",
                            sample.0
                        );
                        assert!(
                            executed.contains(&(step, call)),
                            "unit committed without this execution"
                        );
                        assert!(
                            committed.insert((step, call)),
                            "unit committed twice in one cut"
                        );
                        present.insert(call);
                    }
                    *totals.entry("facts".into()).or_default() += sample.number("fact_rows")?;
                }
                "graph_commit" => {
                    if sample.text("graph_result_id")?.is_empty() {
                        assert_eq!(sample.number("graph_revision")?, 0);
                        for field in [
                            "staged_support_rows",
                            "inserted_rows",
                            "closed_rows",
                            "detector_inserted_rows",
                            "detector_closed_rows",
                        ] {
                            assert_eq!(
                                sample.number(field)?,
                                0,
                                "empty Graph packet changed {field}"
                            );
                        }
                        assert!(
                            !committed.iter().any(|(committed, _)| *committed == step),
                            "empty Graph packet changed a unit"
                        );
                    } else {
                        let report = sample.number("coverage_revision")?;
                        assert!(
                            report == source.previous_report || report == source.report_revision,
                            "execution used another coverage report: {:?}",
                            sample.0
                        );
                        if sample.number("detector_closed_rows")? != 0 {
                            assert!(
                                committed.iter().any(|(committed, _)| *committed == step),
                                "detector rows closed without a changed new unit"
                            );
                        }
                    }
                    *totals.entry("graph_commit".into()).or_default() +=
                        sample.number("staged_support_rows")?;
                    for (key, field) in [
                        ("inserted", "inserted_rows"),
                        ("closed", "closed_rows"),
                        ("pins", "pin_rows"),
                        ("detector_inserted", "detector_inserted_rows"),
                        ("detector_closed", "detector_closed_rows"),
                    ] {
                        *totals.entry(key.into()).or_default() += sample.number(field)?;
                    }
                }
                _ => {}
            }
        }
        assert_eq!(present.len(), araphor_data::FindingV1::PACKAGES.len());
        for key in [
            "capture",
            "source",
            "graph_input",
            "context",
            "package",
            "graph_commit",
            "journal_bytes",
        ] {
            assert!(
                totals.contains_key(key),
                "missing real execution stage {key}"
            );
        }
        assert_eq!(
            totals["journal_rows"], 1,
            "single arrival reread journal events"
        );
        assert_eq!(
            totals["journal_reads"], 1,
            "single arrival reread journal frames"
        );
        erebor_telemetry::debug!(
            source = source.seed,
            cursor = source.cursor,
            ?totals,
            "Incremental source work observed"
        );
        Ok(())
    }

    fn lineage(&self, sources: &[Source]) -> Result<()> {
        let samples = self
            .samples
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let expected = sources
            .iter()
            .map(|source| ManagedGraphOperation::Evaluate.instance_id(&source.identity))
            .collect::<std::collections::BTreeSet<_>>();
        let mut commits = Vec::new();
        for Sample(fields) in samples.iter().filter(|Sample(fields)| {
            fields.get("stage").map(String::as_str) == Some("call_commit")
                && fields
                    .get("instance_id")
                    .is_some_and(|id| expected.contains(id))
        }) {
            let publication: u64 = fields
                .get("publication_revision")
                .ok_or("call publication")?
                .parse()?;
            let call: u64 = fields.get("call_id").ok_or("committed call")?.parse()?;
            commits.push((publication, call, fields));
        }
        commits.sort_by_key(|(publication, call, _)| (*publication, *call));
        let mut calls = BTreeMap::<String, std::collections::BTreeSet<u64>>::new();
        let mut previous = BTreeMap::<(String, u64), (String, u64)>::new();
        for (publication, call, fields) in commits {
            let key = (
                fields.get("instance_id").ok_or("call instance")?.clone(),
                call,
            );
            let result = fields.get("result_id").ok_or("committed result")?;
            let base = fields.get("base_result_id").ok_or("actual change base")?;
            let reset: bool = fields.get("reset").ok_or("actual reset flag")?.parse()?;
            let base_revision: u64 = fields
                .get("base_revision")
                .ok_or("actual base publication")?
                .parse()?;
            calls.entry(key.0.clone()).or_default().insert(call);
            if let Some((expected, revision)) = previous.insert(key, (result.clone(), publication))
            {
                assert!(!reset, "continuing subscription reset: {fields:?}");
                assert_eq!(base, &expected, "wrong previous package result");
                assert_eq!(
                    base_revision, revision,
                    "wrong previous package publication"
                );
            } else {
                assert!(
                    reset && base.is_empty() && base_revision == 0,
                    "initial subscription base: {fields:?}"
                );
            }
        }
        assert_eq!(
            calls
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            expected
        );
        assert!(calls
            .values()
            .all(|calls| calls.len() == araphor_data::FindingV1::PACKAGES.len()));
        Ok(())
    }
}

struct Source {
    input: EffectObservationStore,
    identity: EvidenceIntakeIdentityV1,
    seed: u8,
    cursor: u64,
    upload_bytes: u64,
    report_revision: u64,
    previous_report: u64,
    denials: usize,
    expected: Vec<u8>,
    previous: Option<(String, u64, u64, u64)>,
    values: BTreeMap<String, u64>,
    notices: BTreeMap<String, String>,
}

impl Source {
    fn open(tls: &MtlsFixture, seed: u8) -> Result<Self> {
        let input = wal(tls, &format!("incremental-{seed}"), seed)?;
        let snapshot = input.coverage_snapshot().ok_or("source coverage")?;
        let identity = snapshot
            .current_intervals()
            .into_iter()
            .find(|interval| interval.cpu_id == 3)
            .map(|interval| tls.identity(interval.source_id.to_be_bytes()))
            .ok_or("source identity")?;
        Ok(Self {
            input,
            identity,
            seed,
            cursor: 0,
            upload_bytes: 0,
            report_revision: 0,
            previous_report: 0,
            denials: 0,
            expected: Vec::new(),
            previous: None,
            values: BTreeMap::new(),
            notices: BTreeMap::new(),
        })
    }

    async fn append(
        &mut self,
        tls: &MtlsFixture,
        node: &mut ControlConnection,
        template: EffectObservationV1,
        count: u64,
        denied: bool,
    ) -> Result<()> {
        for cursor in self.cursor + 1..=self.cursor + count {
            let mut event = template;
            event.source_cpu_id = 3;
            event.source_sequence = cursor;
            event.observed_boottime_ns = 100 + cursor;
            event.task_cookie = if denied {
                7
            } else {
                (u64::from(self.seed) << 32) | cursor
            };
            event.process_instance_id = EvidenceIdV1::new(u64::from(self.seed), cursor)
                .to_be_bytes()
                .into();
            event.entry_instance_id = EvidenceIdV1::new(cursor, u64::from(self.seed))
                .to_be_bytes()
                .into();
            self.input.record_bytes(event.as_bytes());
        }
        let (identity, uploaded) = upload_on(tls, node, &self.input).await?;
        assert_eq!(identity, self.identity);
        self.expected.extend_from_slice(&uploaded);
        self.upload_bytes = u64::try_from(uploaded.len())?;
        self.previous_report = self.report_revision;
        self.report_revision = self
            .input
            .coverage_snapshot()
            .ok_or("acknowledged coverage")?
            .revision;
        self.cursor += count;
        if denied {
            self.denials += usize::try_from(count)?;
        }
        Ok(())
    }
}

struct Received {
    cursor: u64,
    bytes: Vec<u8>,
    position: StorePositionV1,
}

struct Flow {
    streams: [tonic::Streaming<wire::QueryFrame>; 4],
    events: BTreeMap<[u8; 16], Received>,
    graphs: BTreeMap<Vec<u8>, wire::QueryRow>,
    findings: BTreeMap<String, wire::QueryRow>,
    notices: BTreeMap<String, (String, u64)>,
    revisions: [u64; 4],
    exhausted: [bool; 4],
}

impl Flow {
    async fn subscribe(client: &erebor_runtime_client::AraphorClient) -> Result<Self> {
        let mut streams = Vec::new();
        for sql in [
            "SELECT source_id, cpu_id, source_cursor, commit_revision, ordinal, framed_record FROM events",
            "WITH heads AS (SELECT * FROM graph_manifest QUALIFY ROW_NUMBER() OVER (PARTITION BY source_key, first_cursor ORDER BY commit_revision DESC) = 1) SELECT source_key, graph_result_id, commit_revision, first_cursor, last_cursor, subject_count, relationship_count, notice_coverage_revision FROM heads WHERE NOT retained_input_expired",
            "SELECT source_key, graph_result_id, finding_id, finding_value_id, state, commit_revision FROM findings WHERE package_id = 'HF-PROC-001' QUALIFY ROW_NUMBER() OVER (PARTITION BY source_key, finding_id ORDER BY commit_revision DESC) = 1",
            "SELECT finding_id, finding_result_id, finding_value_id FROM notifications WHERE package_id = 'HF-PROC-001' AND route_id = 'primary'",
        ] {
            streams.push(client.query(wire::QueryRequest { sql: sql.into(), follow: true,
                ..Default::default() }).await?);
        }
        let streams = streams.try_into().map_err(|_| "subscription count")?;
        Ok(Self {
            streams,
            events: BTreeMap::new(),
            graphs: BTreeMap::new(),
            findings: BTreeMap::new(),
            notices: BTreeMap::new(),
            revisions: [0; 4],
            exhausted: [false; 4],
        })
    }

    async fn next(&mut self) -> Result<()> {
        let (source, frame) = {
            let [events, graphs, findings, notices] = &mut self.streams;
            tokio::select! {
                frame = events.message() => (0, frame?),
                frame = graphs.message() => (1, frame?),
                frame = findings.message() => (2, frame?),
                frame = notices.message() => (3, frame?),
            }
        };
        let frame = frame.ok_or("pipeline subscription closed")?;
        match frame.payload {
            Some(Payload::Rows(rows)) => {
                self.revisions[source] = 0;
                self.exhausted[source] = !rows.limited;
                if frame.operation == wire::QueryOperation::Replace as i32 {
                    match source {
                        0 => assert!(
                            self.events.is_empty(),
                            "immutable event subscription replaced rows"
                        ),
                        1 => self.graphs.clear(),
                        2 => self.findings.clear(),
                        3 => self.notices.clear(),
                        _ => unreachable!(),
                    }
                }
                for row in rows.rows {
                    match source {
                        0 => {
                            let id: [u8; 16] = Incident::binary(&row, 0)?.try_into()?;
                            assert_eq!(Incident::number(&row, 1)?, 3);
                            let cursor = Incident::number(&row, 2)?;
                            let position = StorePositionV1 {
                                commit_revision: Incident::number(&row, 3)?,
                                ordinal: Incident::number(&row, 4)?.try_into()?,
                            };
                            let received = self.events.entry(id).or_insert_with(|| Received {
                                cursor: 0,
                                bytes: Vec::new(),
                                position,
                            });
                            assert_eq!(cursor, received.cursor + 1, "event order or duplicate");
                            received.bytes.extend_from_slice(Incident::binary(&row, 5)?);
                            received.cursor = cursor;
                            received.position = position;
                        }
                        1 => {
                            self.graphs.insert(Incident::binary(&row, 0)?.to_vec(), row);
                        }
                        2 => {
                            self.findings.insert(Incident::text(&row, 2)?.into(), row);
                        }
                        3 => {
                            self.notices.insert(
                                Incident::text(&row, 0)?.into(),
                                (Incident::text(&row, 1)?.into(), Incident::number(&row, 2)?),
                            );
                        }
                        _ => unreachable!(),
                    }
                }
            }
            Some(Payload::Checkpoint(_)) if self.exhausted[source] => {
                self.revisions[source] = frame.read_revision
            }
            Some(Payload::Error(error)) => {
                return Err(format!("pipeline subscription {source}: {error:?}").into())
            }
            Some(Payload::Terminal(terminal)) => {
                return Err(format!("pipeline subscription {source} ended: {terminal:?}").into())
            }
            _ => {}
        }
        Ok(())
    }

    async fn during<T>(&mut self, work: impl std::future::Future<Output = Result<T>>) -> Result<T> {
        tokio::pin!(work);
        loop {
            tokio::select! {
                result = &mut work => return result,
                result = self.next() => result?,
            }
        }
    }

    fn ready(&self, source: &Source) -> Result<bool> {
        let Some(received) = self.events.get(&source.identity.source_id) else {
            return Ok(false);
        };
        let Some(graph) = self.graphs.get(&source.identity.key()) else {
            return Ok(false);
        };
        let publication = Incident::number(graph, 2)?;
        if received.cursor != source.cursor
            || Incident::number(graph, 4)? != source.cursor
            || Incident::number(graph, 7)? < source.report_revision
            || self.revisions[1..3]
                .iter()
                .any(|revision| *revision < publication)
        {
            return Ok(false);
        }
        let id = Incident::text(graph, 1)?;
        let mut findings = Vec::new();
        for row in self.findings.values() {
            if Incident::binary(row, 0)? == source.identity.key() {
                if Incident::text(row, 1)? != id || Incident::text(row, 4)? != "confirmed" {
                    return Ok(false);
                }
                findings.push((Incident::text(row, 2)?, Incident::number(row, 3)?));
            }
        }
        Ok(findings.len() == source.denials
            && findings.into_iter().all(|(finding, value)| {
                self.notices
                    .get(finding)
                    .is_some_and(|(reference, native)| {
                        !reference.is_empty()
                            && *native == value
                            && source
                                .notices
                                .get(finding)
                                .is_none_or(|old| reference == old)
                    })
            }))
    }

    async fn wait(&mut self, source: &mut Source) -> Result<(String, u64, u64)> {
        tokio::time::timeout(Duration::from_secs(90), async {
            while !self.ready(source)? {
                self.next().await?;
            }
            let received = self
                .events
                .get_mut(&source.identity.source_id)
                .ok_or("subscribed events")?;
            assert_eq!(received.bytes, source.expected);
            received.bytes.clear();
            source.expected.clear();
            let graph = self
                .graphs
                .get(&source.identity.key())
                .ok_or("subscribed Graph")?;
            let id = Incident::text(graph, 1)?.to_owned();
            let publication = Incident::number(graph, 2)?;
            assert_eq!(Incident::number(graph, 3)?, 1);
            let subjects = Incident::number(graph, 5)?;
            let relationships = Incident::number(graph, 6)?;
            assert!(subjects > 0 && relationships > 0);
            if let Some((_, _, old_subjects, old_relationships)) = &source.previous {
                assert!(subjects >= *old_subjects && relationships >= *old_relationships);
            }
            let mut values = BTreeMap::new();
            for row in self.findings.values() {
                if Incident::binary(row, 0)? == source.identity.key() {
                    values.insert(
                        Incident::text(row, 2)?.to_owned(),
                        Incident::number(row, 3)?,
                    );
                }
            }
            for (finding, value) in &source.values {
                assert_eq!(
                    values.get(finding),
                    Some(value),
                    "old finding value changed"
                );
            }
            source.notices = values
                .keys()
                .map(|finding| {
                    Ok((
                        finding.clone(),
                        self.notices
                            .get(finding)
                            .ok_or("subscribed notification")?
                            .0.clone(),
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            source.values = values;
            source.previous = Some((id.clone(), publication, subjects, relationships));
            Ok::<_, Box<dyn std::error::Error>>((
                id,
                publication,
                received.position.commit_revision,
            ))
        })
        .await
        .map_err(|_| {
            let received = self.events.get(&source.identity.source_id).map(|received| received.cursor);
            let graph = self.graphs.get(&source.identity.key()).map(|row| (
                Incident::number(row, 2), Incident::number(row, 4),
            ));
            format!("subscription progress: source {}, expected cursor {}, received {received:?}, graph publication/cursor {graph:?}, checkpoints {:?}, findings {}, notifications {}",
                source.seed, source.cursor, self.revisions, self.findings.len(), self.notices.len())
        })?
    }
}

#[tokio::test]
async fn follows_incremental_sources() -> Result<()> {
    let total_time = Instant::now();
    let work = Work::default();
    let output = erebor_telemetry::tracing_subscriber::fmt::layer()
        .with_test_writer()
        .with_ansi(false)
        .with_filter(erebor_telemetry::tracing_subscriber::EnvFilter::from_default_env());
    let dispatch = erebor_telemetry::tracing::Dispatch::new(
        Registry::default().with(work.clone()).with(output),
    );
    async move {
        let startup_time = Instant::now();
        let tls = MtlsFixture::new(false)?;
        let oidc = OidcFixture::start(&tls.files, "incremental-operator").await?;
        let outcome: Result<()> = async {
            let config_time = Instant::now();
            let (mut config, _, authority) = configuration(&tls, &oidc).await?;
            config.data_retention.raw_max_age_ns = None;
            let auth = config
                .client
                .as_ref()
                .ok_or("subscription auth")?
                .auth
                .clone();
            let at = i64::try_from(now()?)?;
            input::policy_config(&mut config, tls.path())?;
            let fixture = Fixture::configured(config, authority)?;
            erebor_telemetry::debug!(
                stage = "live_test",
                section = "configuration",
                elapsed_s = config_time.elapsed().as_secs_f64(),
                inclusive = false,
                "Live subscription test section completed"
            );
            let listen_time = Instant::now();
            let (fixture, server) = fixture.listening(&tls).await?;
            let credential = tls.path().join("incremental-token");
            fs::write(&credential, b"fixture-access")?;
            let (client, query) = fixture
                .client(
                    &tls,
                    &auth,
                    &credential,
                    EvidenceIdV1::new(1, 2).to_be_bytes(),
                )
                .await?;
            erebor_telemetry::debug!(
                stage = "live_test",
                section = "listening",
                elapsed_s = listen_time.elapsed().as_secs_f64(),
                inclusive = false,
                "Live subscription test section completed"
            );
            let tested: Result<()> = async {
                let subscribe_time = Instant::now();
                let mut flow = Flow::subscribe(&client).await?;
                erebor_telemetry::debug!(
                    stage = "live_test",
                    section = "subscriptions",
                    elapsed_s = subscribe_time.elapsed().as_secs_f64(),
                    inclusive = false,
                    "Live subscription test section completed"
                );
                let policy_time = Instant::now();
                let owner = fixture
                    .control
                    .policy_desired_state()
                    .ok_or("policy owner")?;
                let prepared = signed_catalog(owner, tls.path(), [7; 16].into(), at, None)?;
                assert!(fixture
                    .control
                    .replace_kubernetes_workload_inventory(vec![prepared.workload])?);
                let mut trust = TrustCache::load(&tls.path().join("incremental-trust"))?;
                let registration = OutagePolicyFixture::registration([7; 16], false);
                let mut node: ControlConnection = tls
                    .connector(&server, "node-a", [7; 16])
                    .connect(registration, false, &mut trust)
                    .await?;
                node.report_readiness(true, true).await?;
                fixture.control.bind_kubernetes_node_session(
                    "worker-a",
                    "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                )?;
                let delivered = input::fetch_policy(&mut node, &prepared.bundle).await?;
                let ack = OutagePolicyFixture::active_acknowledgement(&delivered, 8, at);
                assert_eq!(node.acknowledge_policy(ack).await?.rollout_state, "ACTIVE");
                erebor_telemetry::debug!(
                    stage = "live_test",
                    section = "policy",
                    elapsed_s = policy_time.elapsed().as_secs_f64(),
                    inclusive = false,
                    "Live subscription test section completed"
                );
                let catalog = Arc::new(prepared.catalog);
                let mut sources = [33, 34, 35, 36]
                    .into_iter()
                    .map(|seed| Source::open(&tls, seed))
                    .collect::<Result<Vec<_>>>()?;
                for source in &sources {
                    source
                        .input
                        .set_discovery_context(Some(Arc::clone(&catalog)));
                }
                let [denied, allowed] = input::events(prepared.raw);
                erebor_telemetry::debug!(
                    stage = "live_test",
                    section = "startup",
                    elapsed_s = startup_time.elapsed().as_secs_f64(),
                    inclusive = true,
                    "Live subscription test section completed"
                );
                let first = work.start();
                for source in &mut sources {
                    let arrival_time = Instant::now();
                    let observed = async {
                        source.append(&tls, &mut node, denied, 1, true).await?;
                        flow.wait(source).await
                    }
                    .await;
                    erebor_telemetry::debug!(
                        stage = "live_test",
                        section = "initial_notice",
                        source = source.seed,
                        cursor = source.cursor,
                        elapsed_s = arrival_time.elapsed().as_secs_f64(),
                        inclusive = true,
                        success = observed.is_ok(),
                        "Live subscription test section completed"
                    );
                    let (id, publication, journal) = observed?;
                    work.read(source, first, &id, publication, journal).await?;
                }
                let bulk_time = Instant::now();
                flow.during(async {
                    for _ in 0..15 {
                        for source in &mut sources {
                            source.append(&tls, &mut node, allowed, 256, false).await?;
                        }
                    }
                    for source in &mut sources {
                        source.append(&tls, &mut node, allowed, 255, false).await?;
                    }
                    Ok(())
                })
                .await?;
                for source in &mut sources {
                    let (id, publication, _) = flow.wait(source).await?;
                    work.completed(source, 0, &id, publication).await?;
                }
                erebor_telemetry::debug!(
                    stage = "live_test",
                    section = "bulk_fill_drain",
                    elapsed_s = bulk_time.elapsed().as_secs_f64(),
                    inclusive = true,
                    "Live subscription test section completed"
                );
                for _ in 0..2 {
                    for index in 0..sources.len() {
                        let untouched = sources
                            .iter()
                            .enumerate()
                            .filter(|(other, _)| *other != index)
                            .map(|(_, source)| {
                                Ok((
                                    source.identity.key(),
                                    source
                                        .previous
                                        .as_ref()
                                        .ok_or("untouched source")?
                                        .0
                                        .clone(),
                                ))
                            })
                            .collect::<Result<Vec<_>>>()?;
                        let started = work.start();
                        let arrival_time = Instant::now();
                        let observed = async {
                            sources[index]
                                .append(&tls, &mut node, denied, 1, true)
                                .await?;
                            flow.wait(&mut sources[index]).await
                        }
                        .await;
                        erebor_telemetry::debug!(
                            stage = "live_test",
                            section = "warm_notice",
                            source = sources[index].seed,
                            cursor = sources[index].cursor,
                            elapsed_s = arrival_time.elapsed().as_secs_f64(),
                            inclusive = true,
                            success = observed.is_ok(),
                            "Live subscription test section completed"
                        );
                        let (id, publication, journal) = observed?;
                        for (identity, expected) in untouched {
                            let graph = flow
                                .graphs
                                .get(&identity)
                                .ok_or("untouched Graph subscription")?;
                            assert_eq!(Incident::text(graph, 1)?, expected);
                        }
                        let work_time = Instant::now();
                        let checked = work
                            .read(&sources[index], started, &id, publication, journal)
                            .await;
                        erebor_telemetry::debug!(
                            stage = "live_test",
                            section = "warm_work",
                            source = sources[index].seed,
                            cursor = sources[index].cursor,
                            elapsed_s = work_time.elapsed().as_secs_f64(),
                            arrival_elapsed_s = arrival_time.elapsed().as_secs_f64(),
                            inclusive = false,
                            arrival_inclusive = true,
                            success = checked.is_ok(),
                            "Live subscription test section completed"
                        );
                        checked?;
                    }
                }
                work.lineage(&sources)?;
                Ok(())
            }
            .await;
            let teardown_time = Instant::now();
            drop(client);
            query.shutdown().await?;
            let (network, stopped) = tokio::join!(server.shutdown(), fixture.shutdown());
            network?;
            stopped?;
            erebor_telemetry::debug!(
                stage = "live_test",
                section = "teardown",
                component = "pipeline",
                elapsed_s = teardown_time.elapsed().as_secs_f64(),
                inclusive = true,
                "Live subscription test section completed"
            );
            tested
        }
        .await;
        let teardown_time = Instant::now();
        let stopped = oidc.shutdown().await;
        erebor_telemetry::debug!(
            stage = "live_test",
            section = "teardown",
            component = "oidc",
            elapsed_s = teardown_time.elapsed().as_secs_f64(),
            inclusive = false,
            success = stopped.is_ok(),
            "Live subscription test section completed"
        );
        erebor_telemetry::debug!(
            stage = "live_test",
            section = "total",
            elapsed_s = total_time.elapsed().as_secs_f64(),
            inclusive = true,
            success = outcome.is_ok() && stopped.is_ok(),
            "Live subscription test section completed"
        );
        stopped?;
        outcome
    }
    .with_subscriber(dispatch)
    .await
}
