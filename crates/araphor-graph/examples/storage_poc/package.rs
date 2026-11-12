use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::Instant;

use araphor_analysis_builtins::causal::Causal;
use araphor_analysis_sdk as sdk;
use araphor_graph::{Journal, Read};
use arrow_array::{Array, RecordBatch};
use serde::Serialize;

use super::{
    GraphRead, Result,
    fixture::{Fixture, Spec, Step},
    incident::Incident,
};

#[derive(Serialize)]
pub struct Call {
    pub writer: u64,
    pub operation: String,
    pub relation: u64,
    pub key_count: usize,
    pub rows: usize,
    pub elapsed_s: f64,
    #[serde(skip)]
    pub keys: Vec<Vec<u8>>,
}
impl Call {
    pub fn signature(&self) -> (u64, &str, u64, &[Vec<u8>], usize) {
        (
            self.writer,
            &self.operation,
            self.relation,
            &self.keys,
            self.rows,
        )
    }
}

struct Host<'a> {
    view: &'a dyn GraphRead,
    fixture: &'a Fixture,
    writer: u64,
    journal: RefCell<Journal>,
    calls: RefCell<Vec<Call>>,
}
impl<'a> Host<'a> {
    fn new(view: &'a dyn GraphRead, fixture: &'a Fixture, writer: u64) -> Result<Self> {
        Ok(Self {
            view,
            fixture,
            writer,
            journal: RefCell::new(Journal::new(writer)?),
            calls: RefCell::new(Vec::new()),
        })
    }
    fn record(
        &self,
        operation: &str,
        relation: u64,
        keys: Vec<Vec<u8>>,
        rows: usize,
        started: Instant,
    ) {
        self.calls.borrow_mut().push(Call {
            writer: self.writer,
            operation: operation.into(),
            relation,
            key_count: keys.len(),
            rows,
            elapsed_s: started.elapsed().as_secs_f64(),
            keys,
        });
    }
    fn error(error: impl std::fmt::Display) -> sdk::Error {
        sdk::Error::contract(sdk::ErrorCode::Failed, error.to_string())
    }
}
impl sdk::InvocationHost for Host<'_> {
    fn read(&self, operation: &str, arguments: &sdk::Dataset) -> sdk::Result<sdk::Input> {
        let started = Instant::now();
        let relation = Fixture::relation(&arguments.name).map_err(Self::error)?;
        let read = match operation {
            "nodes" => Read::Nodes,
            "outgoing" => Read::Outgoing,
            "incoming" => Read::Incoming,
            "neighbors" => Read::Neighbors,
            "owned" => Read::Owned(self.writer),
            _ => return Err(Self::error("unknown Graph operation")),
        };
        let [keys] = arguments.batches.as_slice() else {
            return Err(Self::error("Graph argument batch"));
        };
        let requested = if operation == "owned" {
            Vec::new()
        } else {
            super::binary(keys, "key")
                .map_err(Self::error)?
                .iter()
                .flatten()
                .map(<[u8]>::to_vec)
                .collect()
        };
        let base = self.view.query(relation, read, keys).map_err(Self::error)?;
        let batches = self
            .journal
            .borrow()
            .overlay(
                relation,
                &self.fixture.shapes[&relation],
                read,
                &requested,
                base,
            )
            .map_err(Self::error)?;
        self.record(
            operation,
            relation,
            requested,
            batches.iter().map(RecordBatch::num_rows).sum(),
            started,
        );
        Ok(sdk::Input {
            data: sdk::Dataset {
                name: arguments.name.clone(),
                batches,
            },
            revision: sdk::Revision {
                owner: "Graph".into(),
                id: "captured".into(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        })
    }
    fn stage(&self, commands: &sdk::Dataset) -> sdk::Result<()> {
        let [batch] = commands.batches.as_slice() else {
            return Err(Self::error("Graph command batch"));
        };
        let prepared = if commands.name == "graph_clear" {
            self.journal
                .borrow()
                .prepare_clear(batch.clone())
                .map_err(Self::error)?
        } else {
            let started = Instant::now();
            let relation = Fixture::relation(&commands.name).map_err(Self::error)?;
            let present = self
                .view
                .presence(self.writer, relation, batch)
                .map_err(Self::error)?;
            let keys = super::binary(batch, "key")
                .map_err(Self::error)?
                .iter()
                .flatten()
                .map(<[u8]>::to_vec)
                .collect();
            self.record(
                "presence",
                relation,
                keys,
                present.iter().filter(|v| **v).count(),
                started,
            );
            self.journal
                .borrow()
                .prepare(
                    relation,
                    &self.fixture.shapes[&relation],
                    batch.clone(),
                    &present,
                )
                .map_err(Self::error)?
        };
        self.journal
            .borrow_mut()
            .publish(prepared)
            .map_err(Self::error)
    }
}

pub struct Prepared {
    pub step: Step,
    pub calls: Vec<Call>,
    pub frontier: Vec<usize>,
    pub index_s: f64,
    pub resolve_s: f64,
    pub detect_s: f64,
    pub normalize_s: f64,
}

pub fn evaluate(
    view: &dyn GraphRead,
    fixture: &Fixture,
    incident: &Incident,
    spec: Spec,
    input: &sdk::Evaluation,
) -> Result<Prepared> {
    let package = Causal::descriptor();
    let index = Host::new(view, fixture, 1)?;
    let started = Instant::now();
    let mut checked = package.check_evaluation(input)?;
    checked.bind_host(&index)?;
    let output = checked.evaluate(Causal::compute)?;
    let index_s = started.elapsed().as_secs_f64();
    let started = Instant::now();
    let (input, frontier) = incident.detect_input(&output, spec)?;
    let resolve_s = started.elapsed().as_secs_f64();
    let detect = Host::new(view, fixture, 2)?;
    let started = Instant::now();
    let mut checked = package.check_evaluation(&input)?;
    checked.bind_host(&detect)?;
    let output = checked.evaluate(Causal::compute)?;
    let summary = output.datasets.first().ok_or("summary absent")?;
    let findings = summary
        .batches
        .first()
        .ok_or("summary batch absent")?
        .column(0)
        .as_any()
        .downcast_ref::<arrow_array::UInt64Array>()
        .ok_or("summary type")?
        .value(0);
    assert_eq!(findings, spec.expected_findings as u64);
    let detect_s = started.elapsed().as_secs_f64();
    let mut calls = index.calls.into_inner();
    calls.extend(detect.calls.into_inner());
    let started = Instant::now();
    let step = Step::new(
        spec,
        BTreeMap::from([
            (1, index.journal.into_inner()),
            (2, detect.journal.into_inner()),
        ]),
    )?;
    let normalize_s = started.elapsed().as_secs_f64();
    Ok(Prepared {
        step,
        calls,
        frontier,
        index_s,
        resolve_s,
        detect_s,
        normalize_s,
    })
}
