use super::Result;
use araphor_analysis_builtins::causal::Causal;
use araphor_graph::{Journal, Relation, Staged};
use arrow_array::{Array, RecordBatch, StructArray, UInt64Array};
use arrow_schema::Schema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct Row {
    pub writer: u64,
    pub relation: u64,
    pub owner: Vec<u8>,
    pub key: Vec<u8>,
    pub endpoints: Option<[Vec<u8>; 3]>,
    pub properties: Arc<RecordBatch>,
    pub row: usize,
    pub opened: u64,
}

impl Row {
    pub fn identity(&self) -> (u64, u64, Vec<u8>, Vec<u8>) {
        (
            self.writer,
            self.relation,
            self.owner.clone(),
            self.key.clone(),
        )
    }

    pub fn value(&self) -> Result<RecordBatch> {
        Ok(arrow_select::take::take_record_batch(
            &self.properties,
            &UInt64Array::from(vec![self.row as u64]),
        )?)
    }

    pub fn assert_equal(&self, other: &Self) -> Result<()> {
        assert_eq!(self.identity(), other.identity());
        assert_eq!(self.endpoints, other.endpoints);
        assert_eq!(self.opened, other.opened);
        assert_eq!(self.value()?, other.value()?);
        Ok(())
    }
}

pub struct Group {
    pub rows: Vec<Row>,
}

#[derive(Clone, Copy)]
pub struct Spec {
    pub revision: u64,
    pub captured: u64,
    pub previous: u64,
    pub expected_findings: usize,
    pub expected_frontier: usize,
}

pub struct Step {
    pub revision: u64,
    pub captured: u64,
    pub previous: u64,
    pub groups: Vec<Group>,
    pub clears: Vec<(u64, Option<Vec<u8>>)>,
    pub journals: BTreeMap<u64, Journal>,
}

impl Step {
    pub fn new(spec: Spec, journals: BTreeMap<u64, Journal>) -> Result<Self> {
        let mut groups = Vec::new();
        let mut clears = Vec::new();
        for (&writer, journal) in &journals {
            for staged in journal.batches() {
                match staged {
                    Staged::Clear { batch, .. } => {
                        let owners = super::binary(batch, "owner")?;
                        clears.extend((0..batch.num_rows()).map(|i| {
                            (
                                writer,
                                (!owners.is_null(i)).then(|| owners.value(i).to_vec()),
                            )
                        }));
                    }
                    Staged::Edits {
                        relation, batch, ..
                    } => {
                        let props = batch
                            .column_by_name("properties")
                            .ok_or("properties absent")?
                            .as_any()
                            .downcast_ref::<StructArray>()
                            .ok_or("property struct absent")?;
                        let properties = Arc::new(RecordBatch::try_new(
                            Arc::new(Schema::new(props.fields().clone())),
                            props.columns().to_vec(),
                        )?);
                        let owners = super::binary(batch, "owner")?;
                        let keys = super::binary(batch, "key")?;
                        let edge = (*relation == 3)
                            .then(|| ["from", "to", "label"].map(|name| super::binary(batch, name)))
                            .map(|a| {
                                let [from, to, label] = a;
                                Ok::<_, Box<dyn std::error::Error>>([from?, to?, label?])
                            })
                            .transpose()?;
                        let rows = (0..batch.num_rows())
                            .map(|i| Row {
                                writer,
                                relation: *relation,
                                owner: owners.value(i).to_vec(),
                                key: keys.value(i).to_vec(),
                                endpoints: edge.as_ref().map(|a| a.map(|x| x.value(i).to_vec())),
                                properties: Arc::clone(&properties),
                                row: i,
                                opened: spec.revision,
                            })
                            .collect();
                        groups.push(Group { rows });
                    }
                }
            }
        }
        Ok(Self {
            revision: spec.revision,
            captured: spec.captured,
            previous: spec.previous,
            groups,
            clears,
            journals,
        })
    }
    pub fn added(&self) -> usize {
        self.groups.iter().map(|g| g.rows.len()).sum()
    }
    pub fn state(&self, writer: u64) -> Vec<u8> {
        [
            writer.to_be_bytes().as_slice(),
            self.captured.to_be_bytes().as_slice(),
            &[0x7f; 64],
        ]
        .concat()
    }
}

pub struct Fixture {
    pub shapes: BTreeMap<u64, Relation>,
    pub steps: Vec<Spec>,
}
impl Fixture {
    pub fn new() -> Result<Self> {
        let package = Causal::descriptor();
        let mut shapes = BTreeMap::new();
        for model in &package.exports {
            for relation in &model
                .graph
                .as_ref()
                .ok_or("Graph declaration absent")?
                .relations
            {
                shapes.insert(Self::relation(&relation.name)?, relation.engine());
            }
        }
        let mut previous = 1;
        let steps = [
            (26, 24, 0, 5),
            (29, 27, 1, 6),
            (44, 36, 1, 6),
            (46, 44, 1, 6),
            (62, 48, 1, 6),
            (64, 62, 2, 12),
            (85, 71, 2, 12),
            (87, 85, 3, 18),
        ]
        .into_iter()
        .map(
            |(revision, captured, expected_findings, expected_frontier)| {
                let spec = Spec {
                    revision,
                    captured,
                    previous,
                    expected_findings,
                    expected_frontier,
                };
                previous = revision;
                spec
            },
        )
        .collect();
        Ok(Self { shapes, steps })
    }
    pub fn relation(name: &str) -> Result<u64> {
        match name {
            "araphor_findings_v1" => Ok(1),
            "causal_entities_v1" => Ok(2),
            "causal_links_v1" => Ok(3),
            _ => Err(format!("unknown scenario relation {name}").into()),
        }
    }
    pub fn assert_rows(expected: &[Row], actual: &mut [Row]) -> Result<()> {
        actual.sort_by_key(Row::identity);
        assert_eq!(expected.len(), actual.len());
        for (a, b) in expected.iter().zip(actual) {
            a.assert_equal(b)?;
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Member {
    pub writer: u64,
    pub owner: u64,
    pub relation: u64,
    pub entity: u64,
    pub opened: u64,
    pub closed: Option<u64>,
    pub property: u64,
    pub endpoints: Option<[u64; 3]>,
}
