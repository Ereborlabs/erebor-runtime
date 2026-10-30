use serde::{Deserialize, Serialize};

use super::*;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeBasis {
    Complete,
    Progress,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Resume {
    pub basis: ResumeBasis,
}

impl Resume {
    pub fn port() -> sdk::Port {
        sdk::Port::new(
            "graph_resume",
            sdk::Schema::new(vec![sdk::Field::new("basis", sdk::DataType::Utf8, false)]),
        )
    }

    pub fn encode(basis: ResumeBasis) -> sdk::Result<sdk::Dataset> {
        let port = Self::port();
        let rows = [Self { basis }];
        let batch = serde_arrow::to_record_batch(port.schema.fields(), &rows)
            .map_err(|error| sdk::arrow_schema::ArrowError::ExternalError(Box::new(error)))?;
        Ok(sdk::Dataset {
            name: port.name,
            batches: vec![batch],
        })
    }

    pub fn basis(checkpoint: &sdk::Checkpoint) -> sdk::Result<ResumeBasis> {
        let mut found = checkpoint
            .datasets
            .iter()
            .filter(|dataset| dataset.name == Self::port().name);
        let data = found
            .next()
            .ok_or_else(|| Computation::invalid("graph resume basis"))?;
        if found.next().is_some() || data.batches.len() != 1 {
            return Err(Computation::invalid("graph resume basis"));
        }
        let batch = &data.batches[0];
        if batch.schema().as_ref() != &Self::port().schema {
            return Err(Computation::invalid("graph resume schema"));
        }
        let mut rows: Vec<Self> = serde_arrow::from_record_batch(batch)
            .map_err(|error| sdk::arrow_schema::ArrowError::ExternalError(Box::new(error)))?;
        if rows.len() != 1 {
            return Err(Computation::invalid("graph resume basis"));
        }
        Ok(rows.remove(0).basis)
    }

    pub fn for_append(
        detector: Detector,
        checkpoint: &sdk::Checkpoint,
        inputs: &[sdk::Input],
        prior: &[Progress],
    ) -> sdk::Result<Option<sdk::Checkpoint>> {
        if Self::basis(checkpoint)? != ResumeBasis::Complete || prior.is_empty() {
            return Ok(None);
        }
        let input = |name: &str| {
            inputs
                .iter()
                .find(|input| input.data.name == name)
                .map(|input| &input.data)
                .ok_or_else(|| Computation::invalid("graph resume input"))
        };
        let records = Observation::decode(input("records")?)?;
        let facts = Fact::decode(input("facts")?)?;
        let manifests = Manifest::decode(input("manifest")?)?;
        let [manifest] = manifests.as_slice() else {
            return Err(Computation::invalid("graph resume manifest"));
        };
        if !Self::append_eligible(detector, &records, &facts, manifest, prior)? {
            return Ok(None);
        }
        let mut checkpoint = checkpoint.clone();
        let basis = checkpoint
            .datasets
            .iter_mut()
            .find(|dataset| dataset.name == Self::port().name)
            .ok_or_else(|| Computation::invalid("graph resume basis"))?;
        *basis = Self::encode(ResumeBasis::Progress)?;
        Ok(Some(checkpoint))
    }

    pub(super) fn append_eligible(
        detector: Detector,
        records: &[Observation],
        facts: &[Fact],
        manifest: &Manifest,
        prior: &[Progress],
    ) -> sdk::Result<bool> {
        let mut rows = BTreeMap::new();
        for (index, record) in records.iter().enumerate() {
            if rows.insert(&record.id, index).is_some() {
                return Err(Computation::invalid("graph resume record identity"));
            }
        }
        let mut by_record: Vec<Vec<&Fact>> = vec![Vec::new(); records.len()];
        for fact in facts {
            let row = by_record
                .get_mut(fact.record as usize)
                .ok_or_else(|| Computation::invalid("graph resume fact record"))?;
            row.push(fact);
        }
        let mut old = BTreeSet::new();
        let mut last = None;
        for progress in prior {
            if !progress.compatible(detector) || !old.insert(&progress.record) {
                return Err(Computation::invalid("graph resume progress identity"));
            }
            let Some(&index) = rows.get(&progress.record) else {
                return Ok(false);
            };
            let record = &records[index];
            if Progress::new(record, manifest.window_ns, &by_record[index])?.digest
                != progress.digest
            {
                return Ok(false);
            }
            last = Some(last.map_or(record.position, |position: Position| {
                position.max(record.position)
            }));
        }
        let last = last.ok_or_else(|| Computation::invalid("graph resume progress"))?;
        let all_host = facts
            .iter()
            .any(|fact| fact.sensitivity == ContextSensitivityV1::HostRestricted);
        let old_host = facts.iter().any(|fact| {
            fact.sensitivity == ContextSensitivityV1::HostRestricted
                && old.contains(&records[fact.record as usize].id)
        });
        if all_host != old_host {
            return Ok(false);
        }
        for record in records {
            if !old.contains(&record.id) && record.position <= last {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
