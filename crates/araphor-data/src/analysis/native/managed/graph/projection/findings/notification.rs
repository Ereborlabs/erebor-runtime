use std::ops::Bound::{Included, Unbounded};

use super::super::super::super::{graph::GraphPublication, results::StoredResult};
use super::*;

impl FindingRead<'_> {
    pub(in crate::analysis) fn heads(
        &self,
        ids: &BTreeSet<&str>,
    ) -> Result<BTreeMap<String, String>> {
        if ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let mut heads = BTreeMap::<String, (u64, String)>::new();
        for (&(tenant, graph), _) in self
            .view
            .graphs
            .range((Included((self.tenant, 0)), Unbounded))
        {
            self.charge(0)?;
            if tenant != self.tenant {
                break;
            }
            let Some(bytes) = Records::read(
                &GraphPublication::key(GraphPublication::HEAD, graph),
                &self.view.snapshot,
            )?
            else {
                continue;
            };
            let publication = GraphPublication::read(
                NativeStore::number(&bytes)?,
                self.view.metadata_revision,
                |key| Records::read(key, &self.view.snapshot),
                &mut |bytes| self.charge(bytes),
            )?
            .ok_or_else(|| Code::Missing.error("native finding head"))?;
            if publication.tenant != tenant || publication.graph != graph {
                return Err(Code::Invalid.error("native finding head identity"));
            }
            for &id in ids {
                self.charge(id.len().saturating_mul(4))?;
                let identity = rmp_serde::to_vec(&("graph-finding", graph, tenant, id))
                    .context(crate::ManagedEncodingSnafu)?;
                let Some(group) =
                    Records::find(&identity, |key| Records::read(key, &self.view.snapshot))?
                else {
                    continue;
                };
                let prefix = Index::key(Index::GROUP, &[group]);
                let Some(entry) = self.view.snapshot.prefix(&prefix).next() else {
                    continue;
                };
                let (key, value) = entry.context(NativeStorageSnafu {
                    operation: "read requested finding head",
                })?;
                if key.len() != prefix.len() + 8 || NativeStore::number(&value)? == 0 {
                    return Err(Code::Invalid.error("native finding head member"));
                }
                let result = &publication.reference.result_id;
                let revision = publication.reference.commit_revision;
                if heads
                    .get(id)
                    .is_none_or(|(prior, value)| (revision, result) > (*prior, value))
                {
                    self.charge(
                        (id.len() + result.len())
                            .saturating_mul(4)
                            .saturating_add(12 * size_of::<(String, (u64, String))>()),
                    )?;
                    heads.insert(id.to_owned(), (revision, result.clone()));
                }
            }
        }
        Ok(heads
            .into_iter()
            .map(|(id, (_, result))| (id, result))
            .collect())
    }

    fn cached_rows(&mut self, result: &str, id: &str) -> Result<Arc<Vec<FindingRow>>> {
        self.charge((result.len() + id.len()).saturating_mul(4))?;
        let key = (result.to_owned(), id.to_owned());
        if let Some(rows) = self.findings.get(&key) {
            return Ok(Arc::clone(rows));
        }
        let publication = Records::find(&StoredResult::identity(self.tenant, result)?, |key| {
            Records::read(key, &self.view.snapshot)
        })?;
        let present = publication
            .map(|id| {
                Records::read(
                    &GraphPublication::key(GraphPublication::PREFIX, id),
                    &self.view.snapshot,
                )
            })
            .transpose()?
            .flatten()
            .is_some();
        let rows = if present {
            self.rows(result, &BTreeSet::from([id.to_owned()]))?
        } else {
            Vec::new()
        };
        self.charge(12 * size_of::<(String, String, Arc<Vec<FindingRow>>)>())?;
        let rows = Arc::new(rows);
        self.findings.insert(key, Arc::clone(&rows));
        Ok(rows)
    }

    pub(in crate::analysis) fn value(
        &mut self,
        result: &str,
        id: &str,
    ) -> Result<Option<FindingV1>> {
        Ok(self
            .cached_rows(result, id)?
            .first()
            .map(|row| row.finding.value.clone()))
    }

    pub(in crate::analysis) fn revision(
        &mut self,
        result: &str,
        id: &str,
    ) -> Result<GraphRevisionV1> {
        let rows = self.cached_rows(result, id)?;
        let (_, _, revision) = self.basis(&rows, true)?;
        if let Some(row) = rows.first() {
            revision.validate_finding(&row.finding.value)?;
        }
        Ok(revision)
    }

    fn canonical(&mut self, rows: &[FindingRow]) -> Result<Option<u64>> {
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let producer = self.producer(row.member.writer, row.member.revision)?;
        self.view
            .graph_finding_value(producer.origin.graph, &row.member)
            .map(Some)
    }

    pub(in crate::analysis) fn changed(
        &mut self,
        reference: &NotificationFindingRefV1,
        prior: &NotificationFindingRefV1,
    ) -> Result<bool> {
        if reference.result_id == prior.result_id {
            return Ok(false);
        }
        let current = self.cached_rows(&reference.result_id, &reference.finding_id)?;
        let canonical = self
            .canonical(&current)?
            .ok_or_else(|| Code::Missing.error("native current finding"))?;
        let previous = self.cached_rows(&prior.result_id, &prior.finding_id)?;
        Ok(self
            .canonical(&previous)?
            .is_none_or(|value| value != canonical))
    }
}
