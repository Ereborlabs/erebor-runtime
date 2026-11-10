use std::collections::{BTreeMap, BTreeSet};

use araphor_graph::native::Graph;
use snafu::ResultExt as _;

use super :: super :: { results :: { ResultBody , StoredResult } , InstanceRecord } ;
use super::{cuts::GraphPublication, origin::GraphOrigin, ManagedGraph, Records};
use crate::analysis::native::NativeStore;
use crate :: { AnalysisReadControl , ManagedAttempt , NativeStorageSnafu , PackageErrorCodeV1 as Code , Result } ;

impl NativeStore {
    pub(in crate::analysis::native) fn validate_graph_recovery(&self) -> Result<()> {
        let current = self.view()?;
        Graph::validate(&current.snapshot, &|_, _, _| Ok(None))?;
        let control = AnalysisReadControl::default();
        let mut owners = BTreeMap::new();
        let mut writers = BTreeMap::new();
        for entry in current.snapshot.prefix(b"\0data/G") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "read managed Graph recovery owners",
            })?;
            if key.len() == 23 {
                continue;
            }
            if key.len() != 15 {
                return Err(Code::Invalid.error("managed Graph owner key"));
            }
            let graph = Self::number(&key[7..])?;
            let mapping = ManagedGraph::read(graph, |key| Records::read(key, &current.snapshot))?
                .ok_or_else(|| Code::Missing.error("managed Graph recovery mapping"))?;
            let bytes = Records::payload(&Records::key(b'J', graph), |key| {
                Records::read(key, &current.snapshot)
            })?
            .ok_or_else(|| Code::Missing.error("managed Graph recovery instance"))?;
            let instance: InstanceRecord = Records::decode(&bytes)?;
            for (call, writer) in &mapping.writers {
                writers.insert(*writer, (graph, *call));
            }
            owners.insert(graph, (instance.tenant, instance.id, mapping));
        }
        let mut origins = BTreeSet::new();
        let mut publications = BTreeSet::new();
        let mut layers = BTreeMap::new();
        let mut models = BTreeMap::new();
        for layer in Graph::layers(&current.snapshot) {
            let (writer, id, _, revision) = layer?;
            let Some(&(graph, call)) = writers.get(&writer) else {
                continue;
            };
            let (tenant, instance, _) = &owners[&graph];
            let origin = current.graph_origin(writer, revision)?;
            let (result_id, result, attempt) = current.result_owner(
                *tenant,
                &origin.reference.result_id,
                &control,
                &mut |_| Ok(()),
            )?;
            let ResultBody::Call(record) = &result.body else {
                return Err(Code::Invalid.error("managed Graph layer result kind"));
            };
            if result_id != id
                || result.revision != revision
                || origin.graph != graph
                || origin.layer != id
                || origin.call != call
                || origin.instance != *instance
                || record.call != call
                || origin.grant != attempt.0.capture.grant
                || record.instance != *instance
            {
                return Err(Code::Invalid.error("managed Graph layer owner"));
            }
            let declaration = &attempt.1.spec.manifest.calls[&call];
            let package = current.managed_contract(&attempt.1.spec, declaration)?;
            let model = package
                .exports
                .iter()
                .find(|model| model.name == declaration.export)
                .and_then(|model| model.graph.as_ref())
                .ok_or_else(|| Code::Invalid.error("managed Graph result declaration"))?;
            models.insert((writer, revision), model.clone());
            self.validate_graph_reads(&origin, &attempt)?;
            origins.insert(GraphOrigin::key(writer, revision));
            layers.insert(id, (writer, revision));
            let receipt = attempt
                .receipt()
                .ok_or_else(|| Code::Missing.error("managed Graph receipt"))?;
            let selected = Records::find(
                &StoredResult::identity(*tenant, &receipt.selected.result_id)?,
                |key| Records::read(key, &current.snapshot),
            )?
            .ok_or_else(|| Code::Missing.error("managed Graph selected identity"))?;
            publications.insert(selected);
        }
        for entry in current.snapshot.prefix(b"\0data/O") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate managed Graph origin set",
            })?;
            if key.len() == 31 {
                continue;
            }
            if !origins.remove(key.as_ref()) {
                return Err(Code::Invalid.error("managed Graph origin set"));
            }
        }
        if !origins.is_empty() {
            return Err(Code::Missing.error("managed Graph origin set"));
        }
        let mut history = BTreeMap::<u64, BTreeMap<u64, (u64, GraphPublication)>>::new();
        for entry in current.snapshot.prefix(GraphPublication::PREFIX) {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate Graph publication set",
            })?;
            if key.len() == GraphPublication::PREFIX.len() + 16 {
                continue;
            }
            if key.len() != GraphPublication::PREFIX.len() + 8 {
                return Err(Code::Invalid.error("managed Graph publication key"));
            }
            let id = Self::number(&key[GraphPublication::PREFIX.len()..])?;
            if !publications.remove(&id) {
                return Err(Code::Invalid.error("managed Graph publication set"));
            }
            let publication = GraphPublication::read(
                id,
                current.metadata_revision,
                |key| Records::read(key, &current.snapshot),
                &mut |_| Ok(()),
            )?
            .ok_or_else(|| Code::Missing.error("managed Graph publication"))?;
            let (tenant, instance, _) = owners
                .get(&publication.graph)
                .ok_or_else(|| Code::Missing.error("managed Graph publication owner"))?;
            if publication.tenant != *tenant || publication.instance != *instance {
                return Err(Code::Invalid.error("managed Graph publication identity"));
            }
            let (result, stored, _) = current.result_owner(
                *tenant,
                &publication.reference.result_id,
                &control,
                &mut |_| Ok(()),
            )?;
            if result != id
                || stored.revision != publication.reference.commit_revision
                || !matches!(stored.body, ResultBody::Selected(_))
            {
                return Err(Code::Invalid.error("managed Graph publication selected owner"));
            }
            let captured = self.read_at(publication.reference.commit_revision)?;
            let view = Graph::new(publication.graph)?.view(
                captured.snapshot.clone(),
                BTreeMap::new(),
                &|_, _, _| Ok(None),
            )?;
            let mut actual = BTreeMap::new();
            for writer in view.writers() {
                if let Some(layer) = view.head(writer)? {
                    let (owner, revision) = *layers
                        .get(&layer)
                        .ok_or_else(|| Code::Missing.error("managed Graph publication layer"))?;
                    if owner != writer {
                        return Err(Code::Invalid.error("managed Graph publication writer"));
                    }
                    actual.insert(writer, (layer, revision));
                }
            }
            if actual != publication.heads {
                return Err(Code::Invalid.error("managed Graph publication writer cuts"));
            }
            if history
                .entry(publication.graph)
                .or_default()
                .insert(publication.reference.commit_revision, (id, publication))
                .is_some()
            {
                return Err(Code::Invalid.error("managed Graph publication revision"));
            }
        }
        if !publications.is_empty() {
            return Err(Code::Missing.error("managed Graph publication set"));
        }
        let mut heads = BTreeMap::new();
        for (graph, entries) in history {
            let mut previous = None;
            for (_, (id, publication)) in entries {
                if publication.previous != previous {
                    return Err(Code::Invalid.error("managed Graph publication predecessor"));
                }
                previous = Some(publication.reference);
                heads.insert(GraphPublication::key(GraphPublication::HEAD, graph), id);
            }
        }
        current.validate_heads(GraphPublication::HEAD, heads)?;
        self.validate_graph_projection(&owners, &models)?;
        Ok(())
    }

    fn validate_graph_reads(&self, origin: &GraphOrigin, attempt: &ManagedAttempt) -> Result<()> {
        let current = self.view()?;
        let control = AnalysisReadControl::default();
        let capture = &attempt.0.capture;
        let (_, stored, _) = current.result_owner(
            capture.tenant,
            &origin.reference.result_id,
            &control,
            &mut |_| Ok(()),
        )?;
        let ResultBody::Call(record) = stored.body else {
            return Err(Code::Invalid.error("managed Graph read consumer"));
        };
        let mut restricted = false;
        for reference in record.contexts.iter().chain(&record.derived) {
            let (value, revision) = current
                .context(&reference.key)?
                .ok_or_else(|| Code::Missing.error("Graph disclosure context"))?;
            if revision != reference.commit_revision {
                return Err(Code::Invalid.error("Graph disclosure context revision"));
            }
            restricted |= value.sensitivity == crate::ContextSensitivityV1::HostRestricted;
        }
        if origin
            .reads
            .windows(2)
            .any(|pair| (pair[0].0, pair[0].1) >= (pair[1].0, pair[1].1))
            || origin.rows.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Code::Invalid.error("Graph read receipt order"));
        }
        let mut reads = BTreeMap::new();
        for (writer, revision, reference) in &origin.reads {
            let producer = current.graph_origin(*writer, *revision)?;
            if *revision == 0
                || *revision > capture.revision
                || producer.graph != origin.graph
                || producer.instance != origin.instance
                || producer.reference != *reference
            {
                return Err(Code::Denied.error("Graph recovered read authority"));
            }
            producer.grant.permitted_by(&capture.grant.selection)?;
            restricted |= producer.restricted;
            reads.insert((*writer, *revision), reference);
        }
        let receipt = attempt
            .receipt()
            .ok_or_else(|| Code::Missing.error("Graph consumer receipt"))?;
        let ancestors = attempt.1.spec.manifest.input_calls(origin.call)?;
        let mapping = current
            .managed_graph(capture.tenant, &capture.instance, &control)?
            .ok_or_else(|| Code::Missing.error("Graph pending mapping"))?;
        for (call, reference) in &origin.pending {
            if *call == origin.call
                || !ancestors.contains(call)
                || receipt.results.get(call) != Some(reference)
            {
                return Err(Code::Denied.error("Graph pending read authority"));
            }
            let writer = *mapping
                .writers
                .get(call)
                .ok_or_else(|| Code::Missing.error("Graph pending writer"))?;
            let producer = current.graph_origin(writer, origin.reference.commit_revision)?;
            let (_, _, owner) = current.result_owner(
                capture.tenant,
                &reference.result_id,
                &control,
                &mut |_| Ok(()),
            )?;
            if producer.reference != *reference || owner.0 != attempt.0 {
                return Err(Code::Denied.error("Graph pending producer"));
            }
            restricted |= producer.restricted;
        }
        if restricted && !origin.restricted {
            return Err(Code::Denied.error("Graph disclosure floor"));
        }
        if !origin.rows.is_empty() {
            let captured = self.read_at(capture.revision)?;
            let view = Graph::new(origin.graph)?.view(
                captured.snapshot.clone(),
                BTreeMap::new(),
                &|_, _, _| Ok(None),
            )?;
            for row in &origin.rows {
                if !reads.contains_key(&(row.writer, row.revision)) {
                    return Err(Code::Denied.error("Graph read row origin"));
                }
                let member = view
                    .member(
                        row.writer,
                        row.relation,
                        &row.owner,
                        &row.key,
                        &|_, _, _| Ok(None),
                    )?
                    .ok_or_else(|| Code::Denied.error("Graph historical read member"))?;
                if member.revision != row.revision {
                    return Err(Code::Denied.error("Graph historical read revision"));
                }
            }
        }
        Ok(())
    }
}
