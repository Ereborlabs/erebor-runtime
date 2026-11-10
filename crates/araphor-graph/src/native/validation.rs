use std::collections::{BTreeMap, BTreeSet};

use fjall::BranchSnapshot;
use snafu::ResultExt as _;

use super::{
    record::{Dictionary, Fragment, Head, Key, Properties, StoredMember, StoredRelation},
    Graph, Reserve,
};
use crate::{
    error::{InvalidSnafu, NativeSnafu},
    scratch::Scratch,
    Result,
};

impl Graph {
    /// Check one native snapshot. The caller checks its retained historical cuts separately.
    pub fn validate(snapshot: &BranchSnapshot, reserve: &Reserve<'_>) -> Result<()> {
        let mut memory = Scratch::new(reserve);
        let mut relations = BTreeMap::new();
        let mut shapes = BTreeMap::new();
        let mut writers = BTreeMap::new();
        let mut installation = BTreeMap::new();
        for entry in snapshot.prefix(b"\0graph/") {
            memory.check(0)?;
            let (key, _) = entry.context(NativeSnafu {
                operation: "check native Graph keys",
            })?;
            if key.as_ref() == b"\0graph/next" {
                continue;
            }
            let width = match key.get(7) {
                Some(b'f' | b'w' | b'h' | b'l' | b'q' | b'V') => 16,
                Some(b'g' | b'v') => 24,
                Some(b'L') => 32,
                Some(b'M' | b'R' | b'K') => 40,
                Some(b'O' | b'I') => 48,
                Some(b'E') => 64,
                Some(b'P') if key.len() == 16 || key.len() == 24 => key.len(),
                Some(b'D') if (25..=u16::MAX as usize).contains(&key.len()) => key.len(),
                _ => {
                    return InvalidSnafu {
                        field: "native Graph key",
                    }
                    .fail()
                }
            };
            if key.len() != width {
                return InvalidSnafu {
                    field: "native Graph key width",
                }
                .fail();
            }
        }
        for entry in snapshot.prefix(Key::record(b'f', &[])) {
            let (key, bytes) = entry.context(NativeSnafu {
                operation: "check native Graph relations",
            })?;
            let id = Key::number(&key[8..])?;
            memory.charge(0, bytes.len().saturating_mul(4).saturating_add(256))?;
            let stored: StoredRelation = Key::decode(&bytes)?;
            let shape = stored.shape()?;
            if id == 0 || stored.graph == 0 {
                return InvalidSnafu {
                    field: "native Graph relation identity",
                }
                .fail();
            }
            installation.insert(
                Key::record(b'g', &[stored.graph, id]),
                id.to_be_bytes().to_vec(),
            );
            shapes.insert(id, shape);
            relations.insert(id, stored);
        }
        for relation in relations.values() {
            if let Some((from, to)) = relation.endpoints {
                for endpoint in [from, to] {
                    if relations
                        .get(&endpoint)
                        .is_none_or(|node| node.graph != relation.graph || node.endpoints.is_some())
                    {
                        return InvalidSnafu {
                            field: "native Graph endpoint declaration",
                        }
                        .fail();
                    }
                }
            }
        }
        for entry in snapshot.prefix(Key::record(b'w', &[])) {
            let (key, value) = entry.context(NativeSnafu {
                operation: "check native Graph writers",
            })?;
            let writer = Key::number(&key[8..])?;
            let graph = Key::number(&value)?;
            if writer == 0 || graph == 0 {
                return InvalidSnafu {
                    field: "native Graph writer identity",
                }
                .fail();
            }
            memory.charge(writer, 256)?;
            installation.insert(
                Key::record(b'v', &[graph, writer]),
                writer.to_be_bytes().to_vec(),
            );
            writers.insert(writer, graph);
        }
        for kind in [b'g', b'v'] {
            for entry in snapshot.prefix(Key::record(kind, &[])) {
                let (key, value) = entry.context(NativeSnafu {
                    operation: "check native Graph installation index",
                })?;
                if installation.remove(key.as_ref()).as_deref() != Some(value.as_ref()) {
                    return InvalidSnafu {
                        field: "native Graph installation index",
                    }
                    .fail();
                }
            }
        }
        if !installation.is_empty() {
            return InvalidSnafu {
                field: "native Graph installation index",
            }
            .fail();
        }
        let mut layers = BTreeMap::new();
        let mut history = BTreeMap::<u64, BTreeMap<u64, u64>>::new();
        let mut stamps = BTreeMap::new();
        for layer in Self::layers(snapshot) {
            let (writer, id, parent, revision) = layer?;
            memory.charge(writer, 512)?;
            let head = Head {
                layer: id,
                parent,
                revision,
            };
            if !writers.contains_key(&writer)
                || history
                    .entry(writer)
                    .or_default()
                    .insert(head.revision, id)
                    .is_some()
            {
                return InvalidSnafu {
                    field: "native Graph stored layer",
                }
                .fail();
            }
            let stamp = snapshot
                .get(Key::record(b'q', &[id]))
                .context(NativeSnafu {
                    operation: "check native Graph layer cut",
                })?
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "native Graph layer cut",
                    }
                    .build()
                })?;
            let stamp = fjall::Revision::from_bytes(Key::number(&stamp)?.to_be_bytes());
            if stamp.to_bytes() == 0u64.to_be_bytes() || stamp > snapshot.revision() {
                return InvalidSnafu {
                    field: "native Graph layer cut",
                }
                .fail();
            }
            stamps.insert(id, stamp);
            layers.insert(id, (writer, head));
        }
        for entry in snapshot.prefix(Key::record(b'q', &[])) {
            let (key, _) = entry.context(NativeSnafu {
                operation: "check native Graph cut set",
            })?;
            if !layers.contains_key(&Key::number(&key[8..])?) {
                return InvalidSnafu {
                    field: "native Graph cut owner",
                }
                .fail();
            }
        }
        let mut heads = BTreeMap::new();
        for (writer, revisions) in &history {
            let mut previous = None;
            for id in revisions.values() {
                let head = &layers[id].1;
                if head.parent != previous
                    || previous.is_some_and(|prior| stamps[&prior] >= stamps[id])
                {
                    return InvalidSnafu {
                        field: "native Graph layer predecessor",
                    }
                    .fail();
                }
                previous = Some(*id);
                heads.insert(*writer, head.clone());
            }
        }
        for entry in snapshot.prefix(Key::record(b'h', &[])) {
            let (key, value) = entry.context(NativeSnafu {
                operation: "check native Graph heads",
            })?;
            let writer = Key::number(&key[8..])?;
            if heads.remove(&writer) != Some(Key::decode::<Head>(&value)?) {
                return InvalidSnafu {
                    field: "native Graph writer head",
                }
                .fail();
            }
        }
        if !heads.is_empty() {
            return InvalidSnafu {
                field: "native Graph writer head",
            }
            .fail();
        }
        let graphs = writers
            .values()
            .copied()
            .chain(relations.values().map(|relation| relation.graph))
            .collect::<BTreeSet<_>>();
        let mut dictionary = BTreeSet::new();
        let mut allocated = 0;
        for entry in snapshot.prefix(b"\0graph/D") {
            let (key, value) = entry.context(NativeSnafu {
                operation: "check native Graph dictionary",
            })?;
            let kind = key[8];
            let scope = Key::number(&key[9..17])?;
            let parent = Key::number(&key[17..25])?;
            let id = Key::number(&value)?;
            let reverse = snapshot
                .get(Key::record(b'V', &[id]))
                .context(NativeSnafu {
                    operation: "check native Graph dictionary reverse",
                })?
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "Graph dictionary reference",
                    }
                    .build()
                })?;
            let mut temporary = Scratch::new(reserve);
            temporary.charge(0, reverse.len().saturating_mul(4))?;
            let fragment: Fragment = Key::decode(&reverse)?;
            fragment.check(kind, scope, parent, &key[25..])?;
            if id <= parent || !dictionary.insert(id) {
                return InvalidSnafu {
                    field: "Graph dictionary identity",
                }
                .fail();
            }
            memory.charge(0, 128)?;
            allocated = allocated.max(id);
        }
        for entry in snapshot.prefix(Key::record(b'V', &[])) {
            let (key, value) = entry.context(NativeSnafu {
                operation: "check native Graph dictionary identity",
            })?;
            let id = Key::number(&key[8..])?;
            let mut temporary = Scratch::new(reserve);
            temporary.charge(0, value.len().saturating_mul(4))?;
            let fragment: Fragment = Key::decode(&value)?;
            if !dictionary.remove(&id)
                || fragment.parent >= id
                || fragment.bytes.len() > Dictionary::WIDTH
                || fragment.parent != 0 && fragment.bytes.is_empty()
                || !match fragment.kind {
                    0 => writers.contains_key(&fragment.scope),
                    1 => relations.contains_key(&fragment.scope),
                    2 => graphs.contains(&fragment.scope),
                    _ => false,
                }
            {
                return InvalidSnafu {
                    field: "Graph dictionary chain",
                }
                .fail();
            }
            if fragment.parent != 0 {
                let parent = snapshot
                    .get(Key::record(b'V', &[fragment.parent]))
                    .context(NativeSnafu {
                        operation: "check native Graph dictionary parent",
                    })?
                    .ok_or_else(|| {
                        InvalidSnafu {
                            field: "Graph dictionary parent",
                        }
                        .build()
                    })?;
                let parent: Fragment = Key::decode(&parent)?;
                if parent.kind != fragment.kind
                    || parent.scope != fragment.scope
                    || parent.bytes.len() != Dictionary::WIDTH
                {
                    return InvalidSnafu {
                        field: "Graph dictionary parent scope",
                    }
                    .fail();
                }
            }
        }
        if !dictionary.is_empty() {
            return InvalidSnafu {
                field: "Graph dictionary reference set",
            }
            .fail();
        }
        let mut properties = BTreeMap::<u64, Vec<(u64, u64, usize)>>::new();
        for entry in snapshot.prefix(Key::record(b'L', &[])) {
            let (key, value) = entry.context(NativeSnafu {
                operation: "check native Graph property references",
            })?;
            let relation = Key::number(&key[8..16])?;
            let writer = Key::number(&key[16..24])?;
            let property = Key::number(&key[24..])?;
            let (chunk, row, revision): (u64, usize, u64) = Key::decode(&value)?;
            let declaration = relations.get(&relation).ok_or_else(|| {
                InvalidSnafu {
                    field: "native Graph property relation",
                }
                .build()
            })?;
            if property == 0
                || writers.get(&writer) != Some(&declaration.graph)
                || !history
                    .get(&writer)
                    .is_some_and(|values| values.contains_key(&revision))
            {
                return InvalidSnafu {
                    field: "native Graph property owner",
                }
                .fail();
            }
            allocated = allocated.max(property);
            memory.charge(writer, 256)?;
            properties
                .entry(chunk)
                .or_default()
                .push((relation, writer, row));
        }
        for entry in snapshot.prefix(Key::record(b'P', &[])) {
            let (key, value) = entry.context(NativeSnafu {
                operation: "check native Graph property chunks",
            })?;
            let id = Key::number(&key[8..16])?;
            allocated = allocated.max(id);
            if id == 0 {
                return InvalidSnafu {
                    field: "native Graph property identity",
                }
                .fail();
            }
            if key.len() == 16 {
                let mut temporary = Scratch::new(reserve);
                let batch = Properties::load(snapshot, id, 0, &mut temporary)?;
                for (relation, _, row) in properties.remove(&id).into_iter().flatten() {
                    if row >= batch.num_rows()
                        || batch.schema().as_ref() != &shapes[&relation].properties
                    {
                        return InvalidSnafu {
                            field: "native Graph property row",
                        }
                        .fail();
                    }
                }
            } else {
                let manifest = snapshot
                    .get(Key::record(b'P', &[id]))
                    .context(NativeSnafu {
                        operation: "check native Graph property manifest",
                    })?
                    .ok_or_else(|| {
                        InvalidSnafu {
                            field: "native Graph property manifest",
                        }
                        .build()
                    })?;
                let len = Key::number(&manifest)?;
                let slot = Key::number(&key[16..])?;
                if slot >= len.div_ceil(u32::MAX as u64)
                    || value.len() as u64 != (len - slot * u32::MAX as u64).min(u32::MAX as u64)
                {
                    return InvalidSnafu {
                        field: "native Graph property fragment set",
                    }
                    .fail();
                }
            }
        }
        if !properties.is_empty() {
            return InvalidSnafu {
                field: "native Graph property reference set",
            }
            .fail();
        }
        let mut indexes = BTreeMap::new();
        let mut nodes = BTreeSet::new();
        let mut edges = Vec::new();
        for entry in snapshot.prefix(Key::record(b'M', &[])) {
            let (key, value) = entry.context(NativeSnafu {
                operation: "check native Graph members",
            })?;
            let mut temporary = Scratch::new(reserve);
            temporary.charge(0, value.len().saturating_mul(4))?;
            let member: StoredMember = Key::decode(&value)?;
            let relation = relations.get(&member.relation).ok_or_else(|| {
                InvalidSnafu {
                    field: "native Graph member relation",
                }
                .build()
            })?;
            if key.as_ref() != member.key()
                || writers.get(&member.writer) != Some(&relation.graph)
                || member.property == 0
                || member.owner == 0
                || member.entity == 0
                || !history
                    .get(&member.writer)
                    .is_some_and(|layers| layers.contains_key(&member.revision))
                || member.endpoints.is_some() != relation.endpoints.is_some()
            {
                return InvalidSnafu {
                    field: "native Graph stored member",
                }
                .fail();
            }
            Dictionary::resolve(
                snapshot,
                0,
                member.writer,
                member.owner,
                member.writer,
                &mut temporary,
            )?;
            Dictionary::resolve(
                snapshot,
                1,
                member.relation,
                member.entity,
                member.writer,
                &mut temporary,
            )?;
            let property = snapshot
                .get(Key::record(
                    b'L',
                    &[member.relation, member.writer, member.property],
                ))
                .context(NativeSnafu {
                    operation: "check native Graph member property",
                })?
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "native Graph member property",
                    }
                    .build()
                })?;
            if Key::decode::<(u64, usize, u64)>(&property)?
                != (member.chunk, member.row, member.revision)
            {
                return InvalidSnafu {
                    field: "native Graph member property tuple",
                }
                .fail();
            }
            if let (Some((from, to)), Some([source, target, label])) =
                (relation.endpoints, member.endpoints)
            {
                Dictionary::resolve(snapshot, 1, from, source, member.writer, &mut temporary)?;
                Dictionary::resolve(snapshot, 1, to, target, member.writer, &mut temporary)?;
                Dictionary::resolve(
                    snapshot,
                    2,
                    relation.graph,
                    label,
                    member.writer,
                    &mut temporary,
                )?;
                memory.charge(member.writer, 128)?;
                edges.push([(from, source), (to, target)]);
            } else {
                memory.charge(member.writer, 128)?;
                nodes.insert((member.relation, member.entity));
            }
            for index in member.indexes(relation.graph, relation.endpoints) {
                memory.charge(
                    member.writer,
                    index.len().saturating_add(key.len()).saturating_add(128),
                )?;
                if indexes
                    .insert(index, key.to_vec())
                    .is_some_and(|prior| prior.as_slice() != key.as_ref())
                {
                    return InvalidSnafu {
                        field: "native Graph duplicate member index",
                    }
                    .fail();
                }
            }
        }
        for endpoints in edges {
            for endpoint in endpoints {
                if !nodes.contains(&endpoint) {
                    return InvalidSnafu {
                        field: "native Graph missing endpoint",
                    }
                    .fail();
                }
            }
        }
        for kind in [b'R', b'K', b'O', b'I', b'E'] {
            for entry in snapshot.prefix(Key::record(kind, &[])) {
                let (key, value) = entry.context(NativeSnafu {
                    operation: "check native Graph member indexes",
                })?;
                if indexes.remove(key.as_ref()).as_deref() != Some(value.as_ref()) {
                    return InvalidSnafu {
                        field: "native Graph member index",
                    }
                    .fail();
                }
            }
        }
        if !indexes.is_empty() {
            return InvalidSnafu {
                field: "native Graph member index set",
            }
            .fail();
        }
        let next = snapshot
            .get(b"\0graph/next")
            .context(NativeSnafu {
                operation: "check native Graph allocator",
            })?
            .map(|bytes| Key::number(&bytes))
            .transpose()?
            .unwrap_or(1);
        if next == 0 || next <= allocated {
            return InvalidSnafu {
                field: "native Graph allocator floor",
            }
            .fail();
        }
        Ok(())
    }
}
