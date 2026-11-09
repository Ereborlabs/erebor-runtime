use std::collections::{BTreeMap, BTreeSet};

use snafu::ResultExt as _;

use super::{ContextRecord, DataView, NativeStore, Records};
use crate::{
    AnalysisReadControl, ApprovedNotificationRouteV1, DiscoveryContextRevisionV1, NativeStateSnafu,
    NativeStorageSnafu, Result,
};

impl DataView {
    pub(in crate::analysis::native) fn validate_contexts(&self) -> Result<()> {
        let mut heads = BTreeMap::<Vec<u8>, (u64, u64)>::new();
        let mut documents =
            BTreeMap::<Vec<u8>, BTreeMap<u64, (u64, DiscoveryContextRevisionV1)>>::new();
        let mut scopes = BTreeSet::new();
        let mut contexts = BTreeSet::new();
        let mut verified = crate::analysis::context::VerifiedPackages::default();
        for entry in self.snapshot.prefix(b"\0data/C") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate native contexts",
            })?;
            if key.len() == 23 {
                continue;
            }
            if key.len() != 15 {
                return NativeStateSnafu {
                    field: "context record key",
                }
                .fail();
            }
            let id = NativeStore::number(&key[7..])?;
            let row = ContextRecord::load(id, |key| Records::read(key, &self.snapshot))?;
            if row.revision > self.metadata_revision
                || ContextRecord::id(&row.version.key, |key| Records::read(key, &self.snapshot))?
                    != Some(id)
            {
                return NativeStateSnafu {
                    field: "context record identity",
                }
                .fail();
            }
            contexts.insert(id);
            let input = &row.version;
            Self::check_fact(id, input, |key| Records::read(key, &self.snapshot))?;
            verified
                .check_context(input, |tenant, package, revision| {
                    self.package_revision(
                        tenant,
                        package,
                        revision,
                        &AnalysisReadControl::default(),
                    )
                })
                .map_err(crate::Error::stored_artifact)?;
            if input.key.owner_id == crate::NOTIFICATION_STATE_OWNER {
                crate::analysis::notification::NotificationKeys::from_context(input)?;
            }
            if input.key.owner_id == crate::NOTIFICATION_ROUTE_OWNER {
                ApprovedNotificationRouteV1::try_from(input)?;
            }
            let base = Records::find(&ContextRecord::identity(&input.key, false)?, |key| {
                Records::read(key, &self.snapshot)
            })?
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "context head identity",
                }
                .build()
            })?;
            heads
                .entry(Records::key(b'H', base))
                .and_modify(|head| {
                    if input.key.owner_revision > head.0 {
                        *head = (input.key.owner_revision, id);
                    }
                })
                .or_insert((input.key.owner_revision, id));
            if ContextRecord::internable(input) {
                let scope = Records::find(&ContextRecord::scope(input)?, |key| {
                    Records::read(key, &self.snapshot)
                })?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "qualified context scope",
                    }
                    .build()
                })?;
                scopes.insert([Records::key(b'V', scope), id.to_be_bytes().to_vec()].concat());
            }
            if input.key.owner_id == "discovery-context-v1" {
                let document = DiscoveryContextRevisionV1::try_from(input)?;
                let scope = Records::find(&ContextRecord::document(&input.key)?, |key| {
                    Records::read(key, &self.snapshot)
                })?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "imported context scope",
                    }
                    .build()
                })?;
                if documents
                    .entry(Records::key(b'M', scope))
                    .or_default()
                    .insert(input.key.owner_revision, (id, document))
                    .is_some()
                {
                    return NativeStateSnafu {
                        field: "imported context revision",
                    }
                    .fail();
                }
            }
        }
        for entry in self.snapshot.prefix(b"\0data/K") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate canonical fact index",
            })?;
            if key.len() == 23 {
                continue;
            }
            if key.len() != 15 || !contexts.contains(&NativeStore::number(&key[7..])?) {
                return NativeStateSnafu {
                    field: "orphan canonical fact index",
                }
                .fail();
            }
        }
        for entry in self.snapshot.prefix(b"\0data/V") {
            let (key, value) = entry.context(NativeStorageSnafu {
                operation: "validate qualified context scopes",
            })?;
            if !value.is_empty() || !scopes.remove(key.as_ref()) {
                return NativeStateSnafu {
                    field: "qualified context scope",
                }
                .fail();
            }
        }
        if !scopes.is_empty() {
            return NativeStateSnafu {
                field: "qualified context scope",
            }
            .fail();
        }
        let mut imported = BTreeMap::new();
        for (key, versions) in documents {
            let mut previous = None;
            for (_, (id, value)) in versions {
                value.validate_history(previous.as_ref())?;
                previous = Some(value);
                imported.insert(key.clone(), id);
            }
        }
        self.validate_heads(
            b"\0data/H",
            heads.into_iter().map(|(key, (_, id))| (key, id)).collect(),
        )?;
        self.validate_heads(b"\0data/M", imported)?;
        Ok(())
    }
}
