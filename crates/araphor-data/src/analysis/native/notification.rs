use snafu::ResultExt as _;

use super::{context::ContextRecord, records::Records, DataView, DataWrite, NativeStore};
use crate::analysis::notification::{NotificationKeys, NotificationLookup};
use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, NativeStateSnafu, NativeStorageSnafu, Result,
    NOTIFICATION_STATE_OWNER,
};

struct NoticeIndex;

impl NoticeIndex {
    const PREFIX: &'static [u8] = b"\0data/notice/";

    fn identity(kind: u8, lookup: &[u8]) -> Vec<u8> {
        [b"\0data/notice/lookup/".as_slice(), &[kind], lookup].concat()
    }

    fn prefix(kind: u8, scope: u64) -> Vec<u8> {
        [Self::PREFIX, &[kind], &scope.to_be_bytes()].concat()
    }

    fn key(kind: u8, scope: u64, entity: &[u8]) -> Vec<u8> {
        [Self::prefix(kind, scope), entity.to_vec()].concat()
    }

    fn keys(keys: NotificationKeys) -> impl Iterator<Item = (u8, Vec<u8>)> {
        [(b'F', keys.finding), (b'C', keys.concern)]
            .into_iter()
            .filter_map(|(kind, key)| key.map(|key| (kind, key)))
    }

    fn lookup(tenant: [u8; 16], lookup: NotificationLookup<'_>) -> Result<(u8, Vec<u8>)> {
        let kind = match lookup {
            NotificationLookup::Finding(id, _) if !id.is_empty() => b'F',
            NotificationLookup::Concern(id, route)
                if id != [0; 16] && crate::NotificationGrantV1::identifier(route, 64) =>
            {
                b'C'
            }
            _ => {
                return NativeStateSnafu {
                    field: "notification lookup",
                }
                .fail()
            }
        };
        if tenant == [0; 16] {
            return NativeStateSnafu {
                field: "notification tenant",
            }
            .fail();
        }
        Ok((kind, NotificationKeys::lookup(tenant, lookup)?))
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn index_notification(
        &mut self,
        previous: Option<&AnalysisContextVersionV1>,
        input: &AnalysisContextVersionV1,
        keys: NotificationKeys,
    ) -> Result<()> {
        if let Some(previous) = previous {
            for (kind, lookup) in NoticeIndex::keys(NotificationKeys::from_context(previous)?) {
                let scope = Records::find(&NoticeIndex::identity(kind, &lookup), |key| {
                    Records::staged(key, &self.transaction)
                })?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "notification lookup scope",
                    }
                    .build()
                })?;
                self.transaction
                    .remove(NoticeIndex::key(kind, scope, &input.key.entity_key));
            }
        }
        for (kind, lookup) in NoticeIndex::keys(keys) {
            let scope =
                Records::intern(&mut self.transaction, &NoticeIndex::identity(kind, &lookup))?;
            self.transaction
                .insert(NoticeIndex::key(kind, scope, &input.key.entity_key), []);
        }
        Ok(())
    }
}

impl NativeStore {
    pub fn notification_states(
        &self,
        tenant: [u8; 16],
        lookup: NotificationLookup<'_>,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        self.view()?.notification_states(tenant, lookup)
    }
}

impl DataView {
    pub fn notification_states(
        &self,
        tenant: [u8; 16],
        lookup: NotificationLookup<'_>,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        self.notification_states_charged(tenant, lookup, &mut |_| Ok(()))
    }

    pub(in crate::analysis) fn notification_states_charged(
        &self,
        tenant: [u8; 16],
        lookup: NotificationLookup<'_>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        let (kind, lookup) = NoticeIndex::lookup(tenant, lookup)?;
        let Some(scope) = Records::find(&NoticeIndex::identity(kind, &lookup), |key| {
            Records::read(key, &self.snapshot)
        })?
        else {
            return Ok(Vec::new());
        };
        let prefix = NoticeIndex::prefix(kind, scope);
        let mut states = Vec::new();
        let limit = if kind == b'C' { 2 } else { usize::MAX };
        for entry in self.snapshot.prefix(&prefix).take(limit) {
            charge(0)?;
            let (key, value) = entry.context(NativeStorageSnafu {
                operation: "read notification lookup",
            })?;
            if key.len() != prefix.len() + 16 || !value.is_empty() {
                return NativeStateSnafu {
                    field: "notification lookup entry",
                }
                .fail();
            }
            let key = AnalysisContextKeyV1 {
                tenant_id: tenant,
                owner_id: NOTIFICATION_STATE_OWNER.into(),
                entity_key: key[prefix.len()..].to_vec(),
                lifetime_key: b"obligation".to_vec(),
                owner_revision: 0,
            };
            let name = ContextRecord::name(&key);
            let base = self.contexts.get(&name).ok_or_else(|| {
                NativeStateSnafu {
                    field: "notification head identity",
                }
                .build()
            })?;
            let (context, _) = self
                .head_context_charged(&name, *base, charge)?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "notification head",
                    }
                    .build()
                })?;
            if !NoticeIndex::keys(NotificationKeys::from_context(&context)?)
                .any(|(tag, key)| tag == kind && key == lookup)
            {
                return NativeStateSnafu {
                    field: "notification lookup identity",
                }
                .fail();
            }
            states.push(context);
        }
        Ok(states)
    }

    pub(in crate::analysis::native) fn validate_notice_indexes(&self) -> Result<()> {
        let mut expected = std::collections::BTreeSet::new();
        for (name, base) in &self.contexts {
            if name.1 != NOTIFICATION_STATE_OWNER {
                continue;
            }
            let (context, _) = self.head_context(name, *base)?.ok_or_else(|| {
                NativeStateSnafu {
                    field: "notification head",
                }
                .build()
            })?;
            for (kind, lookup) in NoticeIndex::keys(NotificationKeys::from_context(&context)?) {
                let scope = Records::find(&NoticeIndex::identity(kind, &lookup), |key| {
                    Records::read(key, &self.snapshot)
                })?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "notification lookup scope",
                    }
                    .build()
                })?;
                expected.insert(NoticeIndex::key(kind, scope, &context.key.entity_key));
            }
        }
        for entry in self.snapshot.prefix(NoticeIndex::PREFIX) {
            let (key, value) = entry.context(NativeStorageSnafu {
                operation: "validate notification lookups",
            })?;
            if !value.is_empty() || !expected.remove(key.as_ref()) {
                return NativeStateSnafu {
                    field: "notification lookup set",
                }
                .fail();
            }
        }
        if !expected.is_empty() {
            return NativeStateSnafu {
                field: "notification lookup set",
            }
            .fail();
        }
        Ok(())
    }
}
