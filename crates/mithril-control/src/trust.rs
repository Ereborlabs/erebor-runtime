use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::error::ControlStoreSnafu;
use crate::{ControlStore, Result, TrustGenerationV1};

const TRUST_SUBSCRIBER_CAPACITY: usize = 8;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustGenerationAcknowledgementV1 {
    pub node_id: String,
    pub node_boot_id: [u8; 16],
    pub label_epoch: u64,
    pub generation: u64,
    pub bundle_digest: String,
}

#[derive(Clone)]
pub struct TrustBundleOwner {
    store: Option<ControlStore>,
    state: Arc<Mutex<TrustBundleState>>,
}

struct TrustBundleState {
    current: TrustGenerationV1,
    acknowledgements: BTreeMap<String, TrustGenerationV1>,
    subscribers: Vec<mpsc::Sender<TrustGenerationV1>>,
}

impl TrustBundleOwner {
    pub fn open(store: ControlStore, configured: TrustGenerationV1) -> Result<Self> {
        store.install_trust_generation(configured)?;
        let current = store.current_trust_generation()?.ok_or_else(|| {
            ControlStoreSnafu {
                path: store.root(),
                reason: "the durable trust owner has no current generation".to_owned(),
            }
            .build()
        })?;
        Ok(Self {
            store: Some(store),
            state: Arc::new(Mutex::new(TrustBundleState {
                current,
                acknowledgements: BTreeMap::new(),
                subscribers: Vec::new(),
            })),
        })
    }

    #[must_use]
    pub fn static_generation(current: TrustGenerationV1) -> Self {
        Self {
            store: None,
            state: Arc::new(Mutex::new(TrustBundleState {
                current,
                acknowledgements: BTreeMap::new(),
                subscribers: Vec::new(),
            })),
        }
    }

    pub fn install(&self, generation: TrustGenerationV1) -> Result<()> {
        let store = self.store.as_ref().ok_or_else(|| {
            ControlStoreSnafu {
                path: std::path::PathBuf::from("<static-trust-owner>"),
                reason: "a static trust owner cannot rotate generations".to_owned(),
            }
            .build()
        })?;
        store.install_trust_generation(generation.clone())?;
        let mut state = self.lock()?;
        if generation == state.current {
            return Ok(());
        }
        state.current = generation.clone();
        state
            .acknowledgements
            .retain(|_, acknowledged| acknowledged == &generation);
        state
            .subscribers
            .retain(|subscriber| subscriber.try_send(generation.clone()).is_ok());
        Ok(())
    }

    pub fn current(&self) -> Result<TrustGenerationV1> {
        Ok(self.lock()?.current.clone())
    }

    pub fn subscribe(&self) -> Result<mpsc::Receiver<TrustGenerationV1>> {
        let (sender, receiver) = mpsc::channel(TRUST_SUBSCRIBER_CAPACITY);
        let mut state = self.lock()?;
        sender.try_send(state.current.clone()).map_err(|error| {
            ControlStoreSnafu {
                path: std::path::PathBuf::from("<trust-subscriber>"),
                reason: format!("the current trust generation cannot enter a new stream: {error}"),
            }
            .build()
        })?;
        state.subscribers.push(sender);
        Ok(receiver)
    }

    pub fn acknowledge(
        &self,
        node_id: &str,
        node_boot_id: [u8; 16],
        label_epoch: u64,
        generation: u64,
        bundle_digest: &str,
    ) -> Result<()> {
        let current = self.current()?;
        if generation != current.generation || bundle_digest != current.bundle_digest {
            return ControlStoreSnafu {
                path: self.store.as_ref().map_or_else(
                    || std::path::PathBuf::from("<static-trust-owner>"),
                    ControlStore::root,
                ),
                reason: "the node trust acknowledgement is stale or has the wrong digest"
                    .to_owned(),
            }
            .fail();
        }
        if let Some(store) = &self.store {
            store.acknowledge_trust_generation(TrustGenerationAcknowledgementV1 {
                node_id: node_id.to_owned(),
                node_boot_id,
                label_epoch,
                generation,
                bundle_digest: bundle_digest.to_owned(),
            })?;
        }
        self.lock()?
            .acknowledgements
            .insert(node_id.to_owned(), current);
        Ok(())
    }

    pub fn acknowledged(&self, node_id: &str) -> Result<Option<TrustGenerationV1>> {
        if let Some(store) = &self.store {
            let Some(acknowledgement) = store.latest_trust_acknowledgement(node_id)? else {
                return Ok(None);
            };
            let current = self.current()?;
            return Ok((acknowledgement.generation == current.generation
                && acknowledgement.bundle_digest == current.bundle_digest)
                .then_some(current));
        }
        Ok(self.lock()?.acknowledgements.get(node_id).cloned())
    }

    pub fn require_acknowledged(&self, node_id: &str) -> Result<()> {
        if self.acknowledged(node_id)?.is_none() {
            return ControlStoreSnafu {
                path: self.store.as_ref().map_or_else(
                    || std::path::PathBuf::from("<static-trust-owner>"),
                    ControlStore::root,
                ),
                reason: "the node has not acknowledged the current trust generation".to_owned(),
            }
            .fail();
        }
        Ok(())
    }

    pub fn require_session_acknowledged(
        &self,
        node_id: &str,
        node_boot_id: [u8; 16],
        label_epoch: u64,
    ) -> Result<()> {
        let current = self.current()?;
        let matches = if let Some(store) = &self.store {
            store
                .trust_acknowledgement(node_id, node_boot_id, label_epoch, current.generation)?
                .is_some_and(|acknowledgement| {
                    acknowledgement.bundle_digest == current.bundle_digest
                })
        } else {
            self.lock()?
                .acknowledgements
                .get(node_id)
                .is_some_and(|acknowledged| acknowledged == &current)
        };
        if !matches {
            return ControlStoreSnafu {
                path: self.store.as_ref().map_or_else(
                    || std::path::PathBuf::from("<static-trust-owner>"),
                    ControlStore::root,
                ),
                reason: "the current node boot and label epoch have not acknowledged trust"
                    .to_owned(),
            }
            .fail();
        }
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, TrustBundleState>> {
        self.state.lock().map_err(|_| {
            ControlStoreSnafu {
                path: std::path::PathBuf::from("<poisoned-trust-owner>"),
                reason: "the trust owner lock is poisoned".to_owned(),
            }
            .build()
        })
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::TrustBundleOwner;
    use crate::{ControlStore, PolicySignerTrustV1, TrustGenerationV1};

    fn generation(
        number: u64,
        issuer_epoch: u64,
        signers: Vec<PolicySignerTrustV1>,
    ) -> TrustGenerationV1 {
        let mut trust = TrustGenerationV1 {
            generation: number,
            bundle_digest: String::new(),
            policy_issuer_sequence_epoch: issuer_epoch,
            policy_signers: signers,
        };
        let mut digest = Sha256::new();
        digest.update(b"MITHRIL-CONTROL-TRUST-BUNDLE-V1\0");
        digest.update(trust.generation.to_be_bytes());
        digest.update(trust.policy_issuer_sequence_epoch.to_be_bytes());
        for signer in &trust.policy_signers {
            digest.update(
                u64::try_from(signer.signing_key_id.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            digest.update(signer.signing_key_id.as_bytes());
            digest.update(signer.ed25519_public_key_hex.as_bytes());
            digest.update([u8::from(signer.revoked)]);
        }
        trust.bundle_digest = format!("{:x}", digest.finalize());
        trust
    }

    fn signer(key_id: &str, byte: char, revoked: bool) -> PolicySignerTrustV1 {
        PolicySignerTrustV1 {
            signing_key_id: key_id.to_owned(),
            ed25519_public_key_hex: byte.to_string().repeat(64),
            revoked,
        }
    }

    #[test]
    fn durable_owner_rotates_revokes_and_recovers_acknowledgements(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let first = generation(1, 7, vec![signer("key-a", 'a', false)]);
        let owner = TrustBundleOwner::open(store.clone(), first.clone())?;
        let mut subscriber = owner.subscribe()?;
        assert_eq!(subscriber.try_recv()?, first);
        owner.acknowledge("node-a", [1; 16], 3, first.generation, &first.bundle_digest)?;
        assert_eq!(owner.acknowledged("node-a")?, Some(first.clone()));

        let second = generation(
            2,
            7,
            vec![signer("key-a", 'a', true), signer("key-b", 'b', false)],
        );
        owner.install(second.clone())?;
        assert_eq!(subscriber.try_recv()?, second);
        assert!(owner.acknowledged("node-a")?.is_none());
        assert!(owner.require_acknowledged("node-a").is_err());
        owner.acknowledge("node-a", [1; 16], 3, 2, &owner.current()?.bundle_digest)?;

        drop(owner);
        let recovered = TrustBundleOwner::open(
            store.clone(),
            generation(
                2,
                7,
                vec![signer("key-a", 'a', true), signer("key-b", 'b', false)],
            ),
        )?;
        assert_eq!(
            recovered.acknowledged("node-a")?,
            Some(recovered.current()?)
        );
        recovered.require_session_acknowledged("node-a", [1; 16], 3)?;
        assert!(recovered
            .require_session_acknowledged("node-a", [2; 16], 3)
            .is_err());
        recovered.acknowledge("node-a", [2; 16], 3, 2, &recovered.current()?.bundle_digest)?;
        recovered.require_session_acknowledged("node-a", [2; 16], 3)?;
        assert!(TrustBundleOwner::open(store.clone(), first).is_err());

        let reversed_revocation = generation(
            3,
            8,
            vec![signer("key-a", 'a', false), signer("key-b", 'b', false)],
        );
        assert!(recovered.install(reversed_revocation).is_err());
        let changed_key = generation(
            3,
            8,
            vec![signer("key-a", 'a', true), signer("key-b", 'c', false)],
        );
        assert!(recovered.install(changed_key).is_err());
        assert_eq!(recovered.current()?.generation, 2);
        Ok(())
    }
}
