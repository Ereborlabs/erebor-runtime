use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::AuthorityErrorCodeV1;
use crate::Result;

const REPLAY_WINDOW_BITS: usize = 4096;
const REPLAY_WINDOW_WORDS: usize = REPLAY_WINDOW_BITS / u64::BITS as usize;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntentReplayKeyV1<Id> {
    pub trust_domain_id: Id,
    pub issuer_id: Id,
    pub key_id: Vec<u8>,
    pub sequence_epoch: u64,
}

impl<Id: Eq> IntentReplayKeyV1<Id> {
    pub fn conflicts(&self, other: &Self) -> bool {
        self.trust_domain_id == other.trust_domain_id
            && self.issuer_id == other.issuer_id
            && self.sequence_epoch == other.sequence_epoch
            && self.key_id != other.key_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentReplayWindowV1 {
    highest_sequence: u64,
    seen: [u64; REPLAY_WINDOW_WORDS],
}

impl Default for IntentReplayWindowV1 {
    fn default() -> Self {
        Self {
            highest_sequence: 0,
            seen: [0; REPLAY_WINDOW_WORDS],
        }
    }
}

impl IntentReplayWindowV1 {
    pub fn accept(&mut self, sequence: u64) -> Result<()> {
        AuthorityErrorCodeV1::Replay.require(sequence > 0, "issuer sequence")?;
        if self.highest_sequence == 0 {
            self.highest_sequence = sequence;
            self.seen[0] = 1;
            return Ok(());
        }
        if sequence > self.highest_sequence {
            let shift = sequence - self.highest_sequence;
            let previous = self.seen;
            self.seen.fill(0);
            if shift < REPLAY_WINDOW_BITS as u64 {
                for distance in 0..REPLAY_WINDOW_BITS - shift as usize {
                    if previous[distance / 64] & (1_u64 << (distance % 64)) != 0 {
                        let moved = distance + shift as usize;
                        self.seen[moved / 64] |= 1_u64 << (moved % 64);
                    }
                }
            }
            self.highest_sequence = sequence;
            self.seen[0] |= 1;
            return Ok(());
        }
        let distance = usize::try_from(self.highest_sequence - sequence).unwrap_or(usize::MAX);
        AuthorityErrorCodeV1::Replay.require(
            distance < REPLAY_WINDOW_BITS
                && self.seen[distance / 64] & (1_u64 << (distance % 64)) == 0,
            "issuer replay window",
        )?;
        self.seen[distance / 64] |= 1_u64 << (distance % 64);
        Ok(())
    }
}

impl Serialize for IntentReplayWindowV1 {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        (&self.highest_sequence, self.seen.as_slice()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IntentReplayWindowV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let (highest_sequence, seen): (u64, Vec<u64>) = Deserialize::deserialize(deserializer)?;
        let seen: [u64; REPLAY_WINDOW_WORDS] = seen
            .try_into()
            .map_err(|_| serde::de::Error::custom("the intent replay window must have 64 words"))?;
        if (highest_sequence == 0 && seen != [0; REPLAY_WINDOW_WORDS])
            || (highest_sequence > 0 && seen[0] & 1 == 0)
        {
            return Err(serde::de::Error::custom(
                "the intent replay window state is invalid",
            ));
        }
        Ok(Self {
            highest_sequence,
            seen,
        })
    }
}
