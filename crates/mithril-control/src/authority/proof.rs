use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use minicbor::{data::Token, Decoder, Encoder};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use super::AuthorityErrorCodeV1;
use crate::Result;

pub const INTENT_SIGNATURE_DOMAIN: &[u8] = b"MITHRIL-INTENT-V1\0";
pub const MAX_INTENT_PAYLOAD_BYTES: usize = 32 * 1024;
const MAX_AGGREGATE_BYTES: usize = 24 * 1024;
const MAX_ARRAY_MEMBERS: usize = 512;
const MAX_NESTING_DEPTH: usize = 8;
const REPLAY_WINDOW_BITS: usize = 4096;
const REPLAY_WINDOW_WORDS: usize = REPLAY_WINDOW_BITS / u64::BITS as usize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedIntentEnvelopeV1 {
    pub key_id: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedIntentEnvelopeV1 {
    pub fn sign(payload: &[u8], key_id: &[u8], key: &SigningKey) -> Result<Vec<u8>> {
        CanonicalIntentV1::validate(payload)?;
        AuthorityErrorCodeV1::Invalid.require(
            (1..=128).contains(&key_id.len())
                && (1..=MAX_INTENT_PAYLOAD_BYTES).contains(&payload.len()),
            "intent size",
        )?;
        let signature = key.sign(&Self::input(payload)).to_bytes();
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .map(5)?
            .u8(0)?
            .u8(1)?
            .u8(1)?
            .bytes(key_id)?
            .u8(2)?
            .u8(1)?
            .u8(3)?
            .bytes(payload)?
            .u8(4)?
            .bytes(&signature)?;
        Ok(bytes)
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<()> {
        AuthorityErrorCodeV1::Denied.require(
            Signature::from_slice(&self.signature).is_ok_and(|signature| {
                key.verify_strict(&Self::input(&self.payload), &signature)
                    .is_ok()
            }),
            "intent signature",
        )
    }

    fn input(payload: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(INTENT_SIGNATURE_DOMAIN.len() + 32);
        input.extend_from_slice(INTENT_SIGNATURE_DOMAIN);
        input.extend_from_slice(&Sha256::digest(payload));
        input
    }
}

impl TryFrom<&[u8]> for SignedIntentEnvelopeV1 {
    type Error = crate::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        AuthorityErrorCodeV1::Invalid.require(
            bytes.len() <= MAX_INTENT_PAYLOAD_BYTES + 256,
            "envelope size",
        )?;
        CanonicalIntentV1::validate(bytes)?;
        let mut decoder = Decoder::new(bytes);
        AuthorityErrorCodeV1::Invalid.require(decoder.map()? == Some(5), "envelope fields")?;
        for expected in [0, 1, 2, 3, 4] {
            AuthorityErrorCodeV1::Invalid.require(decoder.u8()? == expected, "envelope key")?;
            match expected {
                0 | 2 => {
                    AuthorityErrorCodeV1::Invalid
                        .require(decoder.u8()? == 1, "envelope version or algorithm")?;
                }
                1 | 3 | 4 => {
                    decoder.bytes()?;
                }
                _ => {}
            }
        }
        AuthorityErrorCodeV1::Invalid
            .require(decoder.position() == bytes.len(), "envelope trailing data")?;
        let mut decoder = Decoder::new(bytes);
        decoder.map()?;
        for _ in 0..3 {
            decoder.u8()?;
        }
        let key_id = decoder.bytes()?.to_vec();
        for _ in 0..3 {
            decoder.u8()?;
        }
        let payload = decoder.bytes()?.to_vec();
        decoder.u8()?;
        let signature = decoder.bytes()?.to_vec();
        AuthorityErrorCodeV1::Invalid.require(
            (1..=128).contains(&key_id.len())
                && (1..=MAX_INTENT_PAYLOAD_BYTES).contains(&payload.len())
                && signature.len() == 64,
            "envelope bounds",
        )?;
        Ok(Self {
            key_id,
            payload,
            signature,
        })
    }
}

pub struct CanonicalIntentV1;

impl CanonicalIntentV1 {
    pub fn validate(bytes: &[u8]) -> Result<()> {
        AuthorityErrorCodeV1::Invalid.require(
            !bytes.is_empty() && bytes.len() <= MAX_INTENT_PAYLOAD_BYTES + 256,
            "CBOR size",
        )?;
        let mut decoder = Decoder::new(bytes);
        let tokens = decoder
            .tokens()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        AuthorityErrorCodeV1::Invalid.require(
            decoder.position() == bytes.len()
                && !tokens.iter().any(|token| {
                    matches!(
                        token,
                        Token::BeginBytes
                            | Token::BeginString
                            | Token::BeginArray
                            | Token::BeginMap
                            | Token::Break
                            | Token::F16(_)
                            | Token::F32(_)
                            | Token::F64(_)
                            | Token::Tag(_)
                            | Token::Simple(_)
                            | Token::Null
                            | Token::Undefined
                    )
                }),
            "CBOR token",
        )?;
        let mut position = 0;
        let mut counters = CborCounters::default();
        counters.item(&tokens, &mut position, 1)?;
        AuthorityErrorCodeV1::Invalid.require(
            position == tokens.len()
                && counters.aggregate_bytes <= MAX_AGGREGATE_BYTES
                && counters.array_members <= MAX_ARRAY_MEMBERS,
            "CBOR aggregate bounds",
        )?;
        let mut canonical = Vec::with_capacity(bytes.len());
        Encoder::new(&mut canonical).tokens(&tokens)?;
        AuthorityErrorCodeV1::Invalid.require(canonical == bytes, "CBOR shortest form")
    }
}

#[derive(Default)]
struct CborCounters {
    aggregate_bytes: usize,
    array_members: usize,
}

impl CborCounters {
    fn item(&mut self, tokens: &[Token<'_>], position: &mut usize, depth: usize) -> Result<()> {
        AuthorityErrorCodeV1::Invalid.require(depth <= MAX_NESTING_DEPTH, "CBOR depth")?;
        let token = tokens
            .get(*position)
            .ok_or_else(|| AuthorityErrorCodeV1::Invalid.error("CBOR truncated"))?;
        *position += 1;
        match token {
            Token::Map(length) => {
                let mut previous = None;
                for _ in 0..*length {
                    let key = Self::unsigned(
                        tokens
                            .get(*position)
                            .ok_or_else(|| AuthorityErrorCodeV1::Invalid.error("CBOR map key"))?,
                    )?;
                    AuthorityErrorCodeV1::Invalid.require(
                        previous.is_none_or(|previous| key > previous),
                        "CBOR key order",
                    )?;
                    previous = Some(key);
                    *position += 1;
                    self.item(tokens, position, depth + 1)?;
                }
            }
            Token::Array(length) => {
                let length = usize::try_from(*length)
                    .map_err(|_| AuthorityErrorCodeV1::Invalid.error("CBOR array length"))?;
                self.array_members = self
                    .array_members
                    .checked_add(length)
                    .ok_or_else(|| AuthorityErrorCodeV1::Invalid.error("CBOR member count"))?;
                AuthorityErrorCodeV1::Invalid.require(
                    self.array_members <= MAX_ARRAY_MEMBERS,
                    "CBOR array members",
                )?;
                for _ in 0..length {
                    self.item(tokens, position, depth + 1)?;
                }
            }
            Token::Bytes(value) => self.add_bytes(value.len())?,
            Token::String(value) => self.add_bytes(value.len())?,
            Token::Bool(_)
            | Token::U8(_)
            | Token::U16(_)
            | Token::U32(_)
            | Token::U64(_)
            | Token::I8(_)
            | Token::I16(_)
            | Token::I32(_)
            | Token::I64(_)
            | Token::Int(_) => {}
            _ => return Err(AuthorityErrorCodeV1::Invalid.error("CBOR token")),
        }
        Ok(())
    }

    fn add_bytes(&mut self, amount: usize) -> Result<()> {
        self.aggregate_bytes = self
            .aggregate_bytes
            .checked_add(amount)
            .ok_or_else(|| AuthorityErrorCodeV1::Invalid.error("CBOR byte count"))?;
        AuthorityErrorCodeV1::Invalid
            .require(self.aggregate_bytes <= MAX_AGGREGATE_BYTES, "CBOR bytes")
    }

    fn unsigned(token: &Token<'_>) -> Result<u64> {
        match token {
            Token::U8(value) => Ok(u64::from(*value)),
            Token::U16(value) => Ok(u64::from(*value)),
            Token::U32(value) => Ok(u64::from(*value)),
            Token::U64(value) => Ok(*value),
            _ => Err(AuthorityErrorCodeV1::Invalid.error("CBOR unsigned key")),
        }
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
