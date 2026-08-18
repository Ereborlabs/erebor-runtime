use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

use super::super::source::*;
use super::{Validate, ValidationResult};

// Policy values validate their signed lexical representation.
pub(super) enum PolicyValue<'a> {
    LocalId(&'a str),
    RegistrySymbol(&'a str),
    CanonicalUuid(&'a str),
    Uuid(&'a str),
    Digest(&'a str),
    Duration(&'a str, bool),
}

impl Validate for PolicyValue<'_> {
    fn validate(&self) -> ValidationResult {
        let (valid, code, reason) = match *self {
            Self::LocalId(value) => (
                (1..=128).contains(&value.len())
                    && value.as_bytes()[0].is_ascii_lowercase()
                    && value.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b'-')
                    }),
                "CFG_LOCAL_ID",
                format!("`{value}` is not a PolicyLocalIdV1"),
            ),
            Self::RegistrySymbol(value) => (
                (1..=128).contains(&value.len())
                    && value.as_bytes()[0].is_ascii_uppercase()
                    && value.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                    }),
                "CFG_REGISTRY_SYMBOL",
                format!("`{value}` is not an uppercase registry symbol"),
            ),
            Self::CanonicalUuid(value) => (
                Uuid::parse_str(value).is_ok_and(|uuid| uuid.hyphenated().to_string() == value),
                "CFG_ID128",
                "value must be a canonical lowercase hyphenated Id128 UUID".to_owned(),
            ),
            Self::Uuid(value) => (
                Uuid::parse_str(value).is_ok(),
                "CFG_ID128",
                "value must be a UUID".to_owned(),
            ),
            Self::Digest(value) => (
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "CFG_DIGEST",
                "value must be a 64-character hexadecimal digest".to_owned(),
            ),
            Self::Duration(value, zero_allowed) => {
                let suffix =
                    if value.ends_with("ns") || value.ends_with("us") || value.ends_with("ms") {
                        2
                    } else if value.ends_with('s') || value.ends_with('m') || value.ends_with('h') {
                        1
                    } else {
                        0
                    };
                let valid = suffix > 0
                    && value[..value.len() - suffix]
                        .parse::<u64>()
                        .is_ok_and(|duration| zero_allowed || duration > 0);
                (
                    valid,
                    "CFG_DURATION",
                    "value must be a bounded duration".to_owned(),
                )
            }
        };
        require!(valid, code, reason);
        Ok(())
    }
}

// Each child record validates only the fields that it owns.
impl Validate for PolicyMetadataV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::CanonicalUuid(&self.profile_id).validate()?;
        PolicyValue::CanonicalUuid(&self.trust_domain_id).validate()?;
        let parse = |value: &str| {
            OffsetDateTime::parse(value, &Rfc3339)
                .ok()
                .filter(|time| time.offset().is_utc())
                .and_then(|time| i64::try_from(time.unix_timestamp_nanos()).ok())
        };
        let from = parse(&self.valid_from_utc);
        require!(
            from.is_some(),
            "CFG_TIMESTAMP",
            "valid_from_utc must be a UTC timestamp"
        );
        require!(
            self.valid_until_utc
                .as_deref()
                .is_none_or(|until| parse(until).is_some_and(|until| Some(until) > from)),
            "CFG_VALIDITY_WINDOW",
            "valid_until_utc must be a later UTC timestamp"
        );
        Ok(())
    }
}

impl Validate for ProtectedUniverseV1 {
    fn validate(&self) -> ValidationResult {
        for id in self.workload_selector_ids.iter().chain(&self.role_ids) {
            PolicyValue::LocalId(id).validate()?;
        }
        for id in &self.object_class_ids {
            PolicyValue::RegistrySymbol(id).validate()?;
        }
        Ok(())
    }
}
local_id_only! { WorkloadSelectorV1 => workload_selector_id, ObjectClassifierBindingV1 => classifier_binding_id, RoleDefinitionV1 => role_id, NativeRoleTransitionRuleV1 => transition_rule_id }
