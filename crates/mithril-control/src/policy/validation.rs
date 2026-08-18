use crate::error::PolicyValidationSnafu;

type ValidationResult = std::result::Result<(), ValidationIssue>;

pub(super) trait Validate {
    fn validate(&self) -> ValidationResult;
}

pub(super) struct ValidationIssue {
    code: &'static str,
    reason: String,
}

impl ValidationIssue {
    pub(super) fn for_policy(self, policy_id: &str) -> crate::Error {
        PolicyValidationSnafu {
            policy_id,
            code: self.code,
            reason: self.reason,
        }
        .build()
    }
}

// These macros keep repeated validation checks uniform at each owner.
macro_rules! require {
    ($condition:expr, $code:expr, $reason:expr) => {
        if !$condition {
            return Err($crate::policy::validation::ValidationIssue {
                code: $code,
                reason: ($reason).into(),
            });
        }
    };
}

macro_rules! validate_each {
    ($document:expr; $($field:ident),+ $(,)?) => {
        $(
            for value in &$document.$field {
                value.validate()?;
            }
        )+
    };
}

macro_rules! local_id_only {
    ($($type:ty => $field:ident),+ $(,)?) => {
        $(
            impl Validate for $type {
                fn validate(&self) -> ValidationResult {
                    PolicyValue::LocalId(&self.$field).validate()
                }
            }
        )+
    };
}

macro_rules! string_set {
    ($values:expr) => {
        $values.iter().map(String::as_str).collect::<BTreeSet<_>>()
    };
}

macro_rules! ordered {
    ($($values:expr),+ $(,)?) => {
        $(ordered_unique($values))&&+
    };
}

macro_rules! all_in {
    ($values:expr, $set:expr) => {
        $values.iter().all(|value| $set.contains(value.as_str()))
    };
}

macro_rules! bounded {
    ($ids:expr; $($count:expr),+ $(,)?) => {
        ordered_unique($ids)
            && [$($count),+]
                .into_iter()
                .all(|count| *count > 0)
    };
}

mod authority;
mod document;
mod records;
mod rules;
mod value;
