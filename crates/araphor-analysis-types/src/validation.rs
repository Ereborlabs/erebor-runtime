use crate::{
    error::{ContractSnafu, InvalidSnafu},
    Result,
};
use crate::values::{GraphSubjectKeyV1, GraphSubjectAuthorityV1,DeclaredFindingReasonV1, FindingReasonV1, FindingV1};
use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

pub struct Validation;

impl Validation {
    fn contract_id(package_id: &str) -> Result<()> {
        if FindingV1::PACKAGES.contains(&package_id) {
            Ok(())
        } else {
            InvalidSnafu {
                field: "analysis package identity",
            }
            .fail()
        }
    }

    pub fn validate_reason(reason: &FindingReasonV1, package: &str) -> Result<()> {
        match reason {
            FindingReasonV1::Declared(reason) => Self::validate_declared(reason, package),
            _ => Self::contract_id(package),
        }
    }
    fn validate_declared(reason: &DeclaredFindingReasonV1, package: &str) -> Result<()> {
        match reason.validate(package) {
            Err(sdk::Error::Contract {
                code: sdk::ErrorCode::Invalid,
                field,
                ..
            }) if field == "finding reason namespace" => InvalidSnafu {
                field: "finding reason namespace",
            }
            .fail(),
            Err(sdk::Error::Contract {
                code: sdk::ErrorCode::Invalid,
                field,
                ..
            }) if field == "finding reason details" => InvalidSnafu {
                field: "finding reason details",
            }
            .fail(),
            result => result.context(ContractSnafu),
        }
    }
}

impl Validation {
    pub fn validate(subject: &GraphSubjectKeyV1) -> Result<()> {
        let valid_authority = match &subject.authority {
            GraphSubjectAuthorityV1::Native {
                node_id,
                node_boot_id,
                label_epoch,
            } => !node_id.is_empty() && *node_boot_id != [0; 16] && *label_epoch > 0,
            GraphSubjectAuthorityV1::Provider { authority_id }
            | GraphSubjectAuthorityV1::External { authority_id } => !authority_id.is_empty(),
            GraphSubjectAuthorityV1::Kubernetes { cluster_id } => !cluster_id.is_empty(),
        };
        if subject.tenant_id == [0; 16] || !valid_authority || subject.identity.is_empty() {
            return Err(crate::error::InvalidSnafu { field: "subject lifetime" }.build());
        }
        Ok(())
    }

}
