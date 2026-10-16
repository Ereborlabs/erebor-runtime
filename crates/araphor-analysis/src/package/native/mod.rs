use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};
use snafu::IntoError as _;

use super::PackageErrorCodeV1 as Code;
use crate::{AnalysisReadControl, Result};

mod artifact;
mod files;
mod loading;

#[cfg(test)]
use araphor_data::Dependency;
use araphor_data::Qualification;
use artifact::NativeAdmission;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLimits {
    pub memory_bytes: Option<u64>,
    pub cpu_seconds: Option<u64>,
}

impl NativeLimits {
    pub fn validate(&self) -> Result<()> {
        if self.memory_bytes == Some(0) || self.cpu_seconds == Some(0) {
            return Err(Code::Invalid.error("native resource configuration").into());
        }
        if self.memory_bytes.is_some() || self.cpu_seconds.is_some() {
            return Err(Code::Unsupported
                .error("in-process native resource limits")
                .into());
        }
        Ok(())
    }
}

pub(crate) struct NativeExecution {
    limits: NativeLimits,
}

impl NativeExecution {
    pub(crate) fn new(limits: NativeLimits) -> Result<Self> {
        Ok(Self { limits })
    }

    pub(crate) fn admit(&self, artifact: &[u8], qualification: &Qualification) -> Result<()> {
        self.limits.validate()?;
        NativeAdmission::validate(qualification, artifact)
    }

    pub(crate) fn evaluate(
        &self,
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
        artifact: &[u8],
        qualification: &Qualification,
        output_limits: sdk::Limits,
        control: &AnalysisReadControl,
    ) -> Result<sdk::Output> {
        control.check()?;
        self.admit(artifact, qualification)?;
        control.check()?;
        let loaded = loading::NativeLibrary::load(artifact, qualification, control);
        control.check()?;
        let library = loaded?;
        let invocation =
            sdk::native::Invocation::new(package, evaluation, || control.check().is_err())
                .map_err(|source| crate::AnalysisContractSnafu.into_error(source))?;
        let result = library.call(invocation, output_limits);
        control.check()?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_limits_allow_execution() -> Result<()> {
        NativeLimits::default().validate()?;
        assert!(matches!(
            NativeLimits {
                memory_bytes: Some(0),
                cpu_seconds: None
            }
            .validate(),
            Err(crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Invalid,
                    ..
                }
            })
        ));
        assert!(matches!(
            NativeLimits {
                memory_bytes: Some(1),
                cpu_seconds: None
            }
            .validate(),
            Err(crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Unsupported,
                    ..
                }
            })
        ));
        Ok(())
    }

    #[test]
    fn caps_allow_owner_startup() -> Result<()> {
        let execution = NativeExecution::new(NativeLimits {
            memory_bytes: Some(1024),
            cpu_seconds: None,
        })?;
        let qualification = Qualification {
            exports: vec!["detect".into()],
            target: env!("ARAPHOR_NATIVE_TARGET").into(),
            cpu_features: Vec::new(),
            contract_version: 1,
            system_libraries: Vec::new(),
            dependencies: Vec::new(),
        };
        assert!(matches!(
            execution.admit(b"invalid", &qualification),
            Err(crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Unsupported,
                    field: "in-process native resource limits",
                    ..
                }
            })
        ));
        Ok(())
    }
}
