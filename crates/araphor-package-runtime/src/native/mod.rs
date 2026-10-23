use serde::{Deserialize, Serialize};

use super::PackageErrorCodeV1 as Code;
use crate::Result;

mod artifact;
mod files;
mod loading;

#[cfg(test)]
use araphor_data::Dependency;
use araphor_data::Qualification;
pub use artifact::NativeAdmission;
pub use loading::NativeLibrary;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_limits_allow_execution() -> Result<()> {
        NativeLimits::default().validate()?;
        for native in [
            NativeLimits {
                memory_bytes: Some(0),
                cpu_seconds: None,
            },
            NativeLimits {
                memory_bytes: None,
                cpu_seconds: Some(0),
            },
        ] {
            assert!(matches!(
                crate::Runtime::new(crate::Limits {
                    native,
                    ..Default::default()
                }),
                Err(crate::Error::Data {
                    source: araphor_data::Error::Package {
                        code: Code::Invalid,
                        field: "native resource configuration",
                        ..
                    }
                })
            ));
        }
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
}
