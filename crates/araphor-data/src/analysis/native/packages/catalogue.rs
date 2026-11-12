use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{DataView, PackageRecord, PackageRevisionV1, Records};
use crate::{NativeStateSnafu, NativeStorageSnafu, PackageRefV1, Result};

impl DataView {
    pub(in crate::analysis::native) fn package_bound(&self, mut bound: u64) -> Result<u64> {
        if bound == 0 {
            return Ok(0);
        }
        for row in self.snapshot.prefix(PackageHeader::PREFIX) {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "read retained package history",
            })?;
            if key.len() == PackageHeader::PREFIX.len() + 16 {
                continue;
            }
            if key.len() != PackageHeader::PREFIX.len() + 8 {
                return NativeStateSnafu {
                    field: "package history key",
                }
                .fail();
            }
            let bytes = Records::payload(&key, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "package history header",
                    }
                    .build()
                })?;
            let (_, _, revision, _): (
                serde::de::IgnoredAny,
                serde::de::IgnoredAny,
                u64,
                serde::de::IgnoredAny,
            ) = Records::decode(&bytes)?;
            if revision == 0 || revision > self.metadata_revision {
                return NativeStateSnafu {
                    field: "package history revision",
                }
                .fail();
            }
            bound = bound.min(revision);
        }
        Ok(bound)
    }
}

#[derive(Deserialize, Serialize, Eq, PartialEq)]
pub(super) struct PackageHeader {
    pub tenant: [u8; 16],
    pub root: PackageRefV1,
    pub revision: u64,
    pub dependencies: Vec<u64>,
}

impl PackageHeader {
    pub(super) const PREFIX: &'static [u8] = b"\0data/@package/";

    pub(super) fn key(id: u64) -> Vec<u8> {
        [Self::PREFIX, &id.to_be_bytes()].concat()
    }

    pub(super) fn from_package(
        package: &PackageRevisionV1,
        revision: u64,
        mut id: impl FnMut(&[u8]) -> Result<u64>,
    ) -> Result<Self> {
        let dependencies = package
            .dependencies
            .iter()
            .map(|dependency| {
                id(&PackageRecord::identity(
                    package.tenant_id,
                    &dependency.package_id,
                    Some(&dependency.revision),
                )?)
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            tenant: package.tenant_id,
            root: PackageRefV1 {
                package_id: package.package_id.clone(),
                revision: package.revision.clone(),
            },
            revision,
            dependencies,
        })
    }

    pub(super) fn check(
        package: &PackageRevisionV1,
        revision: u64,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<u64> {
        let missing = || {
            NativeStateSnafu {
                field: "package catalogue entry",
            }
            .build()
        };
        let id = Records::find(
            &PackageRecord::identity(
                package.tenant_id,
                &package.package_id,
                Some(&package.revision),
            )?,
            &mut get,
        )?
        .ok_or_else(missing)?;
        let bytes = Records::payload(&Self::key(id), &mut get)?.ok_or_else(missing)?;
        let mut saved: Self = Records::decode(&bytes)?;
        let mut expected = Self::from_package(package, revision, |identity| {
            Records::find(identity, &mut get)?.ok_or_else(missing)
        })?;
        saved.dependencies.sort_unstable();
        expected.dependencies.sort_unstable();
        if saved != expected {
            return Err(missing());
        }
        Ok(id)
    }
}
