use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu, JsonSnafu};
use crate::Result;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRegistryV1 {
    schema_version: u32,
    fixture_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureFamiliesV1 {
    schema_version: u32,
    families: Vec<FixtureFamilyV1>,
    forbidden_active_fixture_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureFamilyV1 {
    family_id: String,
    member_fixture_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClosureLedgerV1 {
    pub fixture_ids: Vec<String>,
}

pub struct QualificationRegistry {
    spec_root: PathBuf,
}

impl QualificationRegistry {
    #[must_use]
    pub fn new(spec_root: impl Into<PathBuf>) -> Self {
        Self {
            spec_root: spec_root.into(),
        }
    }

    pub fn verify(&self) -> Result<ClosureLedgerV1> {
        let fixture_path = self.spec_root.join("qualification/v1/fixtures.yaml");
        let families_path = self.spec_root.join("qualification/v1/families.yaml");
        let fixture_registry: FixtureRegistryV1 = self.read_json_subset(&fixture_path)?;
        let families: FixtureFamiliesV1 = self.read_json_subset(&families_path)?;

        ensure!(
            fixture_registry.schema_version == 1 && families.schema_version == 1,
            InvalidInputSnafu {
                path: fixture_path.clone(),
                reason: "only fixture schema Version 1 is accepted"
            }
        );

        let registered = unique_set(&fixture_registry.fixture_ids, &fixture_path)?;
        ensure!(
            !registered.is_empty(),
            InvalidInputSnafu {
                path: fixture_path.clone(),
                reason: "the qualification registry must contain a fixture"
            }
        );
        self.verify_families(&families_path, &families, &registered)?;

        Ok(ClosureLedgerV1 {
            fixture_ids: registered.into_iter().collect(),
        })
    }

    fn verify_families(
        &self,
        path: &Path,
        families: &FixtureFamiliesV1,
        registered: &BTreeSet<String>,
    ) -> Result<()> {
        let mut family_ids = BTreeSet::new();
        for family in &families.families {
            ensure!(
                family_ids.insert(family.family_id.as_str()),
                InvalidInputSnafu {
                    path: path.to_path_buf(),
                    reason: format!("duplicate fixture family `{}`", family.family_id)
                }
            );
            ensure!(
                unique_set(&family.member_fixture_ids, path)?.is_subset(registered),
                InvalidInputSnafu {
                    path: path.to_path_buf(),
                    reason: format!(
                        "fixture family `{}` has an unknown member",
                        family.family_id
                    )
                }
            );
        }
        for forbidden in &families.forbidden_active_fixture_ids {
            ensure!(
                !registered.contains(forbidden),
                InvalidInputSnafu {
                    path: path.to_path_buf(),
                    reason: format!("rejected fixture `{forbidden}` is active")
                }
            );
        }
        Ok(())
    }

    fn read_json_subset<T>(&self, path: &Path) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        // The qualification runner consumes this registry as data. Planning
        // documents do not define executable fixture ownership.
        let bytes = fs::read(path).context(IoSnafu {
            path: path.to_path_buf(),
        })?;
        serde_json::from_slice(&bytes).context(JsonSnafu {
            path: path.to_path_buf(),
        })
    }
}

fn unique_set(values: &[String], path: &Path) -> Result<BTreeSet<String>> {
    let set = values.iter().cloned().collect::<BTreeSet<_>>();
    ensure!(
        set.len() == values.len(),
        InvalidInputSnafu {
            path: path.to_path_buf(),
            reason: "values must be sorted and unique"
        }
    );
    ensure!(
        values.windows(2).all(|pair| pair[0] < pair[1]),
        InvalidInputSnafu {
            path: path.to_path_buf(),
            reason: "values must be in canonical lexical order"
        }
    );
    Ok(set)
}
