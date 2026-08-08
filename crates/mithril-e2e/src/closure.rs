use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu, JsonSnafu};
use crate::{DigestV1, Result};

const ARCHITECTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/plans/mithril-hugging-face-intrusion-prevention/policy-and-protection-algorithm-architecture-readable.md"
));
const MASTER_PLAN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/plans/mithril-hugging-face-intrusion-prevention/README.md"
));
const EXPECTED_FIXTURE_COUNT: usize = 134;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureRegistryV1 {
    schema_version: u32,
    architecture_revision_sha256: String,
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
pub struct SectionLedgerRowV1 {
    pub section_id: String,
    pub title: String,
    pub owning_phases: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InvariantLedgerRowV1 {
    pub invariant_id: String,
    pub rule: String,
    pub physical_oracle: String,
    pub owning_phases: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureLedgerRowV1 {
    pub fixture_id: String,
    pub owning_phase: u8,
    pub criterion_numbers: Vec<u8>,
    pub oracle_class: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DurableOwnerLedgerRowV1 {
    pub owner: String,
    pub first_owning_phases: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClosureLedgerV1 {
    pub architecture_revision_sha256: String,
    pub sections: Vec<SectionLedgerRowV1>,
    pub invariants: Vec<InvariantLedgerRowV1>,
    pub fixtures: Vec<FixtureLedgerRowV1>,
    pub durable_owners: Vec<DurableOwnerLedgerRowV1>,
}

pub struct ArchitectureClosure {
    spec_root: PathBuf,
}

impl ArchitectureClosure {
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
        let architecture_digest = DigestV1::of(ARCHITECTURE).to_hex();

        ensure!(
            fixture_registry.schema_version == 1 && families.schema_version == 1,
            InvalidInputSnafu {
                path: fixture_path.clone(),
                reason: "only fixture schema Version 1 is accepted"
            }
        );
        ensure!(
            fixture_registry.architecture_revision_sha256 == architecture_digest,
            InvalidInputSnafu {
                path: fixture_path.clone(),
                reason: "architecture revision digest does not match the validated document"
            }
        );

        let registered = unique_set(&fixture_registry.fixture_ids, &fixture_path)?;
        let architecture_fixtures = architecture_fixture_ids();
        ensure!(
            registered.len() == EXPECTED_FIXTURE_COUNT && registered == architecture_fixtures,
            InvalidInputSnafu {
                path: fixture_path.clone(),
                reason: format!(
                    "fixture registry must equal all {EXPECTED_FIXTURE_COUNT} Appendix C IDs"
                )
            }
        );

        let allocations = master_fixture_allocations();
        let allocated = allocations
            .values()
            .flatten()
            .cloned()
            .collect::<BTreeSet<_>>();
        ensure!(
            allocated == registered,
            InvalidInputSnafu {
                path: fixture_path.clone(),
                reason: "master first-owner allocation differs from the normative registry"
            }
        );

        let criteria = criterion_allocations();
        ensure!(
            criteria.keys().cloned().collect::<BTreeSet<_>>() == registered,
            InvalidInputSnafu {
                path: fixture_path.clone(),
                reason: "criterion allocation differs from the normative registry"
            }
        );
        self.verify_families(&families_path, &families, &registered, &allocations)?;
        self.verify_rejected_contracts()?;

        let fixtures = registered
            .into_iter()
            .map(|fixture_id| FixtureLedgerRowV1 {
                owning_phase: owner_of(&allocations, &fixture_id),
                criterion_numbers: criteria.get(&fixture_id).cloned().unwrap_or_default(),
                oracle_class: oracle_class(&fixture_id).to_owned(),
                fixture_id,
            })
            .collect();

        let sections = section_rows();
        let invariants = invariant_rows();
        let durable_owners = durable_owner_rows();
        ensure!(
            sections
                .iter()
                .map(|row| row.section_id.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                == sections.len()
                && sections.iter().all(|row| !row.owning_phases.is_empty()),
            InvalidInputSnafu {
                path: PathBuf::from("validated architecture headings"),
                reason: "architecture section IDs must be unique and have an owning phase"
            }
        );
        ensure!(
            invariants
                .iter()
                .map(|row| row.invariant_id.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                == invariants.len()
                && invariants
                    .iter()
                    .all(|row| !row.physical_oracle.is_empty() && !row.owning_phases.is_empty()),
            InvalidInputSnafu {
                path: PathBuf::from("validated architecture invariants"),
                reason: "invariants must be unique and have a physical oracle and owning phase"
            }
        );
        ensure!(
            durable_owners
                .iter()
                .map(|row| row.owner.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                == durable_owners.len(),
            InvalidInputSnafu {
                path: PathBuf::from("master durable owner allocation"),
                reason: "durable owners must be unique"
            }
        );

        Ok(ClosureLedgerV1 {
            architecture_revision_sha256: architecture_digest,
            sections,
            invariants,
            fixtures,
            durable_owners,
        })
    }

    fn verify_families(
        &self,
        path: &Path,
        families: &FixtureFamiliesV1,
        registered: &BTreeSet<String>,
        allocations: &BTreeMap<u8, Vec<String>>,
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
            let members = unique_set(&family.member_fixture_ids, path)?;
            ensure!(
                members.is_subset(registered),
                InvalidInputSnafu {
                    path: path.to_path_buf(),
                    reason: format!(
                        "fixture family `{}` has an unknown member",
                        family.family_id
                    )
                }
            );
            if family.family_id == "PHASE_0_REQUIRED" {
                let phase_zero = allocations
                    .get(&0)
                    .map(|items| items.iter().cloned().collect())
                    .unwrap_or_default();
                ensure!(
                    members == phase_zero,
                    InvalidInputSnafu {
                        path: path.to_path_buf(),
                        reason: "PHASE_0_REQUIRED differs from the master allocation"
                    }
                );
            }
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
        let bytes = fs::read(path).context(IoSnafu {
            path: path.to_path_buf(),
        })?;
        serde_json::from_slice(&bytes).context(JsonSnafu {
            path: path.to_path_buf(),
        })
    }

    fn verify_rejected_contracts(&self) -> Result<()> {
        let rejected = rejected_contract_names();
        let Some(repo_root) = self.spec_root.parent() else {
            return InvalidInputSnafu {
                path: self.spec_root.clone(),
                reason: "spec root has no repository parent",
            }
            .fail();
        };
        for relative in [
            "bpf/erebor-interceptor",
            "crates/erebor-interceptor-abi",
            "crates/mithril-e2e/src",
        ] {
            verify_tree_omits_names(&repo_root.join(relative), &rejected)?;
        }
        Ok(())
    }
}

fn rejected_contract_names() -> BTreeSet<String> {
    section_after(
        ARCHITECTURE,
        "### A.8 Complete Version 1 type-ownership catalog",
    )
    .lines()
    .take_while(|line| !line.starts_with("### A.9 "))
    .filter(|line| {
        let lower = line.to_ascii_lowercase();
        lower.contains("rejected") || lower.contains("abandoned")
    })
    .flat_map(type_names)
    .collect()
}

fn type_names(line: &str) -> impl Iterator<Item = String> + '_ {
    line.split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| {
            token.len() > 2
                && token.ends_with("V1")
                && token
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_uppercase())
        })
        .map(str::to_owned)
}

fn verify_tree_omits_names(root: &Path, rejected: &BTreeSet<String>) -> Result<()> {
    let entries = fs::read_dir(root).context(IoSnafu {
        path: root.to_path_buf(),
    })?;
    for entry in entries {
        let entry = entry.context(IoSnafu {
            path: root.to_path_buf(),
        })?;
        let path = entry.path();
        if path.is_dir() {
            verify_tree_omits_names(&path, rejected)?;
            continue;
        }
        if !matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("rs" | "c" | "h")
        ) {
            continue;
        }
        let source = fs::read_to_string(&path).context(IoSnafu { path: path.clone() })?;
        let active = type_names(&source).collect::<BTreeSet<_>>();
        let forbidden = active.intersection(rejected).cloned().collect::<Vec<_>>();
        ensure!(
            forbidden.is_empty(),
            InvalidInputSnafu {
                path,
                reason: format!(
                    "active source uses rejected contracts: {}",
                    forbidden.join(", ")
                )
            }
        );
    }
    Ok(())
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

fn architecture_fixture_ids() -> BTreeSet<String> {
    fenced_ids_after(ARCHITECTURE, "### C.1 Exact fixture set")
}

fn master_fixture_allocations() -> BTreeMap<u8, Vec<String>> {
    let allocation = section_after(MASTER_PLAN, "## Exact Fixture Allocation");
    let mut phase = None;
    let mut result = BTreeMap::<u8, Vec<String>>::new();
    let mut in_fence = false;
    for line in allocation.lines() {
        if line.starts_with("## Cross-Cutting") {
            break;
        }
        if let Some(value) = line.strip_prefix("### Phase ") {
            phase = value
                .split_once(|character: char| !character.is_ascii_digit())
                .map_or(value, |(number, _)| number)
                .parse::<u8>()
                .ok();
        } else if line.starts_with("```text") {
            in_fence = true;
        } else if line.starts_with("```") {
            in_fence = false;
        } else if in_fence && is_fixture_id(line.trim()) {
            if let Some(owner) = phase {
                result
                    .entry(owner)
                    .or_default()
                    .push(line.trim().to_owned());
            }
        }
    }
    result
}

fn criterion_allocations() -> BTreeMap<String, Vec<u8>> {
    let section = section_after(ARCHITECTURE, "### C.2 Exact criterion allocation");
    let mut result = BTreeMap::<String, Vec<u8>>::new();
    for line in section.lines().filter(|line| line.starts_with("| ")) {
        let columns = line.split('|').map(str::trim).collect::<Vec<_>>();
        let Some(criterion) = columns.get(1).and_then(|value| value.parse::<u8>().ok()) else {
            continue;
        };
        for token in backtick_tokens(line) {
            if is_fixture_id(token) {
                result.entry(token.to_owned()).or_default().push(criterion);
            }
        }
    }
    result
}

fn section_rows() -> Vec<SectionLedgerRowV1> {
    ARCHITECTURE
        .lines()
        .filter_map(|line| {
            let heading = line.trim_start_matches('#');
            if heading.len() == line.len() || !heading.starts_with(' ') {
                return None;
            }
            let heading = heading.trim_start();
            let (section_id, title) = heading.split_once(' ')?;
            let section_id = section_id.trim_end_matches('.');
            if !is_architecture_section(section_id) {
                return None;
            }
            Some(SectionLedgerRowV1 {
                section_id: section_id.to_owned(),
                title: title.to_owned(),
                owning_phases: phases_for_section(section_id),
            })
        })
        .collect()
}

fn invariant_rows() -> Vec<InvariantLedgerRowV1> {
    section_after(ARCHITECTURE, "### 10. Protection Invariants")
        .lines()
        .take_while(|line| !line.starts_with("### 11."))
        .filter_map(|line| {
            if !line.starts_with("| `INV-") {
                return None;
            }
            let columns = line.split('|').map(str::trim).collect::<Vec<_>>();
            Some(InvariantLedgerRowV1 {
                invariant_id: columns.get(1)?.trim_matches('`').to_owned(),
                rule: columns.get(2)?.to_string(),
                physical_oracle: columns.get(3)?.to_string(),
                owning_phases: (0..=12).collect(),
            })
        })
        .collect()
}

fn durable_owner_rows() -> Vec<DurableOwnerLedgerRowV1> {
    let section = section_after(MASTER_PLAN, "### Durable Owner Allocation");
    section
        .lines()
        .take_while(|line| !line.starts_with("## Not In Scope"))
        .filter_map(|line| {
            if !line.starts_with("| `") {
                return None;
            }
            let columns = line.split('|').map(str::trim).collect::<Vec<_>>();
            Some(DurableOwnerLedgerRowV1 {
                owner: columns.get(1)?.trim_matches('`').to_owned(),
                first_owning_phases: columns.get(2)?.to_string(),
            })
        })
        .collect()
}

fn phases_for_section(section_id: &str) -> Vec<u8> {
    let major = section_id.split('.').next().unwrap_or(section_id);
    match major {
        "1" | "2" | "3" | "4" => vec![0, 11],
        "5" => vec![0, 1, 11],
        "6" => vec![2],
        "7" => vec![2, 4, 8, 11],
        "8" => vec![0, 2, 7, 10],
        "9" => vec![2, 6],
        "10" | "31" => (0..=12).collect(),
        "11" | "12" | "13" => vec![0, 3, 4],
        "14" => vec![0, 1, 3, 4, 5, 12],
        "15" | "16" | "17" => vec![0, 3, 4],
        "18" => vec![2, 3, 4, 5],
        "19" => vec![3, 5, 7, 10],
        "20" => vec![0, 3, 4],
        "21" => vec![0, 3, 4, 11, 12],
        "22" => vec![0, 6, 7],
        "23" => vec![7, 8, 10],
        "24" => vec![9, 10],
        "25" => (0..=11).collect(),
        "26" => vec![10, 12],
        "27" | "28" | "29" => (0..=6).collect(),
        "30" => (1..=10).collect(),
        "32" => vec![1, 2, 6, 9, 11],
        "33" => vec![0, 1, 2, 3, 4, 5, 6, 11],
        "34" => vec![0, 1, 7, 9, 10],
        "35" | "36" => (0..=12).collect(),
        "37" => vec![11],
        "A" => appendix_a_phases(section_id),
        "B" | "C" => (0..=12).collect(),
        "D" => vec![0],
        _ => Vec::new(),
    }
}

fn appendix_a_phases(section_id: &str) -> Vec<u8> {
    match section_id.split('.').nth(1) {
        Some("1" | "2" | "3" | "4" | "5" | "6" | "7") => vec![0, 6, 11],
        Some("8" | "9" | "10" | "11" | "12") => vec![0, 2, 3, 4],
        Some("13") => vec![0, 3, 4, 5, 11, 12],
        Some("14") => vec![2, 3, 4],
        Some("15") => vec![6, 7, 8, 9, 10],
        Some("16") => vec![10, 12],
        _ => vec![0],
    }
}

fn oracle_class(fixture_id: &str) -> &'static str {
    if fixture_id.contains("GOLDEN") || fixture_id == "FIXTURE-REGISTRY-COMPLETE-001" {
        "CANONICAL_BYTES_OR_REGISTRY_EQUALITY"
    } else if fixture_id.starts_with("SOURCE-") {
        "HOSTILE_SOURCE_MECHANISM_OR_BOUND"
    } else if fixture_id.starts_with("CI-") || fixture_id.starts_with("EDGE-") {
        "AUTHORITY_OWNED_RESULT_OR_EXPLICIT_UNSUPPORTED"
    } else if fixture_id.starts_with("HF-GRAN-") || fixture_id.starts_with("HF-RESP") {
        "INCIDENT_BRANCH_PHYSICAL_POSTCONDITION"
    } else {
        "KERNEL_OR_PLATFORM_PHYSICAL_EFFECT"
    }
}

fn owner_of(allocations: &BTreeMap<u8, Vec<String>>, fixture_id: &str) -> u8 {
    allocations
        .iter()
        .find_map(|(phase, ids)| ids.iter().any(|id| id == fixture_id).then_some(*phase))
        .unwrap_or(u8::MAX)
}

fn fenced_ids_after(document: &str, heading: &str) -> BTreeSet<String> {
    let section = section_after(document, heading);
    let mut in_fence = false;
    let mut result = BTreeSet::new();
    for line in section.lines() {
        if line.starts_with("```text") {
            in_fence = true;
        } else if line.starts_with("```") && in_fence {
            break;
        } else if in_fence && is_fixture_id(line.trim()) {
            result.insert(line.trim().to_owned());
        }
    }
    result
}

fn section_after<'a>(document: &'a str, heading: &str) -> &'a str {
    document
        .find(heading)
        .map_or("", |index| &document[index + heading.len()..])
}

fn backtick_tokens(line: &str) -> impl Iterator<Item = &str> {
    line.split('`').enumerate().filter_map(
        |(index, token)| {
            if index % 2 == 1 {
                Some(token)
            } else {
                None
            }
        },
    )
}

fn is_fixture_id(value: &str) -> bool {
    let Some((prefix, digits)) = value.rsplit_once('-') else {
        return false;
    };
    digits.len() == 3
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && prefix.contains('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_architecture_section(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let first_is_chapter = first
        .parse::<u8>()
        .is_ok_and(|chapter| (1..=37).contains(&chapter));
    let first_is_appendix = value.contains('.') && matches!(first, "A" | "B" | "C" | "D");
    (first_is_chapter || first_is_appendix)
        && parts.all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{ArchitectureClosure, EXPECTED_FIXTURE_COUNT};

    fn spec_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec")
    }

    #[test]
    fn fixture_registry_matches_architecture_master_and_criteria() -> crate::Result<()> {
        let ledger = ArchitectureClosure::new(spec_root()).verify()?;
        assert_eq!(ledger.fixtures.len(), EXPECTED_FIXTURE_COUNT);
        assert_eq!(ledger.invariants.len(), 15);
        assert_eq!(ledger.sections.len(), 170);
        assert!((1..=37).all(|chapter| {
            let prefix = format!("{chapter}.");
            ledger.sections.iter().any(|row| {
                row.section_id == chapter.to_string() || row.section_id.starts_with(&prefix)
            })
        }));
        assert!((1..=16).all(|appendix| {
            let prefix = format!("A.{appendix}");
            ledger.sections.iter().any(|row| {
                row.section_id == prefix
                    || row
                        .section_id
                        .strip_prefix(&prefix)
                        .is_some_and(|suffix| suffix.starts_with('.'))
            })
        }));
        assert!(ledger.durable_owners.len() >= 15);
        assert!(ledger.fixtures.iter().all(
            |fixture| fixture.owning_phase != u8::MAX && !fixture.criterion_numbers.is_empty()
        ));
        assert!(ledger
            .invariants
            .iter()
            .all(|invariant| !invariant.physical_oracle.is_empty()));
        Ok(())
    }
}
