use super::{decode, encode, port, views::*, *};

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct SupportRow {
    record: RecordIdRow,
    proof: ProofRow,
    facts: Vec<ContextKeyRow>,
}

impl From<&UnitSupport> for SupportRow {
    fn from(value: &UnitSupport) -> Self {
        Self {
            record: RecordIdRow::from(&value.record),
            proof: ProofRow::from(&value.proof),
            facts: value.facts.iter().map(ContextKeyRow::from).collect(),
        }
    }
}

impl TryFrom<SupportRow> for UnitSupport {
    type Error = sdk::Error;

    fn try_from(value: SupportRow) -> sdk::Result<Self> {
        Ok(Self {
            record: value.record.try_into()?,
            proof: value.proof.try_into()?,
            facts: value
                .facts
                .into_iter()
                .map(TryInto::try_into)
                .collect::<sdk::Result<_>>()?,
        })
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct UnitRow {
    record: RecordIdRow,
    window_ns: u64,
    restricted: bool,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AffectedRow {
    record: RecordIdRow,
}

impl From<&Unit> for UnitRow {
    fn from(value: &Unit) -> Self {
        Self {
            record: RecordIdRow::from(&value.record),
            window_ns: value.window_ns,
            restricted: value.restricted,
        }
    }
}

impl TryFrom<UnitRow> for Unit {
    type Error = sdk::Error;

    fn try_from(value: UnitRow) -> sdk::Result<Self> {
        Ok(Self {
            record: value.record.try_into()?,
            window_ns: value.window_ns,
            restricted: value.restricted,
        })
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct UnitStateRow {
    state: views::StateRow,
    position: Position,
    fact: Option<ContextKeyRow>,
}

impl From<&UnitState> for UnitStateRow {
    fn from(value: &UnitState) -> Self {
        Self {
            state: views::StateRow::from(&value.state),
            position: value.position,
            fact: value.fact.as_ref().map(ContextKeyRow::from),
        }
    }
}

impl TryFrom<UnitStateRow> for UnitState {
    type Error = sdk::Error;

    fn try_from(value: UnitStateRow) -> sdk::Result<Self> {
        Ok(Self {
            state: value.state.try_into()?,
            position: value.position,
            fact: value.fact.map(TryInto::try_into).transpose()?,
        })
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ContributionRow {
    record: RecordIdRow,
    support: Vec<SupportRow>,
    subjects: Vec<u64>,
    relationships: Vec<u64>,
    findings: Vec<u64>,
    state: Option<UnitStateRow>,
}

impl From<&Contribution> for ContributionRow {
    fn from(value: &Contribution) -> Self {
        Self {
            record: RecordIdRow::from(&value.record),
            support: value.support.iter().map(SupportRow::from).collect(),
            subjects: value.subjects.clone(),
            relationships: value.relationships.clone(),
            findings: value.findings.clone(),
            state: value.state.as_ref().map(UnitStateRow::from),
        }
    }
}

impl TryFrom<ContributionRow> for Contribution {
    type Error = sdk::Error;

    fn try_from(value: ContributionRow) -> sdk::Result<Self> {
        Ok(Self {
            record: value.record.try_into()?,
            support: value
                .support
                .into_iter()
                .map(TryInto::try_into)
                .collect::<sdk::Result<_>>()?,
            subjects: value.subjects,
            relationships: value.relationships,
            findings: value.findings,
            state: value.state.map(TryInto::try_into).transpose()?,
        })
    }
}

impl Unit {
    pub fn affected_port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<AffectedRow>("affected", &PORT)
    }

    pub fn encode_affected(
        rows: &[crate::discovery::DiscoveryRecordIdV1],
    ) -> sdk::Result<sdk::Dataset> {
        encode(Self::affected_port(), rows, |record| AffectedRow {
            record: RecordIdRow::from(record),
        })
    }

    pub fn decode_affected(
        data: &sdk::Dataset,
    ) -> sdk::Result<Vec<crate::discovery::DiscoveryRecordIdV1>> {
        decode::<AffectedRow, _>(Self::affected_port(), data, |row| row.record.try_into())
    }

    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<UnitRow>("units", &PORT)
    }

    pub fn removals_port() -> sdk::Port {
        let mut port = Self::port();
        port.name = "unit_removals".into();
        port
    }

    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, UnitRow::from)
    }

    pub fn encode_removals(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::removals_port(), rows, UnitRow::from)
    }

    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        let port = if data.name == "unit_removals" {
            Self::removals_port()
        } else {
            Self::port()
        };
        decode::<UnitRow, Self>(port, data, TryInto::try_into)
    }
}

impl Contribution {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<ContributionRow>("contributions", &PORT)
    }

    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        if rows.iter().any(|row| {
            row.state.as_ref().is_some_and(|state| {
                matches!(&state.state, GraphPackageStateV1::Declared(value) if value.is_empty())
            })
        }) {
            return Err(invalid("graph native package state"));
        }
        encode(Self::port(), rows, ContributionRow::from)
    }

    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<ContributionRow, Self>(Self::port(), data, TryInto::try_into)
    }
}
