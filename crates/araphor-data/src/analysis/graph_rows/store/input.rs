mod proof;
pub use proof::InputProof;

pub struct ResolvedInput;

impl ResolvedInput {
    pub const EVENTS_SQL: &'static str = include_str!("input/events.sql");

    pub const SQL: &'static str = include_str!("input/resolved.sql");
}
