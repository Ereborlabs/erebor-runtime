use snafu::{Location, Snafu};

pub type EvidenceModelResult<T> = std::result::Result<T, EvidenceModelError>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum EvidenceModelError {
    #[snafu(display("Mithril evidence model is invalid: {reason}"))]
    Invalid {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
}
