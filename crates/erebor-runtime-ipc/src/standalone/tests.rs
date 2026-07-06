mod decision;
mod envelope;
mod request;

use prost::Message;

pub(crate) fn decode_prost<T>(bytes: &[u8]) -> Result<T, String>
where
    T: Message + Default,
{
    T::decode(bytes).map_err(|error| error.to_string())
}
