use arrow_data::{layout, ArrayData};

use crate::{Error, ErrorCode, Result};

pub(super) struct ArrayBudget {
    pub(super) scratch: usize,
}

impl ArrayBudget {
    pub(super) fn new(arrays: &[ArrayData], limit: u64) -> Result<Self> {
        let mut pending = arrays.iter().collect::<Vec<_>>();
        let mut bytes = 0_u64;
        let mut scratch = 0_usize;
        while let Some(array) = pending.pop() {
            for buffer in array.buffers() {
                bytes = bytes.saturating_add(buffer.len() as u64);
            }
            // A nullable parent can require a temporary child validity buffer.
            bytes = bytes.saturating_add((array.len() as u64).div_ceil(8));
            if bytes > limit {
                return Err(Error::contract(ErrorCode::Limit, "decoded dataset"));
            }
            if array.nulls().is_none() && layout(array.data_type()).can_contain_null_mask {
                let bitmap = array.len().div_ceil(8);
                // The IPC writer aligns each buffer to 64 bytes.
                let padded = bitmap
                    .checked_add(63)
                    .map(|bytes| bytes & !63)
                    .unwrap_or(usize::MAX);
                scratch = scratch.saturating_add(padded);
            }
            pending.extend(array.child_data());
        }
        Ok(Self { scratch })
    }
}

#[cfg(test)]
mod tests;
