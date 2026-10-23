use arrow_data::{layout, ArrayData};

use crate::{Error, ErrorCode, Result};

pub(super) struct ArrayBudget {
    pub(super) scratch: usize,
}

impl ArrayBudget {
    pub(super) fn new(arrays: &[ArrayData], copy_bytes: Option<usize>) -> Result<Self> {
        let mut pending = arrays.iter().collect::<Vec<_>>();
        let mut bytes = 0_usize;
        let mut scratch = 0_usize;
        while let Some(array) = pending.pop() {
            for buffer in array.buffers() {
                bytes = bytes
                    .checked_add(buffer.len())
                    .ok_or_else(|| Error::contract(ErrorCode::Limit, "decoded dataset"))?;
            }
            // A nullable parent can require a temporary child validity buffer.
            bytes = bytes
                .checked_add(array.len().div_ceil(8))
                .ok_or_else(|| Error::contract(ErrorCode::Limit, "decoded dataset"))?;
            if copy_bytes.is_some_and(|limit| bytes > limit) {
                return Err(Error::contract(ErrorCode::Limit, "decoded dataset"));
            }
            if array.nulls().is_none() && layout(array.data_type()).can_contain_null_mask {
                let bitmap = array.len().div_ceil(8);
                // The IPC writer aligns each buffer to 64 bytes.
                let padded = bitmap
                    .checked_add(63)
                    .map(|bytes| bytes & !63)
                    .ok_or_else(|| Error::contract(ErrorCode::Limit, "encoding scratch"))?;
                scratch = scratch
                    .checked_add(padded)
                    .ok_or_else(|| Error::contract(ErrorCode::Limit, "encoding scratch"))?;
            }
            pending.extend(array.child_data());
        }
        Ok(Self { scratch })
    }
}

#[cfg(test)]
mod tests;
