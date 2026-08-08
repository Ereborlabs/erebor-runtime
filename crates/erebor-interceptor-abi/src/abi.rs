use core::mem::{offset_of, size_of};

use crate::{EffectDecisionKeyV1, Id128, PhysicalDecisionV1};

#[cfg(target_endian = "big")]
compile_error!("Erebor Interceptor ABI Version 1 is qualified only for little-endian targets");

impl Id128 {
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }
}

impl EffectDecisionKeyV1 {
    #[must_use]
    pub fn encode_map_bytes(&self) -> Vec<u8> {
        let mut output = vec![0; size_of::<Self>()];
        write_u64(
            &mut output,
            offset_of!(Self, profile_generation_ref_id),
            self.profile_generation_ref_id,
        );
        write_u32(
            &mut output,
            offset_of!(Self, active_role_id),
            self.active_role_id,
        );
        write_u16(&mut output, offset_of!(Self, entry_kind), self.entry_kind);
        write_u16(
            &mut output,
            offset_of!(Self, effect_family),
            self.effect_family,
        );
        write_u16(&mut output, offset_of!(Self, operation), self.operation);
        write_u64(
            &mut output,
            offset_of!(Self, composite_atom_id),
            self.composite_atom_id,
        );
        write_u64(
            &mut output,
            offset_of!(Self, exact_object_key_id),
            self.exact_object_key_id,
        );
        write_u32(
            &mut output,
            offset_of!(Self, process_state_vector_id),
            self.process_state_vector_id,
        );
        output[offset_of!(Self, binding_lifecycle_state)] = self.binding_lifecycle_state.0;
        output
    }
}

impl PhysicalDecisionV1 {
    #[must_use]
    pub fn encode_map_bytes(&self) -> Vec<u8> {
        let mut output = vec![0; size_of::<Self>()];
        output[offset_of!(Self, decision)] = self.decision.0;
        write_i16(&mut output, offset_of!(Self, errno), self.errno);
        write_u32(
            &mut output,
            offset_of!(Self, evidence_class_id),
            self.evidence_class_id,
        );
        write_u32(
            &mut output,
            offset_of!(Self, transition_id),
            self.transition_id,
        );
        write_u32(
            &mut output,
            offset_of!(Self, exception_numeric_handle),
            self.exception_numeric_handle,
        );
        output
    }
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + size_of::<u16>()].copy_from_slice(&value.to_le_bytes());
}

fn write_i16(output: &mut [u8], offset: usize, value: i16) {
    output[offset..offset + size_of::<i16>()].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
}
