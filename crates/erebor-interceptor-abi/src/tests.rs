use std::error::Error;
use std::fs;
use std::process::Command;

use crate::{
    BindingLifecycleStateV1, EffectDecisionKeyV1, PhysicalDecisionKindV1, PhysicalDecisionV1,
    ABI_LAYOUTS_V1, C_HEADER_V1,
};

#[test]
fn generated_c_header_compiles_with_every_layout_assertion() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let header = directory.path().join("erebor_interceptor_abi_v1.h");
    let source = directory.path().join("layout.c");
    let object = directory.path().join("layout.o");
    fs::write(&header, C_HEADER_V1)?;
    fs::write(
        &source,
        "#include \"erebor_interceptor_abi_v1.h\"\nint main(void) { return 0; }\n",
    )?;
    let output = Command::new("clang")
        .args(["-std=c11", "-Werror", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()?;
    assert!(
        output.status.success(),
        "generated C layout failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!ABI_LAYOUTS_V1.is_empty());
    for layout in ABI_LAYOUTS_V1 {
        assert!(C_HEADER_V1.contains(layout.name));
    }
    Ok(())
}

#[test]
fn decision_set_golden_bytes_are_stable() {
    let key = EffectDecisionKeyV1 {
        profile_generation_ref_id: 0x0102_0304_0506_0708,
        active_role_id: 0x1112_1314,
        entry_kind: 0x2122,
        effect_family: 0x3132,
        operation: 0x4142,
        composite_atom_id: 0x5152_5354_5556_5758,
        exact_object_key_id: 0x6162_6364_6566_6768,
        process_state_vector_id: 0x7172_7374,
        binding_lifecycle_state: BindingLifecycleStateV1::ACTIVE,
    };
    let decision = PhysicalDecisionV1 {
        decision: PhysicalDecisionKindV1::DENY,
        errno: -13,
        evidence_class_id: 0x8182_8384,
        transition_id: 0x9192_9394,
        exception_numeric_handle: 0xa1a2_a3a4,
    };
    let mut bytes = key.encode_map_bytes();
    bytes.extend(decision.encode_map_bytes());
    assert_eq!(
        hex(&bytes),
        include_str!("../golden/decision-set-v1.hex").trim()
    );
}

#[test]
fn unknown_abi_enum_values_are_never_known() {
    assert!(BindingLifecycleStateV1::ACTIVE.is_known());
    assert!(!BindingLifecycleStateV1(255).is_known());
    assert!(PhysicalDecisionKindV1::DENY.is_known());
    assert!(!PhysicalDecisionKindV1(255).is_known());
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}
