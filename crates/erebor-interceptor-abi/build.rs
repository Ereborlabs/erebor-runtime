use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

mod authority {
    include!("abi/v1.rs");
}

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=abi/v1.rs");
    let output = PathBuf::from(
        env::var_os("OUT_DIR").ok_or_else(|| std::io::Error::other("Cargo did not set OUT_DIR"))?,
    );
    fs::write(
        output.join("erebor_interceptor_abi_v1.rs"),
        RustGenerator.generate(),
    )?;
    fs::write(
        output.join("erebor_interceptor_abi_v1.h"),
        CGenerator.generate(),
    )?;
    Ok(())
}

struct Layout {
    size: usize,
    alignment: usize,
    offsets: Vec<usize>,
}

impl Layout {
    fn for_struct(spec: &authority::StructSpec) -> Self {
        let mut size = 0;
        let mut alignment = 1;
        let mut offsets = Vec::with_capacity(spec.fields.len());
        for field in spec.fields {
            let (field_size, field_alignment) = type_layout(field.ty);
            alignment = alignment.max(field_alignment);
            size = align_up(size, field_alignment);
            offsets.push(size);
            size += field_size;
        }
        size = align_up(size, alignment);
        Self {
            size,
            alignment,
            offsets,
        }
    }
}

fn align_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

fn type_layout(ty: &str) -> (usize, usize) {
    match ty {
        "u8"
        | "BindingLifecycleStateV1"
        | "PhysicalDecisionKindV1"
        | "NegativeDecisionKindV1"
        | "InstalledStateV1"
        | "MembershipStateV1"
        | "FloorRequirementKindV1"
        | "TransitionKindV1" => (1, 1),
        "u16" | "i16" => (2, 2),
        "u32" => (4, 4),
        "u64" => (8, 8),
        "Id128" => (16, 1),
        unknown => unreachable!("unknown ABI authority type {unknown}"),
    }
}

struct RustGenerator;

impl RustGenerator {
    fn generate(self) -> String {
        let mut output = String::from(
            "// @generated from abi/v1.rs; do not edit.\n\
             #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]\n\
             #[repr(C)]\n\
             pub struct Id128 { pub bytes: [u8; 16] }\n\n",
        );
        for spec in authority::ENUMS {
            let _ = writeln!(
                output,
                "#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]\n#[repr(transparent)]\npub struct {}(pub u8);",
                spec.name
            );
            let _ = writeln!(output, "impl {} {{", spec.name);
            for variant in spec.variants {
                let _ = writeln!(
                    output,
                    "    pub const {}: Self = Self({});",
                    variant.name, variant.value
                );
            }
            let first = spec.variants.first().map_or(0, |variant| variant.value);
            let last = spec.variants.last().map_or(0, |variant| variant.value);
            let comparison = if first == 0 {
                format!("self.0 <= {last}")
            } else {
                format!("self.0 >= {first} && self.0 <= {last}")
            };
            let _ = writeln!(
                output,
                "    #[must_use]\n    pub const fn is_known(self) -> bool {{ {comparison} }}\n}}\n"
            );
        }
        output.push_str(
            "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
             pub struct AbiFieldLayoutV1 { pub name: &'static str, pub offset: usize }\n\n\
             #[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
             pub struct AbiStructLayoutV1 { pub name: &'static str, pub size: usize, pub alignment: usize, pub fields: &'static [AbiFieldLayoutV1] }\n\n",
        );
        for spec in authority::STRUCTS {
            let layout = Layout::for_struct(spec);
            let _ = writeln!(
                output,
                "#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]\n#[repr(C)]\npub struct {} {{",
                spec.name
            );
            for field in spec.fields {
                let _ = writeln!(output, "    pub {}: {},", field.name, field.ty);
            }
            output.push_str("}\n");
            let _ = writeln!(
                output,
                "const _: [(); {}] = [(); core::mem::size_of::<{}>()];\nconst _: [(); {}] = [(); core::mem::align_of::<{}>()];",
                layout.size, spec.name, layout.alignment, spec.name
            );
            for (field, offset) in spec.fields.iter().zip(&layout.offsets) {
                let _ = writeln!(
                    output,
                    "const _: [(); {}] = [(); core::mem::offset_of!({}, {})];",
                    offset, spec.name, field.name
                );
            }
            let _ = writeln!(
                output,
                "const {}_FIELDS: &[AbiFieldLayoutV1] = &[",
                spec.name.to_uppercase()
            );
            for (field, offset) in spec.fields.iter().zip(&layout.offsets) {
                let _ = writeln!(
                    output,
                    "    AbiFieldLayoutV1 {{ name: \"{}\", offset: {} }},",
                    field.name, offset
                );
            }
            output.push_str("];\n\n");
        }
        output.push_str("pub const ABI_LAYOUTS_V1: &[AbiStructLayoutV1] = &[\n");
        for spec in authority::STRUCTS {
            let layout = Layout::for_struct(spec);
            let _ = writeln!(
                output,
                "    AbiStructLayoutV1 {{ name: \"{}\", size: {}, alignment: {}, fields: {}_FIELDS }},",
                spec.name,
                layout.size,
                layout.alignment,
                spec.name.to_uppercase()
            );
        }
        output.push_str("];\n");
        output
    }
}

struct CGenerator;

impl CGenerator {
    fn generate(self) -> String {
        let mut output = String::from(
            "/* @generated from abi/v1.rs; do not edit. */\n\
             #ifndef EREBOR_INTERCEPTOR_ABI_V1_H\n\
             #define EREBOR_INTERCEPTOR_ABI_V1_H\n\
             typedef struct { unsigned char bytes[16]; } Id128;\n\n",
        );
        for spec in authority::ENUMS {
            let _ = writeln!(output, "typedef unsigned char {};", spec.name);
            for variant in spec.variants {
                let _ = writeln!(
                    output,
                    "#define {}_{} (({}){})",
                    screaming_snake(spec.name),
                    variant.name,
                    spec.name,
                    variant.value
                );
            }
            output.push('\n');
        }
        for spec in authority::STRUCTS {
            let layout = Layout::for_struct(spec);
            let _ = writeln!(output, "typedef struct {} {{", spec.name);
            for field in spec.fields {
                let _ = writeln!(output, "    {} {};", c_type(field.ty), field.name);
            }
            let _ = writeln!(output, "}} {};", spec.name);
            let _ = writeln!(
                output,
                "_Static_assert(sizeof({}) == {}, \"{} size\");\n_Static_assert(_Alignof({}) == {}, \"{} alignment\");",
                spec.name, layout.size, spec.name, spec.name, layout.alignment, spec.name
            );
            for (field, offset) in spec.fields.iter().zip(&layout.offsets) {
                let _ = writeln!(
                    output,
                    "_Static_assert(__builtin_offsetof({}, {}) == {}, \"{}.{} offset\");",
                    spec.name, field.name, offset, spec.name, field.name
                );
            }
            output.push('\n');
        }
        output.push_str("#endif\n");
        output
    }
}

fn c_type(ty: &str) -> &str {
    match ty {
        "u8" => "unsigned char",
        "u16" => "unsigned short",
        "i16" => "signed short",
        "u32" => "unsigned int",
        "u64" => "unsigned long long",
        other => other,
    }
}

fn screaming_snake(name: &str) -> String {
    let mut result = String::new();
    for (index, character) in name.chars().enumerate() {
        if character.is_uppercase() && index > 0 {
            result.push('_');
        }
        result.extend(character.to_uppercase());
    }
    result
}
