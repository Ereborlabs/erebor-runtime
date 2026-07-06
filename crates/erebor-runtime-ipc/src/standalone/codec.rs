pub(super) const PROTOCOL_VERSION: u32 = 1;

pub(super) fn write_varint_field(output: &mut Vec<u8>, field_number: u64, value: u64) {
    write_varint(output, field_number << 3);
    write_varint(output, value);
}

pub(super) fn write_string_field(output: &mut Vec<u8>, field_number: u64, value: &str) {
    write_bytes_field(output, field_number, value.as_bytes());
}

pub(super) fn write_bytes_field(output: &mut Vec<u8>, field_number: u64, value: &[u8]) {
    write_varint(output, (field_number << 3) | 2);
    write_varint(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn write_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

pub(super) fn read_varint(bytes: &[u8], cursor: &mut usize) -> Result<u64, String> {
    let mut shift = 0;
    let mut value = 0_u64;
    loop {
        if *cursor >= bytes.len() {
            return Err(String::from("unexpected end of protobuf varint"));
        }
        let byte = bytes[*cursor];
        *cursor += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            return Err(String::from("protobuf varint is too large"));
        }
    }
}

pub(super) fn read_string(bytes: &[u8], cursor: &mut usize) -> Result<String, String> {
    let value = read_bytes(bytes, cursor)?;
    String::from_utf8(value).map_err(|error| format!("protobuf string is not UTF-8: {error}"))
}

pub(super) fn read_bytes(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, String> {
    let len = read_varint(bytes, cursor)? as usize;
    if bytes.len().saturating_sub(*cursor) < len {
        return Err(String::from("unexpected end of protobuf bytes field"));
    }
    let value = bytes[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(value)
}

pub(super) fn skip_field(bytes: &[u8], cursor: &mut usize, wire: u64) -> Result<(), String> {
    match wire {
        0 => {
            let _value = read_varint(bytes, cursor)?;
            Ok(())
        }
        2 => {
            let len = read_varint(bytes, cursor)? as usize;
            if bytes.len().saturating_sub(*cursor) < len {
                return Err(String::from("unexpected end of protobuf field"));
            }
            *cursor += len;
            Ok(())
        }
        _ => Err(format!("unsupported protobuf wire type {wire}")),
    }
}
