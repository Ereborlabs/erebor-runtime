use std::os::raw::c_long;

use super::{
    sys::{LinuxSys, Pid},
    MAX_ARGV,
};

pub(super) fn read_argv(pid: Pid, argv_address: u64) -> Vec<String> {
    if argv_address == 0 {
        return Vec::new();
    }

    let mut argv = Vec::new();
    for index in 0..MAX_ARGV {
        let pointer_address = argv_address + (index * std::mem::size_of::<u64>()) as u64;
        let Some(pointer) = read_pointer(pid, pointer_address) else {
            break;
        };
        if pointer == 0 {
            break;
        }
        let argument = read_cstring(pid, pointer, 256);
        if argument.is_empty() {
            break;
        }
        argv.push(argument);
    }
    argv
}

pub(super) fn read_pointer(pid: Pid, address: u64) -> Option<u64> {
    ptrace_peek(pid, address).map(|value| value as u64)
}

pub(super) fn read_cstring(pid: Pid, address: u64, size: usize) -> String {
    if address == 0 || size == 0 {
        return String::new();
    }

    let mut bytes = Vec::new();
    let word_size = std::mem::size_of::<c_long>();
    while bytes.len() + 1 < size {
        let Some(word) = ptrace_peek(pid, address + bytes.len() as u64) else {
            break;
        };
        for byte in word.to_ne_bytes() {
            if bytes.len() + 1 >= size {
                break;
            }
            if byte == 0 {
                return String::from_utf8_lossy(&bytes).to_string();
            }
            bytes.push(byte);
        }
        if word_size == 0 {
            break;
        }
    }

    String::from_utf8_lossy(&bytes).to_string()
}

fn ptrace_peek(pid: Pid, address: u64) -> Option<c_long> {
    LinuxSys::peek_data(pid, address)
}
