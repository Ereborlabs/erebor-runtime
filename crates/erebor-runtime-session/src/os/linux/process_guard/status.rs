use std::os::raw::c_int;

pub(super) fn wait_exited(status: c_int) -> bool {
    status & 0x7f == 0
}

pub(super) fn wait_exit_status(status: c_int) -> c_int {
    (status >> 8) & 0xff
}

pub(super) fn wait_signaled(status: c_int) -> bool {
    let term_signal = status & 0x7f;
    term_signal != 0 && term_signal != 0x7f
}

pub(super) fn wait_term_signal(status: c_int) -> c_int {
    status & 0x7f
}

pub(super) fn wait_stopped(status: c_int) -> bool {
    status & 0xff == 0x7f
}

pub(super) fn wait_stop_signal(status: c_int) -> c_int {
    (status >> 8) & 0xff
}

pub(super) fn ptrace_event(status: c_int) -> u32 {
    (status as u32) >> 16
}

#[cfg(test)]
mod tests {
    use super::{
        ptrace_event, wait_exit_status, wait_exited, wait_signaled, wait_stop_signal, wait_stopped,
        wait_term_signal,
    };
    use crate::sys::{PTRACE_EVENT_CLONE, SIGTRAP};

    #[test]
    fn wait_status_helpers_do_not_treat_stops_as_signals() {
        let stopped = (SIGTRAP << 8) | 0x7f;

        assert!(wait_stopped(stopped));
        assert!(!wait_signaled(stopped));
        assert!(!wait_exited(stopped));
        assert_eq!(wait_stop_signal(stopped), SIGTRAP);
    }

    #[test]
    fn wait_status_helpers_decode_exit_and_signal_statuses() {
        let exited = 42 << 8;
        let signaled = 9;

        assert!(wait_exited(exited));
        assert_eq!(wait_exit_status(exited), 42);
        assert!(wait_signaled(signaled));
        assert_eq!(wait_term_signal(signaled), 9);
    }

    #[test]
    fn ptrace_event_decodes_high_status_bits() {
        let status = (PTRACE_EVENT_CLONE as i32) << 16;

        assert_eq!(ptrace_event(status), PTRACE_EVENT_CLONE);
    }
}
