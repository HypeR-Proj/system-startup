// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Standard integer formatting and rendering of supervised Process termination details.

use hyper_os::task::{ProcessInfo, ProcessTermination};

/// Writes the reason-specific portion of one typed Process lifecycle report.
///
/// The callback receives short borrowed fragments so the coordinator can report
/// predecessor termination through its diagnostic Console.
pub fn write_process_termination(info: ProcessInfo, mut write: impl FnMut(&[u8])) {
    match info.terminal {
        Some(ProcessTermination::Requested) => write(b"reason=requested"),
        Some(ProcessTermination::ThreadExited { status }) => {
            write(b"reason=thread-exited status=");
            write_signed(status, &mut write);
        }
        Some(ProcessTermination::ProcessExited { status }) => {
            write(b"reason=process-exited status=");
            write_signed(status, &mut write);
        }
        Some(ProcessTermination::LastThreadExited { status }) => {
            write(b"reason=last-thread-exited status=");
            write_signed(status, &mut write);
        }
        Some(ProcessTermination::Fault { class, code }) => {
            write(b"reason=fault class=");
            write_unsigned(u64::from(class), &mut write);
            write(b" code=");
            write_unsigned(code, &mut write);
        }
        Some(ProcessTermination::TaskGroupStop { generation }) => {
            write(b"reason=task-group-stop generation=");
            write_unsigned(generation, &mut write);
        }
        None => write(b"reason=unavailable"),
    }
}

fn write_signed(value: i64, write: &mut impl FnMut(&[u8])) {
    write(value.to_string().as_bytes());
}

fn write_unsigned(value: u64, write: &mut impl FnMut(&[u8])) {
    write(value.to_string().as_bytes());
}

#[cfg(test)]
#[path = "../tests/diagnostics.rs"]
mod tests;
