// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

extern crate std;

use hyper_os::task::{ProcessInfo, ProcessPhase, ProcessTermination};
use std::string::String;
use std::vec::Vec;

use super::write_process_termination;

fn render(terminal: Option<ProcessTermination>) -> String {
    let mut bytes = Vec::new();
    write_process_termination(
        ProcessInfo {
            phase: ProcessPhase::Stopped,
            terminal,
        },
        |fragment| bytes.extend_from_slice(fragment),
    );
    String::from_utf8(bytes).unwrap_or_default()
}

#[test]
fn renders_exit_statuses_without_losing_sign_or_range() {
    assert_eq!(
        render(Some(ProcessTermination::ThreadExited { status: 0 })),
        "reason=thread-exited status=0"
    );
    assert_eq!(
        render(Some(ProcessTermination::ProcessExited { status: i64::MIN })),
        "reason=process-exited status=-9223372036854775808"
    );
    assert_eq!(
        render(Some(ProcessTermination::LastThreadExited {
            status: i64::MAX,
        })),
        "reason=last-thread-exited status=9223372036854775807"
    );
}

#[test]
fn renders_non_exit_reasons_and_missing_terminal_detail() {
    assert_eq!(
        render(Some(ProcessTermination::Requested)),
        "reason=requested"
    );
    assert_eq!(
        render(Some(ProcessTermination::Fault {
            class: u32::MAX,
            code: u64::MAX,
        })),
        "reason=fault class=4294967295 code=18446744073709551615"
    );
    assert_eq!(
        render(Some(ProcessTermination::TaskGroupStop {
            generation: u64::MAX,
        })),
        "reason=task-group-stop generation=18446744073709551615"
    );
    assert_eq!(render(None), "reason=unavailable");
}
