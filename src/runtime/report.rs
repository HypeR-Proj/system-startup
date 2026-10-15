// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Coordinator diagnostics use its journal-bound stderr, including early buffered output.

use crate::diagnostics::write_process_termination;
use hyper_os::handle::{ConsoleObject, OwnedHandle, ProcessObject};
use std::io::Write;

pub(super) fn report_service_termination(
    _output: &OwnedHandle<ConsoleObject>,
    service: &str,
    critical: bool,
    supervisor: &OwnedHandle<ProcessObject>,
) {
    let mut console = std::io::stderr();
    if critical {
        let _ = console.write_all(b"HypeR system-startup: critical service '");
    } else {
        let _ = console.write_all(b"HypeR system-startup: service '");
    }
    let _ = console.write_all(service.as_bytes());
    let _ = console.write_all(b"' terminated: ");
    match supervisor.as_process_supervisor().info() {
        Ok(info) => {
            write_process_termination(info, |fragment| {
                let _ = console.write_all(fragment);
            });
        }
        Err(_) => {
            let _ = console.write_all(b"process-info-unavailable");
        }
    }
    let _ = console.write_all(b"\n");
}

pub(super) fn report_fleet_configured(_output: &OwnedHandle<ConsoleObject>) {
    eprintln!("HypeR system-startup: VM fleet configured");
}

pub(super) fn report_fleet_unavailable(_output: &OwnedHandle<ConsoleObject>) {
    eprintln!(
        "HypeR system-startup: VM fleet configuration unavailable; Native services remain available"
    );
}
