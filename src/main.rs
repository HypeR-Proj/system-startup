// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Finite bootstrap adoption coordinator entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    let Ok(mut startup) = hyper_rt::process::startup() else {
        return ExitCode::FAILURE;
    };
    match hyper_system_startup::runtime::run_system(&mut startup) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            use std::io::Write;
            let _ = std::io::stderr().write_all(error.diagnostic());
            ExitCode::FAILURE
        }
    }
}
