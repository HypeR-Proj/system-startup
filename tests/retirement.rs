// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::retirement_blocker;
use hyper_os::{Error, Status, task::ProcessPhase};

const PROVIDERS: [Option<usize>; 3] = [Some(0), Some(1), Some(2)];

#[test]
fn confirmed_provider_replacements_do_not_block_retirement() {
    let result = retirement_blocker(3, &PROVIDERS, |_| {
        panic!("confirmed provider must not be inspected as an unreplaced service")
    });
    assert_eq!(result.ok(), Some(None));
}

#[test]
fn custom_core_service_must_not_be_stopped_with_its_bootstrap_group() {
    for phase in [
        ProcessPhase::Prepared,
        ProcessPhase::Created,
        ProcessPhase::Running,
        ProcessPhase::Stopping,
    ] {
        for critical in [false, true] {
            let result = retirement_blocker(4, &PROVIDERS, |index| {
                assert_eq!(index, 3);
                Ok(Some((critical, phase)))
            });
            assert_eq!(result.ok(), Some(Some(3)), "{phase:?}, {critical}");
        }
    }
}

#[test]
fn completed_one_shot_can_retire_but_critical_exit_must_remain_supervised() {
    for phase in [
        ProcessPhase::Stopped,
        ProcessPhase::Retiring,
        ProcessPhase::Retired,
    ] {
        let optional = retirement_blocker(4, &PROVIDERS, |_| Ok(Some((false, phase))));
        assert_eq!(optional.ok(), Some(None), "{phase:?}");
        let critical = retirement_blocker(4, &PROVIDERS, |_| Ok(Some((true, phase))));
        assert_eq!(critical.ok(), Some(Some(3)), "{phase:?}");
    }
}

#[test]
fn absent_optional_owners_do_not_hide_a_later_live_core_service() {
    let result = retirement_blocker(6, &PROVIDERS, |index| match index {
        3 => Ok(None),
        4 => Ok(Some((false, ProcessPhase::Retired))),
        5 => Ok(Some((false, ProcessPhase::Running))),
        _ => Err(Error::InvalidResponse),
    });
    assert_eq!(result.ok(), Some(Some(5)));
}

#[test]
fn failed_inspection_does_not_authorize_retirement() {
    let result = retirement_blocker(4, &PROVIDERS, |_| Err(Error::Status(Status::IO_ERROR)));
    assert!(matches!(result, Err(Error::Status(Status::IO_ERROR))));
}
