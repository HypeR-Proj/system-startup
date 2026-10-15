// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::cell::Cell;

fn optional_failure(error: LaunchError) -> (Result<FleetConfiguration, LaunchError>, usize) {
    let stopped = Cell::new(0);
    let result = recover_manager_failure(false, error, |_| {
        stopped.set(stopped.get() + 1);
        Ok(())
    });
    (result, stopped.get())
}

#[test]
fn result_pipe_can_close_before_manager_termination_is_observed() {
    let reads = Cell::new(0);
    let result = poll_result(Ok(0), |_| {
        reads.set(reads.get() + 1);
        Err(hyper_os::Error::InvalidResponse)
    });
    assert_eq!(reads.get(), 0);
    assert!(matches!(result, Err(LaunchError::VmFleetReplyClosed)));
    let Err(error) = result else { return };
    let (result, stops) = optional_failure(error);
    assert!(matches!(result, Ok(FleetConfiguration::Unavailable)));
    assert_eq!(stops, 1);

    // The writer can also disappear between readiness and the actual read.
    let result = poll_result(Ok(u64::MAX), |_| {
        Err(hyper_os::Error::Status(hyper_os::Status::PEER_CLOSED))
    });
    assert!(matches!(result, Err(LaunchError::VmFleetReplyClosed)));
}

#[test]
fn queued_reply_is_drained_before_eof_without_stopping_a_valid_manager() {
    // All bits include READABLE and PEER_CLOSED: a final queued reply is valid.
    for (reply, expected) in [
        (
            vm_contract::ProvisionResult::Configured,
            FleetConfiguration::Configured,
        ),
        (
            vm_contract::ProvisionResult::Rejected,
            FleetConfiguration::Unavailable,
        ),
    ] {
        let result = poll_result(Ok(u64::MAX), |buffer| {
            let bytes = reply.encode();
            buffer[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        });
        assert!(matches!(result, Ok(Some(value)) if value == expected));
    }
}

#[test]
fn malformed_or_oversized_manager_results_disable_only_optional_manager() {
    let valid = vm_contract::ProvisionResult::Configured.encode();
    for bytes in [
        vec![],
        valid[..valid.len() - 1].to_vec(),
        vec![0; valid.len()],
    ] {
        let result = poll_result(Ok(u64::MAX), |buffer| {
            buffer[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        });
        assert!(matches!(result, Err(LaunchError::VmFleetReplyInvalid)));
        let Err(error) = result else { continue };
        let (result, stops) = optional_failure(error);
        assert!(matches!(result, Ok(FleetConfiguration::Unavailable)));
        assert_eq!(stops, 1);
    }
    for result in [
        Err(hyper_os::Error::MessageTooLarge {
            bytes: 1024,
            handles: 0,
        }),
        Ok(vm_contract::MESSAGE_BYTES + 1),
    ] {
        assert!(matches!(
            poll_result(Ok(u64::MAX), |_| result),
            Err(LaunchError::VmFleetReplyInvalid)
        ));
    }
}

#[test]
fn readiness_race_retries_but_timeout_withdraws_pending_admission() {
    assert!(matches!(
        poll_result(Ok(u64::MAX), |_| {
            Err(hyper_os::Error::Status(hyper_os::Status::WOULD_BLOCK))
        }),
        Ok(None)
    ));
    let read_called = Cell::new(false);
    let result = poll_result(Err(LaunchError::WaitTimedOut), |_| {
        read_called.set(true);
        Ok(0)
    });
    // A failed supervised wait must never consume a late reply.
    assert!(!read_called.get());
    assert!(matches!(result, Err(LaunchError::WaitTimedOut)));
    let Err(error) = result else { return };
    let (result, stops) = optional_failure(error);
    assert!(matches!(result, Ok(FleetConfiguration::Unavailable)));
    assert_eq!(stops, 1);
}

#[test]
fn critical_manager_and_core_failures_are_never_downgraded() {
    for error in [
        LaunchError::VmProvisioningClosed,
        LaunchError::VmFleetReplyClosed,
        LaunchError::VmFleetReplyInvalid,
        LaunchError::WaitTimedOut,
    ] {
        let stopped = Cell::new(false);
        assert!(
            recover_manager_failure(true, error, |_| {
                stopped.set(true);
                Ok(())
            })
            .is_err()
        );
        assert!(!stopped.get());
    }
    for error in [
        LaunchError::OperatingSystem,
        LaunchError::InvalidPlan,
        LaunchError::UnsupportedAuthority,
    ] {
        let read_called = Cell::new(false);
        let result = poll_result(Err(error), |_| {
            read_called.set(true);
            Ok(0)
        });
        assert!(!read_called.get());
        assert!(result.is_err());
        let Err(error) = result else { return };
        let (result, stops) = optional_failure(error);
        assert!(result.is_err());
        assert_eq!(stops, 0);
    }
    assert!(matches!(
        poll_result(Ok(u64::MAX), |_| {
            Err(hyper_os::Error::Status(hyper_os::Status::BAD_HANDLE))
        }),
        Err(LaunchError::OperatingSystem)
    ));
}

#[test]
fn observed_optional_exit_and_stop_failure_keep_their_own_policy() {
    let read_called = Cell::new(false);
    let result = poll_result(Err(LaunchError::RequiredServiceUnavailable), |_| {
        read_called.set(true);
        Ok(0)
    });
    assert!(!read_called.get());
    assert!(result.is_err());
    let Err(error) = result else { return };
    assert!(matches!(
        optional_failure(error).0,
        Ok(FleetConfiguration::Unavailable)
    ));
    assert!(matches!(
        recover_manager_failure(false, LaunchError::VmFleetReplyInvalid, |_| Err(
            LaunchError::OperatingSystem
        )),
        Err(LaunchError::OperatingSystem)
    ));
}
