// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Capability-plan admission and launch-error classification.
//! Component lifecycle and restart policy belong to component-manager.

use crate::manifest::{Manifest, RestartPolicy};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportError {
    RestartPolicy,
    MissingCriticalService,
}

/// Expected image/configuration availability failures. Invalid capabilities,
/// local arguments and kernel/protocol failures remain fatal to bootstrap.
#[must_use]
pub fn service_unavailable(error: &hyper_os::Error) -> bool {
    matches!(
        error,
        hyper_os::Error::Status(
            hyper_os::Status::NOT_FOUND
                | hyper_os::Status::NOT_DIRECTORY
                | hyper_os::Status::IS_DIRECTORY
                | hyper_os::Status::SYMLINK_LOOP
                | hyper_os::Status::ACCESS_DENIED
                | hyper_os::Status::IO_ERROR
                | hyper_os::Status::NO_MEMORY
                | hyper_os::Status::RESOURCE_LIMIT
                | hyper_os::Status::TIMED_OUT
        )
    )
}

/// Loader admission and application loading follow a validated
/// name, argv and capability plan. The loader reports malformed/unsupported
/// ELF using these statuses; they are not availability errors at other calls.
#[must_use]
pub fn service_image_unavailable(error: &hyper_os::Error) -> bool {
    service_unavailable(error)
        || matches!(
            error,
            hyper_os::Error::Status(
                hyper_os::Status::INVALID_ARGUMENT | hyper_os::Status::NOT_SUPPORTED
            )
        )
}

/// A well-formed builder setter can still exhaust memory or its sponsor quota.
/// Unlike image/path admission, its other errors indicate a broken contract.
#[must_use]
pub fn service_resources_unavailable(error: &hyper_os::Error) -> bool {
    matches!(
        error,
        hyper_os::Error::Status(hyper_os::Status::NO_MEMORY | hyper_os::Status::RESOURCE_LIMIT)
    )
}

/// The internal launch projection has no restart policy of its own.
/// Bootstrap inventories retain their critical-service admission invariant.
pub fn validate(manifest: &Manifest<'_>) -> Result<(), SupportError> {
    if manifest
        .services()
        .any(|service| service.restart() != RestartPolicy::Never)
    {
        return Err(SupportError::RestartPolicy);
    }
    if !manifest.services().any(|service| service.critical()) {
        return Err(SupportError::MissingCriticalService);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/supervision.rs"]
mod tests;
