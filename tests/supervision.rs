// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

extern crate std;

use super::{SupportError, validate};
use crate::manifest::parse;

fn manifest(critical: &str, restart: &str) -> std::string::String {
    std::format!(
        r#"{{"format":"hyper.service-manifest","services":[
          {{"name":"first","image":"/svc/first","critical":{critical},"restart":"{restart}","after":[],"capabilities":[]}},
          {{"name":"second","image":"/svc/second","critical":false,"restart":"never","after":[],"capabilities":[]}}
        ]}}"#
    )
}

#[test]
fn accepts_one_or_more_nonrestartable_critical_services() {
    let text = manifest("true", "never");
    let parsed = parse(&text);
    assert!(parsed.is_ok());
    let Ok(parsed) = parsed else {
        return;
    };
    assert_eq!(validate(&parsed), Ok(()));
    let text = text.replace(
        "\"name\":\"second\",\"image\":\"/svc/second\",\"critical\":false",
        "\"name\":\"second\",\"image\":\"/svc/second\",\"critical\":true",
    );
    let parsed = parse(&text);
    assert!(parsed.is_ok());
    let Ok(parsed) = parsed else {
        return;
    };
    assert_eq!(validate(&parsed), Ok(()));
}

#[test]
fn rejects_polling_or_ambiguous_supervision_graphs() {
    for (critical, restart, expected) in [
        ("false", "never", SupportError::MissingCriticalService),
        ("true", "always", SupportError::RestartPolicy),
    ] {
        let text = manifest(critical, restart);
        let parsed = parse(&text);
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else {
            continue;
        };
        assert_eq!(validate(&parsed), Err(expected));
    }
}

#[test]
fn availability_errors_do_not_hide_invalid_capabilities_or_protocols() {
    use hyper_os::{Error, Status};
    for status in [
        Status::NOT_FOUND,
        Status::NOT_DIRECTORY,
        Status::IS_DIRECTORY,
        Status::SYMLINK_LOOP,
        Status::ACCESS_DENIED,
        Status::IO_ERROR,
        Status::NO_MEMORY,
        Status::RESOURCE_LIMIT,
        Status::TIMED_OUT,
    ] {
        assert!(super::service_unavailable(&Error::Status(status)));
    }
    for error in [
        Error::Status(Status::INVALID_ARGUMENT),
        Error::Status(Status::NOT_SUPPORTED),
        Error::Status(Status::BAD_HANDLE),
        Error::Status(Status::BAD_STATE),
        Error::Status(Status::INTERNAL),
        Error::InvalidResponse,
        Error::InvalidWaitSet,
        Error::InvalidProcessName,
        Error::MissingHandle,
        Error::InvalidCapabilityDisposition,
    ] {
        assert!(!super::service_unavailable(&error), "{error:?}");
    }
}

#[test]
fn malformed_image_statuses_are_local_to_the_seal_boundary() {
    use hyper_os::{Error, Status};
    for status in [Status::INVALID_ARGUMENT, Status::NOT_SUPPORTED] {
        let error = Error::Status(status);
        assert!(super::service_image_unavailable(&error));
        assert!(!super::service_unavailable(&error));
    }
    for error in [
        Error::Status(Status::BAD_HANDLE),
        Error::Status(Status::INTERNAL),
        Error::InvalidResponse,
        Error::InvalidProcessArgument,
    ] {
        assert!(!super::service_image_unavailable(&error));
    }
}

#[test]
fn builder_setter_degradation_is_limited_to_resource_exhaustion() {
    use hyper_os::{Error, Status};
    for status in [Status::NO_MEMORY, Status::RESOURCE_LIMIT] {
        assert!(super::service_resources_unavailable(&Error::Status(status)));
    }
    for status in [
        Status::BAD_HANDLE,
        Status::INVALID_ARGUMENT,
        Status::ACCESS_DENIED,
        Status::BAD_STATE,
        Status::INTERNAL,
        Status::NOT_SUPPORTED,
    ] {
        assert!(!super::service_resources_unavailable(&Error::Status(
            status
        )));
    }
}
