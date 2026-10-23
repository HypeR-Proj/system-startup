// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

extern crate std;

use std::fmt::Write;
use std::string::String;

use super::{
    AuthorityDeclaration, AuthorityKey, AuthorityPolicy, CapabilityOperation, MAX_MANIFEST_BYTES,
    MAX_SERVICES, ParseErrorKind, StartupPurposeDeclaration, ValidationErrorKind, parse, validate,
};

const VALID: &str = r#"
{
  "format": "hyper.service-manifest",
  "services": [
    {
      "name": "vmm",
      "image": "/svc/vmm",
      "critical": false,
      "restart": "on-failure",
      "after": ["network"],
      "capabilities": [
        {
          "source": "network.primary",
          "purpose": "vmm.network-primary",
          "operation": "duplicate",
          "rights": ["read", "write"]
        }
      ]
    },
    {
      "name": "network",
      "image": "/svc/network-manager",
      "critical": true,
      "restart": "always",
      "after": [],
      "capabilities": []
    },
    {
      "name": "session",
      "image": "/svc/session-manager",
      "critical": true,
      "restart": "on-failure",
      "after": [],
      "capabilities": [
        {
          "source": "bootstrap.console-manager",
          "purpose": "session.console-manager",
          "operation": "create",
          "rights": ["inspect"]
        }
      ]
    }
  ]
}
"#;

#[test]
fn scheduling_configuration_is_parsed_before_following_service_fields() {
    let configured = VALID.replace(
        "\"image\": \"/svc/vmm\",",
        r#""image": "/svc/vmm", "scheduling": {
            "role": "priority", "band": 64,
            "policy": {"kind": "fair", "weight": 16, "quantum_ns": 5000000}
        },"#,
    );
    let parsed = parse(&configured);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else { return };
    let Some(service) = manifest.service(0) else {
        panic!("configured service missing");
    };
    let Some(scheduling) = service.scheduling else {
        panic!("scheduling configuration missing");
    };
    assert_eq!(scheduling.band, 64);
    assert_eq!(
        scheduling.role,
        hyper_component_config::SchedulingRole::Priority
    );
    assert_eq!(
        scheduling.policy,
        hyper_component_config::SchedulingPolicy::Fair {
            weight: 16,
            quantum_ns: 5_000_000,
            backend: hyper_component_config::FairBackend::Default,
        }
    );
    assert_eq!(service.restart(), super::RestartPolicy::OnFailure);
    assert_eq!(
        service.dependencies().collect::<std::vec::Vec<_>>(),
        ["network"]
    );
    assert!(manifest.service(1).is_some());
}

#[test]
fn scheduling_configuration_rejects_invalid_and_duplicate_fields() {
    let valid = r#"{"role":"priority","band":64,"policy":{"kind":"fifo","priority":10}}"#;
    for (field, expected) in [
        (
            format!("\"scheduling\": {valid}, \"scheduling\": {valid},"),
            ParseErrorKind::DuplicateField,
        ),
        (
            String::from(
                r#""scheduling":{"role":"priority","band":64,"policy":{"kind":"fair","weight":0,"quantum_ns":5000000}},"#,
            ),
            ParseErrorKind::InvalidEnum,
        ),
        (
            String::from(
                r#""scheduling":{"role":"priority","band":64,"policy":{"kind":"fifo","priority":10,"unexpected":0}},"#,
            ),
            ParseErrorKind::UnexpectedToken,
        ),
        (
            String::from(
                r#""scheduling":{"role":"priority","band":64,"band":63,"policy":{"kind":"fifo","priority":10}},"#,
            ),
            ParseErrorKind::UnexpectedToken,
        ),
    ] {
        let configured = VALID.replace(
            "\"image\": \"/svc/vmm\",",
            &format!("\"image\": \"/svc/vmm\", {field}"),
        );
        assert_eq!(
            parse(&configured).map_err(|error| error.kind()),
            Err(expected)
        );
    }
}

#[test]
fn service_phases_default_to_boot_and_reject_reverse_dependencies() {
    let parsed = parse(VALID);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else { return };
    assert!(
        manifest
            .services()
            .all(|service| service.phase() == super::ServicePhase::Boot)
    );

    let system_provider = VALID.replace(
        "\"image\": \"/svc/network-manager\",",
        "\"image\": \"/svc/network-manager\", \"phase\": \"system\",",
    );
    let parsed = parse(&system_provider);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else { return };
    assert_eq!(
        validate(&manifest, &Policy).map_err(|error| error.kind()),
        Err(ValidationErrorKind::BootDependsOnSystem)
    );

    let system_consumer = VALID.replace(
        "\"image\": \"/svc/vmm\",",
        "\"image\": \"/svc/vmm\", \"phase\": \"system\",",
    );
    let parsed = parse(&system_consumer);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else { return };
    assert!(validate(&manifest, &Policy).is_ok());
    assert_eq!(
        manifest.service(0).map(super::Service::phase),
        Some(super::ServicePhase::System)
    );
}

#[test]
fn service_phase_is_strict_and_cannot_be_redeclared() {
    for (field, kind) in [
        ("\"phase\": \"later\",", ParseErrorKind::InvalidEnum),
        (
            "\"phase\": \"boot\", \"phase\": \"system\",",
            ParseErrorKind::DuplicateField,
        ),
    ] {
        let source = VALID.replacen(
            "\"critical\": false,",
            &format!("{field} \"critical\": false,"),
            1,
        );
        assert_eq!(parse(&source).map_err(|error| error.kind()), Err(kind));
    }
}

struct Policy;

const READ: u64 = 0b0000_0001;
const WRITE: u64 = 0b0000_0010;
const INSPECT_DETAILS: u64 = 1 << 33;
const INSPECT: u64 = 0b0000_0100;
const WAIT: u64 = 0b0000_1000;
const CREATE_PROCESS: u64 = 0b0001_0000;
const RETAIN_PROCESS: u64 = 1 << 37;
const ATTACH_PROCESS: u64 = 0b0010_0000;
const SPONSOR: u64 = 0b0100_0000;
const DUPLICATE: u64 = 0b1000_0000;
const TRANSFER: u64 = 0b1_0000_0000;
const EXECUTE: u64 = 0b10_0000_0000;
const PROTECT: u64 = 1 << 35;
const SET_ATTRIBUTES: u64 = 1 << 31;
const LOCK_FILE: u64 = 1 << 32;
const CREATE_TASK_GROUP: u64 = 0b1_0000_0000_0000;
const CREATE_RESOURCE_DOMAIN: u64 = 0b10_0000_0000_0000;
const DERIVE: u64 = 0b0100_0000_0000_0000;
const CREATE_VIRTUAL_MACHINE: u64 = 0b1000_0000_0000_0000;
fn test_authority_key(source: &str) -> AuthorityKey {
    let value = source
        .bytes()
        .fold(0_u16, |hash, byte| hash.wrapping_mul(31) ^ u16::from(byte));
    AuthorityKey::new(value)
}

impl AuthorityPolicy for Policy {
    fn authority<'policy>(&'policy self, source: &str) -> Option<AuthorityDeclaration<'policy>> {
        match source {
            "network.primary" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: Some("network"),
                object_kind: 1,
                rights: 0b11,
                movable: true,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.console-manager" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 2,
                rights: 0b100,
                movable: true,
                duplicable: true,
                creatable: true,
            }),
            "bootstrap.console" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 3,
                rights: 0b1011,
                movable: false,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.service-output-channel" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 4,
                rights: WAIT | WRITE | DUPLICATE | TRANSFER,
                movable: false,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.shell-input-channel" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 4,
                rights: WAIT | READ | DUPLICATE | TRANSFER | INSPECT,
                movable: true,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.console-control-server" | "bootstrap.console-log-server" => {
                Some(AuthorityDeclaration {
                    key: test_authority_key(source),
                    provider: None,
                    object_kind: 22,
                    rights: WAIT | READ | WRITE | DUPLICATE | TRANSFER,
                    movable: true,
                    duplicable: false,
                    creatable: false,
                })
            }
            "bootstrap.console-controller" | "bootstrap.console-log-connector" => {
                Some(AuthorityDeclaration {
                    key: test_authority_key(source),
                    provider: None,
                    object_kind: 22,
                    rights: WAIT | READ | WRITE | DUPLICATE | TRANSFER,
                    movable: false,
                    duplicable: true,
                    creatable: false,
                })
            }
            "bootstrap.shell-output-channel" | "bootstrap.shell-error-channel" => {
                Some(AuthorityDeclaration {
                    key: test_authority_key(source),
                    provider: None,
                    object_kind: 4,
                    rights: WAIT | READ | WRITE | DUPLICATE | TRANSFER,
                    movable: true,
                    duplicable: false,
                    creatable: false,
                })
            }
            "bootstrap.root-directory" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 5,
                rights: READ
                    | WRITE
                    | INSPECT
                    | EXECUTE
                    | PROTECT
                    | DUPLICATE
                    | TRANSFER
                    | SET_ATTRIBUTES
                    | LOCK_FILE,
                movable: false,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.environment-directory" | "bootstrap.boot-environment-directory" => {
                Some(AuthorityDeclaration {
                    key: test_authority_key(source),
                    provider: None,
                    object_kind: 5,
                    rights: READ | INSPECT | EXECUTE | PROTECT | DUPLICATE | TRANSFER,
                    movable: false,
                    duplicable: true,
                    creatable: false,
                })
            }
            "bootstrap.child-loader" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 21,
                rights: READ | EXECUTE | DUPLICATE | TRANSFER,
                movable: false,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.dynamic-library-directory" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 5,
                rights: READ | EXECUTE | PROTECT | DUPLICATE | TRANSFER,
                movable: false,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.task-factory" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 6,
                rights: CREATE_TASK_GROUP | CREATE_PROCESS | RETAIN_PROCESS | DUPLICATE | TRANSFER,
                movable: false,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.task-group" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 7,
                rights: ATTACH_PROCESS | DUPLICATE | TRANSFER,
                movable: false,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.resource-domain" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 8,
                rights: 0b10_0000_0000_0000 | 0b100_0000 | 0b1000_0000 | 0b1_0000_0000,
                movable: false,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.task-inspector" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 16,
                rights: 0b1_1000_0100,
                movable: false,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.object-inspector" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 17,
                rights: 0b1_1000_0100 | INSPECT_DETAILS,
                movable: false,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.memory-inspector" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 18,
                rights: 0b1_1000_0100,
                movable: false,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.cpu-inspector" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 19,
                rights: 0b1_1000_0100 | INSPECT_DETAILS | (1 << 31),
                movable: false,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.vm-creation-authority" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 20,
                rights: 0b1100_0000_0000_0000 | 0b1000_0000 | 0b1_0000_0000,
                movable: false,
                duplicable: true,
                creatable: false,
            }),
            "bootstrap.vm-runtime-image" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 21,
                rights: READ | EXECUTE | PROTECT | DUPLICATE | TRANSFER,
                movable: false,
                duplicable: false,
                creatable: true,
            }),
            "bootstrap.vm-provisioning-channel" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 22,
                rights: WAIT | READ | WRITE | TRANSFER,
                movable: true,
                duplicable: false,
                creatable: false,
            }),
            "bootstrap.vm-manager-connection-channel" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 22,
                rights: WAIT | READ | TRANSFER,
                movable: true,
                duplicable: false,
                creatable: false,
            }),
            "bootstrap.vm-client-connection-channel" => Some(AuthorityDeclaration {
                key: test_authority_key(source),
                provider: None,
                object_kind: 22,
                rights: WAIT | READ | WRITE | DUPLICATE | TRANSFER,
                movable: false,
                duplicable: true,
                creatable: false,
            }),
            _ => None,
        }
    }

    fn startup_purpose(&self, image: &str, name: &str) -> Option<StartupPurposeDeclaration> {
        let (value, object_kind, required_rights) = match (image, name) {
            ("/svc/vmm", "vmm.network-primary") => (100, 1, READ | WRITE),
            ("/svc/session-manager", "session.console-manager")
            | ("/svc/session-manager", "session.console-manager-alias") => (100, 2, INSPECT),
            ("/svc/network-manager", "network.console-manager") => (101, 2, INSPECT),
            ("/svc/console-raw", "console.system") => (200, 3, WAIT | READ | WRITE),
            ("/svc/console-raw", "console.control") => (201, 22, WAIT | READ),
            ("/svc/console-raw", "console.logs") => (202, 22, WAIT | READ),
            ("/svc/session-manager", "session.console-controller") => {
                (203, 22, WAIT | WRITE | DUPLICATE | TRANSFER)
            }
            ("/svc/session-manager", "session.log-connector") => {
                (204, 22, WAIT | WRITE | DUPLICATE | TRANSFER)
            }
            ("/svc/session-manager", "process.task-factory") => (
                304,
                6,
                CREATE_PROCESS | CREATE_TASK_GROUP | RETAIN_PROCESS | DUPLICATE | TRANSFER,
            ),
            ("/bin/sh", "stdio.input") => (300, 4, WAIT | READ | DUPLICATE | TRANSFER | INSPECT),
            ("/bin/sh" | "/svc/session-manager" | "/svc/vm-manager", "stdio.output") => {
                (301, 4, WAIT | WRITE | DUPLICATE | TRANSFER)
            }
            ("/bin/sh" | "/svc/session-manager" | "/svc/vm-manager", "stdio.error") => {
                (302, 4, WAIT | WRITE | DUPLICATE | TRANSFER)
            }
            ("/svc/vm-manager", "process.root-directory") => (303, 5, READ | DUPLICATE | TRANSFER),
            ("/bin/sh" | "/svc/session-manager", "process.root-directory") => (
                303,
                5,
                READ | WRITE
                    | INSPECT
                    | DUPLICATE
                    | TRANSFER
                    | EXECUTE
                    | PROTECT
                    | SET_ATTRIBUTES
                    | LOCK_FILE,
            ),
            ("/bin/sh", "process.task-factory") => (304, 6, CREATE_PROCESS | DUPLICATE | TRANSFER),
            ("/bin/sh" | "/svc/session-manager", "process.task-group") => {
                (305, 7, ATTACH_PROCESS | DUPLICATE | TRANSFER)
            }
            ("/bin/sh" | "/svc/session-manager", "process.resource-domain") => {
                (306, 8, SPONSOR | DUPLICATE | TRANSFER)
            }
            ("/bin/sh" | "/svc/session-manager", "process.task-inspector") => {
                (307, 16, DUPLICATE | TRANSFER | INSPECT)
            }
            ("/bin/sh" | "/svc/session-manager", "process.object-inspector") => {
                (308, 17, DUPLICATE | TRANSFER | INSPECT | INSPECT_DETAILS)
            }
            ("/bin/sh" | "/svc/session-manager", "process.memory-inspector") => {
                (309, 18, DUPLICATE | TRANSFER | INSPECT)
            }
            ("/bin/sh" | "/svc/session-manager", "process.cpu-inspector") => (
                310,
                19,
                DUPLICATE | TRANSFER | INSPECT | INSPECT_DETAILS | (1 << 31),
            ),
            ("/bin/sh" | "/svc/session-manager", "process.environment-directory") => (
                317,
                5,
                READ | INSPECT | EXECUTE | PROTECT | DUPLICATE | TRANSFER,
            ),
            ("/bin/sh" | "/svc/session-manager" | "/svc/vm-manager", "process.child-loader") => {
                (316, 21, READ | EXECUTE | DUPLICATE | TRANSFER)
            }
            ("/bin/sh" | "/svc/session-manager", "process.child-library-directory")
            | ("/svc/vm-manager", "process.child-library-directory") => {
                (315, 5, READ | EXECUTE | PROTECT | DUPLICATE | TRANSFER)
            }
            ("/svc/session-manager", "vm.manager-connection") => (
                hyper_service::vm::MANAGER_CONNECTION.as_raw(),
                22,
                WAIT | WRITE | DUPLICATE | TRANSFER,
            ),
            ("/bin/sh", "vm.manager-connection") => (
                hyper_service::vm::MANAGER_CONNECTION.as_raw(),
                22,
                WAIT | WRITE,
            ),
            ("/svc/vm-manager", "vm.runtime-image") => {
                (312, 21, READ | EXECUTE | PROTECT | DUPLICATE | TRANSFER)
            }
            ("/svc/vm-manager", "vm.provisioning") => {
                (hyper_service::vm::PROVISIONING.as_raw(), 22, WAIT | READ)
            }
            ("/svc/vm-manager", "vm.manager-connection") => (
                hyper_service::vm::MANAGER_CONNECTION.as_raw(),
                22,
                WAIT | READ,
            ),
            ("/svc/vm-manager", "process.task-factory") => {
                (304, 6, CREATE_PROCESS | CREATE_TASK_GROUP | RETAIN_PROCESS)
            }
            ("/svc/vm-manager", "process.resource-domain") => (306, 8, CREATE_RESOURCE_DOMAIN),
            ("/svc/vm-manager", "vm.creation-authority") => {
                (311, 20, DERIVE | CREATE_VIRTUAL_MACHINE)
            }
            _ => return None,
        };
        Some(StartupPurposeDeclaration {
            value,
            object_kind,
            required_rights,
            allowed_rights: required_rights,
        })
    }

    fn right(&self, name: &str) -> Option<u64> {
        match name {
            "read" => Some(READ),
            "write" => Some(WRITE),
            "inspect" => Some(INSPECT),
            "inspect-details" => Some(INSPECT_DETAILS),
            "wait" => Some(WAIT),
            "create-process" => Some(CREATE_PROCESS),
            "retain-process" => Some(RETAIN_PROCESS),
            "attach-process" => Some(ATTACH_PROCESS),
            "sponsor" => Some(SPONSOR),
            "duplicate" => Some(DUPLICATE),
            "transfer" => Some(TRANSFER),
            "execute" => Some(EXECUTE),
            "protect" => Some(PROTECT),
            "set-attributes" => Some(SET_ATTRIBUTES),
            "lock-file" => Some(LOCK_FILE),
            "create-task-group" => Some(CREATE_TASK_GROUP),
            "create-resource-domain" => Some(CREATE_RESOURCE_DOMAIN),
            "derive" => Some(DERIVE),
            "create-virtual-machine" => Some(CREATE_VIRTUAL_MACHINE),
            _ => None,
        }
    }
}

struct CollidingPolicy;

impl AuthorityPolicy for CollidingPolicy {
    fn authority<'policy>(&'policy self, source: &str) -> Option<AuthorityDeclaration<'policy>> {
        let declaration = Policy.authority(source)?;
        Some(AuthorityDeclaration {
            key: AuthorityKey::new(7),
            ..declaration
        })
    }

    fn startup_purpose(&self, image: &str, name: &str) -> Option<StartupPurposeDeclaration> {
        Policy.startup_purpose(image, name)
    }

    fn right(&self, name: &str) -> Option<u64> {
        Policy.right(name)
    }
}

#[test]
fn production_manifest_matches_the_validated_schema() {
    let parsed = parse(include_str!(
        "../../../bootstrap/stage1/init/tests/config/services.json"
    ));
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    let validated = validate(&manifest, &Policy);
    assert!(validated.is_ok());
    let Ok(plan) = validated else {
        return;
    };
    assert_eq!(manifest.service_count(), 3);
    assert_eq!(plan.vm_config_path(), Some("/etc/hyper/vms.json"));
    let shell = manifest
        .services()
        .find(|service| service.name() == "session-manager");
    assert_eq!(
        shell.map(|service| service.capabilities().count()),
        Some(16)
    );
}

#[test]
fn rejects_a_noncanonical_vm_config_path() {
    let text = include_str!("../../../bootstrap/stage1/init/tests/config/services.json")
        .replace("/etc/hyper/vms.json", "/etc/../vms.json");
    let parsed = parse(&text);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    assert_eq!(
        validate(&manifest, &Policy).map_err(|error| error.kind()),
        Err(ValidationErrorKind::InvalidVmConfigPath)
    );
}

#[test]
fn production_vm_manager_is_bound_by_its_unique_provisioning_role() {
    let parsed = parse(include_str!(
        "../../../bootstrap/stage1/init/tests/config/services.json"
    ));
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    let validated = validate(&manifest, &Policy);
    assert!(validated.is_ok());
    let Ok(plan) = validated else {
        return;
    };
    let expected = manifest
        .services()
        .enumerate()
        .find_map(|(index, service)| (service.name() == "vm-manager").then_some(index));
    assert_eq!(
        plan.unique_service_for_purpose(hyper_service::vm::PROVISIONING.as_raw()),
        expected
    );
}

#[test]
fn singleton_role_lookup_rejects_an_ambiguous_purpose() {
    let parsed = parse(VALID);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    let validated = validate(&manifest, &Policy);
    assert!(validated.is_ok());
    let Ok(plan) = validated else {
        return;
    };
    assert_eq!(plan.unique_service_for_purpose(100), None);
    assert_eq!(plan.unique_service_for_purpose(0), None);
}

#[test]
fn production_manifest_marks_required_data_plane_services_critical() {
    let parsed = parse(include_str!(
        "../../../bootstrap/stage1/init/tests/config/services.json"
    ));
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    for name in ["console-raw", "session-manager", "vm-manager"] {
        let service = manifest.services().find(|service| service.name() == name);
        assert!(service.is_some_and(|service| service.critical()));
    }
    let shell = manifest
        .services()
        .find(|service| service.name() == "shell");
    assert!(shell.is_none());
}

#[test]
fn process_launchers_receive_a_separate_delegatable_library_capability() {
    let parsed = parse(include_str!(
        "../../../bootstrap/stage1/init/tests/config/services.json"
    ));
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    let validated = validate(&manifest, &Policy);
    assert!(validated.is_ok());
    let Ok(plan) = validated else {
        return;
    };
    let expected = READ | EXECUTE | PROTECT | DUPLICATE | TRANSFER;
    for image in ["/svc/session-manager", "/svc/vm-manager"] {
        let delegated = manifest
            .services()
            .enumerate()
            .find(|(_, service)| service.image() == image)
            .and_then(|(service_index, service)| {
                service
                    .capabilities()
                    .enumerate()
                    .find(|(_, capability)| {
                        capability.source() == "bootstrap.dynamic-library-directory"
                            && capability.purpose() == "process.child-library-directory"
                    })
                    .and_then(|(capability_index, _)| {
                        plan.capability_grant(service_index, capability_index)
                            .map(super::CapabilityGrant::rights)
                    })
            });
        assert_eq!(delegated, Some(expected));
    }
}

#[test]
fn parses_and_plans_a_complete_manifest_before_launch() {
    let parsed = parse(VALID);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    let validated = validate(&manifest, &Policy);
    assert!(validated.is_ok());
    let Ok(plan) = validated else {
        return;
    };
    assert_eq!(manifest.service_count(), 3);
    assert_eq!(plan.service_count(), 3);
    assert_eq!(plan.service_index(0), Some(1));
    assert_eq!(plan.service_index(1), Some(0));
    assert_eq!(plan.service_index(2), Some(2));
    let first = plan.capability_grant(0, 0);
    assert!(first.is_some());
    let Some(first) = first else {
        return;
    };
    assert_eq!(first.rights(), 0b11);
    assert_eq!(first.object_kind(), 1);
    assert_eq!(first.purpose(), 100);
    assert_eq!(first.authority(), test_authority_key("network.primary"));
    assert_eq!(
        plan.capability_grant(2, 0)
            .map(super::CapabilityGrant::object_kind),
        Some(2)
    );
    assert_eq!(
        plan.capability_grant(2, 0)
            .map(super::CapabilityGrant::purpose),
        Some(100)
    );
}

#[test]
fn rejects_authority_key_reuse_for_distinct_sources() {
    let parsed = parse(VALID);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    assert_eq!(
        validate(&manifest, &CollidingPolicy).map_err(|error| error.kind()),
        Err(ValidationErrorKind::ConflictingAuthorityKey)
    );
}

#[test]
fn rejects_unknown_and_duplicate_fields() {
    let unknown = VALID.replace("\"critical\": false", "\"enabled\": false");
    let parsed = parse(&unknown);
    assert!(parsed.is_err());
    let Err(error) = parsed else {
        return;
    };
    assert_eq!(error.kind(), ParseErrorKind::UnknownField);
    assert_eq!(error.offset(), unknown.find("\"enabled\"").unwrap_or(0));

    let duplicate = VALID.replace(
        "\"critical\": false,",
        "\"critical\": false, \"critical\": false,",
    );
    assert_eq!(
        parse(&duplicate).map_err(|error| error.kind()),
        Err(ParseErrorKind::DuplicateField)
    );
}

#[test]
fn rejects_noncanonical_escaped_strings() {
    let escaped = VALID.replace("\"vmm\"", "\"v\\u006d\"");
    assert_eq!(
        parse(&escaped).map_err(|error| error.kind()),
        Err(ParseErrorKind::EscapeNotAllowed)
    );
}

#[test]
fn enforces_manifest_and_service_count_bounds() {
    let oversized = " ".repeat(MAX_MANIFEST_BYTES + 1);
    assert_eq!(
        parse(&oversized).map_err(|error| error.kind()),
        Err(ParseErrorKind::TooLarge)
    );

    let mut many = String::from("{\"format\":\"hyper.service-manifest\",\"services\":[");
    for index in 0..=MAX_SERVICES {
        if index != 0 {
            many.push(',');
        }
        let write_result = write!(
            many,
            "{{\"name\":\"s{index}\",\"image\":\"/svc/s{index}\",\"critical\":false,\"restart\":\"never\",\"after\":[],\"capabilities\":[]}}"
        );
        assert!(write_result.is_ok());
    }
    many.push_str("]}");
    assert_eq!(
        parse(&many).map_err(|error| error.kind()),
        Err(ParseErrorKind::TooManyServices)
    );
}

#[test]
fn rejects_dependency_cycles() {
    let cyclic = r#"{
      "format":"hyper.service-manifest",
      "services":[
        {"name":"a","image":"/svc/a","critical":true,"restart":"never","after":["b"],"capabilities":[]},
        {"name":"b","image":"/svc/b","critical":true,"restart":"never","after":["a"],"capabilities":[]}
      ]
    }"#;
    let parsed = parse(cyclic);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    assert_eq!(
        validate(&manifest, &Policy).map_err(|error| error.kind()),
        Err(ValidationErrorKind::DependencyCycle)
    );
}

#[test]
fn rejects_rights_escalation() {
    let escalated = VALID.replace(
        "\"rights\": [\"inspect\"]",
        "\"rights\": [\"inspect\", \"write\"]",
    );
    let parsed = parse(&escalated);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    assert_eq!(
        validate(&manifest, &Policy).map_err(|error| error.kind()),
        Err(ValidationErrorKind::RightsEscalation)
    );
}

#[test]
fn rejects_rights_below_the_destination_contract() {
    let under_delegated = VALID.replace(
        "\"rights\": [\"read\", \"write\"]",
        "\"rights\": [\"read\"]",
    );
    let parsed = parse(&under_delegated);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    let error = validate(&manifest, &Policy);
    assert_eq!(
        error.map_err(|error| (error.kind(), error.service(), error.capability())),
        Err((ValidationErrorKind::MissingRequiredRights, Some(0), Some(0)))
    );
}

#[test]
fn rejects_rights_above_the_destination_contract() {
    let production = include_str!("../../../bootstrap/stage1/init/tests/config/services.json")
        .split_whitespace()
        .collect::<String>();
    let over_delegated =
        production.replacen("[\"wait\",\"read\"]", "[\"wait\", \"read\", \"write\"]", 1);
    let parsed = parse(&over_delegated);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    assert_eq!(
        validate(&manifest, &Policy).map_err(|error| (
            error.kind(),
            error.service(),
            error.capability()
        )),
        Err((ValidationErrorKind::ExcessPurposeRights, Some(0), Some(1),))
    );
}

#[test]
fn production_launch_contract_rejects_under_delegated_directory_authority() {
    let production = include_str!("../../../bootstrap/stage1/init/tests/config/services.json")
        .split_whitespace()
        .collect::<String>();
    for (under_delegated, service, capability) in [(
        production.replacen(
            "[\"read\",\"duplicate\",\"transfer\",\"execute\",\"protect\",\"write\",\"inspect\",\"set-attributes\",\"lock-file\"]",
            "[\"read\",\"execute\"]",
            1,
        ),
        1,
        2,
    )] {
        assert_ne!(under_delegated, production, "rights fixture must change the manifest");
        let parsed = parse(&under_delegated);
        assert!(parsed.is_ok());
        let Ok(manifest) = parsed else {
            continue;
        };
        assert_eq!(
            validate(&manifest, &Policy).map_err(|error| (
                error.kind(),
                error.service(),
                error.capability()
            )),
            Err((
                ValidationErrorKind::MissingRequiredRights,
                Some(service),
                Some(capability),
            ))
        );
    }
}

#[test]
fn rejects_hidden_provider_dependencies() {
    let hidden = VALID.replace("\"after\": [\"network\"]", "\"after\": []");
    let parsed = parse(&hidden);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    assert_eq!(
        validate(&manifest, &Policy).map_err(|error| error.kind()),
        Err(ValidationErrorKind::MissingProviderDependency)
    );
}

#[test]
fn rejects_one_shot_authority_for_a_restartable_service() {
    let one_shot = VALID.replace("\"operation\": \"create\"", "\"operation\": \"move\"");
    let parsed = parse(&one_shot);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    assert_eq!(
        validate(&manifest, &Policy).map_err(|error| error.kind()),
        Err(ValidationErrorKind::RestartConsumesAuthority)
    );
}

#[test]
fn rejects_reuse_of_a_moved_authority() {
    let repeated = VALID
        .replace(
            "\"capabilities\": []",
            r#""capabilities": [{
          "source":"bootstrap.console-manager",
          "purpose":"network.console-manager",
          "operation":"duplicate",
          "rights":["inspect"]
        }]"#,
        )
        .replace("\"operation\": \"create\"", "\"operation\": \"move\"");
    let parsed = parse(&repeated);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    assert_eq!(
        validate(&manifest, &Policy).map_err(|error| error.kind()),
        Err(ValidationErrorKind::MoveSourceReused)
    );
}

#[test]
fn rejects_invalid_and_duplicate_startup_purposes() {
    let invalid = VALID.replacen(
        "\"purpose\": \"vmm.network-primary\"",
        "\"purpose\": \"0bad\"",
        1,
    );
    let parsed = parse(&invalid);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    assert_eq!(
        validate(&manifest, &Policy).map_err(|error| error.kind()),
        Err(ValidationErrorKind::InvalidPurposeName)
    );

    let duplicate = VALID.replace(
        r#""rights": ["inspect"]"#,
        r#""rights": ["inspect"]
        }, {
          "source": "bootstrap.console-manager",
          "purpose": "session.console-manager-alias",
          "operation": "duplicate",
          "rights": ["inspect"]"#,
    );
    let parsed = parse(&duplicate);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    assert_eq!(
        validate(&manifest, &Policy).map_err(|error| error.kind()),
        Err(ValidationErrorKind::DuplicateCapabilityPurpose)
    );

    let unknown = VALID.replacen(
        "\"purpose\": \"vmm.network-primary\"",
        "\"purpose\": \"vmm.unknown\"",
        1,
    );
    let parsed = parse(&unknown);
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    assert_eq!(
        validate(&manifest, &Policy).map_err(|error| error.kind()),
        Err(ValidationErrorKind::UnknownCapabilityPurpose)
    );
}

#[test]
fn native_service_manifest_does_not_require_a_vm_fleet() {
    let parsed = parse(include_str!(
        "../../../bootstrap/stage1/init/config/services-console-only.json"
    ));
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    let validated = validate(&manifest, &Policy);
    assert!(validated.is_ok());
    let Ok(plan) = validated else {
        return;
    };
    assert_eq!(manifest.service_count(), 2);
    assert_eq!(plan.vm_config_path(), None);
    assert_eq!(
        plan.unique_service_for_purpose(hyper_service::vm::PROVISIONING.as_raw()),
        None
    );
    assert!(manifest.services().all(|service| {
        service
            .capabilities()
            .all(|capability| !capability.source().starts_with("bootstrap.vm-"))
    }));
}

#[test]
fn services_have_output_without_input_or_physical_console_authority() {
    let parsed = parse(include_str!(
        "../../../bootstrap/stage1/init/tests/config/services.json"
    ));
    assert!(parsed.is_ok());
    let Ok(manifest) = parsed else {
        return;
    };
    assert!(validate(&manifest, &Policy).is_ok());
    for name in ["session-manager", "vm-manager"] {
        let service = manifest.services().find(|service| service.name() == name);
        assert!(service.is_some());
        let Some(service) = service else {
            return;
        };
        for purpose in ["stdio.output", "stdio.error"] {
            let output = service
                .capabilities()
                .find(|capability| capability.purpose() == purpose);
            assert!(output.is_some());
            let Some(output) = output else {
                return;
            };
            assert_eq!(output.source(), "bootstrap.service-output-channel");
            assert_eq!(output.operation(), CapabilityOperation::Duplicate);
            assert_eq!(
                output.rights().collect::<Vec<_>>(),
                ["wait", "write", "duplicate", "transfer"]
            );
        }
        assert!(
            !service
                .capabilities()
                .any(|capability| capability.purpose() == "stdio.input"
                    || capability.source() == "bootstrap.console")
        );
    }
    for name in ["console-raw"] {
        let service = manifest.services().find(|service| service.name() == name);
        assert!(service.is_some());
        let Some(service) = service else {
            return;
        };
        assert!(
            !service
                .capabilities()
                .any(|capability| capability.purpose().starts_with("stdio."))
        );
    }
}

#[test]
fn system_manifest_adopts_core_indexes_and_resolves_cross_stage_dependencies() -> Result<(), String>
{
    let boot = r#"{"format":"hyper.service-manifest","services":[{"name":"core","image":"/boot/svc/core","critical":true,"restart":"never","phase":"boot","after":[],"capabilities":[]}]}"#;
    let system = r#"{"format":"hyper.service-manifest","services":[{"name":"policy","image":"/svc/policy","critical":false,"restart":"never","phase":"system","after":["core"],"capabilities":[]}]}"#;
    let boot = parse(boot).map_err(|e| format!("{e:?}"))?;
    let system = parse(system).map_err(|e| format!("{e:?}"))?;
    let combined = boot.append_system(system).ok_or("stage merge rejected")?;
    assert_eq!(combined.service(0).map(|s| s.name()), Some("core"));
    assert_eq!(combined.service(1).map(|s| s.name()), Some("policy"));
    assert!(validate(&combined, &Policy).is_ok());
    Ok(())
}

#[test]
fn system_manifest_cannot_redeclare_boot_services_or_start_before_handoff() -> Result<(), String> {
    let boot = r#"{"format":"hyper.service-manifest","services":[{"name":"core","image":"/boot/svc/core","critical":true,"restart":"never","phase":"boot","after":[],"capabilities":[]}]}"#;
    let parse_boot = || parse(boot).map_err(|e| format!("{e:?}"));
    assert!(parse_boot()?.append_system(parse_boot()?).is_none());
    let system = boot.replace("\"phase\":\"boot\"", "\"phase\":\"system\"");
    let combined = parse_boot()?
        .append_system(parse(&system).map_err(|e| format!("{e:?}"))?)
        .ok_or("stage merge rejected")?;
    assert_eq!(
        validate(&combined, &Policy).map_err(|e| e.kind()),
        Err(ValidationErrorKind::DuplicateServiceName)
    );
    Ok(())
}

#[test]
fn loader_policy_is_explicit_and_independent_of_service_phase() -> Result<(), String> {
    use hyper_service::process::LoaderKind;
    let defaults = parse(VALID).map_err(|e| format!("{e:?}"))?;
    assert!(
        defaults
            .services()
            .all(|service| service.loader() == LoaderKind::Dynamic)
    );
    let boot = VALID.replacen(
        "\"critical\": false,",
        "\"loader\": \"bootstrap\", \"critical\": false,",
        1,
    );
    assert_eq!(
        parse(&boot)
            .map_err(|e| format!("{e:?}"))?
            .service(0)
            .ok_or("missing service")?
            .loader(),
        LoaderKind::Bootstrap
    );
    let invalid = boot.replace("\"loader\": \"bootstrap\"", "\"loader\": \"auto\"");
    assert_eq!(
        parse(&invalid)
            .err()
            .ok_or("accepted unknown loader")?
            .kind(),
        ParseErrorKind::InvalidEnum
    );
    Ok(())
}
