// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Immutable bootstrap authority and service-contract policy.

use crate::manifest::{
    AuthorityDeclaration, AuthorityKey, AuthorityPolicy, Service, ServicePhase,
    StartupPurposeDeclaration,
};
use hyper_os::handle::{
    ByteChannelObject, CapabilityChannelObject, ConsoleObject, CpuInspectorObject,
    DeviceAssignmentAuthorityObject, DirectoryObject, FileObject, MemoryInspectorObject,
    ObjectInspectorObject, ResourceDomainObject, Rights, TaskFactoryObject, TaskGroupObject,
    TaskInspectorObject, TypedObject, VirtualMachineCreationAuthorityObject,
};
use hyper_service::{
    StartupContract, console as console_contract, process as process_contract,
    session as session_contract, stdio as stdio_contract, vm as vm_contract,
};

const CONSOLE_RAW_IMAGE: &str = "/svc/console-raw";
const SESSION_IMAGE: &str = "/svc/session-manager";
const SHELL_IMAGE: &str = "/bin/sh";
const VM_MANAGER_IMAGE: &str = "/svc/vm-manager";
pub const IO_RUNTIME_IMAGE: &str = "/svc/io-runtime";
pub const FS_BACKEND_IMAGE: &str = "/svc/fs-backend";
pub const VM_RUNTIME_IMAGE: &str = "/svc/vm-runtime";

macro_rules! define_bootstrap_authorities {
    ($( $variant:ident = $value:literal => $source:literal ),+ $(,)?) => {
        #[repr(u16)]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum BootstrapAuthority {
            $($variant = $value),+
        }

        impl BootstrapAuthority {
            pub const fn key(self) -> AuthorityKey {
                AuthorityKey::new(self as u16)
            }

            pub fn from_source(source: &str) -> Option<Self> {
                match source {
                    $($source => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub const fn from_key(key: AuthorityKey) -> Option<Self> {
                match key.as_raw() {
                    $($value => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

define_bootstrap_authorities! {
    ComponentObserve = 40 => "component.observe",
    ComponentControl = 41 => "component.control",
    JournalQuery = 42 => "journal.query",
    Console = 1 => "bootstrap.console",
    ConsoleControlServer = 2 => "bootstrap.console-control-server",
    ConsoleController = 3 => "bootstrap.console-controller",
    ConsoleLogServer = 4 => "bootstrap.console-log-server",
    ConsoleLogConnector = 5 => "bootstrap.console-log-connector",
    ChildLoader = 35 => "bootstrap.child-loader",
    EnvironmentDirectory = 36 => "bootstrap.environment-directory",
    BootEnvironmentDirectory = 37 => "bootstrap.boot-environment-directory",
    RootDirectory = 12 => "bootstrap.root-directory",
    DynamicLibraryDirectory = 13 => "bootstrap.dynamic-library-directory",
    TaskFactory = 14 => "bootstrap.task-factory",
    TaskGroup = 15 => "bootstrap.task-group",
    ResourceDomain = 16 => "bootstrap.resource-domain",
    TaskInspector = 17 => "bootstrap.task-inspector",
    ObjectInspector = 18 => "bootstrap.object-inspector",
    MemoryInspector = 19 => "bootstrap.memory-inspector",
    CpuInspector = 20 => "bootstrap.cpu-inspector",
    VmAuthority = 21 => "bootstrap.vm-creation-authority",
    VmRuntimeImage = 22 => "bootstrap.vm-runtime-image",
    VmProvisioningChannel = 23 => "bootstrap.vm-provisioning-channel",
    VmManagerConnectionChannel = 24 => "bootstrap.vm-manager-connection-channel",
    VmClientConnectionChannel = 25 => "bootstrap.vm-client-connection-channel",
    ServiceOutputChannel = 26 => "bootstrap.service-output-channel",
    DeviceAuthority = 27 => "bootstrap.device-assignment-authority",
    IoReadyChannel = 28 => "bootstrap.io-ready-channel",
    IoBrokerServer = 29 => "bootstrap.io-broker-server",
    IoBrokerClient = 30 => "bootstrap.io-broker-client",
    FilesystemAttach = 31 => "bootstrap.filesystem-attach",
    FilesystemProvider = 32 => "bootstrap.filesystem-provider",
    FilesystemControlServer = 33 => "bootstrap.filesystem-control-server",
    FilesystemControlClient = 34 => "bootstrap.filesystem-control-client",
}

/// Stateless policy used to validate a manifest before touching live handles.
pub struct BootstrapPolicy;

impl AuthorityPolicy for BootstrapPolicy {
    fn authority<'policy>(&'policy self, source: &str) -> Option<AuthorityDeclaration<'policy>> {
        let authority = BootstrapAuthority::from_source(source)?;
        Some(match authority {
            BootstrapAuthority::Console => {
                duplicate_authority(authority, ConsoleObject::KIND.as_raw(), console_rights())
            }
            BootstrapAuthority::IoReadyChannel => move_authority(authority),
            BootstrapAuthority::ComponentObserve
            | BootstrapAuthority::ComponentControl
            | BootstrapAuthority::JournalQuery
            | BootstrapAuthority::ConsoleController
            | BootstrapAuthority::ConsoleLogConnector => duplicate_authority(
                authority,
                CapabilityChannelObject::KIND.as_raw(),
                Rights::WAIT
                    .union(Rights::WRITE)
                    .union(Rights::DUPLICATE)
                    .union(Rights::TRANSFER),
            ),
            BootstrapAuthority::ServiceOutputChannel => duplicate_authority(
                authority,
                ByteChannelObject::KIND.as_raw(),
                stdio_contract::STANDARD_OUTPUT_CONTRACT.allowed_rights(),
            ),
            BootstrapAuthority::ChildLoader => duplicate_authority(
                authority,
                FileObject::KIND.as_raw(),
                process_contract::CHILD_LOADER_CONTRACT.allowed_rights(),
            ),
            BootstrapAuthority::EnvironmentDirectory
            | BootstrapAuthority::BootEnvironmentDirectory => duplicate_authority(
                authority,
                DirectoryObject::KIND.as_raw(),
                process_contract::ENVIRONMENT_DIRECTORY_CONTRACT.allowed_rights(),
            ),
            BootstrapAuthority::RootDirectory => duplicate_authority(
                authority,
                DirectoryObject::KIND.as_raw(),
                root_directory_rights(),
            ),
            BootstrapAuthority::DynamicLibraryDirectory => duplicate_authority(
                authority,
                DirectoryObject::KIND.as_raw(),
                library_directory_rights(),
            ),
            BootstrapAuthority::TaskFactory => duplicate_authority(
                authority,
                TaskFactoryObject::KIND.as_raw(),
                task_factory_rights(),
            ),
            BootstrapAuthority::TaskGroup => duplicate_authority(
                authority,
                TaskGroupObject::KIND.as_raw(),
                task_group_rights(),
            ),
            BootstrapAuthority::ResourceDomain => duplicate_authority(
                authority,
                ResourceDomainObject::KIND.as_raw(),
                resource_domain_rights(),
            ),
            BootstrapAuthority::TaskInspector => duplicate_authority(
                authority,
                TaskInspectorObject::KIND.as_raw(),
                inspector_rights(),
            ),
            BootstrapAuthority::ObjectInspector => duplicate_authority(
                authority,
                ObjectInspectorObject::KIND.as_raw(),
                inspector_rights().union(Rights::INSPECT_DETAILS),
            ),
            BootstrapAuthority::MemoryInspector => duplicate_authority(
                authority,
                MemoryInspectorObject::KIND.as_raw(),
                observation_rights(),
            ),
            BootstrapAuthority::CpuInspector => duplicate_authority(
                authority,
                CpuInspectorObject::KIND.as_raw(),
                observation_rights()
                    .union(Rights::SET_ATTRIBUTES)
                    .union(Rights::INSPECT_DETAILS),
            ),
            BootstrapAuthority::VmAuthority => duplicate_authority(
                authority,
                VirtualMachineCreationAuthorityObject::KIND.as_raw(),
                vm_authority_rights(),
            ),
            BootstrapAuthority::DeviceAuthority => duplicate_authority(
                authority,
                DeviceAssignmentAuthorityObject::KIND.as_raw(),
                Rights::ASSIGN_DEVICE
                    .union(Rights::MAP_DMA)
                    .union(Rights::INSPECT)
                    .union(Rights::DUPLICATE)
                    .union(Rights::TRANSFER),
            ),
            BootstrapAuthority::VmRuntimeImage => create_authority(
                authority,
                FileObject::KIND.as_raw(),
                hyper_service::process::EXECUTABLE_FILE_RIGHTS.as_rights(),
            ),
            BootstrapAuthority::ConsoleControlServer
            | BootstrapAuthority::ConsoleLogServer
            | BootstrapAuthority::VmProvisioningChannel
            | BootstrapAuthority::IoBrokerServer
            | BootstrapAuthority::IoBrokerClient
            | BootstrapAuthority::FilesystemAttach
            | BootstrapAuthority::FilesystemProvider
            | BootstrapAuthority::FilesystemControlServer => AuthorityDeclaration {
                key: authority.key(),
                provider: None,
                object_kind: CapabilityChannelObject::KIND.as_raw(),
                rights: Rights::WAIT
                    .union(Rights::READ)
                    .union(Rights::WRITE)
                    .union(Rights::TRANSFER)
                    .bits(),
                movable: true,
                duplicable: false,
                creatable: false,
            },
            BootstrapAuthority::VmManagerConnectionChannel => AuthorityDeclaration {
                key: authority.key(),
                provider: None,
                object_kind: CapabilityChannelObject::KIND.as_raw(),
                rights: Rights::WAIT
                    .union(Rights::READ)
                    .union(Rights::TRANSFER)
                    .bits(),
                movable: true,
                duplicable: false,
                creatable: false,
            },
            BootstrapAuthority::FilesystemControlClient => duplicate_authority(
                authority,
                CapabilityChannelObject::KIND.as_raw(),
                hyper_service::filesystem::DELEGATED_CONTROL_CLIENT_CONTRACT.allowed_rights(),
            ),
            BootstrapAuthority::VmClientConnectionChannel => duplicate_authority(
                authority,
                CapabilityChannelObject::KIND.as_raw(),
                vm_contract::MANAGER_CONNECTION_RIGHTS,
            ),
        })
    }

    fn startup_purpose(&self, image: &str, name: &str) -> Option<StartupPurposeDeclaration> {
        if name == "filesystem.control-client" {
            return Some(contract_declaration(
                hyper_service::filesystem::DELEGATED_CONTROL_CLIENT_CONTRACT,
            ));
        }
        let purpose = match name {
            "component.observe" => Some(hyper_component::OBSERVE.as_raw()),
            "component.control" => Some(hyper_component::CONTROL.as_raw()),
            "journal.query" => Some(hyper_journal::QUERY.as_raw()),
            _ => None,
        };
        if let Some(value) = purpose {
            return Some(StartupPurposeDeclaration {
                value,
                object_kind: CapabilityChannelObject::KIND.as_raw(),
                required_rights: hyper_service_ipc::CLIENT_RIGHTS.bits(),
                allowed_rights: hyper_service_ipc::CLIENT_RIGHTS.bits(),
            });
        }
        // Deployment prefixes do not change a service startup contract.
        let image = image.strip_prefix("/boot").unwrap_or(image);
        let contract = match image {
            CONSOLE_RAW_IMAGE => find_contract(console_contract::STARTUP_CONTRACTS, name),
            SESSION_IMAGE => find_contract(session_contract::STARTUP_CONTRACTS, name)
                .or_else(|| find_contract(stdio_contract::STARTUP_CONTRACTS, name))
                .or_else(|| find_contract(process_contract::SHELL_STARTUP_CONTRACTS, name))
                .or_else(|| find_contract(vm_contract::CLIENT_STARTUP_CONTRACTS, name)),
            SHELL_IMAGE => find_contract(stdio_contract::STARTUP_CONTRACTS, name)
                .or_else(|| find_contract(process_contract::SHELL_STARTUP_CONTRACTS, name))
                .or_else(|| find_contract(vm_contract::CLIENT_STARTUP_CONTRACTS, name)),
            VM_MANAGER_IMAGE => find_contract(vm_contract::MANAGER_STARTUP_CONTRACTS, name)
                .or_else(|| find_contract(stdio_contract::STARTUP_CONTRACTS, name))
                .or_else(|| find_contract(process_contract::VM_MANAGER_STARTUP_CONTRACTS, name)),
            IO_RUNTIME_IMAGE => find_contract(hyper_service::io::STARTUP_CONTRACTS, name)
                .or_else(|| find_contract(stdio_contract::APPLICATION_STARTUP_CONTRACTS, name))
                .or_else(|| find_contract(process_contract::APPLICATION_STARTUP_CONTRACTS, name)),
            FS_BACKEND_IMAGE => {
                find_contract(hyper_service::filesystem::MANAGER_STARTUP_CONTRACTS, name)
                    .or_else(|| find_contract(process_contract::VM_MANAGER_STARTUP_CONTRACTS, name))
                    .or_else(|| find_contract(stdio_contract::APPLICATION_STARTUP_CONTRACTS, name))
                    .or_else(|| {
                        find_contract(process_contract::APPLICATION_STARTUP_CONTRACTS, name)
                    })
            }
            // Ordinary apps use standard contracts without an executable allowlist.
            // The manifest must still explicitly request existing authority; this
            // lookup neither creates handles nor grants service-private roles.
            _ => find_contract(stdio_contract::APPLICATION_STARTUP_CONTRACTS, name)
                .or_else(|| find_contract(process_contract::APPLICATION_STARTUP_CONTRACTS, name)),
        }?;
        Some(contract_declaration(contract))
    }

    fn service_purpose(
        &self,
        service: &Service<'_>,
        name: &str,
    ) -> Option<StartupPurposeDeclaration> {
        if service.phase() == ServicePhase::Boot
            && service.loader() == process_contract::LoaderKind::Bootstrap
            && service
                .image()
                .strip_prefix("/boot")
                .unwrap_or(service.image())
                == FS_BACKEND_IMAGE
            && name == process_contract::TASK_FACTORY_NAME
        {
            // This declaration describes the predecessor running from ramfs.
            // The formal replacement gets its stronger supervisor authority
            // separately in delegate_filesystem_launch during adoption.
            return Some(contract_declaration(StartupContract::exact(
                process_contract::TASK_FACTORY_NAME,
                hyper_os::startup::TASK_FACTORY,
                Rights::CREATE_PROCESS.union(Rights::CREATE_TASK_GROUP),
            )));
        }
        self.startup_purpose(service.image(), name)
    }

    fn right(&self, name: &str) -> Option<u64> {
        match name {
            "duplicate" => Some(Rights::DUPLICATE.bits()),
            "transfer" => Some(Rights::TRANSFER.bits()),
            "wait" => Some(Rights::WAIT.bits()),
            "inspect" => Some(Rights::INSPECT.bits()),
            "inspect-details" => Some(Rights::INSPECT_DETAILS.bits()),
            "read" => Some(Rights::READ.bits()),
            "write" => Some(Rights::WRITE.bits()),
            "assign-device" => Some(Rights::ASSIGN_DEVICE.bits()),
            "map-dma" => Some(Rights::MAP_DMA.bits()),
            "execute" => Some(Rights::EXECUTE.bits()),
            "protect" => Some(Rights::PROTECT.bits()),
            "set-attributes" => Some(Rights::SET_ATTRIBUTES.bits()),
            "lock-file" => Some(Rights::LOCK_FILE.bits()),
            "create-process" => Some(Rights::CREATE_PROCESS.bits()),
            "retain-process" => Some(Rights::RETAIN_PROCESS.bits()),
            "create-task-group" => Some(Rights::CREATE_TASK_GROUP.bits()),
            "create-resource-domain" => Some(Rights::CREATE_RESOURCE_DOMAIN.bits()),
            "create-virtual-machine" => Some(Rights::CREATE_VIRTUAL_MACHINE.bits()),
            "attach-process" => Some(Rights::TASK_GROUP_ATTACH_PROCESS.bits()),
            "sponsor" => Some(Rights::RESOURCE_DOMAIN_SPONSOR.bits()),
            "derive" => Some(Rights::DERIVE.bits()),
            _ => None,
        }
    }
}

fn find_contract(contracts: &[StartupContract], name: &str) -> Option<StartupContract> {
    contracts
        .iter()
        .copied()
        .find(|contract| contract.name() == name)
}

const fn contract_declaration(contract: StartupContract) -> StartupPurposeDeclaration {
    StartupPurposeDeclaration {
        value: contract.purpose(),
        object_kind: contract.object_kind(),
        required_rights: contract.required_rights().bits(),
        allowed_rights: contract.allowed_rights().bits(),
    }
}

const fn duplicate_authority(
    authority: BootstrapAuthority,
    object_kind: u32,
    rights: Rights,
) -> AuthorityDeclaration<'static> {
    AuthorityDeclaration {
        key: authority.key(),
        provider: None,
        object_kind,
        rights: rights.bits(),
        movable: false,
        duplicable: true,
        creatable: false,
    }
}

const fn move_authority(authority: BootstrapAuthority) -> AuthorityDeclaration<'static> {
    AuthorityDeclaration {
        key: authority.key(),
        provider: None,
        object_kind: ByteChannelObject::KIND.as_raw(),
        rights: byte_channel_rights().bits(),
        movable: true,
        duplicable: false,
        creatable: false,
    }
}

const fn create_authority(
    authority: BootstrapAuthority,
    object_kind: u32,
    rights: Rights,
) -> AuthorityDeclaration<'static> {
    AuthorityDeclaration {
        key: authority.key(),
        provider: None,
        object_kind,
        rights: rights.bits(),
        movable: false,
        duplicable: false,
        creatable: true,
    }
}

const fn console_rights() -> Rights {
    Rights::DUPLICATE
        .union(Rights::TRANSFER)
        .union(Rights::WAIT)
        .union(Rights::INSPECT)
        .union(Rights::READ)
        .union(Rights::WRITE)
}

const fn byte_channel_rights() -> Rights {
    Rights::DUPLICATE
        .union(Rights::TRANSFER)
        .union(Rights::WAIT)
        .union(Rights::INSPECT)
        .union(Rights::READ)
        .union(Rights::WRITE)
}

const fn root_directory_rights() -> Rights {
    library_directory_rights()
        .union(Rights::WRITE)
        .union(Rights::SET_ATTRIBUTES)
        .union(Rights::LOCK_FILE)
}

const fn library_directory_rights() -> Rights {
    Rights::DUPLICATE
        .union(Rights::TRANSFER)
        .union(Rights::INSPECT)
        .union(Rights::READ)
        .union(Rights::EXECUTE)
        .union(Rights::PROTECT)
}

const fn task_factory_rights() -> Rights {
    Rights::DUPLICATE
        .union(Rights::TRANSFER)
        .union(Rights::INSPECT)
        .union(Rights::CREATE_PROCESS)
        .union(Rights::RETAIN_PROCESS)
        .union(Rights::CREATE_TASK_GROUP)
}

const fn task_group_rights() -> Rights {
    Rights::DUPLICATE
        .union(Rights::TRANSFER)
        .union(Rights::INSPECT)
        .union(Rights::REQUEST_STOP)
        .union(Rights::TASK_GROUP_ATTACH_PROCESS)
}

const fn resource_domain_rights() -> Rights {
    Rights::DUPLICATE
        .union(Rights::TRANSFER)
        .union(Rights::INSPECT)
        .union(Rights::CREATE_RESOURCE_DOMAIN)
        .union(Rights::RESOURCE_DOMAIN_SPONSOR)
}

const fn vm_authority_rights() -> Rights {
    Rights::DUPLICATE
        .union(Rights::TRANSFER)
        .union(Rights::INSPECT)
        .union(Rights::DERIVE)
        .union(Rights::CREATE_VIRTUAL_MACHINE)
}

const fn inspector_rights() -> Rights {
    Rights::DUPLICATE
        .union(Rights::TRANSFER)
        .union(Rights::INSPECT)
        .union(Rights::DERIVE)
}

const fn observation_rights() -> Rights {
    Rights::DUPLICATE
        .union(Rights::TRANSFER)
        .union(Rights::INSPECT)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoReadyPlanError {
    InvalidGrant,
    MultipleServices,
}

/// Readiness is bound to the dedicated moved capability, never an image name
/// or path prefix. Reject substituting another channel with the same purpose.
pub fn io_ready_service(
    plan: &crate::manifest::LaunchPlan<'_>,
) -> Result<Option<usize>, IoReadyPlanError> {
    let mut selected = None;
    for service in 0..plan.service_count() {
        for index in 0..crate::manifest::MAX_CAPABILITIES_PER_SERVICE {
            let Some(grant) = plan.capability_grant(service, index) else {
                continue;
            };
            let source = grant.authority() == BootstrapAuthority::IoReadyChannel.key();
            let purpose = grant.purpose() == hyper_service::io::READY.as_raw();
            if !source && !purpose {
                continue;
            }
            if !source
                || !purpose
                || grant.operation() != crate::manifest::CapabilityOperation::Move
            {
                return Err(IoReadyPlanError::InvalidGrant);
            }
            if selected.replace(service).is_some() {
                return Err(IoReadyPlanError::MultipleServices);
            }
        }
    }
    Ok(selected)
}

/// Storage control and its selected filesystem worker are separate processes;
/// both bootstrap rendezvous ends must be explicitly granted to distinct services.
pub fn filesystem_enabled(
    plan: &crate::manifest::LaunchPlan<'_>,
) -> Result<bool, IoReadyPlanError> {
    paired_authorities(
        plan,
        [
            (
                BootstrapAuthority::FilesystemAttach,
                hyper_service::filesystem::ATTACH.as_raw(),
            ),
            (
                BootstrapAuthority::FilesystemProvider,
                hyper_service::filesystem::PROVIDER.as_raw(),
            ),
        ],
    )
}

fn paired_authorities(
    plan: &crate::manifest::LaunchPlan<'_>,
    endpoints: [(BootstrapAuthority, u32); 2],
) -> Result<bool, IoReadyPlanError> {
    let mut ends = [None, None];
    for service in 0..plan.service_count() {
        for index in 0..crate::manifest::MAX_CAPABILITIES_PER_SERVICE {
            let Some(grant) = plan.capability_grant(service, index) else {
                continue;
            };
            for (end, (source, purpose)) in endpoints.into_iter().enumerate() {
                if grant.authority() != source.key() && grant.purpose() != purpose {
                    continue;
                }
                if grant.authority() != source.key()
                    || grant.purpose() != purpose
                    || grant.operation() != crate::manifest::CapabilityOperation::Move
                    || ends[end].replace(service).is_some()
                {
                    return Err(IoReadyPlanError::InvalidGrant);
                }
            }
        }
    }
    match ends {
        [None, None] => Ok(false),
        [Some(server), Some(client)] if server != client => Ok(true),
        _ => Err(IoReadyPlanError::InvalidGrant),
    }
}

#[cfg(test)]
#[path = "../tests/bootstrap_policy.rs"]
mod tests;
