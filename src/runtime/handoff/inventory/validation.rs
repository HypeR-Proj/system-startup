// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Admit the complete supervisor and launch authority before accepting MOVE.

use super::*;
use crate::bootstrap_policy::BootstrapAuthority;
use crate::manifest::{CapabilityOperation, LaunchPlan, Manifest};

const PROPAGATE: Rights = Rights::DUPLICATE.union(Rights::TRANSFER);
const SUPERVISOR: Rights = Rights::WAIT
    .union(Rights::INSPECT)
    .union(Rights::REQUEST_STOP)
    .union(Rights::TRANSFER);

fn require(slots: &[Slot], key: u16, required: Rights) -> hyper_os::Result<()> {
    let slot = slots
        .iter()
        .find(|slot| slot.key == key)
        .ok_or(hyper_os::Error::MissingHandle)?;
    let rights = Rights::from_bits(slot.rights).ok_or(hyper_os::Error::InvalidResponse)?;
    if !rights.contains(required) {
        return Err(hyper_os::Error::MissingHandle);
    }
    Ok(())
}

/// Validates all role/type/shape invariants before registration can accept MOVE.
pub(super) fn validate_inventory(slots: &[Slot], core_count: usize) -> hyper_os::Result<()> {
    if slots.len() > MAX_SLOTS || core_count > MAX_SERVICES {
        return Err(hyper_os::Error::InvalidResponse);
    }
    for (index, slot) in slots.iter().enumerate() {
        if !matches!(
            slot.key,
            ROOT_DIRECTORY..=LOG_SERVER
                | IO_BROKER_SERVER..=FILESYSTEM_CONTROL_CLIENT
                | VM_AUTHORITY
                | SYSTEM_GROUP..=ROOT_TRANSITION
        ) && !(PROCESS_BASE..PROCESS_BASE + MAX_SERVICES as u16).contains(&slot.key)
        {
            return Err(hyper_os::Error::InvalidResponse);
        }
        if Rights::from_bits(slot.rights).is_none() {
            return Err(hyper_os::Error::InvalidResponse);
        }
        if slots[..index].iter().any(|s| s.key == slot.key)
            || (slot.key >= PROCESS_BASE && usize::from(slot.key - PROCESS_BASE) >= core_count)
        {
            return Err(hyper_os::Error::InvalidResponse);
        }
    }
    for required in [
        ROOT_TRANSITION,
        BOOT_ENVIRONMENT,
        SYSTEM_ENVIRONMENT,
        ROOT_DIRECTORY,
        LIBRARY_DIRECTORY,
        FACTORY,
        GROUP,
        DOMAIN,
        TASK_INSPECTOR,
        OBJECT_INSPECTOR,
        MEMORY_INSPECTOR,
        CPU_INSPECTOR,
        LOG_CONNECTOR,
        SYSTEM_GROUP,
        CONSOLE,
    ] {
        if !slots.iter().any(|s| s.key == required) {
            return Err(hyper_os::Error::InvalidResponse);
        }
    }
    validate_namespace_source(slots)?;
    for (key, required) in [
        (ROOT_TRANSITION, Rights::WRITE.union(Rights::TRANSFER)),
        (
            FACTORY,
            Rights::CREATE_PROCESS
                .union(Rights::CREATE_TASK_GROUP)
                .union(Rights::LOCK_MEMORY)
                .union(Rights::RETAIN_PROCESS),
        ),
        (
            GROUP,
            Rights::REQUEST_STOP
                .union(Rights::WAIT)
                .union(Rights::INSPECT)
                .union(PROPAGATE),
        ),
        (SYSTEM_GROUP, Rights::TASK_GROUP_ATTACH_PROCESS),
        (DOMAIN, Rights::RESOURCE_DOMAIN_SPONSOR),
        (
            LIBRARY_DIRECTORY,
            Rights::READ
                .union(Rights::EXECUTE)
                .union(Rights::PROTECT)
                .union(PROPAGATE),
        ),
        (LOG_CONNECTOR, Rights::WRITE.union(Rights::WAIT)),
        (CONSOLE, Rights::WRITE.union(Rights::WAIT)),
        (
            BOOT_ENVIRONMENT,
            hyper_service::process::ENVIRONMENT_DIRECTORY_CONTRACT.required_rights(),
        ),
        (
            SYSTEM_ENVIRONMENT,
            hyper_service::process::ENVIRONMENT_DIRECTORY_CONTRACT.required_rights(),
        ),
    ] {
        require(slots, key, required)?;
    }
    for slot in slots.iter().filter(|slot| slot.key >= PROCESS_BASE) {
        require(slots, slot.key, SUPERVISOR)?;
    }
    Ok(())
}

/// The live root must support both namespace publication and opening the
/// delegated ELF/environment handles used by every formal launch.
pub(super) fn validate_namespace_source(slots: &[Slot]) -> hyper_os::Result<()> {
    require(
        slots,
        ROOT_DIRECTORY,
        hyper_service::process::ENVIRONMENT_DIRECTORY_CONTRACT
            .required_rights()
            .union(Rights::MANAGE_NAMESPACE)
            .union(Rights::WRITE),
    )
}

/// Failed optional bootstrap services need no owner. A live provider can be
/// adopted only together with its supervisor and private migration endpoint.
pub(in crate::runtime::handoff) fn validate_core_sources(
    slots: &[Slot],
    core: &Manifest<'_>,
    providers: [Option<usize>; 3],
    storage_ready: bool,
) -> hyper_os::Result<()> {
    for (index, service) in core.services().enumerate() {
        if service.critical() {
            require(slots, PROCESS_BASE + index as u16, SUPERVISOR)?;
        }
    }
    for (role, index) in providers.into_iter().enumerate() {
        let Some(index) = index else { continue };
        if role != 0 && !storage_ready {
            continue;
        }
        require(slots, PROCESS_BASE + index as u16, SUPERVISOR)?;
        match role {
            0 => {
                require(
                    slots,
                    CONSOLE_DRAIN,
                    Rights::READ.union(Rights::WRITE).union(Rights::WAIT),
                )?;
                require(
                    slots,
                    CONSOLE,
                    Rights::READ
                        .union(Rights::WRITE)
                        .union(Rights::WAIT)
                        .union(PROPAGATE),
                )?;
            }
            1 => require(
                slots,
                STORAGE_HANDOFF,
                Rights::READ
                    .union(Rights::WRITE)
                    .union(Rights::WAIT)
                    .union(Rights::TRANSFER),
            )?,
            2 => {
                require(
                    slots,
                    FILESYSTEM_HANDOFF,
                    Rights::READ
                        .union(Rights::WRITE)
                        .union(Rights::WAIT)
                        .union(Rights::TRANSFER),
                )?;
                require(
                    slots,
                    FACTORY,
                    Rights::CREATE_PROCESS
                        .union(Rights::CREATE_TASK_GROUP)
                        .union(Rights::LOCK_MEMORY)
                        .union(Rights::RETAIN_PROCESS)
                        .union(PROPAGATE),
                )?;
                require(
                    slots,
                    DOMAIN,
                    Rights::CREATE_RESOURCE_DOMAIN
                        .union(Rights::RESOURCE_DOMAIN_SPONSOR)
                        .union(PROPAGATE),
                )?;
                require(
                    slots,
                    SYSTEM_GROUP,
                    Rights::TASK_GROUP_ATTACH_PROCESS.union(PROPAGATE),
                )?;
            }
            _ => return Err(hyper_os::Error::InvalidResponse),
        }
    }
    Ok(())
}

/// Policy checks the requested grants against its maximum authority; admission
/// must additionally check the authority actually offered by this predecessor.
pub(in crate::runtime::handoff) fn validate_service_sources(
    slots: &[Slot],
    plan: &LaunchPlan<'_>,
    core_count: usize,
    providers: [Option<usize>; 3],
) -> hyper_os::Result<()> {
    let manager = plan.unique_service_for_purpose(hyper_service::vm::PROVISIONING.as_raw());
    if manager.is_some() {
        require(slots, DOMAIN, Rights::CREATE_RESOURCE_DOMAIN)?;
    }
    for service in core_count..plan.service_count() {
        for capability in 0..crate::manifest::MAX_CAPABILITIES_PER_SERVICE {
            let Some(grant) = plan.capability_grant(service, capability) else {
                continue;
            };
            let authority = BootstrapAuthority::from_key(grant.authority())
                .ok_or(hyper_os::Error::InvalidResponse)?;
            let key = match authority {
                BootstrapAuthority::ComponentObserve
                | BootstrapAuthority::ComponentControl
                | BootstrapAuthority::JournalQuery => continue,
                BootstrapAuthority::Console => CONSOLE,
                // Confirmed console adoption publishes fresh full-rights client
                // endpoints before launching the formal graph. Old controller
                // attenuation does not constrain them. If adoption fails, the
                // retained old endpoints may permit only degraded operation.
                BootstrapAuthority::ConsoleController | BootstrapAuthority::ConsoleLogConnector
                    if providers[0].is_some() =>
                {
                    continue;
                }
                BootstrapAuthority::ConsoleControlServer => RAW_CONTROL_SERVER,
                BootstrapAuthority::ConsoleController => RAW_CONTROLLER,
                BootstrapAuthority::ConsoleLogServer => LOG_SERVER,
                BootstrapAuthority::ConsoleLogConnector => LOG_CONNECTOR,
                BootstrapAuthority::EnvironmentDirectory => SYSTEM_ENVIRONMENT,
                BootstrapAuthority::BootEnvironmentDirectory => BOOT_ENVIRONMENT,
                BootstrapAuthority::RootDirectory => ROOT_DIRECTORY,
                BootstrapAuthority::DynamicLibraryDirectory => LIBRARY_DIRECTORY,
                BootstrapAuthority::TaskFactory => FACTORY,
                BootstrapAuthority::TaskGroup if Some(service) != manager => SYSTEM_GROUP,
                BootstrapAuthority::ResourceDomain if Some(service) != manager => DOMAIN,
                BootstrapAuthority::TaskInspector => TASK_INSPECTOR,
                BootstrapAuthority::ObjectInspector => OBJECT_INSPECTOR,
                BootstrapAuthority::MemoryInspector => MEMORY_INSPECTOR,
                BootstrapAuthority::CpuInspector => CPU_INSPECTOR,
                BootstrapAuthority::VmAuthority => VM_AUTHORITY,
                BootstrapAuthority::DeviceAuthority => DEVICE,
                BootstrapAuthority::IoReadyChannel => IO_READY,
                BootstrapAuthority::IoBrokerServer => IO_BROKER_SERVER,
                BootstrapAuthority::IoBrokerClient => IO_BROKER_CLIENT,
                BootstrapAuthority::FilesystemAttach => FILESYSTEM_ATTACH,
                BootstrapAuthority::FilesystemProvider => FILESYSTEM_PROVIDER,
                BootstrapAuthority::FilesystemControlServer => FILESYSTEM_CONTROL_SERVER,
                BootstrapAuthority::FilesystemControlClient => FILESYSTEM_CONTROL_CLIENT,
                // These are opened from the validated environments or freshly
                // created by the coordinator, not transferred from bootstrap.
                BootstrapAuthority::ChildLoader
                | BootstrapAuthority::VmRuntimeImage
                | BootstrapAuthority::VmProvisioningChannel
                | BootstrapAuthority::VmManagerConnectionChannel
                | BootstrapAuthority::VmClientConnectionChannel
                | BootstrapAuthority::ServiceOutputChannel
                | BootstrapAuthority::TaskGroup
                | BootstrapAuthority::ResourceDomain => continue,
            };
            let operation = match grant.operation() {
                CapabilityOperation::Duplicate => PROPAGATE,
                CapabilityOperation::Move => Rights::TRANSFER,
                CapabilityOperation::Create => return Err(hyper_os::Error::InvalidResponse),
            };
            let required =
                Rights::from_bits(grant.rights()).ok_or(hyper_os::Error::InvalidResponse)?;
            require(slots, key, required.union(operation))?;
        }
    }
    Ok(())
}
