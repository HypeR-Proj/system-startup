// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Exact typed inventory. Private wire keys name roles, never sender handle IDs.

mod validation;

use validation::validate_inventory;
#[cfg(test)]
use validation::validate_namespace_source;
pub(super) use validation::{validate_core_sources, validate_service_sources};

use super::super::{
    Runtime, authority::AuthorityInventory, launcher::ServiceLauncher, supervisor::SupervisorSet,
};
use crate::manifest::MAX_SERVICES;
use hyper_os::capability_channel::CapabilityReceiveSlot;
use hyper_os::fs::Directory;
use hyper_os::handle::*;
use serde::{Deserialize, Serialize};

const ROOT_DIRECTORY: u16 = 1;
const LIBRARY_DIRECTORY: u16 = 2;
const FACTORY: u16 = 3;
const GROUP: u16 = 4;
const DOMAIN: u16 = 5;
const TASK_INSPECTOR: u16 = 6;
const OBJECT_INSPECTOR: u16 = 7;
const MEMORY_INSPECTOR: u16 = 8;
const CPU_INSPECTOR: u16 = 9;
const LOG_CONNECTOR: u16 = 10;
const DEVICE: u16 = 11;
const RAW_CONTROL_SERVER: u16 = 12;
const RAW_CONTROLLER: u16 = 13;
const LOG_SERVER: u16 = 14;
const IO_BROKER_SERVER: u16 = 16;
const IO_BROKER_CLIENT: u16 = 17;
const IO_READY: u16 = 18;
const FILESYSTEM_ATTACH: u16 = 19;
const FILESYSTEM_PROVIDER: u16 = 20;
const FILESYSTEM_CONTROL_SERVER: u16 = 21;
const FILESYSTEM_CONTROL_CLIENT: u16 = 22;
const VM_AUTHORITY: u16 = 25;
const SYSTEM_GROUP: u16 = 30;
const CONSOLE: u16 = 31;
const BOOT_ENVIRONMENT: u16 = 32;
const SYSTEM_ENVIRONMENT: u16 = 33;
const STORAGE_HANDOFF: u16 = 34;
const FILESYSTEM_HANDOFF: u16 = 35;
const CONSOLE_DRAIN: u16 = 36;
const ROOT_TRANSITION: u16 = 37;
const LAST_ROLE: u16 = ROOT_TRANSITION;

const PROCESS_BASE: u16 = 100;
const MAX_SLOTS: usize = 64;
const _: () = assert!(LAST_ROLE as usize + MAX_SERVICES <= MAX_SLOTS);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Slot {
    pub(super) key: u16,
    pub(super) rights: u64,
}

fn receive_slot(slot: &Slot) -> hyper_os::Result<CapabilityReceiveSlot> {
    let rights = Rights::from_bits(slot.rights).ok_or(hyper_os::Error::InvalidResponse)?;
    Ok(match slot.key {
        ROOT_DIRECTORY | BOOT_ENVIRONMENT | SYSTEM_ENVIRONMENT => {
            CapabilityReceiveSlot::new::<DirectoryObject>(rights)
        }
        LIBRARY_DIRECTORY => CapabilityReceiveSlot::new::<DirectoryObject>(rights),
        ROOT_TRANSITION => CapabilityReceiveSlot::new::<RootTransitionObject>(rights),
        FACTORY => CapabilityReceiveSlot::new::<TaskFactoryObject>(rights),
        GROUP => CapabilityReceiveSlot::new::<TaskGroupObject>(rights),
        DOMAIN => CapabilityReceiveSlot::new::<ResourceDomainObject>(rights),
        TASK_INSPECTOR => CapabilityReceiveSlot::new::<TaskInspectorObject>(rights),
        OBJECT_INSPECTOR => CapabilityReceiveSlot::new::<ObjectInspectorObject>(rights),
        MEMORY_INSPECTOR => CapabilityReceiveSlot::new::<MemoryInspectorObject>(rights),
        CPU_INSPECTOR => CapabilityReceiveSlot::new::<CpuInspectorObject>(rights),
        LOG_CONNECTOR => CapabilityReceiveSlot::new::<CapabilityChannelObject>(rights),
        DEVICE => CapabilityReceiveSlot::new::<DeviceAssignmentAuthorityObject>(rights),
        RAW_CONTROL_SERVER | RAW_CONTROLLER | LOG_SERVER => {
            CapabilityReceiveSlot::new::<CapabilityChannelObject>(rights)
        }
        STORAGE_HANDOFF | FILESYSTEM_HANDOFF => {
            CapabilityReceiveSlot::new::<CapabilityChannelObject>(rights)
        }
        IO_BROKER_SERVER => CapabilityReceiveSlot::new::<CapabilityChannelObject>(rights),
        IO_BROKER_CLIENT => CapabilityReceiveSlot::new::<CapabilityChannelObject>(rights),
        CONSOLE_DRAIN => CapabilityReceiveSlot::new::<ByteChannelObject>(rights),
        IO_READY => CapabilityReceiveSlot::new::<ByteChannelObject>(rights),
        FILESYSTEM_ATTACH => CapabilityReceiveSlot::new::<CapabilityChannelObject>(rights),
        FILESYSTEM_PROVIDER => CapabilityReceiveSlot::new::<CapabilityChannelObject>(rights),
        FILESYSTEM_CONTROL_SERVER => CapabilityReceiveSlot::new::<CapabilityChannelObject>(rights),
        FILESYSTEM_CONTROL_CLIENT => CapabilityReceiveSlot::new::<CapabilityChannelObject>(rights),
        VM_AUTHORITY => CapabilityReceiveSlot::new::<VirtualMachineCreationAuthorityObject>(rights),
        SYSTEM_GROUP => CapabilityReceiveSlot::new::<TaskGroupObject>(rights),
        CONSOLE => CapabilityReceiveSlot::new::<ConsoleObject>(rights),
        key if (PROCESS_BASE..PROCESS_BASE + MAX_SERVICES as u16).contains(&key) => {
            CapabilityReceiveSlot::new::<ProcessObject>(rights)
        }
        _ => return Err(hyper_os::Error::InvalidResponse),
    })
}

pub(super) fn prepare_receive(
    slots: &[Slot],
    core_count: usize,
) -> hyper_os::Result<Vec<CapabilityReceiveSlot>> {
    validate_inventory(slots, core_count)?;
    slots.iter().map(receive_slot).collect()
}

struct Received<'a> {
    descriptors: &'a [Slot],
    slots: &'a mut [CapabilityReceiveSlot],
}
impl Received<'_> {
    fn optional<T: TypedObject>(&mut self, key: u16) -> hyper_os::Result<Option<OwnedHandle<T>>> {
        match self.descriptors.iter().position(|s| s.key == key) {
            Some(index) => self.slots[index].take::<T>(),
            None => Ok(None),
        }
    }
    fn required<T: TypedObject>(&mut self, key: u16) -> hyper_os::Result<OwnedHandle<T>> {
        self.optional(key)?.ok_or(hyper_os::Error::MissingHandle)
    }
}

pub(super) fn adopt(
    descriptors: &[Slot],
    slots: &mut [CapabilityReceiveSlot],
    installer: OwnedHandle<CapabilityChannelObject>,
) -> hyper_os::Result<Runtime> {
    let mut r = Received { descriptors, slots };
    let authorities = AuthorityInventory {
        observe: None,
        control: None,
        journal_query: None,
        journal_active: false,
        root_directory: Directory::from_handle(r.required(ROOT_DIRECTORY)?),
        boot_environment: Some(Directory::from_handle(r.required(BOOT_ENVIRONMENT)?)),
        system_environment: Some(Directory::from_handle(r.required(SYSTEM_ENVIRONMENT)?)),
        library_directory: Directory::from_handle(r.required(LIBRARY_DIRECTORY)?),
        factory: r.required(FACTORY)?,
        group: r.required(SYSTEM_GROUP)?,
        domain: r.required(DOMAIN)?,
        task_inspector: r.required(TASK_INSPECTOR)?,
        object_inspector: r.required(OBJECT_INSPECTOR)?,
        memory_inspector: r.required(MEMORY_INSPECTOR)?,
        cpu_inspector: r.required(CPU_INSPECTOR)?,
        log_connector: r.required(LOG_CONNECTOR)?,
        device: r.optional(DEVICE)?,
        raw_control_server: r.optional(RAW_CONTROL_SERVER)?,
        raw_controller: r.optional(RAW_CONTROLLER)?,
        log_server: r.optional(LOG_SERVER)?,
        console_drain: r.optional(CONSOLE_DRAIN)?,
        storage_handoff: r.optional(STORAGE_HANDOFF)?,
        filesystem_handoff: r.optional(FILESYSTEM_HANDOFF)?,
        io_broker_server: r.optional(IO_BROKER_SERVER)?,
        io_broker_client: r.optional(IO_BROKER_CLIENT)?,
        io_ready_channel: r.optional(IO_READY)?,
        filesystem_attach: r.optional(FILESYSTEM_ATTACH)?,
        filesystem_provider: r.optional(FILESYSTEM_PROVIDER)?,
        filesystem_control_server: r.optional(FILESYSTEM_CONTROL_SERVER)?,
        filesystem_control_client: r.optional(FILESYSTEM_CONTROL_CLIENT)?,
        vm_creation: r.optional(VM_AUTHORITY)?,
        vm_fleet: None,
        vm_connection: None,
        console: r.required(CONSOLE)?,
    };
    let mut processes = std::array::from_fn(|_| None);
    for (index, process) in processes.iter_mut().enumerate() {
        *process = r.optional(PROCESS_BASE + index as u16)?;
    }
    Ok(Runtime {
        installer: installer.duplicate(hyper_service_ipc::CLIENT_RIGHTS)?,
        launcher: ServiceLauncher { authorities },
        supervisors: SupervisorSet {
            installer,
            managed_paths: core::array::from_fn(|_| None),
            processes,
        },
        _boot_group: r.required(GROUP)?,
        bootstrap_storage_ready: false,
        providers: [None; 3],
        storage_successor: None,
        core_count: 0,
        retired_processes: Vec::new(),
        pending_provider: None,
        unconfirmed_providers: Vec::new(),
        retirement_path: None,
        retirement_ready: false,
        old_console: None,
        session_releases: Vec::new(),
    })
}

#[cfg(test)]
#[path = "../../../tests/handoff_inventory.rs"]
mod tests;
