// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Business VM resources, allocated only when their manager is launched.

use hyper_os::capability_channel::CapabilityChannel;
use hyper_os::handle::{
    CapabilityChannelObject, HandleRef, OwnedHandle, ResourceDomainObject, TaskFactoryObject,
    TaskGroupObject,
};
use hyper_os::task::{create_resource_domain, create_task_group};
use hyper_vm_policy::VM_FLEET_LIMITS;

use super::provision::FleetProvisioner;

/// The I/O runtime never borrows this scope or its provisioning transport.
pub(super) struct VmFleet {
    pub(super) group: OwnedHandle<TaskGroupObject>,
    pub(super) domain: OwnedHandle<ResourceDomainObject>,
    pub(super) provisioning: Option<OwnedHandle<CapabilityChannelObject>>,
    pub(super) provisioner: Option<FleetProvisioner>,
}

impl VmFleet {
    pub(super) fn new(
        factory: HandleRef<'_, TaskFactoryObject>,
        parent: HandleRef<'_, ResourceDomainObject>,
    ) -> hyper_os::Result<Self> {
        let domain = create_resource_domain(parent, VM_FLEET_LIMITS)?;
        let group = create_task_group(factory, domain.as_handle_ref())?;
        let (sender, receiver) = CapabilityChannel::create()?;
        Ok(Self {
            group,
            domain,
            provisioning: Some(receiver.into_handle()),
            provisioner: Some(FleetProvisioner { channel: sender }),
        })
    }
}

/// A shell may receive a connection before the system manager exists. Keeping
/// this rendezvous separate does not allocate a fleet or require VM authority.
pub(super) struct VmManagerConnection {
    pub(super) client: OwnedHandle<CapabilityChannelObject>,
    pub(super) server: Option<OwnedHandle<CapabilityChannelObject>>,
}

impl VmManagerConnection {
    pub(super) fn new() -> hyper_os::Result<Self> {
        let (client, server) = CapabilityChannel::create()?;
        Ok(Self {
            client: client.into_handle(),
            server: Some(server.into_handle()),
        })
    }
}
