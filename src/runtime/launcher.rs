// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Transactional process construction from a validated launch plan.

use crate::manifest::{LaunchPlan, Service, ServicePhase};
use hyper_os::handle::{OwnedHandle, ProcessObject, Rights, RightsOffer};
use hyper_os::startup;
use hyper_os::task::ProcessBuilder;

use super::LaunchError;
use super::authority::AuthorityInventory;
use super::fleet::VmFleet;

/// Applies validated service declarations to the live authority inventory.
pub(super) struct ServiceLauncher {
    pub(super) authorities: AuthorityInventory,
}

pub(super) struct LaunchInstance<'a> {
    pub program: &'a hyper_component_config::Program,
    pub component: &'a str,
    pub installer: hyper_os::handle::HandleRef<'a, hyper_os::handle::CapabilityChannelObject>,
    pub number: u64,
    pub group: &'a OwnedHandle<hyper_os::handle::TaskGroupObject>,
    pub session_start: Option<OwnedHandle<hyper_os::handle::ByteChannelObject>>,
    pub notify: OwnedHandle<hyper_os::handle::ByteChannelObject>,
}

impl ServiceLauncher {
    pub(super) fn launch_service(
        &mut self,
        service: &Service<'_>,
        service_index: usize,
        vm_manager_index: Option<usize>,
        plan: &LaunchPlan<'_>,
        instance: LaunchInstance<'_>,
    ) -> Result<OwnedHandle<ProcessObject>, LaunchError> {
        let LaunchInstance {
            program,
            component,
            installer,
            number,
            group,
            notify,
            session_start,
        } = instance;
        let executable = self
            .authorities
            .root_directory
            .open(
                service.image(),
                hyper_service::process::EXECUTABLE_FILE_RIGHTS,
            )
            .map_err(LaunchError::service_operation)?;
        let vm_fleet_scope = Some(service_index) == vm_manager_index;
        if vm_fleet_scope && self.authorities.vm_fleet.is_none() {
            self.authorities.vm_fleet = Some(
                VmFleet::new(
                    self.authorities.factory.as_handle_ref(),
                    self.authorities.domain.as_handle_ref(),
                )
                .map_err(LaunchError::service_resources)?,
            );
        }
        let environment = match service.phase() {
            ServicePhase::Boot => self
                .authorities
                .boot_environment
                .as_ref()
                .ok_or(LaunchError::InvalidPlan)?,
            ServicePhase::System => self
                .authorities
                .system_environment
                .as_ref()
                .ok_or(LaunchError::InvalidPlan)?,
        };
        // Retain a local fixed scope before offers consume inventory fields.
        let environment = hyper_service::process::open_environment(environment, "/")
            .map_err(LaunchError::service_resources)?;
        let loader = hyper_service::process::open_loader(&environment, service.loader())
            .map_err(LaunchError::service_operation)?;
        let builder = ProcessBuilder::create(
            self.authorities.factory.as_handle_ref(),
            if vm_fleet_scope {
                self.authorities.vm_fleet()?.group.as_handle_ref()
            } else {
                group.as_handle_ref()
            },
            if vm_fleet_scope {
                self.authorities.vm_fleet()?.domain.as_handle_ref()
            } else {
                self.authorities.domain.as_handle_ref()
            },
            executable.as_handle_ref(),
            loader.as_handle_ref(),
        )
        .map_err(LaunchError::service_operation)?;
        builder
            .set_name(component.rsplit('/').next().unwrap_or(component))
            .map_err(LaunchError::service_resources)?;
        builder
            .add_argument(service.image())
            .map_err(LaunchError::service_resources)?;
        builder
            .set_memory_lock_allowed(program.resident)
            .map_err(LaunchError::service_resources)?;
        builder
            .add_handle_duplicate(
                self.authorities.library_directory.as_handle_ref(),
                startup::DYNAMIC_LIBRARY_DIRECTORY.as_raw(),
                RightsOffer::Exact(Rights::READ.union(Rights::EXECUTE).union(Rights::PROTECT)),
            )
            .map_err(LaunchError::service_resources)?;

        for argument in &program.arguments {
            builder
                .add_argument(argument)
                .map_err(LaunchError::service_resources)?;
        }
        self.stdio(&builder, component, number)
            .map_err(LaunchError::service_resources)?;
        builder
            .add_handle_move(
                notify,
                hyper_component::NOTIFY.as_raw(),
                RightsOffer::Exact(Rights::WRITE.union(Rights::WAIT).union(Rights::DUPLICATE)),
            )
            .map_err(|failure| LaunchError::service_resources(failure.error()))?;
        if let Some(start) = session_start {
            builder
                .add_handle_move(
                    start,
                    hyper_service::session::START.as_raw(),
                    RightsOffer::Exact(Rights::READ.union(Rights::WAIT)),
                )
                .map_err(|failure| LaunchError::service_resources(failure.error()))?;
        }
        for (capability_index, _) in service.capabilities().enumerate() {
            let grant = plan
                .capability_grant(service_index, capability_index)
                .ok_or(LaunchError::InvalidPlan)?;
            if grant.purpose() == startup::TASK_GROUP.as_raw() && !vm_fleet_scope {
                let rights = Rights::from_bits(grant.rights()).ok_or(LaunchError::InvalidPlan)?;
                builder
                    .add_handle_duplicate(
                        group.as_handle_ref(),
                        grant.purpose(),
                        RightsOffer::Exact(rights),
                    )
                    .map_err(LaunchError::service_resources)?;
                continue;
            }
            self.authorities
                .offer(grant, vm_fleet_scope, &builder, &loader, &environment)?;
        }

        let selected_group = if vm_fleet_scope {
            &self.authorities.vm_fleet()?.group
        } else {
            group
        };
        let group = selected_group
            .duplicate(
                Rights::WAIT
                    .union(Rights::INSPECT)
                    .union(Rights::REQUEST_STOP)
                    .union(Rights::TRANSFER),
            )
            .map_err(LaunchError::service_resources)?;
        hyper_component::installation::prepared(installer, component, builder, group)
            .map_err(LaunchError::service_resources)
    }
}
